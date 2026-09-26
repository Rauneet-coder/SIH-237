const crypto = require('node:crypto');
const Document = require('../models/Document');
const User = require('../models/User');
const cryptoService = require('./cryptoService');
const keyEnvelopeService = require('./keyEnvelopeService');
const keyAgentClient = require('./keyAgentClient');
const provenanceService = require('./provenanceService');
const collusionService = require('./collusionService');
const logger = require('../utils/logger');
const { NotFoundError, AuthorizationError, ValidationError, CryptoError } = require('../utils/errors');

/**
 * Upload and encrypt a document for multi-recipient distribution
 * - Generates random 32-byte AES DEK
 * - Encrypts plaintext file exactly ONCE using AES-256-GCM
 * - Encapsulates DEK for each recipient using NIST FIPS 203 ML-KEM-1024
 * - Retains legacy RSA-OAEP wrapping for backwards compatibility
 * - Immutably logs upload event
 * - Securely zeroizes plaintext DEK from volatile memory
 */
async function uploadAndEncryptDocument({
  title,
  fileBuffer,
  fileName,
  mimeType = 'application/pdf',
  senderId,
  recipientIds = [],
  classification = 'CONFIDENTIAL'
}) {
  if (!title) {
    throw new ValidationError('Document title is required');
  }
  if (!fileBuffer || fileBuffer.length === 0) {
    throw new ValidationError('Document file buffer is empty or missing');
  }
  if (!senderId) {
    throw new ValidationError('Sender ID is required');
  }

  // 1. Calculate plaintext SHA-256 hash (canonical binding)
  const fileHash = cryptoService.computeHash(fileBuffer);
  const documentId = `DOC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

  // 2. Fetch and validate recipients
  const recipients = await User.find({ _id: { $in: recipientIds }, isActive: true }).exec();
  if (recipients.length === 0 && recipientIds.length > 0) {
    throw new ValidationError('No valid active recipients found for specified IDs');
  }

  // 3. Generate symmetric DEK and encrypt document ONCE with AES-256-GCM
  const symmetricKey = cryptoService.generateSymmetricKey();
  const { encryptedBlob, iv, authTag } = cryptoService.encryptDocument(fileBuffer, symmetricKey);

  // 4. Build per-recipient ML-KEM Key Envelopes and legacy RSA keys
  const keyEnvelopes = [];
  const recipientKeys = [];

  for (const recipient of recipients) {
    // Post-Quantum ML-KEM Envelope
    if (recipient.mlKemPublicKey) {
      try {
        const envelope = await keyEnvelopeService.createEnvelope({
          dek: symmetricKey,
          recipientId: recipient._id.toString(),
          mlKemPublicKey: recipient.mlKemPublicKey,
          documentId,
          documentHash: fileHash
        });
        keyEnvelopes.push(envelope);
      } catch (err) {
        logger.warn(`Failed to create ML-KEM envelope for recipient ${recipient.username}`, {
          error: err.message
        });
      }
    }

    // Legacy RSA Wrapping
    if (recipient.publicKey) {
      const encryptedSymmetricKey = cryptoService.encryptSymmetricKey(
        symmetricKey,
        recipient.publicKey
      );
      recipientKeys.push({
        recipientId: recipient._id,
        encryptedSymmetricKey
      });
    }
  }

  // Also create an envelope for the sender so the sender can manage access later
  const senderUser = await User.findById(senderId).exec();
  if (senderUser && senderUser.mlKemPublicKey) {
    try {
      const senderEnvelope = await keyEnvelopeService.createEnvelope({
        dek: symmetricKey,
        recipientId: senderUser._id.toString(),
        mlKemPublicKey: senderUser.mlKemPublicKey,
        documentId,
        documentHash: fileHash
      });
      keyEnvelopes.push(senderEnvelope);
    } catch (err) {
      logger.warn('Failed to create sender key envelope', { error: err.message });
    }
  }

  // 5. SECURE ZEROIZATION: Purge plaintext DEK from volatile memory
  symmetricKey.fill(0);

  // 6. Store document record
  const document = new Document({
    documentId,
    title,
    senderId,
    fileName: fileName || 'document.pdf',
    mimeType,
    fileSize: fileBuffer.length,
    fileHash,
    encryptedBlob,
    iv,
    authTag,
    classification,
    recipientKeys,
    keyEnvelopes
  });

  await document.save();

  logger.securityAudit('DOCUMENT_UPLOAD_ENCRYPT_ONCE', {
    docId: document._id.toString(),
    documentId,
    fileHash,
    recipientCount: keyEnvelopes.length,
    algorithm: 'AES-256-GCM + ML-KEM-1024'
  });

  // 7. Log upload event to provenance audit chain
  await provenanceService.logProvenanceEvent({
    docId: document._id,
    recipientId: senderId,
    action: 'DOCUMENT_UPLOAD',
    status: 'SUCCESS',
    details: {
      title,
      fileName: document.fileName,
      fileHash,
      recipientCount: keyEnvelopes.length
    }
  });

  return document;
}

/**
 * Decrypt document for an authorized recipient with attribution logging
 * Supports both modern ML-KEM key agent decapsulation and legacy RSA keys
 */
async function decryptDocumentForRecipient({
  docId,
  recipientId,
  recipientPrivateKeyPem = null,
  recipientUsername = null
}) {
  const document = await Document.findById(docId).exec();
  if (!document) {
    throw new NotFoundError('Document');
  }

  // Find recipient user profile
  const user = await User.findById(recipientId).exec();
  const username = recipientUsername || (user ? user.username : recipientId.toString());

  // Check if recipient is authorized in ML-KEM envelopes or legacy keys
  const mlKemEnvelope = (document.keyEnvelopes || []).find(
    (env) => env.recipientId.toString() === recipientId.toString()
  );
  const legacyEntry = (document.recipientKeys || []).find(
    (rk) => rk.recipientId.toString() === recipientId.toString()
  );

  if (!mlKemEnvelope && !legacyEntry) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: 'Unauthorized: recipient not in document distribution list' }
    });
    throw new AuthorizationError('Access denied: you are not an authorized recipient for this document');
  }

  // Log decryption attempt
  await provenanceService.logProvenanceEvent({
    docId,
    recipientId,
    action: 'DECRYPT_ATTEMPT',
    status: 'SUCCESS',
    details: { fileHash: document.fileHash }
  });

  // 1. Recover DEK via ML-KEM Key Agent OR legacy RSA
  let symmetricKey;
  if (mlKemEnvelope && keyAgentClient.hasRecipient(username)) {
    try {
      symmetricKey = await keyEnvelopeService.unwrapEnvelope({
        envelope: mlKemEnvelope,
        recipientUsername: username,
        recipientId: recipientId.toString(),
        documentId: document.documentId || document._id.toString(),
        documentHash: document.fileHash
      });
    } catch (err) {
      logger.warn('ML-KEM unwrap failed, falling back to legacy if provided', { error: err.message });
    }
  }

  if (!symmetricKey && legacyEntry && recipientPrivateKeyPem) {
    try {
      symmetricKey = cryptoService.decryptSymmetricKey(
        legacyEntry.encryptedSymmetricKey,
        recipientPrivateKeyPem
      );
    } catch (err) {
      await provenanceService.logProvenanceEvent({
        docId,
        recipientId,
        action: 'DECRYPT_FAILURE',
        status: 'FAILURE',
        details: { reason: `RSA-OAEP private key unwrap error: ${err.message}` }
      });
      throw new ValidationError(`Decryption failed: invalid private key provided (${err.message})`);
    }
  }

  if (!symmetricKey) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: 'Unable to recover DEK: no active ML-KEM Key Agent or valid RSA key' }
    });
    throw new AuthorizationError('Unable to recover document encryption key. Cryptographic credentials missing or revoked.');
  }

  // 2. Decrypt document with AES-256-GCM and verify authentication tag
  let decryptedBuffer;
  try {
    decryptedBuffer = cryptoService.decryptDocument(
      document.encryptedBlob,
      symmetricKey,
      document.iv,
      document.authTag
    );
  } catch (err) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: `AES-256-GCM decryption failed: ${err.message}` }
    });
    throw new CryptoError('Document decryption failed: ciphertext or auth tag invalid');
  } finally {
    // Zeroize recovered DEK from volatile memory
    symmetricKey.fill(0);
  }

  // 3. Integrity validation: Assert SHA-256(Decrypted) == fileHash
  const decryptedHash = cryptoService.computeHash(decryptedBuffer);
  if (decryptedHash !== document.fileHash) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: 'Decrypted content hash mismatch' }
    });
    throw new CryptoError('Integrity check failed: document hash mismatch');
  }

  // 4. Generate fingerprint codeword
  const biases = collusionService.generateBiasVector(document._id.toString());
  const codeword = collusionService.generateRecipientCodeword(
    document._id.toString(),
    recipientId.toString(),
    biases
  );

  // 5. Decryption success attribution log
  const logEntry = await provenanceService.logProvenanceEvent({
    docId,
    recipientId,
    action: 'DECRYPT_SUCCESS',
    status: 'SUCCESS',
    details: {
      fileHash: document.fileHash,
      fileSize: decryptedBuffer.length,
      fingerprintCodewordHash: cryptoService.computeHash(codeword),
      algorithm: 'TARDOS-256-COLLUSION-RESISTANT'
    }
  });

  // 6. Embed forensic collusion-secure fingerprint
  const fingerprintedBuffer = collusionService.embedForensicFingerprint(decryptedBuffer, {
    codeword,
    recipientId,
    sequenceNumber: logEntry.sequenceNumber
  });

  return {
    document,
    decryptedBuffer: fingerprintedBuffer,
    fingerprintCodeword: codeword
  };
}

module.exports = {
  uploadAndEncryptDocument,
  decryptDocumentForRecipient
};
