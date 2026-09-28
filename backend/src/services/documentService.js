'use strict';

const crypto = require('node:crypto');
const Document = require('../models/Document');
const User = require('../models/User');
const cryptoService = require('./cryptoService');
const keyEnvelopeService = require('./keyEnvelopeService');
const keyAgentClient = require('./keyAgentClient');
const fileVaultService = require('./fileVaultService');
const provenanceService = require('./provenanceService');
const collusionService = require('./collusionService');
const fingerprintService = require('./fingerprintService');
const logger = require('../utils/logger');
const { NotFoundError, AuthorizationError, ValidationError, CryptoError } = require('../utils/errors');

/**
 * Upload and encrypt a document for multi-recipient distribution
 * - Validates PDF buffer format and size boundaries
 * - Generates random 32-byte AES DEK
 * - Encrypts plaintext file exactly ONCE using AES-256-GCM
 * - Encapsulates DEK for each recipient using NIST FIPS 203 ML-KEM-1024
 * - Retains legacy RSA-OAEP wrapping for backwards compatibility
 * - Stores ciphertext in isolated filesystem vault with mode 0600 (omits 50MB Base64 duplicate in MongoDB)
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
  classification = 'CONFIDENTIAL',
  validFrom = null,
  validUntil = null
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

  // 1. Validate PDF format and bounds (HLD 1.6 & 1.7)
  fileVaultService.validatePdfBuffer(fileBuffer);

  // 2. Calculate plaintext SHA-256 hash (canonical binding) & structural layout fingerprint (HLD 1.2 & 1.3)
  const fileHash = cryptoService.computeHash(fileBuffer);
  const structuralFingerprint = fingerprintService.computeStructuralFingerprint(fileBuffer, mimeType);
  // High-entropy 16 hex char (8 byte) document identifier per HLD 1.1
  const documentId = `DOC-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;

  // 3. Fetch and validate recipients
  const recipients = await User.find({ _id: { $in: recipientIds }, isActive: true }).exec();
  if (recipients.length === 0 && recipientIds.length > 0) {
    throw new ValidationError('No valid active recipients found for specified IDs');
  }

  // 4. Generate symmetric DEK and encrypt document ONCE with AES-256-GCM
  const symmetricKey = cryptoService.generateSymmetricKey();
  const { encryptedBlob, iv, authTag } = cryptoService.encryptDocument(fileBuffer, symmetricKey);

  // 5. Build per-recipient ML-KEM Key Envelopes and legacy RSA keys (Fail-Closed: HLD 2.2)
  const keyEnvelopes = [];
  const recipientKeys = [];

  for (const recipient of recipients) {
    let encapsulated = false;

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
        encapsulated = true;
      } catch (err) {
        symmetricKey.fill(0);
        logger.error(`Fail-closed: Key encapsulation failed for recipient ${recipient.username}`, {
          error: err.message
        });
        throw new CryptoError(`Fail-closed: Key encapsulation failed for recipient ${recipient.username}: ${err.message}`);
      }
    }

    // Legacy RSA Wrapping
    if (recipient.publicKey) {
      try {
        const encryptedSymmetricKey = cryptoService.encryptSymmetricKey(
          symmetricKey,
          recipient.publicKey
        );
        recipientKeys.push({
          recipientId: recipient._id,
          encryptedSymmetricKey
        });
        encapsulated = true;
      } catch (err) {
        symmetricKey.fill(0);
        throw new CryptoError(`Fail-closed: RSA key wrapping failed for recipient ${recipient.username}: ${err.message}`);
      }
    }

    if (!encapsulated) {
      symmetricKey.fill(0);
      throw new ValidationError(`Fail-closed: Recipient ${recipient.username} has no valid cryptographic public key registered`);
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

  // 6. SECURE ZEROIZATION: Purge plaintext DEK from volatile memory
  symmetricKey.fill(0);

  // 7. Persist ciphertext to isolated filesystem vault (HLD 2.6) with mode 0600
  let storagePath = null;
  try {
    storagePath = fileVaultService.storeCiphertext(documentId, encryptedBlob);
  } catch (vaultErr) {
    logger.error(`FileVault storage failure: ${vaultErr.message}`);
    throw new CryptoError(`Failed to persist document ciphertext to secure vault: ${vaultErr.message}`);
  }

  // 8. Store document record with structural fingerprint and temporal policy
  // When stored to filesystem vault, omit duplicated Base64 blob from MongoDB
  const document = new Document({
    documentId,
    title,
    senderId,
    fileName: fileName || 'document.pdf',
    mimeType,
    fileSize: fileBuffer.length,
    fileHash,
    structuralFingerprint,
    encryptedBlob: storagePath ? null : encryptedBlob,
    iv,
    authTag,
    storagePath,
    classification,
    validFrom: validFrom ? new Date(validFrom) : null,
    validUntil: validUntil ? new Date(validUntil) : null,
    recipientKeys,
    keyEnvelopes
  });

  try {
    await document.save();
  } catch (dbErr) {
    // Rollback: clean up filesystem ciphertext if DB persistence fails
    fileVaultService.cleanupCiphertext(storagePath);
    throw dbErr;
  }

  logger.securityAudit('DOCUMENT_UPLOAD_ENCRYPT_ONCE', {
    docId: document._id.toString(),
    documentId,
    fileHash,
    structuralFingerprint,
    recipientCount: keyEnvelopes.length,
    classification,
    storagePath,
    algorithm: 'AES-256-GCM + ML-KEM-1024'
  });

  // 9. Log upload event to provenance audit chain
  await provenanceService.logProvenanceEvent({
    docId: document._id,
    recipientId: senderId,
    action: 'DOCUMENT_UPLOAD',
    status: 'SUCCESS',
    details: {
      title,
      fileName: document.fileName,
      fileHash,
      recipientCount: keyEnvelopes.length,
      classification
    }
  });

  return document;
}

/**
 * Decrypt document for an authorized recipient with attribution logging
 * Supports both modern ML-KEM key agent decapsulation and legacy RSA keys.
 * Loads ciphertext from secure filesystem vault.
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
    const ciphertext = fileVaultService.loadCiphertext(document);
    decryptedBuffer = cryptoService.decryptDocument(
      ciphertext,
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
