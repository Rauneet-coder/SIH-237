const Document = require('../models/Document');
const User = require('../models/User');
const cryptoService = require('./cryptoService');
const provenanceService = require('./provenanceService');
const collusionService = require('./collusionService');

/**
 * Upload and encrypt a document for multi-recipient distribution
 * - Generates a 32-byte AES symmetric key
 * - Encrypts plaintext file using AES-256-GCM
 * - Encrypts the symmetric key individually for each recipient using RSA-OAEP
 * - Immutably logs the upload in the provenance chain
 */
async function uploadAndEncryptDocument({
  title,
  fileBuffer,
  fileName,
  mimeType = 'application/pdf',
  senderId,
  recipientIds = []
}) {
  if (!title) {
    throw new Error('Document title is required');
  }
  if (!fileBuffer || fileBuffer.length === 0) {
    throw new Error('Document file buffer is empty or missing');
  }
  if (!senderId) {
    throw new Error('Sender ID is required');
  }

  // 1. Calculate plaintext SHA-256 hash
  const fileHash = cryptoService.computeHash(fileBuffer);

  // 2. Fetch and validate recipients
  const recipients = await User.find({ _id: { $in: recipientIds }, isActive: true }).exec();
  if (recipients.length === 0 && recipientIds.length > 0) {
    throw new Error('No valid active recipients found for specified IDs');
  }

  // 3. Generate symmetric key and encrypt document
  const symmetricKey = cryptoService.generateSymmetricKey();
  const { encryptedBlob, iv, authTag } = cryptoService.encryptDocument(fileBuffer, symmetricKey);

  // 4. Wrap symmetric key for each recipient with their RSA public key
  const recipientKeys = recipients.map((recipient) => {
    const encryptedSymmetricKey = cryptoService.encryptSymmetricKey(
      symmetricKey,
      recipient.publicKey
    );
    return {
      recipientId: recipient._id,
      encryptedSymmetricKey
    };
  });

  // 5. Store document record
  const document = new Document({
    title,
    senderId,
    fileName: fileName || 'document.pdf',
    mimeType,
    fileSize: fileBuffer.length,
    fileHash,
    encryptedBlob,
    iv,
    authTag,
    recipientKeys
  });

  await document.save();

  // 6. Log upload event to provenance audit chain
  await provenanceService.logProvenanceEvent({
    docId: document._id,
    recipientId: senderId,
    action: 'DOCUMENT_UPLOAD',
    status: 'SUCCESS',
    details: {
      title,
      fileName: document.fileName,
      fileHash,
      recipientCount: recipientKeys.length
    }
  });

  return document;
}

/**
 * Decrypt document for an authorized recipient with attribution logging
 * - Logs DECRYPT_ATTEMPT in provenance chain
 * - Validates recipient is authorized
 * - Unwraps recipient's symmetric key using recipient's private key
 * - Decrypts document via AES-256-GCM and verifies hash
 * - Logs DECRYPT_SUCCESS or DECRYPT_FAILURE in provenance chain
 */
async function decryptDocumentForRecipient({ docId, recipientId, recipientPrivateKeyPem }) {
  const document = await Document.findById(docId).exec();
  if (!document) {
    const error = new Error('Document not found');
    error.statusCode = 404;
    throw error;
  }

  // Check if recipient is authorized in recipientKeys
  const recipientEntry = document.recipientKeys.find(
    (rk) => rk.recipientId.toString() === recipientId.toString()
  );

  if (!recipientEntry) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: 'Unauthorized: recipient not in document distribution list' }
    });
    const error = new Error('Access denied: you are not an authorized recipient for this document');
    error.statusCode = 403;
    throw error;
  }

  // Log decryption attempt
  await provenanceService.logProvenanceEvent({
    docId,
    recipientId,
    action: 'DECRYPT_ATTEMPT',
    status: 'SUCCESS',
    details: { fileHash: document.fileHash }
  });

  // Unwrap symmetric key
  let symmetricKey;
  try {
    symmetricKey = cryptoService.decryptSymmetricKey(
      recipientEntry.encryptedSymmetricKey,
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
    const error = new Error('Decryption failed: invalid private key provided');
    error.statusCode = 400;
    throw error;
  }

  // Decrypt document with AES-256-GCM
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
    const error = new Error('Document decryption failed: ciphertext or auth tag invalid');
    error.statusCode = 400;
    throw error;
  }

  // Integrity validation
  const decryptedHash = cryptoService.computeHash(decryptedBuffer);
  if (decryptedHash !== document.fileHash) {
    await provenanceService.logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_FAILURE',
      status: 'FAILURE',
      details: { reason: 'Decrypted content hash mismatch' }
    });
    const error = new Error('Integrity check failed: document hash mismatch');
    error.statusCode = 500;
    throw error;
  }

  // Generate collusion-resistant fingerprint codeword for this recipient
  const biases = collusionService.generateBiasVector(document._id.toString());
  const codeword = collusionService.generateRecipientCodeword(
    document._id.toString(),
    recipientId.toString(),
    biases
  );

  // Decryption success attribution log
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

  // Embed forensic collusion-secure fingerprint into the delivered document
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
