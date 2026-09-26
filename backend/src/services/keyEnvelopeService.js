const crypto = require('node:crypto');
const pqcService = require('./pqcService');
const keyAgentClient = require('./keyAgentClient');
const { KeyEnvelopeError } = require('../utils/errors');
const logger = require('../utils/logger');

const KDF_INFO = Buffer.from('SIH237-DEK-WRAP-v1');

/**
 * ML-KEM Key Envelope Service
 * Handles recipient-specific authenticated DEK encapsulation and decapsulation
 * Conforms strictly to NIST FIPS 203 (ML-KEM-1024) + HKDF-SHA256 + AES-256-GCM wrapping
 */
const keyEnvelopeService = {
  /**
   * Encapsulate document encryption key (DEK) for a specific recipient
   * @param {Object} params
   * @param {Buffer} params.dek - 32-byte plaintext AES-256 key
   * @param {string} params.recipientId - Recipient user ID string
   * @param {string} params.mlKemPublicKey - Base64 ML-KEM-1024 public key
   * @param {string} params.documentId - Document ID string
   * @param {string} params.documentHash - SHA-256 hex string of document plaintext
   * @returns {Promise<Object>} KeyEnvelope record
   */
  async createEnvelope({ dek, recipientId, mlKemPublicKey, documentId, documentHash }) {
    if (!dek || !Buffer.isBuffer(dek) || dek.length !== 32) {
      throw new KeyEnvelopeError('Invalid DEK: must be a 32-byte Buffer');
    }
    if (!mlKemPublicKey) {
      throw new KeyEnvelopeError(`Cannot create ML-KEM envelope: missing ML-KEM public key for recipient ${recipientId}`);
    }

    try {
      // 1. Post-Quantum ML-KEM Encapsulation
      const { cipherText: kemCiphertext, sharedSecret } = await pqcService.encapsulate(mlKemPublicKey);
      const sharedSecretBuf = Buffer.from(sharedSecret, 'base64');

      // 2. KDF: Derive Key-Wrapping Key (KWK) using HKDF-SHA256 bound to documentHash
      const saltBuf = Buffer.from(documentHash, 'hex');
      const kwk = Buffer.from(crypto.hkdfSync('sha256', sharedSecretBuf, saltBuf, KDF_INFO, 32));

      // 3. Authenticated DEK Wrapping via AES-256-GCM with AAD binding
      const wrappingNonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', kwk, wrappingNonce);
      const aad = Buffer.from(`${recipientId}:${documentId}`);
      cipher.setAAD(aad);

      const wrappedDek = Buffer.concat([cipher.update(dek), cipher.final()]);
      const wrappingTag = cipher.getAuthTag();

      // Zeroize intermediate wrapping key from memory
      kwk.fill(0);

      logger.info('Created ML-KEM-1024 key envelope for recipient', {
        recipientId,
        documentId
      });

      return {
        recipientId,
        kemAlgorithm: 'ML-KEM-1024',
        kemCiphertext,
        wrappedDek: wrappedDek.toString('base64'),
        wrappingNonce: wrappingNonce.toString('hex'),
        wrappingTag: wrappingTag.toString('hex'),
        keyVersion: '1.0'
      };
    } catch (err) {
      throw new KeyEnvelopeError(`Key envelope creation failed: ${err.message}`);
    }
  },

  /**
   * Decapsulate and recover DEK using recipient's private key inside Key Agent
   * @param {Object} params
   * @param {Object} params.envelope - Stored KeyEnvelope record
   * @param {string} params.recipientUsername - Username or Key Agent recipient ID
   * @param {string} params.recipientId - Recipient user ID string
   * @param {string} params.documentId - Document ID string
   * @param {string} params.documentHash - SHA-256 hex string of document plaintext
   * @returns {Promise<Buffer>} Recovered 32-byte DEK Buffer
   */
  async unwrapEnvelope({ envelope, recipientUsername, recipientId, documentId, documentHash }) {
    if (!envelope || !envelope.kemCiphertext || !envelope.wrappedDek) {
      throw new KeyEnvelopeError('Invalid or incomplete key envelope');
    }

    try {
      // 1. Decapsulate shared secret inside Key Agent boundary
      const sharedSecretBase64 = await keyAgentClient.decapsulate(
        recipientUsername,
        envelope.kemCiphertext
      );
      const sharedSecretBuf = Buffer.from(sharedSecretBase64, 'base64');

      // 2. Derive identical Key-Wrapping Key (KWK)
      const saltBuf = Buffer.from(documentHash, 'hex');
      const kwk = Buffer.from(crypto.hkdfSync('sha256', sharedSecretBuf, saltBuf, KDF_INFO, 32));

      // 3. Unwrap DEK using AES-256-GCM
      const wrappingNonce = Buffer.from(envelope.wrappingNonce, 'hex');
      const wrappingTag = Buffer.from(envelope.wrappingTag, 'hex');
      const wrappedDekBuf = Buffer.from(envelope.wrappedDek, 'base64');

      const decipher = crypto.createDecipheriv('aes-256-gcm', kwk, wrappingNonce);
      const aad = Buffer.from(`${recipientId}:${documentId}`);
      decipher.setAAD(aad);
      decipher.setAuthTag(wrappingTag);

      const recoveredDek = Buffer.concat([decipher.update(wrappedDekBuf), decipher.final()]);

      // Zeroize intermediate wrapping key
      kwk.fill(0);

      if (recoveredDek.length !== 32) {
        throw new KeyEnvelopeError('Decapsulated DEK length mismatch');
      }

      logger.securityAudit('DEK_UNWRAPPED', {
        recipientId,
        documentId,
        algorithm: 'ML-KEM-1024'
      });

      return recoveredDek;
    } catch (err) {
      throw new KeyEnvelopeError(`ML-KEM DEK unwrap failed: ${err.message}`);
    }
  }
};

module.exports = keyEnvelopeService;
