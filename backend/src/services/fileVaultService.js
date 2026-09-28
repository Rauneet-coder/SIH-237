const fs = require('node:fs');
const path = require('node:path');
const env = require('../config/env');
const logger = require('../utils/logger');
const { ValidationError } = require('../utils/errors');

class FileVaultService {
  constructor() {
    this.vaultDir = path.resolve(env.ENCRYPTED_STORAGE_DIR || './storage/encrypted');
    this._ensureVaultDir();
  }

  _ensureVaultDir() {
    try {
      if (!fs.existsSync(this.vaultDir)) {
        fs.mkdirSync(this.vaultDir, { recursive: true });
      }
    } catch (err) {
      logger.warn(`Could not create vault directory ${this.vaultDir}: ${err.message}`);
    }
  }

  /**
   * Validate PDF buffer format (HLD 1.6)
   * Enforces PDF header signature and sanity bounds
   * @param {Buffer} buffer
   */
  validatePdfBuffer(buffer) {
    if (!buffer || buffer.length < 5) {
      throw new ValidationError('Uploaded file is empty or too small to be a valid document');
    }

    const header = buffer.subarray(0, 5).toString('ascii');
    if (header !== '%PDF-') {
      throw new ValidationError('Invalid document format: File must be a valid PDF (missing %PDF- header)');
    }

    // Check maximum size limit: 50MB (HLD 1.7)
    const MAX_SIZE = 50 * 1024 * 1024;
    if (buffer.length > MAX_SIZE) {
      throw new ValidationError(`File exceeds maximum allowed size of 50MB (received ${(buffer.length / 1024 / 1024).toFixed(1)}MB)`);
    }

    return true;
  }

  /**
   * Store encrypted ciphertext to filesystem vault
   * @param {string} documentId
   * @param {Buffer|string} ciphertext
   * @returns {string} Relative storage path
   */
  storeCiphertext(documentId, ciphertext) {
    this._ensureVaultDir();
    const safeDocId = documentId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `${safeDocId}.enc`;
    const fullPath = path.join(this.vaultDir, filename);

    const dataBuffer = Buffer.isBuffer(ciphertext)
      ? ciphertext
      : Buffer.from(ciphertext, 'base64');

    fs.writeFileSync(fullPath, dataBuffer);
    logger.info(`FileVault: Persisted ciphertext for ${documentId} (${dataBuffer.length} bytes) to ${fullPath}`);

    return path.relative(process.cwd(), fullPath);
  }

  /**
   * Load ciphertext for a document, prioritizing filesystem vault over MongoDB field
   * @param {Object} document
   * @returns {Buffer}
   */
  loadCiphertext(document) {
    if (document.storagePath) {
      const fullPath = path.resolve(process.cwd(), document.storagePath);
      if (fs.existsSync(fullPath)) {
        return fs.readFileSync(fullPath);
      }
    }

    // Fallback: Check standard vault directory
    if (document.documentId) {
      const safeDocId = document.documentId.replace(/[^a-zA-Z0-9_-]/g, '_');
      const standardPath = path.join(this.vaultDir, `${safeDocId}.enc`);
      if (fs.existsSync(standardPath)) {
        return fs.readFileSync(standardPath);
      }
    }

    // Fallback to in-database Base64 encryptedBlob
    if (document.encryptedBlob) {
      return Buffer.from(document.encryptedBlob, 'base64');
    }

    throw new Error(`Ciphertext not found for document ${document._id || document.documentId}`);
  }
}

const fileVaultService = new FileVaultService();

module.exports = fileVaultService;
