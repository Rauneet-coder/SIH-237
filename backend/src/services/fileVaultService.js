'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const env = require('../config/env');
const logger = require('../utils/logger');
const { ValidationError, CryptoError } = require('../utils/errors');

class FileVaultService {
  constructor() {
    this.vaultDir = path.resolve(env.ENCRYPTED_STORAGE_DIR || './storage/encrypted');
    this._ensureVaultDir();
  }

  _ensureVaultDir() {
    try {
      if (!fs.existsSync(this.vaultDir)) {
        fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
      }
    } catch (err) {
      logger.warn(`Could not create vault directory ${this.vaultDir}: ${err.message}`);
    }
  }

  /**
   * Validate PDF buffer format and enforce strict security bounds (HLD 1.6 & 1.7)
   * - Enforces %PDF- header magic bytes
   * - Enforces 50MB file size limit
   * - Validates basic structural trailer markers
   * @param {Buffer} buffer
   * @returns {{ valid: boolean, size: number, version: string }}
   */
  validatePdfBuffer(buffer) {
    if (!buffer || !Buffer.isBuffer(buffer) || buffer.length < 16) {
      throw new ValidationError('Uploaded file is empty or too small to be a valid PDF document');
    }

    // Check maximum size limit: 50MB
    const MAX_SIZE = 50 * 1024 * 1024;
    if (buffer.length > MAX_SIZE) {
      throw new ValidationError(
        `File exceeds maximum allowed size of 50MB (received ${(buffer.length / 1024 / 1024).toFixed(1)}MB)`
      );
    }

    const header = buffer.subarray(0, 8).toString('ascii');
    if (!header.startsWith('%PDF-')) {
      throw new ValidationError('Invalid document format: File must be a valid PDF (missing %PDF- magic header)');
    }

    const versionMatch = header.match(/%PDF-([0-9.]+)/);
    const version = versionMatch ? versionMatch[1] : '1.4';

    // Verify basic PDF integrity (check that trailer or EOF marker is present)
    const tail = buffer.subarray(Math.max(0, buffer.length - 1024)).toString('ascii');
    if (!tail.includes('%EOF') && !tail.includes('trailer') && !tail.includes('xref')) {
      // Allow minor trailing whitespace or non-standard EOF if header is valid, but log warning
      logger.warn('PDF validation: trailing %EOF marker not found within last 1KB, proceeding with caution');
    }

    return {
      valid: true,
      size: buffer.length,
      version
    };
  }

  /**
   * Store encrypted ciphertext to filesystem vault using atomic write and safe permissions (mode 0600)
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

    // Atomic write via temp file with mode 0600
    const tmpPath = `${fullPath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(tmpPath, dataBuffer, { mode: 0o600 });
      try {
        fs.chmodSync(tmpPath, 0o600);
      } catch {
        // Best-effort
      }
      fs.renameSync(tmpPath, fullPath);
      logger.info(`FileVault: Persisted ciphertext for ${documentId} (${dataBuffer.length} bytes) to ${fullPath}`);
      return path.relative(process.cwd(), fullPath);
    } catch (err) {
      if (fs.existsSync(tmpPath)) {
        try { fs.unlinkSync(tmpPath); } catch {}
      }
      throw new CryptoError(`FileVault: Failed to persist ciphertext to disk: ${err.message}`);
    }
  }

  /**
   * Clean up stored ciphertext file (e.g. after upload rollback)
   */
  cleanupCiphertext(storagePath) {
    if (!storagePath) return;
    try {
      const fullPath = path.resolve(process.cwd(), storagePath);
      if (fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
        logger.info(`FileVault: Cleaned up ciphertext file at ${fullPath}`);
      }
    } catch (err) {
      logger.warn(`FileVault: Failed to clean up file at ${storagePath}: ${err.message}`);
    }
  }

  /**
   * Load ciphertext for a document, prioritizing filesystem vault over legacy in-database blob
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

    // Fallback: Check standard vault directory by documentId
    if (document.documentId) {
      const safeDocId = document.documentId.replace(/[^a-zA-Z0-9_-]/g, '_');
      const standardPath = path.join(this.vaultDir, `${safeDocId}.enc`);
      if (fs.existsSync(standardPath)) {
        return fs.readFileSync(standardPath);
      }
    }

    // Backward compatibility: Fallback to in-database Base64 encryptedBlob
    if (document.encryptedBlob) {
      return Buffer.from(document.encryptedBlob, 'base64');
    }

    throw new NotFoundError(`Ciphertext not found for document ${document._id || document.documentId}`);
  }
}

const fileVaultService = new FileVaultService();

module.exports = fileVaultService;
