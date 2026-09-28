const crypto = require('node:crypto');
const watermarkBridge = require('./watermarkBridge');
const { WatermarkError } = require('../utils/errors');
const logger = require('../utils/logger');

const FINGERPRINT_INFO = Buffer.from('SIH237-FORENSIC-FINGERPRINT-v1');

/**
 * Forensic Fingerprinting & Watermark Management Service
 * Generates opaque, session-unique fingerprints without embedding raw PII.
 * Integrates with Watermark Microservice for multi-layer invisible embedding.
 */
const fingerprintService = {
  /**
   * Cryptographically derive an opaque forensic fingerprint and commitment
   * @param {Object} params
   * @param {string} params.recipientId
   * @param {string} params.documentId
   * @param {string} params.documentHash
   * @param {string} params.sessionId
   * @param {string} params.sessionNonce
   * @returns {{ fingerprintPayload: Buffer, watermarkId: string, watermarkCommitment: string }}
   */
  deriveFingerprint({ recipientId, documentId, documentHash, sessionId, sessionNonce }) {
    if (!recipientId || !documentId || !documentHash || !sessionId || !sessionNonce) {
      throw new WatermarkError('Missing mandatory parameters for fingerprint derivation');
    }

    // Input Keying Material (IKM)
    const ikm = Buffer.from(`${recipientId}:${sessionId}:${documentId}`);
    // Salt incorporates document hash and high-entropy session nonce
    const salt = Buffer.from(`${documentHash}:${sessionNonce}`);

    // HKDF-SHA256 Derivation
    const derived = crypto.hkdfSync('sha256', ikm, salt, FINGERPRINT_INFO, 32);
    const fingerprintPayload = Buffer.from(derived);

    // Opaque 128-bit Watermark Identifier (Hex)
    const watermarkId = `WID-${fingerprintPayload.subarray(0, 16).toString('hex').toUpperCase()}`;

    // Cryptographic Commitment: SHA-256(fingerprintPayload)
    const watermarkCommitment = crypto
      .createHash('sha256')
      .update(fingerprintPayload)
      .digest('hex');

    logger.info('Derived opaque forensic fingerprint and commitment', {
      watermarkId,
      sessionId
    });

    return {
      fingerprintPayload,
      watermarkId,
      watermarkCommitment
    };
  },

  /**
   * Embed invisible multi-layer forensic watermark into decrypted document buffer
   * @param {Buffer} decryptedBuffer
   * @param {string} watermarkId
   * @param {string} sessionId
   * @returns {Promise<Buffer>} Watermarked document buffer
   */
  async embedWatermark(decryptedBuffer, watermarkId, sessionId) {
    if (!Buffer.isBuffer(decryptedBuffer) || decryptedBuffer.length === 0) {
      throw new WatermarkError('Cannot embed watermark into empty document buffer');
    }

    try {
      const watermarked = await watermarkBridge.embed(decryptedBuffer, watermarkId, sessionId);
      if (!watermarked || watermarked.length === 0) {
        throw new WatermarkError('Watermark embedding produced empty output');
      }
      return watermarked;
    } catch (err) {
      throw new WatermarkError(`Watermark embedding pipeline failed: ${err.message}`);
    }
  },

  /**
   * Extract watermark from leaked file or screen photograph
   * @param {Buffer} leakedBuffer
   * @returns {Promise<Object>} Extraction result { status, watermark_id, confidence }
   */
  async extractWatermark(leakedBuffer) {
    if (!Buffer.isBuffer(leakedBuffer) || leakedBuffer.length === 0) {
      throw new WatermarkError('Invalid leaked document buffer');
    }

    return await watermarkBridge.extract(leakedBuffer);
  },

  /**
   * Compute normalized structural layout fingerprint for a document (HLD Stage 1.3)
   * Captures PDF structural layout, object catalog, fonts, and page geometry
   * independent of volatile compression or minor byte drift.
   *
   * @param {Buffer} fileBuffer
   * @param {string} [mimeType='application/pdf']
   * @returns {string} Hex SHA-256 structural content fingerprint
   */
  computeStructuralFingerprint(fileBuffer, mimeType = 'application/pdf') {
    if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
      throw new WatermarkError('Invalid file buffer for structural fingerprinting');
    }

    const rawStr = fileBuffer.toString('binary');
    const structuralTokens = [];

    // 1. PDF Header Version
    const headerMatch = rawStr.match(/^%PDF-([0-9.]+)/);
    structuralTokens.push(headerMatch ? headerMatch[0] : '%PDF-GENERIC');

    // 2. Page & MediaBox geometry
    const pageMatches = rawStr.match(/\/Type\s*\/Page\b/g);
    structuralTokens.push(`PAGES:${pageMatches ? pageMatches.length : 0}`);

    const mediaBoxes = rawStr.match(/\/MediaBox\s*\[[^\]]+\]/g);
    if (mediaBoxes) {
      structuralTokens.push(`BOXES:${mediaBoxes.sort().join(';')}`);
    }

    // 3. Font and Resource dictionary names
    const fontMatches = rawStr.match(/\/BaseFont\s*\/([A-Za-z0-9_\-+]+)/g);
    if (fontMatches) {
      const uniqueFonts = Array.from(new Set(fontMatches)).sort();
      structuralTokens.push(`FONTS:${uniqueFonts.join(',')}`);
    }

    // 4. Object count and structure
    const objMatches = rawStr.match(/\b\d+\s+\d+\s+obj\b/g);
    structuralTokens.push(`OBJECTS:${objMatches ? objMatches.length : 0}`);

    // If PDF markers are absent, tokenize alphanumeric words/layout
    if (structuralTokens.length <= 2) {
      const normalizedWords = rawStr
        .replace(/[^a-zA-Z0-9]/g, ' ')
        .split(/\s+/)
        .filter((w) => w.length > 3)
        .slice(0, 100);
      structuralTokens.push(`WORDS:${normalizedWords.join(',')}`);
    }

    const canonicalStructure = structuralTokens.join('|');
    return crypto
      .createHash('sha256')
      .update('SIH237-STRUCTURAL-LAYOUT-v1:')
      .update(canonicalStructure)
      .digest('hex');
  }
};

module.exports = fingerprintService;
