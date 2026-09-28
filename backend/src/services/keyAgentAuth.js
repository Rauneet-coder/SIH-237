'use strict';

const crypto = require('node:crypto');

/**
 * SIH26237 — Key Agent Authentication Protocol
 * 
 * Provides deterministic canonical request signing and verification between
 * the backend services and the isolated Key Agent daemon process.
 */

/**
 * Builds the canonical string for HMAC authentication:
 * METHOD\nPATH\nRECIPIENT_ID\nTIMESTAMP\nNONCE\nBODY_HASH
 * 
 * @param {Object} params
 * @param {string} params.method HTTP method (GET, POST)
 * @param {string} params.path URL path (e.g. /provision, /decapsulate)
 * @param {string} [params.recipientId=''] Target recipient ID
 * @param {string|number} params.timestamp Request timestamp (ISO or epoch ms)
 * @param {string} params.nonce Unique request nonce
 * @param {string} params.bodyHash SHA-256 hex digest of raw request body
 * @returns {string}
 */
function createCanonicalString({ method, path, recipientId = '', timestamp, nonce, bodyHash }) {
  return [
    (method || 'GET').toUpperCase(),
    (path || '/').replace(/\/$/, '') || '/',
    String(recipientId || ''),
    String(timestamp || ''),
    String(nonce || ''),
    String(bodyHash || '')
  ].join('\n');
}

/**
 * Compute SHA-256 hex digest of request body
 * @param {string|Buffer|object} rawBody
 * @returns {string}
 */
function hashBody(rawBody) {
  if (!rawBody) {
    return crypto.createHash('sha256').update('').digest('hex');
  }
  if (Buffer.isBuffer(rawBody)) {
    return crypto.createHash('sha256').update(rawBody).digest('hex');
  }
  if (typeof rawBody === 'string') {
    return crypto.createHash('sha256').update(rawBody, 'utf8').digest('hex');
  }
  return crypto.createHash('sha256').update(JSON.stringify(rawBody), 'utf8').digest('hex');
}

/**
 * Generate HMAC-SHA256 signature for canonical string
 * @param {string} secret HMAC secret
 * @param {string} canonicalString Canonical request string
 * @returns {string} hex signature
 */
function generateHmac(secret, canonicalString) {
  return crypto.createHmac('sha256', secret).update(canonicalString, 'utf8').digest('hex');
}

/**
 * Constant-time verification of HMAC-SHA256 signature
 * @param {string} secret HMAC secret
 * @param {string} canonicalString Canonical request string
 * @param {string} signatureHex Provided signature
 * @returns {boolean}
 */
function verifyHmac(secret, canonicalString, signatureHex) {
  if (!signatureHex || typeof signatureHex !== 'string') return false;
  try {
    const expected = generateHmac(secret, canonicalString);
    const expectedBuf = Buffer.from(expected, 'hex');
    const actualBuf = Buffer.from(signatureHex, 'hex');
    if (expectedBuf.length !== actualBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    return false;
  }
}

module.exports = {
  createCanonicalString,
  hashBody,
  generateHmac,
  verifyHmac
};
