const crypto = require('node:crypto');
const pqcService = require('./pqcService');
const keyAgentClient = require('./keyAgentClient');
const { CryptoError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Deterministic Canonical JSON Serializer (RFC 8785)
 * Recursively sorts keys alphabetically and serializes with zero extraneous whitespace.
 */
function canonicalizeJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((key) => {
    return JSON.stringify(key) + ':' + canonicalizeJson(obj[key]);
  });

  return '{' + pairs.join(',') + '}';
}

const canonicalEventService = {
  /**
   * Serialize object deterministically according to RFC 8785
   */
  serializeCanonical(obj) {
    return canonicalizeJson(obj);
  },

  /**
   * Construct canonical decryption event object
   */
  createDecryptionEvent({
    eventId,
    documentId,
    documentHash,
    recipientId,
    sessionId,
    deviceId,
    watermarkId,
    watermarkCommitment,
    signingKeyId,
    timestamp
  }) {
    return {
      deviceId,
      documentHash,
      documentId,
      eventId: eventId || `EVT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
      eventType: 'DOCUMENT_DECRYPTION',
      eventVersion: '1.0',
      recipientId,
      sessionId,
      signingKeyId: signingKeyId || 'ML-DSA-65-V1',
      timestamp: timestamp || new Date().toISOString(),
      watermarkCommitment,
      watermarkId
    };
  },

  /**
   * Compute SHA-256 digest of canonical event
   */
  computeEventDigest(canonicalEvent) {
    const canonicalString = canonicalizeJson(canonicalEvent);
    const canonicalBytes = Buffer.from(canonicalString, 'utf-8');
    const eventDigest = crypto.createHash('sha256').update(canonicalBytes).digest('hex');
    return {
      canonicalString,
      canonicalBytes,
      eventDigest
    };
  },

  /**
   * Sign canonical event using recipient's private ML-DSA key via Key Agent
   * and cryptographically verify the signature before returning.
   */
  async signAndVerifyEvent({
    canonicalEvent,
    recipientUsername,
    recipientPublicKey
  }) {
    const { canonicalString, canonicalBytes, eventDigest } = this.computeEventDigest(canonicalEvent);
    const digestBuf = Buffer.from(eventDigest, 'hex');

    // Sign through secure Key Agent boundary
    const signature = await keyAgentClient.sign(recipientUsername, digestBuf);

    // Immediate Self-Verification Gate
    const isValid = await pqcService.verify(signature, digestBuf, recipientPublicKey);
    if (!isValid) {
      throw new CryptoError('ML-DSA event signature failed self-verification check');
    }

    logger.securityAudit('CANONICAL_EVENT_SIGNED', {
      eventId: canonicalEvent.eventId,
      recipientId: canonicalEvent.recipientId,
      eventDigestPrefix: eventDigest.slice(0, 16),
      algorithm: 'ML-DSA-65'
    });

    return {
      canonicalEvent,
      canonicalString,
      eventDigest,
      signature
    };
  }
};

module.exports = canonicalEventService;
