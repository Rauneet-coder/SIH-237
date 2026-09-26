const crypto = require('node:crypto');
const DecryptionSession = require('../models/DecryptionSession');
const Document = require('../models/Document');
const User = require('../models/User');
const Device = require('../models/Device');
const keyEnvelopeService = require('./keyEnvelopeService');
const cryptoService = require('./cryptoService');
const fingerprintService = require('./fingerprintService');
const canonicalEventService = require('./canonicalEventService');
const provenanceService = require('./provenanceService');
const {
  NotFoundError,
  AuthorizationError,
  FailClosedError,
  ValidationError
} = require('../utils/errors');
const logger = require('../utils/logger');

// Ephemeral volatile buffer store for active, released sessions
const sessionBufferCache = new Map();

const decryptionSessionService = {
  /**
   * Initialize a new Decryption Session for a recipient and document
   */
  async createSession({ documentId, recipientId, deviceId }) {
    if (!documentId || !recipientId || !deviceId) {
      throw new ValidationError('documentId, recipientId, and deviceId are required');
    }

    const document = await Document.findById(documentId).exec();
    if (!document) {
      throw new NotFoundError('Document');
    }

    // Verify recipient authorization in envelopes
    const isAuthorized =
      (document.keyEnvelopes || []).some(
        (env) => env.recipientId.toString() === recipientId.toString()
      ) ||
      (document.recipientKeys || []).some(
        (rk) => rk.recipientId.toString() === recipientId.toString()
      );

    if (!isAuthorized) {
      throw new AuthorizationError('Recipient is not authorized for this document');
    }

    const sessionId = `SES-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const sessionNonce = crypto.randomBytes(32).toString('hex');
    const startedAt = new Date();
    const expiresAt = new Date(startedAt.getTime() + 60 * 60 * 1000); // 1 hour

    const session = await DecryptionSession.create({
      sessionId,
      documentId: document._id,
      recipientId,
      deviceId,
      sessionNonce,
      status: 'CREATED',
      startedAt,
      expiresAt
    });

    logger.securityAudit('DECRYPTION_SESSION_CREATED', {
      sessionId,
      recipientId: recipientId.toString(),
      documentId: document._id.toString()
    });

    return session;
  },

  /**
   * Execute Fail-Closed Decryption, Fingerprinting, Signing, and Commitment Pipeline
   */
  async prepareSession({ sessionId, recipientId, deviceId }) {
    const session = await DecryptionSession.findOne({ sessionId }).exec();
    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }

    if (session.status === 'RELEASED') {
      return { session, status: 'ALREADY_RELEASED' };
    }

    if (session.status === 'FAILED') {
      throw new FailClosedError(session.failureReason || 'Session previously failed');
    }

    if (new Date() > session.expiresAt) {
      session.status = 'FAILED';
      session.failureReason = 'Session expired';
      await session.save();
      throw new FailClosedError('Decryption session expired');
    }

    let rawDek = null;
    let decryptedPlaintext = null;
    let watermarkedBuffer = null;

    try {
      // ── STAGE 1: Authorization & Device Verification ────────────────────────
      const user = await User.findById(recipientId).exec();
      if (!user || user.keyStatus !== 'ACTIVE') {
        throw new AuthorizationError('Recipient account or cryptographic keys are revoked');
      }

      const device = await Device.findOne({ userId: recipientId, deviceId }).exec();
      if (device && device.status === 'REVOKED') {
        throw new AuthorizationError(`Device ${deviceId} is revoked`);
      }

      session.status = 'AUTHORIZED';
      await session.save();

      // ── STAGE 2: Post-Quantum ML-KEM Decapsulation & AES Decryption ─────────
      const document = await Document.findById(session.documentId).exec();
      const envelope = (document.keyEnvelopes || []).find(
        (e) => e.recipientId.toString() === recipientId.toString()
      );

      if (!envelope) {
        throw new AuthorizationError('No ML-KEM key envelope found for recipient');
      }

      // Recover DEK via Key Agent
      rawDek = await keyEnvelopeService.unwrapEnvelope({
        envelope,
        recipientUsername: user.username,
        recipientId: recipientId.toString(),
        documentId: document.documentId || document._id.toString(),
        documentHash: document.fileHash
      });

      // Decrypt document with AES-256-GCM
      decryptedPlaintext = cryptoService.decryptDocument(
        document.encryptedBlob,
        rawDek,
        document.iv,
        document.authTag
      );

      // Verify Document Hash
      const contentHash = cryptoService.computeHash(decryptedPlaintext);
      if (contentHash !== document.fileHash) {
        throw new FailClosedError('Document plaintext integrity hash mismatch');
      }

      // Zeroize DEK immediately
      rawDek.fill(0);
      rawDek = null;

      session.status = 'DECRYPTED';
      await session.save();

      // ── STAGE 3: Forensic Fingerprinting & Watermark Embedding ───────────────
      const { watermarkId, watermarkCommitment } = fingerprintService.deriveFingerprint({
        recipientId: recipientId.toString(),
        documentId: document.documentId || document._id.toString(),
        documentHash: document.fileHash,
        sessionId: session.sessionId,
        sessionNonce: session.sessionNonce
      });

      session.watermarkId = watermarkId;
      session.watermarkCommitment = watermarkCommitment;

      watermarkedBuffer = await fingerprintService.embedWatermark(
        decryptedPlaintext,
        watermarkId,
        session.sessionId
      );

      session.status = 'WATERMARKED';
      await session.save();

      // ── STAGE 4: Deterministic Canonical Event & ML-DSA Signing ─────────────
      const canonicalEvent = canonicalEventService.createDecryptionEvent({
        documentId: document.documentId || document._id.toString(),
        documentHash: document.fileHash,
        recipientId: recipientId.toString(),
        sessionId: session.sessionId,
        deviceId: session.deviceId,
        watermarkId,
        watermarkCommitment,
        signingKeyId: user.keyVersion ? `ML-DSA-65-V${user.keyVersion}` : 'ML-DSA-65-V1'
      });

      const { eventDigest, signature } = await canonicalEventService.signAndVerifyEvent({
        canonicalEvent,
        recipientUsername: user.username,
        recipientPublicKey: user.mlDsaPublicKey
      });

      session.canonicalEvent = canonicalEvent;
      session.eventDigest = eventDigest;
      session.signature = signature;
      session.signingKeyId = canonicalEvent.signingKeyId;
      session.status = 'SIGNED';
      await session.save();

      // ── STAGE 5: Provenance Ledger Commitment ────────────────────────────────
      const logEntry = await provenanceService.logProvenanceEvent({
        docId: document._id,
        recipientId,
        action: 'DECRYPT_SUCCESS',
        status: 'SUCCESS',
        details: {
          sessionId: session.sessionId,
          watermarkId,
          watermarkCommitment,
          eventDigest,
          mlDsaSignaturePrefix: signature.slice(0, 24)
        }
      });

      session.ledgerTxId = `TX-LOCAL-${logEntry.sequenceNumber}`;
      session.status = 'COMMITTED';
      await session.save();

      // ── FINAL RELEASE GATE ───────────────────────────────────────────────────
      // All prerequisites passed; transition to RELEASED
      session.status = 'RELEASED';
      await session.save();

      // Cache watermarked buffer for controlled viewer access
      sessionBufferCache.set(session.sessionId, {
        buffer: watermarkedBuffer,
        expiresAt: session.expiresAt
      });

      logger.securityAudit('FAIL_CLOSED_GATE_PASSED_RELEASED', {
        sessionId: session.sessionId,
        watermarkId,
        recipientId: recipientId.toString()
      });

      return {
        session,
        status: 'RELEASED',
        watermarkId,
        watermarkCommitment,
        eventDigest,
        signature
      };
    } catch (err) {
      // ── FAIL-CLOSED TRIGGER ──────────────────────────────────────────────────
      if (rawDek) rawDek.fill(0);
      session.status = 'FAILED';
      session.failureReason = err.message;
      await session.save();

      // Evict any cached buffers
      sessionBufferCache.delete(session.sessionId);

      logger.error('FAIL-CLOSED TRIGGERED: Decryption release denied', {
        sessionId: session.sessionId,
        error: err.message
      });

      throw new FailClosedError(err.message);
    }
  },

  /**
   * Retrieve watermarked buffer for an active, RELEASED session only
   */
  async getSessionDocument(sessionId, recipientId) {
    const session = await DecryptionSession.findOne({ sessionId }).exec();
    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }

    if (session.status !== 'RELEASED') {
      throw new FailClosedError(`Document release denied: session is in ${session.status} state`);
    }

    if (session.recipientId.toString() !== recipientId.toString()) {
      throw new AuthorizationError('Unauthorized session access');
    }

    if (new Date() > session.expiresAt) {
      session.status = 'FAILED';
      session.failureReason = 'Session expired';
      await session.save();
      sessionBufferCache.delete(sessionId);
      throw new FailClosedError('Session expired');
    }

    const cached = sessionBufferCache.get(sessionId);
    if (!cached || !cached.buffer) {
      throw new NotFoundError('Document render buffer');
    }

    return cached.buffer;
  }
};

module.exports = decryptionSessionService;
