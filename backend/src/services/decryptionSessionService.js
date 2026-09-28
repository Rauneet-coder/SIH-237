'use strict';

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
const fabricService = require('./fabricService');
const fileVaultService = require('./fileVaultService');
const {
  NotFoundError,
  AuthorizationError,
  FailClosedError,
  ValidationError
} = require('../utils/errors');
const logger = require('../utils/logger');

// Ephemeral volatile buffer store for active, released sessions
const sessionBufferCache = new Map();

// In-flight preparation mutex: sessionId -> Promise
const activePreparations = new Map();

const decryptionSessionService = {
  /**
   * Initialize a new Decryption Session for a recipient and document
   */
  async createSession({
    documentId,
    recipientId,
    deviceId,
    cameraEvidenceHash = null,
    livenessToken = null
  }) {
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

    // ── STAGE 1.4: ABAC Policy Engine - Clearance Check ──
    const CLEARANCE_HIERARCHY = {
      UNCLASSIFIED: 1,
      RESTRICTED: 2,
      CONFIDENTIAL: 3,
      SECRET: 4,
      TOP_SECRET: 5
    };
    const recipientUser = await User.findById(recipientId).exec();
    if (recipientUser) {
      const userClearance = recipientUser.clearance || 'RESTRICTED';
      const userClearanceLevel = CLEARANCE_HIERARCHY[userClearance] || 2;
      const docClassification = document.classification || 'CONFIDENTIAL';
      const docClassificationLevel = CLEARANCE_HIERARCHY[docClassification] || 3;
      if (userClearanceLevel < docClassificationLevel) {
        logger.securityAudit('CLEARANCE_POLICY_DENIED', {
          recipientId: recipientId.toString(),
          userClearance,
          requiredClassification: docClassification
        });
        throw new AuthorizationError(
          `Security clearance insufficient: Recipient clearance ${userClearance} does not meet document classification ${docClassification}`
        );
      }
    }

    // ── STAGE 1.4: ABAC Policy Engine - Temporal Access Window ──
    const now = new Date();
    if (document.validFrom && now < document.validFrom) {
      throw new AuthorizationError('Document access window is not yet active');
    }
    if (document.validUntil && now > document.validUntil) {
      throw new AuthorizationError('Document access window has expired');
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
      cameraEvidenceHash,
      livenessToken,
      status: 'CREATED',
      startedAt,
      expiresAt
    });

    logger.securityAudit('DECRYPTION_SESSION_CREATED', {
      sessionId,
      recipientId: recipientId.toString(),
      documentId: document._id.toString(),
      hasCameraEvidence: Boolean(cameraEvidenceHash)
    });

    return session;
  },

  /**
   * Execute Fail-Closed Decryption, Fingerprinting, Signing, and Commitment Pipeline
   * Safe against concurrent invocations using atomic session locking.
   */
  async prepareSession({ sessionId, recipientId, deviceId }) {
    if (activePreparations.has(sessionId)) {
      return await activePreparations.get(sessionId);
    }

    const prepPromise = (async () => {
      const session = await DecryptionSession.findOne({ sessionId }).exec();
      if (!session) {
        throw new NotFoundError('DecryptionSession');
      }

      // SECURITY: Verify session ownership FIRST — before any early returns
      if (session.recipientId.toString() !== recipientId.toString()) {
        logger.securityAudit('SESSION_OWNERSHIP_VIOLATION', {
          sessionId,
          sessionOwner: session.recipientId.toString(),
          requestingUser: recipientId.toString()
        });
        throw new AuthorizationError('Unauthorized: session belongs to a different recipient');
      }

      // SECURITY: Verify device matches the session's registered device
      if (session.deviceId !== deviceId) {
        logger.securityAudit('SESSION_DEVICE_MISMATCH', {
          sessionId,
          expectedDevice: session.deviceId,
          providedDevice: deviceId
        });
        throw new AuthorizationError('Device mismatch: session was created for a different device');
      }

      // Check expiry before any processing
      if (new Date() > session.expiresAt) {
        session.status = 'FAILED';
        session.failureReason = 'Session expired';
        await session.save();
        throw new FailClosedError('Decryption session expired');
      }

      // Check for already-completed or failed states (AFTER ownership/device checks)
      if (session.status === 'RELEASED') {
        return { session, status: 'ALREADY_RELEASED' };
      }

      if (session.status === 'FAILED') {
        throw new FailClosedError(session.failureReason || 'Session previously failed');
      }

      if (session.status === 'REVOKED') {
        throw new FailClosedError('Session has been revoked');
      }

      let rawDek = null;
      let decryptedPlaintext = null;
      let watermarkedBuffer = null;

      try {
        // ── STAGE 1: Authorization & Device Verification ────────────────────────
        const user = await User.findById(recipientId).exec();
        if (!user || user.keyStatus !== 'ACTIVE' || !user.isActive) {
          throw new AuthorizationError('Recipient account or cryptographic keys are revoked');
        }

        const device = await Device.findOne({ userId: recipientId, deviceId }).exec();
        if (!device || device.status !== 'ACTIVE') {
          throw new AuthorizationError(`Device ${deviceId} is not active (status: ${device?.status || 'NOT_FOUND'})`);
        }

        session.status = 'AUTHORIZED';
        await session.save();

        // ── STAGE 2: Post-Quantum ML-KEM Decapsulation & AES Decryption ─────────
        const document = await Document.findById(session.documentId).exec();
        if (!document) {
          throw new NotFoundError('Associated document not found');
        }

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

        // Decrypt document with AES-256-GCM (load from file vault or fallback to database)
        const ciphertextBuffer = fileVaultService.loadCiphertext(document);
        decryptedPlaintext = cryptoService.decryptDocument(
          ciphertextBuffer,
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

        // Fail-Closed: if watermark embedding fails in secure mode, release is aborted
        watermarkedBuffer = await fingerprintService.embedWatermark(
          decryptedPlaintext,
          watermarkId,
          session.sessionId
        );

        session.status = 'WATERMARKED';
        await session.save();

        // ── STAGE 4: Deterministic Canonical Event & ML-DSA Signing ─────────────
        const canonicalEventId = `EVT-${session.sessionId.replace('SES-', '')}`;
        const canonicalEvent = canonicalEventService.createDecryptionEvent({
          eventId: canonicalEventId,
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

        // ── STAGE 5: Provenance Ledger Commitment (Hyperledger Fabric) ────────────
        const fabricRecord = await fabricService.recordDecryptionEvent({
          eventId: `evt_${session.sessionId}`,
          eventDigest,
          documentId: document.documentId || document._id.toString(),
          documentHash: document.fileHash,
          recipientId: recipientId.toString(),
          sessionId: session.sessionId,
          deviceId: session.deviceId,
          watermarkId,
          watermarkCommitment,
          signingKeyId: canonicalEvent.signingKeyId,
          signature,
          timestamp: canonicalEvent.timestamp
        });

        // Dual-logged to local hash-chained provenance log
        await provenanceService.logProvenanceEvent({
          docId: document._id,
          recipientId,
          action: 'DECRYPT_SUCCESS',
          status: 'SUCCESS',
          details: {
            sessionId: session.sessionId,
            watermarkId,
            watermarkCommitment,
            eventDigest,
            fabricTxId: fabricRecord.txId,
            mlDsaSignaturePrefix: signature.slice(0, 24)
          }
        });

        session.ledgerTxId = fabricRecord.txId;
        session.status = 'COMMITTED';
        await session.save();

        // ── FINAL RELEASE GATE ───────────────────────────────────────────────────
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

        // Record failed attempt in provenance ledger
        try {
          await provenanceService.logProvenanceEvent({
            docId: session.documentId,
            recipientId,
            action: 'DECRYPT_FAILURE',
            status: 'FAILURE',
            details: {
              sessionId: session.sessionId,
              failureReason: err.message
            }
          });
        } catch {
          // Best-effort audit logging
        }

        logger.error('FAIL-CLOSED TRIGGERED: Decryption release denied', {
          sessionId: session.sessionId,
          error: err.message
        });

        throw new FailClosedError(err.message);
      }
    })();

    activePreparations.set(sessionId, prepPromise);
    try {
      return await prepPromise;
    } finally {
      activePreparations.delete(sessionId);
    }
  },

  /**
   * Retrieve watermarked buffer for an active, RELEASED session only.
   * Strictly enforces exact device matching and rechecks active key/device status.
   */
  async getSessionDocument(sessionId, recipientId, deviceId = null) {
    const session = await DecryptionSession.findOne({ sessionId }).exec();
    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }

    if (session.status !== 'RELEASED') {
      throw new FailClosedError(`Document release denied: session is in ${session.status} state`);
    }

    if (session.recipientId.toString() !== recipientId.toString()) {
      throw new AuthorizationError('Unauthorized session access: recipient mismatch');
    }

    // Verify exact device matching if deviceId provided, or enforce device presence
    if (deviceId && session.deviceId !== deviceId) {
      logger.securityAudit('RENDER_DEVICE_MISMATCH', {
        sessionId,
        sessionDevice: session.deviceId,
        requestDevice: deviceId,
        recipientId: recipientId.toString()
      });
      throw new AuthorizationError('Device mismatch: document release is bound to original session device');
    }

    // Recheck current identity and key revocation
    const user = await User.findById(recipientId).exec();
    if (!user || user.keyStatus !== 'ACTIVE' || !user.isActive) {
      session.status = 'REVOKED';
      session.failureReason = 'Recipient account or cryptographic keys have been revoked';
      await session.save();
      sessionBufferCache.delete(sessionId);
      throw new FailClosedError('Cryptographic keys for this recipient have been revoked');
    }

    // Recheck current device status
    const effectiveDeviceId = deviceId || session.deviceId;
    const device = await Device.findOne({ userId: recipientId, deviceId: effectiveDeviceId }).exec();
    if (!device || device.status !== 'ACTIVE') {
      session.status = 'REVOKED';
      session.failureReason = `Device ${effectiveDeviceId} is no longer active (current: ${device?.status || 'NOT_FOUND'})`;
      await session.save();
      sessionBufferCache.delete(sessionId);
      throw new FailClosedError(`Device ${effectiveDeviceId} is not active or has been revoked`);
    }

    // Recheck temporal access window
    const document = await Document.findById(session.documentId).exec();
    if (document) {
      const now = new Date();
      if (document.validFrom && now < document.validFrom) {
        throw new FailClosedError('Document access window is not yet active');
      }
      if (document.validUntil && now > document.validUntil) {
        throw new FailClosedError('Document access window has expired');
      }
    }

    // Recheck session expiry
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
  },

  /**
   * Close / Revoke a decryption session server-side (Viewer Lock action)
   */
  async closeSession(sessionId, recipientId) {
    const session = await DecryptionSession.findOne({ sessionId }).exec();
    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }

    const isOwner = session.recipientId.toString() === recipientId.toString();
    const user = await User.findById(recipientId).exec();
    const isAdmin = user && user.role.toUpperCase() === 'ADMIN';

    if (!isOwner && !isAdmin) {
      throw new AuthorizationError('Unauthorized: only session owner or admin can close session');
    }

    session.status = 'REVOKED';
    session.failureReason = 'Session closed by user or viewer lock';
    await session.save();

    // Securely evict volatile render buffer from memory
    sessionBufferCache.delete(sessionId);

    logger.securityAudit('SESSION_CLOSED', {
      sessionId,
      closedBy: recipientId.toString()
    });

    return {
      success: true,
      sessionId,
      status: 'REVOKED',
      message: 'Decryption session closed and memory wiped'
    };
  },

  /**
   * Get metadata and remaining time for a secure viewer session
   */
  async getSessionMetadata(sessionId, recipientId) {
    const session = await DecryptionSession.findOne({ sessionId })
      .populate('documentId', 'title fileName fileSize classification')
      .exec();
    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }
    if (session.recipientId.toString() !== recipientId.toString()) {
      throw new AuthorizationError('Unauthorized session access');
    }

    const now = new Date();
    const isExpired = now > session.expiresAt;
    const remainingSeconds = Math.max(0, Math.floor((session.expiresAt.getTime() - now.getTime()) / 1000));

    return {
      sessionId: session.sessionId,
      status: session.status,
      watermarkId: session.watermarkId,
      watermarkCommitment: session.watermarkCommitment,
      document: session.documentId,
      remainingSeconds,
      isExpired,
      startedAt: session.startedAt,
      expiresAt: session.expiresAt
    };
  }
};

module.exports = decryptionSessionService;
