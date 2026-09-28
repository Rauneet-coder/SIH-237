const decryptionSessionService = require('../services/decryptionSessionService');
const DecryptionSession = require('../models/DecryptionSession');
const { ValidationError, NotFoundError } = require('../utils/errors');

/**
 * Decryption Session Controller
 * Coordinates initialization, preparation pipeline, and controlled release
 */
async function createSession(req, res, next) {
  try {
    const { documentId, cameraEvidenceHash, livenessToken } = req.body;
    const deviceId = req.headers['x-device-id'] || req.body.deviceId;

    if (!documentId) {
      throw new ValidationError('documentId is required');
    }

    if (!deviceId) {
      throw new ValidationError('Device ID is required. Provide x-device-id header or deviceId in body.');
    }

    const session = await decryptionSessionService.createSession({
      documentId,
      recipientId: req.user._id,
      deviceId,
      cameraEvidenceHash,
      livenessToken
    });

    return res.status(201).json({
      success: true,
      sessionId: session.sessionId,
      status: session.status,
      expiresAt: session.expiresAt
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Execute the complete fail-closed preparation pipeline
 */
async function prepareSession(req, res, next) {
  try {
    const { sessionId } = req.params;
    const deviceId = req.headers['x-device-id'] || req.body.deviceId;

    if (!deviceId) {
      throw new ValidationError('Device ID is required. Provide x-device-id header or deviceId in body.');
    }

    const result = await decryptionSessionService.prepareSession({
      sessionId,
      recipientId: req.user._id,
      deviceId
    });

    return res.json({
      success: true,
      status: result.status,
      sessionId: result.session.sessionId,
      watermarkId: result.watermarkId,
      watermarkCommitment: result.watermarkCommitment,
      eventDigest: result.eventDigest,
      signature: result.signature,
      ledgerTxId: result.session.ledgerTxId
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get current session state and diagnostic metadata
 */
async function getSessionStatus(req, res, next) {
  try {
    const { sessionId } = req.params;
    const session = await DecryptionSession.findOne({ sessionId })
      .select('sessionId documentId recipientId status watermarkId watermarkCommitment ledgerTxId startedAt expiresAt failureReason')
      .exec();

    if (!session) {
      throw new NotFoundError('DecryptionSession');
    }

    // SECURITY: Only session owner or admin can view session status
    const isOwner = session.recipientId.toString() === req.user._id.toString();
    const isAdmin = (req.user.role || '').toUpperCase() === 'ADMIN';
    if (!isOwner && !isAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Access denied: you are not the owner of this session',
        code: 'SESSION_ACCESS_DENIED'
      });
    }

    return res.json({
      success: true,
      session
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Controlled document release endpoint (fail-closed protected)
 */
async function getControlledDocument(req, res, next) {
  try {
    const { sessionId } = req.params;
    const buffer = await decryptionSessionService.getSessionDocument(sessionId, req.user._id);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename=forensic_view.pdf');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    return res.send(buffer);
  } catch (error) {
    next(error);
  }
}

/**
 * Get active session metadata (time remaining, security status, doc info)
 */
async function getSessionMetadata(req, res, next) {
  try {
    const { sessionId } = req.params;
    const metadata = await decryptionSessionService.getSessionMetadata(sessionId, req.user._id);
    return res.json({ success: true, metadata });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  createSession,
  prepareSession,
  getSessionStatus,
  getControlledDocument,
  getSessionMetadata
};
