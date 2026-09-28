const crypto = require('node:crypto');
const mongoose = require('mongoose');
const FabricLedgerRecord = require('../models/FabricLedgerRecord');
const Document = require('../models/Document');
const User = require('../models/User');
const fabricService = require('./fabricService');
const fingerprintService = require('./fingerprintService');
const canonicalEventService = require('./canonicalEventService');
const pqcService = require('./pqcService');
const cryptoService = require('./cryptoService');
const env = require('../config/env');
const logger = require('../utils/logger');
const { ValidationError, NotFoundError } = require('../utils/errors');

/**
 * Forensic Investigation and Attribution Service (HLD / LLD Section 25 & 26)
 *
 * Implements the 5-stage fail-closed forensic verification pipeline:
 * 1. Watermark Detection & Extraction from leaked file
 * 2. Fabric Immutable Ledger Query (Watermark / Event lookup)
 *    -> Handles "NOT FOUND" as a CRITICAL security alert
 * 3. Canonical Event Digest Recomputation
 * 4. ML-DSA-65 Digital Signature Verification on recipient public key
 *    -> Handles "SIGNATURE FAILURE" as a CRITICAL security alert
 * 5. Document Hash & Watermark Commitment Binding Verification
 * 6. Server-signed forensic report generation for non-repudiation
 */
const forensicService = {
  /**
   * Extract forensic watermark from a suspect or leaked document buffer
   * @param {Buffer} fileBuffer
   * @returns {Promise<{ status: string, watermarkId: string|null, confidence: number, layersDetected: Array<string>, robustnessVerdict: string }>}
   */
  async extractWatermark(fileBuffer) {
    if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
      throw new ValidationError('File buffer is empty or missing');
    }

    try {
      const extracted = await fingerprintService.extractWatermark(fileBuffer);
      return {
        status: extracted.status || (extracted.watermark_id ? 'SUCCESS' : 'NOT_FOUND'),
        watermarkId: extracted.watermark_id || null,
        confidence: typeof extracted.confidence === 'number' ? extracted.confidence : (extracted.watermark_id ? 0.95 : 0.0),
        layersDetected: extracted.layers_detected || ['FORENSIC_STREAM_MARKER'],
        robustnessVerdict: extracted.robustness_verdict || (extracted.watermark_id ? 'STRONG_ATTRIBUTION' : 'INCONCLUSIVE')
      };
    } catch (err) {
      logger.warn('Watermark extraction exception:', { error: err.message });
      return {
        status: 'EXTRACTION_ERROR',
        watermarkId: null,
        confidence: 0.0,
        layersDetected: [],
        robustnessVerdict: 'INCONCLUSIVE',
        error: err.message
      };
    }
  },

  /**
   * Run the full cryptographic forensic verification pipeline for attribution
   *
   * @param {Object} query
   * @param {string} [query.watermarkId]
   * @param {string} [query.watermarkCommitment]
   * @param {string} [query.eventId]
   * @param {string} [query.documentHash]
   * @returns {Promise<Object>} ForensicVerificationResult
   */
  async verifyForensicEvidence({ watermarkId, watermarkCommitment, eventId, documentHash }) {
    if (!watermarkId && !watermarkCommitment && !eventId) {
      throw new ValidationError('At least one of watermarkId, watermarkCommitment, or eventId is required for forensic verification');
    }

    const issues = [];
    let ledgerRecord = null;

    // ── STAGE 1: Ledger Lookup ──────────────────────────────────────────────
    if (eventId) {
      ledgerRecord = await FabricLedgerRecord.findOne({ eventId }).lean();
    }

    if (!ledgerRecord && (watermarkId || watermarkCommitment)) {
      const queryOr = [];
      if (watermarkId) queryOr.push({ watermarkId });
      if (watermarkCommitment) queryOr.push({ watermarkCommitment });
      ledgerRecord = await FabricLedgerRecord.findOne({ $or: queryOr }).lean();
    }

    // ── CRITICAL EVENT: NOT FOUND ON IMMUTABLE LEDGER ────────────────────────
    if (!ledgerRecord) {
      const queriedId = watermarkId || watermarkCommitment || eventId;
      logger.securityAudit('FORENSIC_EVENT_NOT_FOUND', {
        queriedId,
        watermarkId,
        eventId,
        alert: 'CRITICAL',
        severity: 'HIGH'
      });

      const notFoundResult = {
        status: 'NOT_FOUND',
        watermarkId: watermarkId || null,
        eventId: eventId || null,
        signatureValid: false,
        documentHashValid: false,
        watermarkCommitmentValid: false,
        digestValid: false,
        isCriticalAlert: true,
        alertLevel: 'CRITICAL',
        message: 'CRITICAL SECURITY ALERT: Watermark identifier was not found on the immutable provenance ledger. The leak originates from an untracked decryption, an offline forgery, or tampered evidence.',
        issues: [`No provenance record found on ledger matching query: ${queriedId}`],
        evidence: {
          queriedAt: new Date().toISOString(),
          extractorVersion: '1.0.0',
          watermarkAlgorithmVersion: 'NIST-PQC-FINGERPRINT-v1',
          ledgerQueried: true
        }
      };

      // Attest report with server private authority signature
      const reportDigest = cryptoService.computeHash(JSON.stringify(notFoundResult));
      const serverSignature = cryptoService.signPayload(reportDigest, env.SERVER_PRIVATE_KEY);

      return {
        ...notFoundResult,
        reportDigest,
        serverSignature,
        serverPublicKey: env.SERVER_PUBLIC_KEY
      };
    }

    // ── STAGE 2: Reconstruct Canonical Event and Verify Digest ───────────────
    let digestValid = false;
    let recomputedDigest = '';
    try {
      const reconstructedEventId = ledgerRecord.eventId.replace('evt_SES-', 'EVT-').replace('evt_', 'EVT-');
      const reconstructedEvent = canonicalEventService.createDecryptionEvent({
        eventId: reconstructedEventId,
        documentId: ledgerRecord.documentId,
        documentHash: ledgerRecord.documentHash,
        recipientId: ledgerRecord.recipientId,
        sessionId: ledgerRecord.sessionId,
        deviceId: ledgerRecord.deviceId || '',
        watermarkId: ledgerRecord.watermarkId,
        watermarkCommitment: ledgerRecord.watermarkCommitment,
        signingKeyId: ledgerRecord.signingKeyId,
        timestamp: ledgerRecord.timestamp
      });

      const digestRes = canonicalEventService.computeEventDigest(reconstructedEvent);
      recomputedDigest = digestRes.eventDigest;
      digestValid = recomputedDigest === ledgerRecord.eventDigest;

      if (!digestValid) {
        issues.push(`Canonical event digest mismatch: stored ${ledgerRecord.eventDigest}, computed ${recomputedDigest}`);
        logger.securityAudit('FORENSIC_EVENT_DIGEST_MISMATCH', {
          eventId: ledgerRecord.eventId,
          storedDigest: ledgerRecord.eventDigest,
          recomputedDigest,
          alert: 'CRITICAL'
        });
      }
    } catch (err) {
      digestValid = false;
      issues.push(`Canonical digest reconstruction error: ${err.message}`);
    }

    // ── STAGE 3: ML-DSA-65 Recipient Signature Verification ─────────────────
    let signatureValid = false;
    let recipientUser = null;
    try {
      recipientUser = await User.findById(ledgerRecord.recipientId).exec();
      if (!recipientUser) {
        issues.push(`Recipient user ${ledgerRecord.recipientId} not found in user registry`);
      } else if (!recipientUser.mlDsaPublicKey) {
        issues.push(`Recipient ${recipientUser.username} has no registered ML-DSA public key`);
      } else {
        const digestBuf = Buffer.from(ledgerRecord.eventDigest, 'hex');
        signatureValid = await pqcService.verify(ledgerRecord.signature, digestBuf, recipientUser.mlDsaPublicKey);
        if (!signatureValid) {
          issues.push('ML-DSA signature verification failed: signature does not match recipient public key');
          logger.securityAudit('FORENSIC_SIGNATURE_VERIFICATION_FAILED', {
            eventId: ledgerRecord.eventId,
            recipientId: ledgerRecord.recipientId,
            username: recipientUser.username,
            alert: 'CRITICAL',
            severity: 'HIGH'
          });
        }
      }
    } catch (sigErr) {
      signatureValid = false;
      issues.push(`ML-DSA signature verification exception: ${sigErr.message}`);
    }

    // ── STAGE 4: Document Hash Binding ──────────────────────────────────────
    let documentHashValid = true;
    let docRecord = null;
    try {
      if (mongoose.Types.ObjectId.isValid(ledgerRecord.documentId)) {
        docRecord = await Document.findById(ledgerRecord.documentId).exec();
      }
      if (!docRecord) {
        // Try looking up by documentId string
        docRecord = await Document.findOne({ documentId: ledgerRecord.documentId }).exec();
      }

      if (documentHash && documentHash !== ledgerRecord.documentHash) {
        documentHashValid = false;
        issues.push(`Queried documentHash (${documentHash}) does not match ledger documentHash (${ledgerRecord.documentHash})`);
      }

      if (docRecord && docRecord.fileHash !== ledgerRecord.documentHash) {
        documentHashValid = false;
        issues.push(`Ledger documentHash does not match actual registered document fileHash`);
      }
    } catch (docErr) {
      issues.push(`Document binding lookup error: ${docErr.message}`);
    }

    // ── STAGE 5: Watermark Commitment Validation ────────────────────────────
    let watermarkCommitmentValid = false;
    if (ledgerRecord.watermarkCommitment && ledgerRecord.watermarkCommitment.length === 64) {
      watermarkCommitmentValid = true;
    } else {
      issues.push('Watermark commitment is missing or malformed');
    }

    // ── STAGE 6: Assemble Comprehensive Attestation Report ─────────────────
    const isVerified = digestValid && signatureValid && documentHashValid && watermarkCommitmentValid && issues.length === 0;
    const isCriticalAlert = !isVerified;
    const status = isVerified ? 'VERIFIED' : 'INVALID';

    if (isCriticalAlert) {
      logger.securityAudit('FORENSIC_VERIFICATION_FAILURE', {
        eventId: ledgerRecord.eventId,
        status,
        issues,
        alert: 'CRITICAL'
      });
    } else {
      logger.securityAudit('FORENSIC_ATTRIBUTION_VERIFIED', {
        eventId: ledgerRecord.eventId,
        recipient: recipientUser ? recipientUser.username : ledgerRecord.recipientId,
        watermarkId: ledgerRecord.watermarkId,
        status: 'VERIFIED'
      });
    }

    const verificationResult = {
      status,
      watermarkId: ledgerRecord.watermarkId,
      watermarkCommitment: ledgerRecord.watermarkCommitment,
      recipientId: ledgerRecord.recipientId,
      recipient: recipientUser
        ? {
            id: recipientUser._id,
            username: recipientUser.username,
            email: recipientUser.email,
            role: recipientUser.role,
            clearance: recipientUser.clearance || 'RESTRICTED'
          }
        : null,
      documentId: ledgerRecord.documentId,
      document: docRecord
        ? {
            id: docRecord._id,
            documentId: docRecord.documentId,
            title: docRecord.title,
            classification: docRecord.classification,
            fileHash: docRecord.fileHash
          }
        : null,
      sessionId: ledgerRecord.sessionId,
      deviceId: ledgerRecord.deviceId,
      eventId: ledgerRecord.eventId,
      ledgerTransactionId: ledgerRecord.txId,
      blockNumber: ledgerRecord.blockNumber,
      timestamp: ledgerRecord.timestamp,
      signingKeyId: ledgerRecord.signingKeyId,
      digestValid,
      signatureValid,
      documentHashValid,
      watermarkCommitmentValid,
      recoveryConfidence: isVerified ? 0.99 : 0.0,
      isCriticalAlert,
      alertLevel: isCriticalAlert ? 'CRITICAL' : 'NONE',
      issues,
      evidence: {
        extractedAt: new Date().toISOString(),
        extractorVersion: '1.0.0',
        watermarkAlgorithmVersion: 'NIST-PQC-FINGERPRINT-v1',
        cryptoStandard: 'NIST FIPS 204 (ML-DSA-65)'
      }
    };

    // Digitally sign the entire forensic result with the server authority key (RSA-SHA256)
    const reportDigest = cryptoService.computeHash(JSON.stringify(verificationResult));
    const serverSignature = cryptoService.signPayload(reportDigest, env.SERVER_PRIVATE_KEY);

    return {
      ...verificationResult,
      reportDigest,
      serverSignature,
      serverPublicKey: env.SERVER_PUBLIC_KEY
    };
  }
};

module.exports = forensicService;
