'use strict';

const crypto = require('node:crypto');
const mongoose = require('mongoose');
const FabricLedgerRecord = require('../models/FabricLedgerRecord');
const DecryptionSession = require('../models/DecryptionSession');
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
 * Implements rigorous, tamper-resistant forensic verification:
 * 1. Extraction from suspect document buffer
 * 2. Immutable Ledger lookup
 * 3. Canonical Event Digest & ML-DSA Signature Verification (Ledger Authenticity)
 * 4. Document / Content Binding Verification (detects marker copying fraud)
 * 5. Recomputation of cryptographic watermark commitment from authenticated session context
 * 6. Digitally attested audit report signed by server authority
 */
const forensicService = {
  /**
   * Extract forensic watermark from a suspect or leaked document buffer
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
        confidence: extracted.confidence !== undefined ? extracted.confidence : null,
        layersDetected: extracted.layers_detected || ['FORENSIC_STREAM_MARKER'],
        robustnessVerdict: extracted.robustness_verdict || (extracted.watermark_id ? 'STRONG_ATTRIBUTION' : 'INCONCLUSIVE'),
        extractionMedium: extracted.extraction_medium || 'DIGITAL_PDF'
      };
    } catch (err) {
      logger.warn('Watermark extraction exception:', { error: err.message });
      return {
        status: 'EXTRACTION_ERROR',
        watermarkId: null,
        confidence: null,
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
   * @param {Buffer} [query.suspectFileBuffer] - Raw buffer of leaked artifact for content binding check
   * @returns {Promise<Object>} ForensicVerificationResult
   */
  async verifyForensicEvidence({ watermarkId, watermarkCommitment, eventId, documentHash, suspectFileBuffer = null }) {
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

    // ── CRITICAL ALERT: Record not found on immutable ledger ────────────────
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
        attributionVerdict: 'UNVERIFIED_FORGERY_OR_UNTRACKED',
        watermarkId: watermarkId || null,
        eventId: eventId || null,
        ledgerSignatureValid: false,
        signatureValid: false,
        documentHashValid: false,
        watermarkCommitmentValid: false,
        evidenceBindingValid: false,
        digestValid: false,
        isCriticalAlert: true,
        alertLevel: 'CRITICAL',
        message: 'CRITICAL SECURITY ALERT: Watermark identifier was not found on the immutable provenance ledger. The leak originates from an untracked decryption, an offline forgery, or tampered evidence.',
        issues: [`No provenance record found on ledger matching query: ${queriedId}`],
        evidence: {
          queriedAt: new Date().toISOString(),
          extractorVersion: '2.0.0',
          watermarkAlgorithmVersion: 'NIST-PQC-FINGERPRINT-v1',
          ledgerQueried: true
        }
      };

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

    // ── STAGE 3: ML-DSA-65 Recipient Signature Verification (Ledger Authenticity) ──
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

    // ── STAGE 4: Document Hash & Source Document Binding ────────────────────
    let documentHashValid = false; // Default to false (fail-closed if missing)
    let docRecord = null;

    try {
      if (mongoose.Types.ObjectId.isValid(ledgerRecord.documentId)) {
        docRecord = await Document.findById(ledgerRecord.documentId).exec();
      }
      if (!docRecord) {
        docRecord = await Document.findOne({ documentId: ledgerRecord.documentId }).exec();
      }

      if (!docRecord) {
        issues.push(`Original source document ${ledgerRecord.documentId} not found in system registry`);
        documentHashValid = false;
      } else {
        if (docRecord.fileHash !== ledgerRecord.documentHash) {
          documentHashValid = false;
          issues.push(`Ledger documentHash (${ledgerRecord.documentHash}) does not match actual registered document fileHash (${docRecord.fileHash})`);
        } else {
          documentHashValid = true;
        }

        if (documentHash && documentHash !== ledgerRecord.documentHash) {
          issues.push(`Client-supplied documentHash (${documentHash}) differs from authenticated ledger documentHash (${ledgerRecord.documentHash})`);
        }
      }
    } catch (docErr) {
      documentHashValid = false;
      issues.push(`Document binding lookup error: ${docErr.message}`);
    }

    // ── STAGE 5: Watermark Commitment Recomputation from Session Context ────
    let watermarkCommitmentValid = false;
    let sessionRecord = null;

    if (ledgerRecord.sessionId) {
      sessionRecord = await DecryptionSession.findOne({ sessionId: ledgerRecord.sessionId }).exec();
    }

    if (sessionRecord && docRecord) {
      try {
        const recomputed = fingerprintService.deriveFingerprint({
          recipientId: sessionRecord.recipientId.toString(),
          documentId: docRecord.documentId || docRecord._id.toString(),
          documentHash: docRecord.fileHash,
          sessionId: sessionRecord.sessionId,
          sessionNonce: sessionRecord.sessionNonce
        });

        const matchesCommitment = recomputed.watermarkCommitment === ledgerRecord.watermarkCommitment;
        const matchesWatermarkId = recomputed.watermarkId === ledgerRecord.watermarkId;

        if (matchesCommitment && matchesWatermarkId) {
          watermarkCommitmentValid = true;
        } else {
          watermarkCommitmentValid = false;
          issues.push(`Cryptographic commitment derivation mismatch: stored commitment does not match recomputed session commitment`);
        }
      } catch (fpErr) {
        watermarkCommitmentValid = false;
        issues.push(`Failed to recompute watermark commitment: ${fpErr.message}`);
      }
    } else {
      watermarkCommitmentValid = false;
      issues.push('Cannot recompute watermark commitment: original session or document record is missing');
    }

    // ── STAGE 6: Content Binding & Marker-Copying Fraud Detection ────────────
    let evidenceBindingValid = true;
    let serverEvidenceHash = null;

    if (suspectFileBuffer && Buffer.isBuffer(suspectFileBuffer) && suspectFileBuffer.length > 0) {
      serverEvidenceHash = cryptoService.computeHash(suspectFileBuffer);

      if (docRecord) {
        // Compare structural layout to verify that the suspect artifact genuinely contains the original document content
        const suspectStructuralFp = fingerprintService.computeStructuralFingerprint(suspectFileBuffer);
        const originalStructuralFp = docRecord.structuralFingerprint;

        if (originalStructuralFp && suspectStructuralFp !== originalStructuralFp) {
          evidenceBindingValid = false;
          issues.push('Marker copying fraud detected: suspect file contains valid watermark identifier but structural layout does not match original document');
          logger.securityAudit('FORENSIC_MARKER_COPYING_DETECTED', {
            watermarkId: ledgerRecord.watermarkId,
            eventId: ledgerRecord.eventId,
            originalDocId: docRecord.documentId
          });
        }
      }
    }

    // ── STAGE 7: Final Attribution Verdict Determination ────────────────────
    const ledgerIntegrityVerified = digestValid && signatureValid;
    const attributionVerified = ledgerIntegrityVerified && documentHashValid && watermarkCommitmentValid && evidenceBindingValid && issues.length === 0;

    let status;
    if (attributionVerified) {
      status = 'VERIFIED';
    } else if (!ledgerIntegrityVerified) {
      status = 'INVALID';
    } else if (!docRecord || !sessionRecord) {
      status = 'INCONCLUSIVE';
    } else {
      status = 'INVALID';
    }

    const isCriticalAlert = status !== 'VERIFIED';

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
      attributionVerdict: attributionVerified ? 'ATTRIBUTION_CONFIRMED' : (status === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : 'ATTRIBUTION_REFUTED'),
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
      ledgerSignatureValid: signatureValid,
      documentHashValid,
      watermarkCommitmentValid,
      evidenceBindingValid,
      serverEvidenceHash,
      isCriticalAlert,
      alertLevel: isCriticalAlert ? (status === 'INCONCLUSIVE' ? 'MEDIUM' : 'CRITICAL') : 'NONE',
      issues,
      evidence: {
        extractedAt: new Date().toISOString(),
        extractorVersion: '2.0.0',
        watermarkAlgorithmVersion: 'NIST-PQC-FINGERPRINT-v1',
        cryptoStandard: 'NIST FIPS 204 (ML-DSA-65)',
        limitations: 'Digital extraction validated on vector PDFs; optical photo/scan extraction requires physical testbed'
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
