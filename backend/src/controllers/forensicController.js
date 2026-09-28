const forensicService = require('../services/forensicService');
const { ValidationError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Forensic Controller (Stage 6 Leak Investigation & Forensic Verification)
 * Coordinates watermark extraction, Fabric ledger attribution, and cryptographic verification
 */
async function extractWatermark(req, res, next) {
  try {
    let fileBuffer = null;

    if (req.file) {
      fileBuffer = req.file.buffer;
    } else if (req.body.fileBase64) {
      fileBuffer = Buffer.from(req.body.fileBase64, 'base64');
    } else if (req.body.content) {
      fileBuffer = Buffer.from(req.body.content, 'utf-8');
    }

    if (!fileBuffer) {
      throw new ValidationError('Leaked file is required. Upload a file or provide fileBase64 / content.');
    }

    const extraction = await forensicService.extractWatermark(fileBuffer);
    return res.json({
      success: true,
      extraction
    });
  } catch (error) {
    next(error);
  }
}

async function verifyForensicEvidence(req, res, next) {
  try {
    const { watermarkId, watermarkCommitment, eventId, documentHash } = req.body;

    if (!watermarkId && !watermarkCommitment && !eventId) {
      throw new ValidationError('At least one of watermarkId, watermarkCommitment, or eventId is required');
    }

    const verification = await forensicService.verifyForensicEvidence({
      watermarkId,
      watermarkCommitment,
      eventId,
      documentHash
    });

    const statusCode = verification.status === 'NOT_FOUND' ? 404 : 200;
    return res.status(statusCode).json({
      success: verification.status === 'VERIFIED',
      verification
    });
  } catch (error) {
    next(error);
  }
}

/**
 * One-shot leak investigation: Upload suspect file -> Extract -> Cryptographically Verify on Ledger
 */
async function investigateLeak(req, res, next) {
  try {
    let fileBuffer = null;

    if (req.file) {
      fileBuffer = req.file.buffer;
    } else if (req.body.fileBase64) {
      fileBuffer = Buffer.from(req.body.fileBase64, 'base64');
    } else if (req.body.content) {
      fileBuffer = Buffer.from(req.body.content, 'utf-8');
    }

    if (!fileBuffer) {
      throw new ValidationError('Leaked file is required for leak investigation.');
    }

    // 1. Extract
    const extraction = await forensicService.extractWatermark(fileBuffer);

    // If watermark extraction failed completely
    if (!extraction.watermarkId) {
      return res.status(400).json({
        success: false,
        extraction,
        verification: {
          status: 'INCONCLUSIVE',
          isCriticalAlert: true,
          alertLevel: 'MEDIUM',
          message: 'Unable to extract forensic watermark from the provided suspect file.',
          confidence: 0.0
        }
      });
    }

    // 2. Verify with server-derived evidence hash and suspectFileBuffer
    const verification = await forensicService.verifyForensicEvidence({
      watermarkId: extraction.watermarkId,
      documentHash: req.body.documentHash,
      suspectFileBuffer: fileBuffer
    });

    const statusCode = verification.status === 'NOT_FOUND' ? 404 : 200;
    return res.status(statusCode).json({
      success: verification.status === 'VERIFIED',
      extraction,
      verification
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  extractWatermark,
  verifyForensicEvidence,
  investigateLeak
};
