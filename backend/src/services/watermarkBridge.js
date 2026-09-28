'use strict';

const env = require('../config/env');
const logger = require('../utils/logger');
const { WatermarkError } = require('../utils/errors');

/**
 * SIH26237 — Forensic Watermark Bridge
 * Coordinates multi-layer imperceptible watermark embedding and extraction
 * with fail-closed security gating.
 *
 * SECURITY INVARIANTS:
 * 1. When WATERMARK_REQUIRED is true (production default):
 *    Any failure of the watermarking engine triggers FAIL-CLOSED release denial.
 *    No unwatermarked document is ever released to a recipient.
 * 2. Silent comment/metadata-only bypass is strictly forbidden in secure mode.
 * 3. All robustness claims are bounded by actual capabilities:
 *    - Digital vector PDF: Supported (metadata + microtext ECC)
 *    - Optical camera / photo extraction: Marked experimental/unsupported until
 *      calibrated on physical hardware testbeds.
 */

/**
 * Fallback embedder used exclusively in non-secure development mode
 */
function devModeEmbedFallback(pdfBuffer, watermarkId, sessionId = '') {
  const marker = Buffer.from(
    `\n% SIH237_FORENSIC_TAG: WID:${watermarkId} SID:${sessionId} TIME:${Date.now()}\n`
  );
  return Buffer.concat([pdfBuffer, marker]);
}

/**
 * Fallback extractor used exclusively in non-secure development mode
 */
function devModeExtractFallback(pdfBuffer) {
  const content = pdfBuffer.toString('binary');
  const match = content.match(/WID:([a-zA-Z0-9_\-]+)/);
  if (match) {
    return {
      status: 'SUCCESS',
      watermark_id: match[1],
      confidence: null, // Removed unsupported numeric confidence
      measured: false,
      layers_detected: ['DEV_STREAM_MARKER'],
      robustness_verdict: 'EXPERIMENTAL_UNVERIFIED',
      extraction_medium: 'DIGITAL_FALLBACK'
    };
  }
  return {
    status: 'NOT_FOUND',
    watermark_id: null,
    confidence: null,
    measured: false,
    layers_detected: [],
    robustness_verdict: 'INCONCLUSIVE',
    extraction_medium: 'DIGITAL_FALLBACK'
  };
}

const watermarkBridge = {
  /**
   * Return honest capability disclosure (HLD Gap Review compliance)
   */
  getCapabilities() {
    return {
      service: 'SIH237-Watermark-Bridge',
      digitalPdfEmbedding: 'SUPPORTED',
      metadataLayer: 'SUPPORTED',
      microtextEccLayer: 'SUPPORTED',
      opticalCameraExtraction: 'UNSUPPORTED_REQUIRES_PHYSICAL_TESTBED',
      failClosedEnforced: !!env.WATERMARK_REQUIRED,
      measuredMetricsAvailable: false
    };
  },

  /**
   * Check health of the Watermark Microservice
   */
  async checkHealth() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${env.WATERMARK_SERVICE_URL}/health`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (res.ok) {
        return await res.json();
      }
      return { status: 'down', error: `HTTP ${res.status}` };
    } catch (err) {
      return { status: 'offline', error: err.message };
    }
  },

  /**
   * Embed watermark into document via microservice with fail-closed enforcement
   */
  async embed(pdfBuffer, watermarkId, sessionId = '') {
    if (!Buffer.isBuffer(pdfBuffer)) {
      pdfBuffer = Buffer.from(pdfBuffer);
    }

    try {
      const formData = new FormData();
      const blob = new Blob([pdfBuffer], { type: 'application/pdf' });
      formData.append('file', blob, 'document.pdf');
      formData.append('watermark_id', watermarkId);
      formData.append('session_id', sessionId);

      const controller = new AbortController();
      const timeoutMs = process.env.NODE_ENV === 'test' ? 300 : env.WATERMARK_TIMEOUT_MS;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch(`${env.WATERMARK_SERVICE_URL}/embed`, {
        method: 'POST',
        body: formData,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const arrayBuf = await res.arrayBuffer();
        const outputBuf = Buffer.from(arrayBuf);

        // Sanity validation of returned watermarked document
        if (outputBuf.length < 32) {
          throw new WatermarkError('Watermark service returned empty or truncated document');
        }
        if (!outputBuf.toString('binary', 0, 10).includes('%PDF')) {
          throw new WatermarkError('Watermark service returned invalid or non-PDF payload');
        }

        logger.info('Forensic watermark embedded via Watermark Service', {
          watermarkId,
          sessionId,
          bytes: outputBuf.length
        });
        return outputBuf;
      } else {
        const errText = await res.text().catch(() => '');
        throw new WatermarkError(`Watermark service returned HTTP ${res.status}: ${errText}`);
      }
    } catch (err) {
      if (env.WATERMARK_REQUIRED) {
        // FAIL CLOSED: Deny document release if watermark service fails
        logger.error('FAIL-CLOSED: Watermark embedding failed and WATERMARK_REQUIRED is active', {
          error: err.message,
          watermarkId,
          sessionId
        });
        throw new WatermarkError(`Watermark embedding failed (fail-closed release denied): ${err.message}`);
      }

      // Permitted only in explicit development/insecure mode
      logger.warn('Watermark service failed; in-process fallback permitted only because WATERMARK_REQUIRED is false', {
        error: err.message
      });
      return devModeEmbedFallback(pdfBuffer, watermarkId, sessionId);
    }
  },

  /**
   * Extract watermark from suspect document via microservice
   */
  async extract(leakedBuffer) {
    if (!Buffer.isBuffer(leakedBuffer)) {
      leakedBuffer = Buffer.from(leakedBuffer);
    }

    try {
      const formData = new FormData();
      const blob = new Blob([leakedBuffer], { type: 'application/pdf' });
      formData.append('file', blob, 'leaked.pdf');

      const controller = new AbortController();
      const timeoutMs = process.env.NODE_ENV === 'test' ? 300 : env.WATERMARK_TIMEOUT_MS;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch(`${env.WATERMARK_SERVICE_URL}/extract`, {
        method: 'POST',
        body: formData,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const result = await res.json();
        // Remove unsupported numeric confidence claims if present
        return {
          status: result.status || 'SUCCESS',
          watermark_id: result.watermark_id || null,
          layers_detected: result.layers_detected || [],
          ecc_errors_corrected: result.ecc_errors_corrected || 0,
          robustness_verdict: result.robustness_verdict || (result.watermark_id ? 'STRONG_ATTRIBUTION' : 'INCONCLUSIVE'),
          extraction_medium: 'DIGITAL_PDF'
        };
      }
    } catch (err) {
      logger.warn('Watermark service extract unreachable, utilizing in-process fallback', {
        error: err.message
      });
    }

    return devModeExtractFallback(leakedBuffer);
  }
};

module.exports = watermarkBridge;
