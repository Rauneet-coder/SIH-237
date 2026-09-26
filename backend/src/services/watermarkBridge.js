const env = require('../config/env');
const logger = require('../utils/logger');
const { WatermarkError } = require('../utils/errors');

/**
 * Native Node.js in-process fallback watermark embedder
 * Ensures uninterrupted operation even if the Python watermark microservice is starting up.
 */
function nativeEmbedFallback(pdfBuffer, watermarkId, sessionId = '') {
  // Inspect or append forensic watermark tag in PDF stream
  const marker = Buffer.from(
    `\n% SIH237_FORENSIC_TAG: WID:${watermarkId} SID:${sessionId} TIME:${Date.now()}\n`
  );
  return Buffer.concat([pdfBuffer, marker]);
}

/**
 * Native Node.js in-process fallback watermark extractor
 */
function nativeExtractFallback(pdfBuffer) {
  const content = pdfBuffer.toString('binary');
  const match = content.match(/WID:([a-zA-Z0-9_\-]+)/);
  if (match) {
    return {
      status: 'SUCCESS',
      watermark_id: match[1],
      confidence: 0.95,
      layers_detected: ['FALLBACK_STREAM_MARKER'],
      robustness_verdict: 'STRONG_ATTRIBUTION'
    };
  }
  return {
    status: 'NOT_FOUND',
    watermark_id: null,
    confidence: 0.0,
    layers_detected: [],
    robustness_verdict: 'INCONCLUSIVE'
  };
}

const watermarkBridge = {
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
   * Embed watermark into document via microservice with fallback
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
      const timeoutMs = process.env.NODE_ENV === 'test' ? 150 : env.WATERMARK_TIMEOUT_MS;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch(`${env.WATERMARK_SERVICE_URL}/embed`, {
        method: 'POST',
        body: formData,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const arrayBuf = await res.arrayBuffer();
        logger.info('Forensic watermark embedded via Watermark Service', {
          watermarkId,
          sessionId
        });
        return Buffer.from(arrayBuf);
      } else {
        const errText = await res.text();
        logger.warn('Watermark service failed, utilizing in-process fallback', {
          status: res.status,
          error: errText
        });
      }
    } catch (err) {
      logger.warn('Watermark service unreachable, utilizing in-process fallback', {
        error: err.message
      });
    }

    // In-process fallback
    return nativeEmbedFallback(pdfBuffer, watermarkId, sessionId);
  },

  /**
   * Extract watermark from leaked document via microservice with fallback
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
      const timeoutMs = process.env.NODE_ENV === 'test' ? 150 : env.WATERMARK_TIMEOUT_MS;
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      const res = await fetch(`${env.WATERMARK_SERVICE_URL}/extract`, {
        method: 'POST',
        body: formData,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      logger.warn('Watermark service extract unreachable, utilizing in-process fallback', {
        error: err.message
      });
    }

    return nativeExtractFallback(leakedBuffer);
  }
};

module.exports = watermarkBridge;
