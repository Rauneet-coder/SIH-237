const Document = require('../models/Document');
const collusionService = require('../services/collusionService');
const cryptoService = require('../services/cryptoService');
const env = require('../config/env');

/**
 * Trace and identify colluders from a leaked or suspect document
 */
async function traceCollusion(req, res, next) {
  try {
    const { id: docId } = req.params;

    const document = await Document.findById(docId)
      .populate('recipientKeys.recipientId', 'username email role')
      .exec();

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    if (!document.recipientKeys || document.recipientKeys.length === 0) {
      return res.status(400).json({ error: 'Document has no registered recipients.' });
    }

    // 1. Extract suspect watermark from uploaded file, text content, or direct codeword
    let suspectWatermark = req.body.watermarkCodeword;

    if (!suspectWatermark) {
      let rawContent;
      if (req.file) {
        rawContent = req.file.buffer;
      } else if (req.body.leakedContent) {
        rawContent = Buffer.from(req.body.leakedContent, req.body.isBase64 ? 'base64' : 'utf-8');
      }

      if (rawContent) {
        const extracted = collusionService.extractForensicFingerprint(rawContent);
        if (extracted && extracted.codeword) {
          suspectWatermark = extracted.codeword;
        }
      }
    }

    if (!suspectWatermark) {
      return res.status(400).json({
        error: 'Unable to detect or extract a forensic watermark. Provide a valid leaked file or watermarkCodeword.'
      });
    }

    // 2. Generate bias vector for this document
    const biases = collusionService.generateBiasVector(docId.toString());

    // 3. Build candidate list of all recipients
    const candidates = document.recipientKeys.map((rk) => {
      const user = rk.recipientId;
      const codeword = collusionService.generateRecipientCodeword(
        docId.toString(),
        user._id.toString(),
        biases
      );
      return {
        recipientId: user._id.toString(),
        username: user.username,
        email: user.email,
        codeword
      };
    });

    // 4. Run Traitor Tracing accusation algorithm
    const report = collusionService.traceTraitors({
      suspectWatermark,
      candidates,
      biases
    });

    // 5. Digitally sign the accusation findings using server private key
    const reportDigest = cryptoService.computeHash(JSON.stringify(report));
    const serverSignature = cryptoService.signPayload(reportDigest, env.SERVER_PRIVATE_KEY);

    return res.json({
      documentId: document._id,
      documentTitle: document.title,
      report,
      reportDigest,
      serverSignature,
      serverPublicKey: env.SERVER_PUBLIC_KEY
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Simulate a coalition collusion attack between recipients and trace them (Evaluation & Demo)
 */
async function simulateCollusionAttack(req, res, next) {
  try {
    const { id: docId } = req.params;
    const { colluderIds, strategy = 'interleaving' } = req.body;

    if (!Array.isArray(colluderIds) || colluderIds.length < 2) {
      return res.status(400).json({
        error: 'colluderIds must be an array of at least 2 recipient user IDs.'
      });
    }

    const document = await Document.findById(docId)
      .populate('recipientKeys.recipientId', 'username email role')
      .exec();

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    // 1. Generate biases and candidate codewords
    const biases = collusionService.generateBiasVector(docId.toString());
    const candidates = document.recipientKeys.map((rk) => {
      const user = rk.recipientId;
      const codeword = collusionService.generateRecipientCodeword(
        docId.toString(),
        user._id.toString(),
        biases
      );
      return {
        recipientId: user._id.toString(),
        username: user.username,
        email: user.email,
        codeword
      };
    });

    // 2. Extract codewords for the specified colluders
    const colluderCodewords = [];
    for (const cid of colluderIds) {
      const found = candidates.find((c) => c.recipientId === cid.toString());
      if (found) {
        colluderCodewords.push(found.codeword);
      }
    }

    if (colluderCodewords.length < 2) {
      return res.status(400).json({
        error: 'At least 2 colluders must match authorized recipients of this document.'
      });
    }

    // 3. Forge hybrid watermark
    const hybridWatermark = collusionService.simulateCollusion(colluderCodewords, strategy);

    // 4. Run traitor tracing on the forged hybrid
    const report = collusionService.traceTraitors({
      suspectWatermark: hybridWatermark,
      candidates,
      biases
    });

    return res.json({
      simulation: {
        documentId: document._id,
        strategy,
        simulatedColluders: colluderIds,
        hybridWatermarkLength: hybridWatermark.length
      },
      tracingResult: report
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  traceCollusion,
  simulateCollusionAttack
};
