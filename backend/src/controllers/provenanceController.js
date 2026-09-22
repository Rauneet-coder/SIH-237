const ProvenanceLog = require('../models/ProvenanceLog');
const provenanceService = require('../services/provenanceService');
const env = require('../config/env');

/**
 * List provenance audit logs with filtering and pagination
 */
async function listLogs(req, res, next) {
  try {
    const { docId, recipientId, action, status, limit = 50, skip = 0 } = req.query;

    const query = {};
    if (docId) query.docId = docId;
    if (recipientId) query.recipientId = recipientId;
    if (action) query.action = action;
    if (status) query.status = status;

    const total = await ProvenanceLog.countDocuments(query);
    const logs = await ProvenanceLog.find(query)
      .populate('docId', 'title fileName fileHash')
      .populate('recipientId', 'username email role')
      .sort({ sequenceNumber: 1 })
      .skip(Number(skip))
      .limit(Number(limit))
      .exec();

    return res.json({
      total,
      limit: Number(limit),
      skip: Number(skip),
      logs
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Run cryptographic verification of the entire provenance log hash chain
 */
async function verifyProvenanceChain(req, res, next) {
  try {
    const auditReport = await provenanceService.verifyChain();
    return res.json({
      report: auditReport,
      serverPublicKey: env.SERVER_PUBLIC_KEY
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get server's public authority key used to sign the provenance chain
 */
async function getServerPublicKey(req, res, next) {
  try {
    return res.json({
      serverPublicKey: env.SERVER_PUBLIC_KEY,
      algorithm: 'RSA-SHA256'
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  listLogs,
  verifyProvenanceChain,
  getServerPublicKey
};
