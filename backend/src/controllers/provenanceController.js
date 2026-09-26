const ProvenanceLog = require('../models/ProvenanceLog');
const provenanceService = require('../services/provenanceService');
const fabricService = require('../services/fabricService');
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

/**
 * Hyperledger Fabric: Get ledger network and sync status
 */
async function getFabricStatus(req, res, next) {
  try {
    const status = await fabricService.getLedgerStatus();
    return res.json({ success: true, status });
  } catch (error) {
    next(error);
  }
}

/**
 * Hyperledger Fabric: Get specific event by eventId
 */
async function getFabricEvent(req, res, next) {
  try {
    const { eventId } = req.params;
    const event = await fabricService.getEvent(eventId);
    return res.json({ success: true, event });
  } catch (error) {
    next(error);
  }
}

/**
 * Hyperledger Fabric: Query events by watermark commitment or watermark ID
 */
async function queryFabricByWatermark(req, res, next) {
  try {
    const { watermarkQuery } = req.params;
    const events = await fabricService.queryByWatermark(watermarkQuery);
    return res.json({ success: true, count: events.length, events });
  } catch (error) {
    next(error);
  }
}

/**
 * Hyperledger Fabric: Query all decryption events for a document
 */
async function queryFabricByDocument(req, res, next) {
  try {
    const { documentId } = req.params;
    const events = await fabricService.queryByDocument(documentId);
    return res.json({ success: true, count: events.length, events });
  } catch (error) {
    next(error);
  }
}

/**
 * Hyperledger Fabric: Query all decryption events for a recipient
 */
async function queryFabricByRecipient(req, res, next) {
  try {
    const { recipientId } = req.params;
    const events = await fabricService.queryByRecipient(recipientId);
    return res.json({ success: true, count: events.length, events });
  } catch (error) {
    next(error);
  }
}

/**
 * Hyperledger Fabric: Cryptographically verify event integrity on-chain
 */
async function verifyFabricEvent(req, res, next) {
  try {
    const { eventId } = req.params;
    const verification = await fabricService.verifyEventIntegrity(eventId);
    return res.json({ success: true, verification });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  listLogs,
  verifyProvenanceChain,
  getServerPublicKey,
  getFabricStatus,
  getFabricEvent,
  queryFabricByWatermark,
  queryFabricByDocument,
  queryFabricByRecipient,
  verifyFabricEvent
};

