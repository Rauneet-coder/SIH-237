'use strict';

const crypto = require('node:crypto');
const ProvenanceLog = require('../models/ProvenanceLog');
const cryptoService = require('./cryptoService');
const env = require('../config/env');

const GENESIS_PREV_HASH = '0'.repeat(64);

/**
 * Deterministically sort object keys for canonical JSON serialization (RFC 8785 style)
 */
function sortKeys(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortKeys(value[key]);
  }
  return sorted;
}

/**
 * Compute canonical SHA-256 hash of entry details object
 * Ensures any tampering with session, watermark, device, or transaction fields is detected.
 */
function computeDetailsHash(details = {}) {
  const normalized = sortKeys(details || {});
  const canonicalJson = JSON.stringify(normalized);
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}

/**
 * Version 1 (Legacy) canonical string representation
 * Provided for backward-compatible verification of historical entries.
 */
function createCanonicalPayload({ sequenceNumber, prevHash, docId, recipientId, action, status, timestampIso }) {
  return `${sequenceNumber}|${prevHash}|${docId}|${recipientId}|${action}|${status}|${timestampIso}`;
}

/**
 * Version 2 Canonical string representation
 * Cryptographically binds all security-relevant details into the signed payload.
 */
function createCanonicalPayloadV2({ sequenceNumber, prevHash, docId, recipientId, action, status, timestampIso, detailsHash }) {
  return `v2|${sequenceNumber}|${prevHash}|${docId}|${recipientId}|${action}|${status}|${timestampIso}|${detailsHash}`;
}

// In-process lock to prevent concurrent append race conditions and sequence forks
let appendLock = Promise.resolve();

/**
 * Append an immutable, hash-chained and digitally signed event to the provenance log
 */
async function logProvenanceEvent({ docId, recipientId, action, status, details = {} }) {
  // Acquire sequential append lock
  let releaseLock;
  const currentLock = appendLock;
  appendLock = new Promise((resolve) => {
    releaseLock = resolve;
  });

  try {
    await currentLock;

    // 1. Fetch the most recent provenance log to determine sequence and prevHash
    const lastEntry = await ProvenanceLog.findOne().sort({ sequenceNumber: -1 }).exec();

    const sequenceNumber = lastEntry ? lastEntry.sequenceNumber + 1 : 1;
    const prevHash = lastEntry ? lastEntry.entryHash : GENESIS_PREV_HASH;
    const timestamp = new Date();
    const timestampIso = timestamp.toISOString();

    // 2. Compute detailsHash and canonical payload v2
    const detailsHash = computeDetailsHash(details);
    const canonicalPayload = createCanonicalPayloadV2({
      sequenceNumber,
      prevHash,
      docId: docId.toString(),
      recipientId: recipientId.toString(),
      action,
      status,
      timestampIso,
      detailsHash
    });

    const entryHash = cryptoService.computeHash(canonicalPayload);

    // 3. Digitally sign entryHash with the server authority private key (RSA-SHA256)
    const signature = cryptoService.signPayload(entryHash, env.SERVER_PRIVATE_KEY);

    // 4. Persist to MongoDB
    const logEntry = new ProvenanceLog({
      sequenceNumber,
      docId,
      recipientId,
      action,
      status,
      timestamp,
      prevHash,
      entryHash,
      signature,
      schemaVersion: 2,
      detailsHash,
      authorityKeyId: 'SERVER-AUTHORITY-RSA-V1',
      details
    });

    await logEntry.save();
    return logEntry;
  } finally {
    releaseLock();
  }
}

/**
 * Cryptographically audit and verify the entire provenance log chain
 * Supports backward-compatible verification of both v1 and v2 entries.
 */
async function verifyChain() {
  const logs = await ProvenanceLog.find().sort({ sequenceNumber: 1 }).exec();
  const issues = [];

  if (logs.length === 0) {
    return {
      isValid: true,
      valid: true,
      tampered: false,
      totalEntries: 0,
      totalBlocks: 0,
      genesisValid: true,
      chainIntegrityValid: true,
      allSignaturesValid: true,
      tamperedSequences: [],
      verifiedAt: new Date().toISOString(),
      issues: []
    };
  }

  for (let i = 0; i < logs.length; i++) {
    const current = logs[i];
    const expectedSeq = i + 1;

    // 1. Check sequence number continuity
    if (current.sequenceNumber !== expectedSeq) {
      issues.push(
        `Sequence gap at index ${i}: expected #${expectedSeq}, found #${current.sequenceNumber}`
      );
    }

    // 2. Check prevHash linkage
    if (i === 0) {
      if (current.prevHash !== GENESIS_PREV_HASH) {
        issues.push(
          `Genesis block #${current.sequenceNumber} has invalid prevHash: expected ${GENESIS_PREV_HASH}, found ${current.prevHash}`
        );
      }
    } else {
      const predecessor = logs[i - 1];
      if (current.prevHash !== predecessor.entryHash) {
        issues.push(
          `Hash chain broken at entry #${current.sequenceNumber}: prevHash ${current.prevHash} does not match predecessor #${predecessor.sequenceNumber} entryHash ${predecessor.entryHash}`
        );
      }
    }

    // 3. Recompute canonical payload and compare entryHash based on version
    let expectedPayload;
    if (current.schemaVersion === 2 || current.detailsHash) {
      const computedDetailsHash = computeDetailsHash(current.details || {});
      if (current.detailsHash && current.detailsHash !== computedDetailsHash) {
        issues.push(
          `Details tampered at entry #${current.sequenceNumber}: stored detailsHash ${current.detailsHash} does not match computed ${computedDetailsHash}`
        );
      }

      expectedPayload = createCanonicalPayloadV2({
        sequenceNumber: current.sequenceNumber,
        prevHash: current.prevHash,
        docId: current.docId.toString(),
        recipientId: current.recipientId.toString(),
        action: current.action,
        status: current.status,
        timestampIso: current.timestamp.toISOString(),
        detailsHash: computedDetailsHash
      });
    } else {
      // Backward-compatible v1 verification for historical entries
      expectedPayload = createCanonicalPayload({
        sequenceNumber: current.sequenceNumber,
        prevHash: current.prevHash,
        docId: current.docId.toString(),
        recipientId: current.recipientId.toString(),
        action: current.action,
        status: current.status,
        timestampIso: current.timestamp.toISOString()
      });
    }

    const expectedHash = cryptoService.computeHash(expectedPayload);
    if (current.entryHash !== expectedHash) {
      issues.push(
        `Hash mismatch at entry #${current.sequenceNumber}: stored ${current.entryHash}, computed ${expectedHash} (payload may be altered)`
      );
    }

    // 4. Verify server digital signature
    const isSignatureValid = cryptoService.verifySignature(
      current.entryHash,
      current.signature,
      env.SERVER_PUBLIC_KEY
    );

    if (!isSignatureValid) {
      issues.push(
        `Invalid digital signature at entry #${current.sequenceNumber}: signature does not authenticate against server public key`
      );
    }
  }

  const genesisValid = logs.length === 0 || logs[0].prevHash === GENESIS_PREV_HASH;
  const tamperedSequences = issues.map((iss) => {
    const match = iss.match(/#(\d+)/);
    return match ? parseInt(match[1], 10) : 1;
  });

  return {
    isValid: issues.length === 0,
    valid: issues.length === 0,
    tampered: issues.length > 0,
    totalEntries: logs.length,
    totalBlocks: logs.length,
    genesisValid,
    chainIntegrityValid: issues.length === 0,
    allSignaturesValid: issues.length === 0,
    tamperedSequences: Array.from(new Set(tamperedSequences)),
    verifiedAt: new Date().toISOString(),
    issues
  };
}

module.exports = {
  GENESIS_PREV_HASH,
  computeDetailsHash,
  createCanonicalPayload,
  createCanonicalPayloadV2,
  logProvenanceEvent,
  verifyChain
};
