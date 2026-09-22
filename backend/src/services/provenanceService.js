const ProvenanceLog = require('../models/ProvenanceLog');
const cryptoService = require('./cryptoService');
const env = require('../config/env');

const GENESIS_PREV_HASH = '0'.repeat(64);

/**
 * Creates a deterministic canonical string representation of a provenance log entry
 * for cryptographic hashing and verification.
 */
function createCanonicalPayload({ sequenceNumber, prevHash, docId, recipientId, action, status, timestampIso }) {
  return `${sequenceNumber}|${prevHash}|${docId}|${recipientId}|${action}|${status}|${timestampIso}`;
}

/**
 * Append an immutable, hash-chained and digitally signed event to the provenance log
 * @param {Object} params
 * @param {string|mongoose.Types.ObjectId} params.docId - Associated document ID
 * @param {string|mongoose.Types.ObjectId} params.recipientId - Recipient or actor ID
 * @param {string} params.action - DOCUMENT_UPLOAD | DECRYPT_ATTEMPT | DECRYPT_SUCCESS | DECRYPT_FAILURE
 * @param {string} params.status - SUCCESS | FAILURE
 * @param {Object} [params.details] - Arbitrary additional metadata
 * @returns {Promise<Object>} Created ProvenanceLog document
 */
async function logProvenanceEvent({ docId, recipientId, action, status, details = {} }) {
  // 1. Fetch the most recent provenance log to determine sequence and prevHash
  const lastEntry = await ProvenanceLog.findOne().sort({ sequenceNumber: -1 }).exec();

  const sequenceNumber = lastEntry ? lastEntry.sequenceNumber + 1 : 1;
  const prevHash = lastEntry ? lastEntry.entryHash : GENESIS_PREV_HASH;
  const timestamp = new Date();
  const timestampIso = timestamp.toISOString();

  // 2. Compute canonical payload and its SHA-256 digest
  const canonicalPayload = createCanonicalPayload({
    sequenceNumber,
    prevHash,
    docId: docId.toString(),
    recipientId: recipientId.toString(),
    action,
    status,
    timestampIso
  });

  const entryHash = cryptoService.computeHash(canonicalPayload);

  // 3. Digitally sign the entryHash using the server's private authority key
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
    details
  });

  await logEntry.save();
  return logEntry;
}

/**
 * Cryptographically audit and verify the entire provenance log chain
 * - Validates sequence continuity (1..N without gaps)
 * - Validates genesis block prevHash (64 zeros)
 * - Validates cryptographic linkage (each entry's prevHash matches predecessor's entryHash)
 * - Recomputes every entryHash from canonical payload
 * - Verifies every digital signature using the server's public key
 * @returns {Promise<{ isValid: boolean, totalEntries: number, verifiedAt: string, issues: string[] }>}
 */
async function verifyChain() {
  const logs = await ProvenanceLog.find().sort({ sequenceNumber: 1 }).exec();
  const issues = [];

  if (logs.length === 0) {
    return {
      isValid: true,
      totalEntries: 0,
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

    // 3. Recompute canonical payload and compare entryHash
    const expectedPayload = createCanonicalPayload({
      sequenceNumber: current.sequenceNumber,
      prevHash: current.prevHash,
      docId: current.docId.toString(),
      recipientId: current.recipientId.toString(),
      action: current.action,
      status: current.status,
      timestampIso: current.timestamp.toISOString()
    });

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
    tamperedSequences,
    verifiedAt: new Date().toISOString(),
    issues
  };
}

module.exports = {
  GENESIS_PREV_HASH,
  createCanonicalPayload,
  logProvenanceEvent,
  verifyChain
};
