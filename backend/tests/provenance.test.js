const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const ProvenanceLog = require('../src/models/ProvenanceLog');
const {
  GENESIS_PREV_HASH,
  createCanonicalPayload,
  logProvenanceEvent,
  verifyChain
} = require('../src/services/provenanceService');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_provenance_test';

describe('Provenance Hash-Chain & Verification Service', () => {
  before(async () => {
    await connectDB(TEST_DB_URI);
  });

  after(async () => {
    await ProvenanceLog.deleteMany({});
    await disconnectDB();
  });

  beforeEach(async () => {
    await ProvenanceLog.deleteMany({});
  });

  test('should create genesis block with 64-zero prevHash and valid signature', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId = new mongoose.Types.ObjectId();

    const entry = await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS',
      details: { fileName: 'defense_briefing.pdf' }
    });

    assert.equal(entry.sequenceNumber, 1);
    assert.equal(entry.prevHash, GENESIS_PREV_HASH);
    assert.equal(entry.action, 'DOCUMENT_UPLOAD');
    assert.equal(entry.status, 'SUCCESS');
    assert.ok(entry.entryHash);
    assert.ok(entry.signature);
  });

  test('should chain subsequent blocks using previous entryHash as prevHash', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId1 = new mongoose.Types.ObjectId();
    const recipientId2 = new mongoose.Types.ObjectId();

    const entry1 = await logProvenanceEvent({
      docId,
      recipientId: recipientId1,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS'
    });

    const entry2 = await logProvenanceEvent({
      docId,
      recipientId: recipientId2,
      action: 'DECRYPT_ATTEMPT',
      status: 'SUCCESS'
    });

    const entry3 = await logProvenanceEvent({
      docId,
      recipientId: recipientId2,
      action: 'DECRYPT_SUCCESS',
      status: 'SUCCESS'
    });

    assert.equal(entry2.sequenceNumber, 2);
    assert.equal(entry2.prevHash, entry1.entryHash);

    assert.equal(entry3.sequenceNumber, 3);
    assert.equal(entry3.prevHash, entry2.entryHash);
  });

  test('should verify valid provenance chain successfully with 0 issues', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId = new mongoose.Types.ObjectId();

    await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS'
    });

    await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_ATTEMPT',
      status: 'SUCCESS'
    });

    await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_SUCCESS',
      status: 'SUCCESS'
    });

    const verification = await verifyChain();
    assert.equal(verification.isValid, true);
    assert.equal(verification.totalEntries, 3);
    assert.equal(verification.issues.length, 0);
  });

  test('should detect payload tampering in the provenance chain', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId = new mongoose.Types.ObjectId();

    await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS'
    });

    const entry2 = await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_SUCCESS',
      status: 'SUCCESS'
    });

    // Tamper with entry2 in the database directly
    await ProvenanceLog.updateOne(
      { _id: entry2._id },
      { $set: { action: 'DECRYPT_FAILURE', status: 'FAILURE' } }
    );

    const verification = await verifyChain();
    assert.equal(verification.isValid, false);
    assert.ok(verification.issues.some((issue) => issue.includes('Hash mismatch at entry #2')));
  });

  test('should detect signature tampering in the provenance chain', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId = new mongoose.Types.ObjectId();

    const entry = await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS'
    });

    // Tamper signature
    const fakeSignature = Buffer.from('corrupted_signature').toString('base64');
    await ProvenanceLog.updateOne(
      { _id: entry._id },
      { $set: { signature: fakeSignature } }
    );

    const verification = await verifyChain();
    assert.equal(verification.isValid, false);
    assert.ok(
      verification.issues.some((issue) =>
        issue.includes('Invalid digital signature at entry #1')
      )
    );
  });

  test('should detect broken hash-chain links (prevHash alteration)', async () => {
    const docId = new mongoose.Types.ObjectId();
    const recipientId = new mongoose.Types.ObjectId();

    await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS'
    });

    const entry2 = await logProvenanceEvent({
      docId,
      recipientId,
      action: 'DECRYPT_SUCCESS',
      status: 'SUCCESS'
    });

    // Tamper with entry2's prevHash
    const brokenHash = 'f'.repeat(64);
    await ProvenanceLog.updateOne(
      { _id: entry2._id },
      { $set: { prevHash: brokenHash } }
    );

    const verification = await verifyChain();
    assert.equal(verification.isValid, false);
    assert.ok(
      verification.issues.some((issue) =>
        issue.includes('Hash chain broken at entry #2')
      )
    );
  });
});
