const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const crypto = require('node:crypto');

const fabricService = require('../src/services/fabricService');
const FabricLedgerRecord = require('../src/models/FabricLedgerRecord');
const decryptionSessionService = require('../src/services/decryptionSessionService');
const documentService = require('../src/services/documentService');
const Document = require('../src/models/Document');
const User = require('../src/models/User');
const Device = require('../src/models/Device');
const DecryptionSession = require('../src/models/DecryptionSession');
const keyAgentClient = require('../src/services/keyAgentClient');
const cryptoService = require('../src/services/cryptoService');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_test_fabric';

describe('Phase 6: Hyperledger Fabric Network & Ledger Invariants', () => {
  let recipient;
  let device;
  let document;
  const DEVICE_ID = 'device_fab_alice_01';

  before(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    await mongoose.connect(TEST_DB_URI);
    await FabricLedgerRecord.deleteMany({});
    await DecryptionSession.deleteMany({});
    await Document.deleteMany({});
    await User.deleteMany({});
    await Device.deleteMany({});

    // Setup recipient & local key agent
    const userKeys = await keyAgentClient.provisionRecipient('fabric_alice');
    const dummyRsa = cryptoService.generateKeyPair(2048);

    recipient = new User({
      username: 'fabric_alice',
      email: 'alice@fabric.mod.gov.in',
      password: 'dummy_password',
      role: 'RECIPIENT',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: userKeys.mlKemPublicKey,
      mlDsaPublicKey: userKeys.mlDsaPublicKey,
      keyVersion: 1,
      keyStatus: 'ACTIVE'
    });
    await recipient.save();

    device = new Device({
      userId: recipient._id,
      deviceId: DEVICE_ID,
      deviceFingerprint: crypto.createHash('sha256').update('alice-fabric-device').digest('hex'),
      platform: 'macos',
      status: 'ACTIVE'
    });
    await device.save();

    // Prepare encrypted document with ML-KEM envelope using documentService
    document = await documentService.uploadAndEncryptDocument({
      title: 'Fabric Provenance Directive',
      fileBuffer: Buffer.from('%PDF-1.4 Classified Operational Directive %EOF'),
      fileName: 'directive_pqc.pdf',
      senderId: recipient._id,
      recipientIds: [recipient._id],
      classification: 'TOP_SECRET'
    });
  });

  after(async () => {
    await FabricLedgerRecord.deleteMany({});
    await DecryptionSession.deleteMany({});
    await Document.deleteMany({});
    await User.deleteMany({});
    await Device.deleteMany({});
    await mongoose.disconnect();
  });

  test('Fabric Service returns valid ledger status metadata', async () => {
    const status = await fabricService.getLedgerStatus();
    assert.ok(status);
    assert.strictEqual(typeof status.mode, 'string');
    assert.strictEqual(status.channel, 'provenance-channel');
    assert.strictEqual(status.chaincode, 'provenance');
    assert.strictEqual(typeof status.totalEvents, 'number');
  });

  test('Commits valid decryption event to append-only Fabric ledger', async () => {
    const eventData = {
      eventId: 'evt_fabric_test_101',
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: 'doc_fab_1001',
      documentHash: crypto.randomBytes(32).toString('hex'),
      recipientId: 'rec_fab_alice',
      sessionId: 'sess_fab_001',
      watermarkId: 'wm_fab_alpha',
      watermarkCommitment: 'commit_fab_alpha_999',
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex'),
      timestamp: new Date().toISOString()
    };

    const committed = await fabricService.recordDecryptionEvent(eventData);

    assert.ok(committed);
    assert.strictEqual(committed.eventId, eventData.eventId);
    assert.strictEqual(committed.status, 'COMMITTED');
    assert.ok(committed.txId);
    assert.ok(committed.txId.startsWith('tx_'));
    assert.strictEqual(committed.blockNumber, 1);
  });

  test('Enforces immutability: Rejects duplicate event ID', async () => {
    const eventData = {
      eventId: 'evt_fabric_test_duplicate',
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: 'doc_fab_1002',
      documentHash: crypto.randomBytes(32).toString('hex'),
      recipientId: 'rec_fab_alice',
      sessionId: 'sess_fab_002',
      watermarkId: 'wm_fab_beta',
      watermarkCommitment: 'commit_fab_beta_888',
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex'),
      timestamp: new Date().toISOString()
    };

    await fabricService.recordDecryptionEvent(eventData);

    // Second attempt with same eventId must be rejected
    await assert.rejects(
      async () => {
        await fabricService.recordDecryptionEvent(eventData);
      },
      (err) => {
        assert.ok(err.message.includes('RECORD_ALREADY_EXISTS'));
        assert.ok(err.message.includes('immutable'));
        return true;
      }
    );
  });

  test('Validates mandatory cryptographic fields before ledger commit', async () => {
    // Missing watermarkCommitment
    await assert.rejects(
      async () => {
        await fabricService.recordDecryptionEvent({
          eventId: 'evt_invalid_001',
          eventDigest: 'digest',
          documentId: 'doc1',
          documentHash: 'hash1',
          recipientId: 'rec1',
          watermarkId: 'wm1',
          signature: 'sig1'
        });
      },
      /VALIDATION_FAILED: watermarkCommitment is required/
    );

    // Missing signature
    await assert.rejects(
      async () => {
        await fabricService.recordDecryptionEvent({
          eventId: 'evt_invalid_002',
          eventDigest: 'digest',
          documentId: 'doc1',
          documentHash: 'hash1',
          recipientId: 'rec1',
          watermarkId: 'wm1',
          watermarkCommitment: 'commit1'
        });
      },
      /VALIDATION_FAILED: signature is required/
    );
  });

  test('Queries ledger by Event ID and verifies integrity', async () => {
    const eventId = 'evt_fabric_query_001';
    await fabricService.recordDecryptionEvent({
      eventId,
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: 'doc_lookup_1',
      documentHash: crypto.randomBytes(32).toString('hex'),
      recipientId: 'rec_lookup_1',
      sessionId: 'sess_lookup_1',
      watermarkId: 'wm_lookup_1',
      watermarkCommitment: 'commit_lookup_1',
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex')
    });

    const event = await fabricService.getEvent(eventId);
    assert.strictEqual(event.eventId, eventId);
    assert.strictEqual(event.status, 'COMMITTED');

    const integrity = await fabricService.verifyEventIntegrity(eventId);
    assert.strictEqual(integrity.verified, true);
    assert.strictEqual(integrity.eventId, eventId);

    // Non-existent event throws EVENT_NOT_FOUND
    await assert.rejects(
      async () => {
        await fabricService.getEvent('evt_does_not_exist');
      },
      /EVENT_NOT_FOUND/
    );
  });

  test('Forensic Attribution: Resolves event by watermark commitment or watermark ID', async () => {
    const wmCommitment = 'target_watermark_commitment_abc123';
    const wmId = 'target_watermark_id_xyz789';

    await fabricService.recordDecryptionEvent({
      eventId: 'evt_forensic_001',
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: 'doc_classified_leak',
      documentHash: crypto.randomBytes(32).toString('hex'),
      recipientId: 'suspect_user_007',
      sessionId: 'sess_leak_001',
      watermarkId: wmId,
      watermarkCommitment: wmCommitment,
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex')
    });

    // 1. Query by watermark commitment
    const resultsByCommitment = await fabricService.queryByWatermark(wmCommitment);
    assert.strictEqual(resultsByCommitment.length, 1);
    assert.strictEqual(resultsByCommitment[0].eventId, 'evt_forensic_001');
    assert.strictEqual(resultsByCommitment[0].recipientId, 'suspect_user_007');

    // 2. Query by watermark ID
    const resultsById = await fabricService.queryByWatermark(wmId);
    assert.strictEqual(resultsById.length, 1);
    assert.strictEqual(resultsById[0].eventId, 'evt_forensic_001');
  });

  test('Queries complete decryption provenance history for a document', async () => {
    const docId = 'doc_multi_decrypt_history';

    await fabricService.recordDecryptionEvent({
      eventId: 'evt_hist_1',
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: docId,
      documentHash: 'hash_common',
      recipientId: 'user_1',
      sessionId: 'sess_1',
      watermarkId: 'wm_1',
      watermarkCommitment: 'commit_1',
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex')
    });

    await fabricService.recordDecryptionEvent({
      eventId: 'evt_hist_2',
      eventDigest: crypto.randomBytes(32).toString('hex'),
      documentId: docId,
      documentHash: 'hash_common',
      recipientId: 'user_2',
      sessionId: 'sess_2',
      watermarkId: 'wm_2',
      watermarkCommitment: 'commit_2',
      signingKeyId: 'ML-DSA-65-V1',
      signature: crypto.randomBytes(64).toString('hex')
    });

    const docHistory = await fabricService.queryByDocument(docId);
    assert.strictEqual(docHistory.length, 2);
    const eventIds = docHistory.map((e) => e.eventId);
    assert.ok(eventIds.includes('evt_hist_1'));
    assert.ok(eventIds.includes('evt_hist_2'));
  });

  test('End-to-End Decryption Pipeline commits to Fabric and passes Fail-Closed gate', async () => {
    // 1. Initialize session
    const session = await decryptionSessionService.createSession({
      documentId: document._id.toString(),
      recipientId: recipient._id.toString(),
      deviceId: DEVICE_ID
    });

    assert.ok(session.sessionId);
    assert.strictEqual(session.status, 'CREATED');

    // 2. Prepare session (triggers Stages 1 -> 2 -> 3 -> 4 -> 5 Fabric commit -> Released)
    const result = await decryptionSessionService.prepareSession({
      sessionId: session.sessionId,
      recipientId: recipient._id.toString(),
      deviceId: DEVICE_ID
    });

    assert.strictEqual(result.status, 'RELEASED');
    assert.ok(result.session.ledgerTxId);
    assert.ok(result.session.ledgerTxId.startsWith('tx_'));

    // Verify on Fabric ledger
    const fabricEvent = await fabricService.getEvent(`evt_${session.sessionId}`);
    assert.ok(fabricEvent);
    assert.strictEqual(fabricEvent.eventId, `evt_${session.sessionId}`);
    assert.strictEqual(fabricEvent.sessionId, session.sessionId);
    assert.strictEqual(fabricEvent.watermarkCommitment, result.watermarkCommitment);
    assert.strictEqual(fabricEvent.status, 'COMMITTED');

    // Verify forensic attribution lookup matches this session
    const matched = await fabricService.queryByWatermark(result.watermarkCommitment);
    assert.strictEqual(matched.length, 1);
    assert.strictEqual(matched[0].sessionId, session.sessionId);
    assert.strictEqual(matched[0].recipientId, recipient._id.toString());
  });
});
