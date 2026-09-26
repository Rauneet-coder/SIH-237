const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const app = require('../src/server');
const User = require('../src/models/User');
const Document = require('../src/models/Document');
const DecryptionSession = require('../src/models/DecryptionSession');
const keyAgentClient = require('../src/services/keyAgentClient');
const documentService = require('../src/services/documentService');
const fingerprintService = require('../src/services/fingerprintService');
const canonicalEventService = require('../src/services/canonicalEventService');
const decryptionSessionService = require('../src/services/decryptionSessionService');
const cryptoService = require('../src/services/cryptoService');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_test_session';

let server;
let baseUrl;

before(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI);
  }
  await User.deleteMany({});
  await Document.deleteMany({});
  await DecryptionSession.deleteMany({});

  server = app.listen(0);
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  if (server) server.close();
  await User.deleteMany({});
  await Document.deleteMany({});
  await DecryptionSession.deleteMany({});
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

describe('Phase 4 & 5: Forensic Fingerprinting, Canonical Events & Fail-Closed Sessions', () => {
  let sender;
  let recipient;
  let intruder;
  let document;
  let recipientToken;
  let intruderToken;

  before(async () => {
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash('password123', 10);

    // 1. Provision users in Key Agent and DB
    const senderKeys = await keyAgentClient.provisionRecipient('sender_general');
    const recipientKeys = await keyAgentClient.provisionRecipient('recipient_colonel');
    const intruderKeys = await keyAgentClient.provisionRecipient('intruder_agent');

    const dummyRsa = cryptoService.generateKeyPair(2048);

    sender = await User.create({
      username: 'sender_general',
      email: 'general@mod.gov.in',
      password: hashedPassword,
      role: 'DOCUMENT_OWNER',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: senderKeys.mlKemPublicKey,
      mlDsaPublicKey: senderKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    recipient = await User.create({
      username: 'recipient_colonel',
      email: 'colonel@mod.gov.in',
      password: hashedPassword,
      role: 'RECIPIENT',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: recipientKeys.mlKemPublicKey,
      mlDsaPublicKey: recipientKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    intruder = await User.create({
      username: 'intruder_agent',
      email: 'intruder@external.org',
      password: hashedPassword,
      role: 'RECIPIENT',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: intruderKeys.mlKemPublicKey,
      mlDsaPublicKey: intruderKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    // 2. Upload and encrypt classified document (Encrypt Once)
    document = await documentService.uploadAndEncryptDocument({
      title: 'Operational Plan Desert Storm 2026',
      fileBuffer: Buffer.from('%PDF-1.4 Classified Operational Briefing %EOF'),
      fileName: 'op_plan.pdf',
      senderId: sender._id,
      recipientIds: [recipient._id],
      classification: 'TOP_SECRET'
    });

    // 3. Issue JWT tokens
    const recLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'recipient_colonel', password: 'password123' })
    });
    recipientToken = (await recLogin.json()).token;

    const intLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'intruder_agent', password: 'password123' })
    });
    intruderToken = (await intLogin.json()).token;
  });

  describe('Forensic Fingerprint Derivation (Phase 4)', () => {
    it('should derive deterministic opaque watermarkId and commitment without PII', () => {
      const fp1 = fingerprintService.deriveFingerprint({
        recipientId: recipient._id.toString(),
        documentId: document.documentId,
        documentHash: document.fileHash,
        sessionId: 'SES-TEST-01',
        sessionNonce: '0102030405060708090a0b0c0d0e0f10'
      });

      const fp2 = fingerprintService.deriveFingerprint({
        recipientId: recipient._id.toString(),
        documentId: document.documentId,
        documentHash: document.fileHash,
        sessionId: 'SES-TEST-01',
        sessionNonce: '0102030405060708090a0b0c0d0e0f10'
      });

      assert.equal(fp1.watermarkId, fp2.watermarkId, 'Identical parameters must derive identical watermark ID');
      assert.equal(fp1.watermarkCommitment, fp2.watermarkCommitment);
      assert.ok(fp1.watermarkId.startsWith('WID-'));
      assert.equal(fp1.watermarkCommitment.length, 64, 'Commitment must be 64 hex chars (SHA-256)');

      // Different session must derive distinct watermark ID
      const fpOther = fingerprintService.deriveFingerprint({
        recipientId: recipient._id.toString(),
        documentId: document.documentId,
        documentHash: document.fileHash,
        sessionId: 'SES-TEST-02',
        sessionNonce: '1112131415161718191a1b1c1d1e1f20'
      });

      assert.notEqual(fp1.watermarkId, fpOther.watermarkId, 'Different sessions must yield distinct watermark IDs');
    });
  });

  describe('Deterministic RFC 8785 Canonical Event Serializer (Phase 5)', () => {
    it('should produce identical canonical strings regardless of JSON key insertion order', () => {
      const objA = {
        sessionId: 'SES-1',
        deviceId: 'DEV-1',
        documentId: 'DOC-1',
        eventType: 'DOCUMENT_DECRYPTION'
      };

      const objB = {
        eventType: 'DOCUMENT_DECRYPTION',
        documentId: 'DOC-1',
        deviceId: 'DEV-1',
        sessionId: 'SES-1'
      };

      const canonA = canonicalEventService.serializeCanonical(objA);
      const canonB = canonicalEventService.serializeCanonical(objB);

      assert.equal(canonA, canonB, 'RFC 8785 canonical serialization must be order-independent');
      assert.equal(canonA, '{"deviceId":"DEV-1","documentId":"DOC-1","eventType":"DOCUMENT_DECRYPTION","sessionId":"SES-1"}');
    });
  });

  describe('Decryption Session State Machine & Fail-Closed Pipeline', () => {
    let activeSessionId;

    it('should create a new decryption session in CREATED state', async () => {
      const res = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-COLONEL-SECURE'
        },
        body: JSON.stringify({
          documentId: document._id
        })
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.sessionId);
      assert.equal(data.status, 'CREATED');
      activeSessionId = data.sessionId;
    });

    it('should execute prepare pipeline, advance to RELEASED, and sign with ML-DSA', async () => {
      const res = await fetch(`${baseUrl}/api/sessions/${activeSessionId}/prepare`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-COLONEL-SECURE'
        }
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'RELEASED');
      assert.ok(data.watermarkId);
      assert.ok(data.watermarkCommitment);
      assert.ok(data.eventDigest);
      assert.ok(data.signature, 'Must have ML-DSA digital signature');
      assert.ok(data.ledgerTxId, 'Must have ledger transaction ID');
    });

    it('should release watermarked document stream only when session is RELEASED', async () => {
      const res = await fetch(`${baseUrl}/api/sessions/${activeSessionId}/render`, {
        headers: {
          Authorization: `Bearer ${recipientToken}`
        }
      });

      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/pdf');
      const body = await res.arrayBuffer();
      assert.ok(body.byteLength > 0, 'Must deliver rendered watermarked PDF');
    });

    it('should reject unauthorized user attempting to initialize or prepare session', async () => {
      const res = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${intruderToken}`,
          'x-device-id': 'DEV-ROGUE-01'
        },
        body: JSON.stringify({
          documentId: document._id
        })
      });

      assert.equal(res.status, 403, 'Unauthorized user must be rejected at session creation');
    });

    it('should deny document render if session is in FAILED or non-released state', async () => {
      // Create session and force to FAILED
      const failedSession = await DecryptionSession.create({
        sessionId: 'SES-FAILED-DEMO',
        documentId: document._id,
        recipientId: recipient._id,
        deviceId: 'DEV-COLONEL-SECURE',
        sessionNonce: 'nonce-12345',
        status: 'FAILED',
        failureReason: 'Tampered watermark detected',
        expiresAt: new Date(Date.now() + 60000)
      });

      const res = await fetch(`${baseUrl}/api/sessions/${failedSession.sessionId}/render`, {
        headers: {
          Authorization: `Bearer ${recipientToken}`
        }
      });

      assert.equal(res.status, 403, 'Failed session must trigger Fail-Closed denial');
      const data = await res.json();
      assert.equal(data.code, 'FAIL_CLOSED_RELEASE_DENIED');
    });
  });
});
