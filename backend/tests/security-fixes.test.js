'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const app = require('../src/server');
const env = require('../src/config/env');
const User = require('../src/models/User');
const Document = require('../src/models/Document');
const Device = require('../src/models/Device');
const DecryptionSession = require('../src/models/DecryptionSession');
const FabricLedgerRecord = require('../src/models/FabricLedgerRecord');
const ProvenanceLog = require('../src/models/ProvenanceLog');
const keyAgentClient = require('../src/services/keyAgentClient');
const documentService = require('../src/services/documentService');
const provenanceService = require('../src/services/provenanceService');
const forensicService = require('../src/services/forensicService');
const fileVaultService = require('../src/services/fileVaultService');
const watermarkBridge = require('../src/services/watermarkBridge');
const cryptoService = require('../src/services/cryptoService');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_test_security_fixes';

let server;
let baseUrl;

before(async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  await mongoose.connect(TEST_DB_URI);

  await User.deleteMany({});
  await Document.deleteMany({});
  await Device.deleteMany({});
  await DecryptionSession.deleteMany({});
  await FabricLedgerRecord.deleteMany({});
  await ProvenanceLog.deleteMany({});

  server = app.listen(0);
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  if (server) server.close();
  await User.deleteMany({});
  await Document.deleteMany({});
  await Device.deleteMany({});
  await DecryptionSession.deleteMany({});
  await FabricLedgerRecord.deleteMany({});
  await ProvenanceLog.deleteMany({});
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

describe('Security & Correctness Regression Suite (Post-Audit Fixes)', () => {
  let sender;
  let recipient;
  let recipientDevice;
  let recipientToken;
  let testDocument;

  before(async () => {
    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash('SecurePassword2026!', 10);

    const senderKeys = await keyAgentClient.provisionRecipient('sec_sender_general');
    const recipientKeys = await keyAgentClient.provisionRecipient('sec_recipient_major');

    const dummyRsa = cryptoService.generateKeyPair(2048);

    sender = await User.create({
      username: 'sec_sender_general',
      email: 'sec_sender@mod.gov.in',
      password: passwordHash,
      role: 'SENDER',
      clearance: 'TOP_SECRET',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: senderKeys.mlKemPublicKey,
      mlDsaPublicKey: senderKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    recipient = await User.create({
      username: 'sec_recipient_major',
      email: 'sec_recipient@mod.gov.in',
      password: passwordHash,
      role: 'RECIPIENT',
      clearance: 'TOP_SECRET',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: recipientKeys.mlKemPublicKey,
      mlDsaPublicKey: recipientKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    recipientDevice = await Device.create({
      userId: recipient._id,
      deviceId: 'DEV-HW-SECURE-99',
      deviceFingerprint: 'hw-sha256-fingerprint-approved',
      platform: 'linux-tpm',
      status: 'ACTIVE'
    });

    // Create a valid encrypted test PDF document
    testDocument = await documentService.uploadAndEncryptDocument({
      title: 'Tactical Reconnaissance Alpha',
      fileBuffer: Buffer.from('%PDF-1.4 Classified Tactical Surveillance Data %EOF'),
      fileName: 'tactical_recon.pdf',
      senderId: sender._id,
      recipientIds: [recipient._id],
      classification: 'TOP_SECRET'
    });

    // Login recipient to acquire JWT
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'sec_recipient_major',
        password: 'SecurePassword2026!'
      })
    });
    const loginData = await loginRes.json();
    recipientToken = loginData.token;
  });

  // ── 1. DEVICE PROOF & RELEASE ENFORCEMENT ──────────────────────────────────
  describe('1. Device Proof & Session Release Enforcement', () => {
    it('should reject session creation when x-device-id header is missing', async () => {
      const res = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });

      assert.equal(res.status, 403);
      const data = await res.json();
      assert.ok(data.error.includes('x-device-id') || data.error.includes('Device'));
    });

    it('should reject session creation for unregistered or unknown device ID', async () => {
      const res = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-UNKNOWN-ROGUE-01'
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });

      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.code, 'AUTHORIZATION_ERROR');
    });

    it('should deny document render when device header does not match session device', async () => {
      // 1. Create legitimate session
      const createRes = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });
      assert.equal(createRes.status, 201);
      const { sessionId } = await createRes.json();

      // 2. Prepare session
      const prepRes = await fetch(`${baseUrl}/api/sessions/${sessionId}/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        }
      });
      assert.equal(prepRes.status, 200);

      // 3. Register second valid device for same user
      await Device.create({
        userId: recipient._id,
        deviceId: 'DEV-HW-SECONDARY-02',
        deviceFingerprint: 'secondary-fp',
        platform: 'linux-tpm',
        status: 'ACTIVE'
      });

      // 4. Attempt render using the other device -> MUST fail-closed with 403
      const renderRes = await fetch(`${baseUrl}/api/sessions/${sessionId}/render`, {
        headers: {
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECONDARY-02'
        }
      });

      assert.equal(renderRes.status, 403);
      const renderData = await renderRes.json();
      assert.ok(renderData.code === 'AUTHORIZATION_ERROR' || renderData.code === 'FAIL_CLOSED_RELEASE_DENIED');
      assert.ok(renderData.error.includes('Device mismatch') || renderData.error.includes('device'));
    });

    it('should close server session via POST /api/sessions/:id/close and block render', async () => {
      // Create and prepare session
      const createRes = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });
      const { sessionId } = await createRes.json();

      await fetch(`${baseUrl}/api/sessions/${sessionId}/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        }
      });

      // User locks viewer -> invokes close session
      const closeRes = await fetch(`${baseUrl}/api/sessions/${sessionId}/close`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${recipientToken}`
        }
      });
      assert.equal(closeRes.status, 200);
      const closeData = await closeRes.json();
      assert.equal(closeData.status, 'REVOKED');

      // Subsequent render attempt MUST be rejected with 403
      const renderRes = await fetch(`${baseUrl}/api/sessions/${sessionId}/render`, {
        headers: {
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        }
      });
      assert.equal(renderRes.status, 403);
      const renderData = await renderRes.json();
      assert.equal(renderData.code, 'FAIL_CLOSED_RELEASE_DENIED');
    });

    it('should block document render if recipient key is revoked after session preparation', async () => {
      const createRes = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });
      const { sessionId } = await createRes.json();

      await fetch(`${baseUrl}/api/sessions/${sessionId}/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        }
      });

      // Revoke recipient key status in DB
      await User.findByIdAndUpdate(recipient._id, { keyStatus: 'REVOKED' });

      // Attempt render -> MUST fail-closed because key is revoked
      const renderRes = await fetch(`${baseUrl}/api/sessions/${sessionId}/render`, {
        headers: {
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        }
      });
      assert.equal(renderRes.status, 403);
      const data = await renderRes.json();
      assert.ok(data.code === 'AUTHORIZATION_ERROR' || data.code === 'FAIL_CLOSED_RELEASE_DENIED');
      assert.ok(data.error.includes('revoked'));

      // Restore key status for subsequent tests
      await User.findByIdAndUpdate(recipient._id, { keyStatus: 'ACTIVE' });
    });

    it('should handle concurrent preparation requests atomically without race conditions', async () => {
      const createRes = await fetch(`${baseUrl}/api/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${recipientToken}`,
          'x-device-id': 'DEV-HW-SECURE-99'
        },
        body: JSON.stringify({ documentId: testDocument._id })
      });
      const { sessionId } = await createRes.json();

      // Launch 2 parallel prepareSession requests simultaneously
      const [res1, res2] = await Promise.all([
        fetch(`${baseUrl}/api/sessions/${sessionId}/prepare`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${recipientToken}`,
            'x-device-id': 'DEV-HW-SECURE-99'
          }
        }),
        fetch(`${baseUrl}/api/sessions/${sessionId}/prepare`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${recipientToken}`,
            'x-device-id': 'DEV-HW-SECURE-99'
          }
        })
      ]);

      const statuses = [res1.status, res2.status];
      assert.ok(statuses.includes(200));

      const updatedSession = await DecryptionSession.findOne({ sessionId });
      assert.equal(updatedSession.status, 'RELEASED');
    });
  });

  // ── 2. FAIL-CLOSED WATERMARKING ENFORCEMENT ───────────────────────────────
  describe('2. Fail-Closed Watermarking Enforcement', () => {
    it('should strictly deny release when WATERMARK_REQUIRED=true and service is offline', async () => {
      const originalEnv = env.WATERMARK_REQUIRED;
      env.WATERMARK_REQUIRED = true;

      try {
        const fakePdf = Buffer.from('%PDF-1.4 Confidential Operational Directive %EOF');
        await assert.rejects(
          async () => {
            await watermarkBridge.embed(fakePdf, 'WM-TEST-FAILCLOSED', 'SES-FAILCLOSED');
          },
          (err) => {
            assert.ok(err.message.includes('fail-closed release denied'));
            return true;
          }
        );
      } finally {
        env.WATERMARK_REQUIRED = originalEnv;
      }
    });

    it('should report honest capabilities without unverified photo/scan claims', () => {
      const caps = watermarkBridge.getCapabilities();
      assert.equal(caps.digitalPdfEmbedding, 'SUPPORTED');
      assert.equal(caps.opticalCameraExtraction, 'UNSUPPORTED_REQUIRES_PHYSICAL_TESTBED');
      assert.equal(caps.measuredMetricsAvailable, false);
    });
  });

  // ── 3. FORENSIC EVIDENCE BINDING & MARKER FRAUD DETECTION ─────────────────
  describe('3. Forensic Evidence Binding & Anti-Fraud Verification', () => {
    it('should detect marker-copying fraud when valid watermark is pasted into unrelated content', async () => {
      const canonicalEventService = require('../src/services/canonicalEventService');
      const watermarkId = 'WID-GENUINE-EVIDENCE-42';
      const watermarkCommitment = crypto.randomBytes(32).toString('hex');
      const timestamp = new Date().toISOString();

      const event = canonicalEventService.createDecryptionEvent({
        eventId: 'EVT-GENUINE-42',
        documentId: testDocument.documentId || testDocument._id.toString(),
        documentHash: testDocument.fileHash,
        recipientId: recipient._id.toString(),
        sessionId: 'SES-GENUINE-42',
        deviceId: 'DEV-HW-SECURE-99',
        watermarkId,
        watermarkCommitment,
        signingKeyId: 'sec_recipient_major',
        timestamp
      });

      const { eventDigest } = canonicalEventService.computeEventDigest(event);
      const signature = await keyAgentClient.sign('sec_recipient_major', Buffer.from(eventDigest, 'hex'));

      await FabricLedgerRecord.create({
        eventId: 'evt_SES-GENUINE-42',
        eventDigest,
        documentId: testDocument.documentId || testDocument._id.toString(),
        documentHash: testDocument.fileHash,
        recipientId: recipient._id.toString(),
        sessionId: 'SES-GENUINE-42',
        deviceId: 'DEV-HW-SECURE-99',
        watermarkId,
        watermarkCommitment,
        signingKeyId: 'sec_recipient_major',
        signature,
        timestamp,
        txId: 'tx_genuine_42',
        blockNumber: 42
      });

      // Also create matching DecryptionSession so session lookup succeeds
      await DecryptionSession.create({
        sessionId: 'SES-GENUINE-42',
        documentId: testDocument._id,
        recipientId: recipient._id,
        deviceId: 'DEV-HW-SECURE-99',
        sessionNonce: 'nonce-genuine-42',
        status: 'RELEASED',
        watermarkId,
        watermarkCommitment,
        expiresAt: new Date(Date.now() + 60000)
      });

      // 2. Adversary creates unrelated PDF with completely different content and structural fingerprint
      const unrelatedPdf = Buffer.from('%PDF-1.4 UNRELATED LEAKED DOCUMENT WITH COPIED MARKER: WID-GENUINE-EVIDENCE-42 %EOF');

      // 3. Forensic verification with unrelated suspect file
      const result = await forensicService.verifyForensicEvidence({
        watermarkId,
        suspectFileBuffer: unrelatedPdf
      });

      // Must detect that structural layout does NOT match original document
      assert.equal(result.evidenceBindingValid, false);
      assert.ok(result.issues.some((issue) => issue.includes('Marker copying fraud detected')));
    });

    it('should return INCONCLUSIVE when source document or session is missing', async () => {
      const canonicalEventService = require('../src/services/canonicalEventService');
      const orphanWatermarkId = 'WID-ORPHAN-NO-DOC-001';
      const orphanCommitment = crypto.randomBytes(32).toString('hex');
      const timestamp = new Date().toISOString();
      const orphanDocId = new mongoose.Types.ObjectId().toString();
      const orphanDocHash = crypto.randomBytes(32).toString('hex');

      const orphanEvent = canonicalEventService.createDecryptionEvent({
        eventId: 'EVT-ORPHAN-001',
        documentId: orphanDocId,
        documentHash: orphanDocHash,
        recipientId: recipient._id.toString(),
        sessionId: 'SES-ORPHAN-001',
        deviceId: 'DEV-HW-SECURE-99',
        watermarkId: orphanWatermarkId,
        watermarkCommitment: orphanCommitment,
        signingKeyId: 'sec_recipient_major',
        timestamp
      });

      const { eventDigest } = canonicalEventService.computeEventDigest(orphanEvent);
      const signature = await keyAgentClient.sign('sec_recipient_major', Buffer.from(eventDigest, 'hex'));

      await FabricLedgerRecord.create({
        eventId: 'evt_SES-ORPHAN-001',
        eventDigest,
        documentId: orphanDocId,
        documentHash: orphanDocHash,
        recipientId: recipient._id.toString(),
        sessionId: 'SES-ORPHAN-001',
        deviceId: 'DEV-HW-SECURE-99',
        watermarkId: orphanWatermarkId,
        watermarkCommitment: orphanCommitment,
        signingKeyId: 'sec_recipient_major',
        signature,
        timestamp,
        txId: 'tx_orphan_01',
        blockNumber: 101
      });

      const result = await forensicService.verifyForensicEvidence({
        watermarkId: orphanWatermarkId
      });

      // Missing source document MUST produce INCONCLUSIVE, not VERIFIED or true
      assert.equal(result.status, 'INCONCLUSIVE');
      assert.equal(result.documentHashValid, false);
    });
  });

  // ── 4. PROVENANCE LEDGER INTEGRITY (v2 CANONICAL PAYLOAD) ───────────────────
  describe('4. Provenance Ledger Canonical Payload v2 & Tamper Resistance', () => {
    it('should include detailsHash in canonical hash chain and detect details tampering', async () => {
      // 1. Append valid provenance entry with security details
      const entry = await provenanceService.logProvenanceEvent({
        docId: testDocument._id,
        recipientId: recipient._id,
        action: 'DECRYPT_SUCCESS',
        status: 'SUCCESS',
        details: {
          classification: 'TOP_SECRET',
          deviceId: 'DEV-HW-SECURE-99',
          watermarkId: 'WID-TAMPER-TEST-01'
        }
      });

      assert.equal(entry.schemaVersion, 2);
      assert.ok(entry.detailsHash);

      // Verify chain initially passes
      const initialVerify = await provenanceService.verifyChain();
      assert.equal(initialVerify.valid, true);

      // 2. Malicious actor tampers with details in MongoDB (e.g. downgrading classification)
      await ProvenanceLog.findByIdAndUpdate(entry._id, {
        $set: { 'details.classification': 'UNCLASSIFIED' }
      });

      // 3. Verify chain MUST detect tampering at this sequence number
      const tamperedVerify = await provenanceService.verifyChain();
      assert.equal(tamperedVerify.valid, false);
      assert.ok(tamperedVerify.tamperedSequences.includes(entry.sequenceNumber));
    });
  });

  // ── 5. FILE VAULT VALIDATION & ATOMIC PERMISSIONS ──────────────────────────
  describe('5. File Vault PDF Validation & Permissions', () => {
    it('should reject non-PDF document uploads with 400 validation error', () => {
      assert.throws(
        () => {
          fileVaultService.validatePdfBuffer(Buffer.from('NOT A PDF FILE PLAIN TEXT'));
        },
        /valid PDF/i
      );
    });

    it('should store ciphertext to isolated vault with mode 0600', () => {
      const docId = 'DOC-VAULT-PERM-TEST';
      const sampleCiphertext = crypto.randomBytes(128).toString('base64');
      const relPath = fileVaultService.storeCiphertext(docId, sampleCiphertext);

      const absPath = path.resolve(__dirname, '..', relPath);
      assert.ok(fs.existsSync(absPath));

      const stats = fs.statSync(absPath);
      // In POSIX mode, mode & 0o777 should be 0o600
      assert.equal(stats.mode & 0o777, 0o600);

      // Cleanup
      fileVaultService.cleanupCiphertext(relPath);
      assert.equal(fs.existsSync(absPath), false);
    });
  });
});
