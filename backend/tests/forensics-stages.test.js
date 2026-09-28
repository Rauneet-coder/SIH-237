const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const crypto = require('node:crypto');

const forensicService = require('../src/services/forensicService');
const fabricService = require('../src/services/fabricService');
const fingerprintService = require('../src/services/fingerprintService');
const documentService = require('../src/services/documentService');
const decryptionSessionService = require('../src/services/decryptionSessionService');
const canonicalEventService = require('../src/services/canonicalEventService');
const keyAgentClient = require('../src/services/keyAgentClient');
const cryptoService = require('../src/services/cryptoService');
const pqcService = require('../src/services/pqcService');
const env = require('../src/config/env');

const FabricLedgerRecord = require('../src/models/FabricLedgerRecord');
const Document = require('../src/models/Document');
const User = require('../src/models/User');
const Device = require('../src/models/Device');
const DecryptionSession = require('../src/models/DecryptionSession');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_test_forensics_stages';

describe('HLD Stage Coverage & Critical Forensic Verification', () => {
  let sender;
  let generalRecipient; // Clearance: TOP_SECRET
  let colonelRecipient; // Clearance: RESTRICTED
  let generalDevice;
  let testDoc;
  let testSession;
  let committedEvent;

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

    // 1. Provision users with PQC keys
    const generalKeys = await keyAgentClient.provisionRecipient('general_sharma');
    const colonelKeys = await keyAgentClient.provisionRecipient('colonel_singh');
    const senderKeys = await keyAgentClient.provisionRecipient('command_sender');

    sender = await User.create({
      username: 'command_sender',
      email: 'hq@army.gov.in',
      password: 'password123',
      role: 'SENDER',
      clearance: 'TOP_SECRET',
      mlKemPublicKey: senderKeys.mlKemPublicKey,
      mlDsaPublicKey: senderKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    generalRecipient = await User.create({
      username: 'general_sharma',
      email: 'general@army.gov.in',
      password: 'password123',
      role: 'RECIPIENT',
      clearance: 'TOP_SECRET',
      mlKemPublicKey: generalKeys.mlKemPublicKey,
      mlDsaPublicKey: generalKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    colonelRecipient = await User.create({
      username: 'colonel_singh',
      email: 'colonel@army.gov.in',
      password: 'password123',
      role: 'RECIPIENT',
      clearance: 'RESTRICTED', // Lower clearance
      mlKemPublicKey: colonelKeys.mlKemPublicKey,
      mlDsaPublicKey: colonelKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    generalDevice = await Device.create({
      userId: generalRecipient._id,
      deviceId: 'DEV-GEN-01',
      deviceFingerprint: crypto.createHash('sha256').update('gen-hardware-fp').digest('hex'),
      status: 'ACTIVE'
    });
  });

  after(async () => {
    await mongoose.disconnect();
  });

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 1: Document Preparation & Security Policy
  // ──────────────────────────────────────────────────────────────────────────
  describe('Stage 1: Document Preparation & Fingerprinting', () => {
    test('1.3 should compute deterministic structural content layout fingerprint for PDF', () => {
      const dummyPdf1 = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /MediaBox [0 0 612 792] >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');
      const dummyPdf2 = Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /MediaBox [0 0 612 792] >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');

      const fp1 = fingerprintService.computeStructuralFingerprint(dummyPdf1);
      const fp2 = fingerprintService.computeStructuralFingerprint(dummyPdf2);

      assert.strictEqual(typeof fp1, 'string');
      assert.strictEqual(fp1.length, 64, 'Structural fingerprint must be 64-char SHA-256');
      assert.strictEqual(fp1, fp2, 'Identical structure must yield identical fingerprint');
    });

    test('1.4 should enforce ABAC security policy: deny session when recipient clearance is below document classification', async () => {
      // Create a TOP_SECRET document
      const pdfBuffer = Buffer.from('%PDF-1.4 DEFENCE TOP SECRET STRATEGY DOCUMENT');
      const secretDoc = await documentService.uploadAndEncryptDocument({
        title: 'Operation Ironclad',
        fileBuffer: pdfBuffer,
        fileName: 'ironclad.pdf',
        senderId: sender._id,
        recipientIds: [generalRecipient._id, colonelRecipient._id],
        classification: 'TOP_SECRET'
      });

      assert.strictEqual(secretDoc.classification, 'TOP_SECRET');
      assert.ok(secretDoc.structuralFingerprint);

      // Attempt session creation by colonel (clearance: RESTRICTED < TOP_SECRET) -> MUST FAIL
      await assert.rejects(
        async () => {
          await decryptionSessionService.createSession({
            documentId: secretDoc._id,
            recipientId: colonelRecipient._id,
            deviceId: 'DEV-COLONEL-01'
          });
        },
        /Security clearance insufficient/,
        'Should fail-closed deny user with insufficient clearance'
      );

      // Attempt session creation by general (clearance: TOP_SECRET == TOP_SECRET) -> MUST SUCCEED
      const allowedSession = await decryptionSessionService.createSession({
        documentId: secretDoc._id,
        recipientId: generalRecipient._id,
        deviceId: generalDevice.deviceId
      });

      assert.ok(allowedSession.sessionId);
      assert.strictEqual(allowedSession.status, 'CREATED');
    });

    test('1.4 should enforce temporal access window: deny session when document window is expired', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4 EXPIRED TIME WINDOW DOCUMENT');
      const expiredDoc = await documentService.uploadAndEncryptDocument({
        title: 'Expired Briefing',
        fileBuffer: pdfBuffer,
        fileName: 'expired.pdf',
        senderId: sender._id,
        recipientIds: [generalRecipient._id],
        classification: 'RESTRICTED',
        validFrom: new Date(Date.now() - 3600000), // 1 hour ago
        validUntil: new Date(Date.now() - 60000)   // 1 minute ago (expired)
      });

      await assert.rejects(
        async () => {
          await decryptionSessionService.createSession({
            documentId: expiredDoc._id,
            recipientId: generalRecipient._id,
            deviceId: generalDevice.deviceId
          });
        },
        /access window has expired/,
        'Should deny access when document validUntil has passed'
      );
    });

    test('2.2 should fail-closed upload if any specified recipient has invalid or missing public key', async () => {
      // Create user without public key
      const keylessUser = await User.create({
        username: 'keyless_recruit',
        email: 'keyless@army.gov.in',
        password: 'password123',
        role: 'RECIPIENT',
        clearance: 'RESTRICTED',
        mlKemPublicKey: null,
        publicKey: null
      });

      const pdfBuffer = Buffer.from('%PDF-1.4 FAILING ENVELOPE DOCUMENT');

      await assert.rejects(
        async () => {
          await documentService.uploadAndEncryptDocument({
            title: 'Mission Blueprint',
            fileBuffer: pdfBuffer,
            fileName: 'blueprint.pdf',
            senderId: sender._id,
            recipientIds: [generalRecipient._id, keylessUser._id],
            classification: 'RESTRICTED'
          });
        },
        /Fail-closed: Recipient keyless_recruit has no valid cryptographic public key/,
        'Upload must fail closed and zeroize if any recipient key is missing'
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 3 & 5: Device Challenge & Session Viewing
  // ──────────────────────────────────────────────────────────────────────────
  describe('Stage 3 & 5: Device Possession & Controlled Session Viewing', () => {
    test('3.5 should store and audit camera/liveness evidence in session', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4 LIVENESS EVIDENCE DOCUMENT');
      const doc = await documentService.uploadAndEncryptDocument({
        title: 'Tactical Recon',
        fileBuffer: pdfBuffer,
        fileName: 'recon.pdf',
        senderId: sender._id,
        recipientIds: [generalRecipient._id],
        classification: 'RESTRICTED'
      });

      const fakeCameraEvidenceHash = crypto.createHash('sha256').update('face-mesh-liveness-pass').digest('hex');
      const session = await decryptionSessionService.createSession({
        documentId: doc._id,
        recipientId: generalRecipient._id,
        deviceId: generalDevice.deviceId,
        cameraEvidenceHash: fakeCameraEvidenceHash,
        livenessToken: 'TOKEN_LIVENESS_OK'
      });

      assert.strictEqual(session.cameraEvidenceHash, fakeCameraEvidenceHash);
      assert.strictEqual(session.livenessToken, 'TOKEN_LIVENESS_OK');
    });

    test('5.5 should retrieve session metadata with time remaining and security flags', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4 METADATA TEST DOCUMENT');
      const doc = await documentService.uploadAndEncryptDocument({
        title: 'Metadata Briefing',
        fileBuffer: pdfBuffer,
        fileName: 'meta.pdf',
        senderId: sender._id,
        recipientIds: [generalRecipient._id],
        classification: 'RESTRICTED'
      });

      const session = await decryptionSessionService.createSession({
        documentId: doc._id,
        recipientId: generalRecipient._id,
        deviceId: generalDevice.deviceId
      });

      const meta = await decryptionSessionService.getSessionMetadata(session.sessionId, generalRecipient._id);
      assert.strictEqual(meta.sessionId, session.sessionId);
      assert.strictEqual(meta.status, 'CREATED');
      assert.strictEqual(meta.isExpired, false);
      assert.ok(meta.remainingSeconds > 0);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // STAGE 6: Critical Forensic Verification & Missing Event Handling
  // ──────────────────────────────────────────────────────────────────────────
  describe('Stage 6: Critical Forensic Verification & Alerting (User Focus)', () => {
    let releasedSession;
    let releasedDocumentBuffer;
    let extractedWatermarkId;

    before(async () => {
      // Create and prepare a full released session
      const pdfBuffer = Buffer.from('%PDF-1.4 AUTHORITATIVE LEAK VERIFICATION SAMPLE');
      testDoc = await documentService.uploadAndEncryptDocument({
        title: 'Operation Desert Falcon',
        fileBuffer: pdfBuffer,
        fileName: 'falcon.pdf',
        senderId: sender._id,
        recipientIds: [generalRecipient._id],
        classification: 'CONFIDENTIAL'
      });

      testSession = await decryptionSessionService.createSession({
        documentId: testDoc._id,
        recipientId: generalRecipient._id,
        deviceId: generalDevice.deviceId
      });

      const prepResult = await decryptionSessionService.prepareSession({
        sessionId: testSession.sessionId,
        recipientId: generalRecipient._id,
        deviceId: generalDevice.deviceId
      });

      releasedSession = prepResult.session;
      releasedDocumentBuffer = await decryptionSessionService.getSessionDocument(
        testSession.sessionId,
        generalRecipient._id
      );

      // Verify Fabric record exists
      committedEvent = await FabricLedgerRecord.findOne({ sessionId: testSession.sessionId });
      assert.ok(committedEvent, 'Committed Fabric ledger event must exist');
    });

    test('6.1 should extract forensic watermark from released document buffer', async () => {
      const extraction = await forensicService.extractWatermark(releasedDocumentBuffer);
      assert.strictEqual(extraction.status, 'SUCCESS');
      assert.ok(extraction.watermarkId);
      assert.ok(extraction.watermarkId.startsWith('WID-'));
      assert.strictEqual(extraction.watermarkId, committedEvent.watermarkId);
      extractedWatermarkId = extraction.watermarkId;
    });

    test('6.2 (CRITICAL) should handle NOT FOUND event on ledger as a high-severity critical security alert', async () => {
      const fakeWatermarkId = 'WID-NONEXISTENT-ROGUE-9999';

      const result = await forensicService.verifyForensicEvidence({
        watermarkId: fakeWatermarkId
      });

      // Assert fail-closed critical alert behavior
      assert.strictEqual(result.status, 'NOT_FOUND');
      assert.strictEqual(result.isCriticalAlert, true, 'Unrecorded leak MUST be flagged as isCriticalAlert: true');
      assert.strictEqual(result.alertLevel, 'CRITICAL');
      assert.strictEqual(result.signatureValid, false);
      assert.strictEqual(result.documentHashValid, false);
      assert.ok(result.message.includes('CRITICAL SECURITY ALERT'));
      assert.ok(result.serverSignature, 'Report must be signed by server authority for auditability');
      assert.ok(result.serverPublicKey);
    });

    test('6.2 should successfully verify genuine leaked document with ML-DSA signature verification', async () => {
      const result = await forensicService.verifyForensicEvidence({
        watermarkId: extractedWatermarkId,
        documentHash: testDoc.fileHash
      });

      assert.strictEqual(result.status, 'VERIFIED');
      assert.strictEqual(result.isCriticalAlert, false);
      assert.strictEqual(result.signatureValid, true, 'ML-DSA signature MUST verify successfully');
      assert.strictEqual(result.digestValid, true);
      assert.strictEqual(result.documentHashValid, true);
      assert.strictEqual(result.watermarkCommitmentValid, true);
      assert.strictEqual(result.recipient.username, 'general_sharma');
      assert.strictEqual(result.recipient.clearance, 'TOP_SECRET');
      assert.strictEqual(result.document.title, 'Operation Desert Falcon');
      assert.ok(result.serverSignature, 'Forensic attestation report must be digitally signed');
    });

    test('6.2 (CRITICAL) should detect tampered ML-DSA signature on ledger and trigger critical alert', async () => {
      // Create a ledger record with an invalid / corrupted ML-DSA signature
      const tamperedWatermarkId = 'WID-TAMPERED-SIG-7777';
      const tamperedRecord = new FabricLedgerRecord({
        eventId: 'evt_SES_TAMPERED_01',
        eventDigest: committedEvent.eventDigest,
        documentId: committedEvent.documentId,
        documentHash: committedEvent.documentHash,
        recipientId: committedEvent.recipientId,
        sessionId: 'SES-TAMPERED-01',
        deviceId: committedEvent.deviceId,
        watermarkId: tamperedWatermarkId,
        watermarkCommitment: committedEvent.watermarkCommitment,
        signingKeyId: committedEvent.signingKeyId,
        signature: 'INVALID_CORRUPTED_ML_DSA_BASE64_SIGNATURE_XXXX==',
        timestamp: committedEvent.timestamp,
        txId: 'tx_tampered_test_01',
        blockNumber: 99
      });
      await tamperedRecord.save();

      const result = await forensicService.verifyForensicEvidence({
        watermarkId: tamperedWatermarkId
      });

      // Verify tampered signature triggered critical alert
      assert.strictEqual(result.status, 'INVALID');
      assert.strictEqual(result.signatureValid, false, 'Tampered signature must fail verification');
      assert.strictEqual(result.isCriticalAlert, true, 'Signature tampering must trigger isCriticalAlert: true');
      assert.strictEqual(result.alertLevel, 'CRITICAL');
      assert.ok(result.issues.some((issue) => issue.includes('ML-DSA signature verification failed')));
    });

    test('6.3 should verify Fabric event integrity safely for unknown event without crashing', async () => {
      const res = await fabricService.verifyEventIntegrity('evt_UNKNOWN_999');
      assert.strictEqual(res.verified, false);
      assert.strictEqual(res.status, 'NOT_FOUND');
      assert.strictEqual(res.isCriticalAlert, true);
      assert.strictEqual(res.alertLevel, 'CRITICAL');
    });
  });
});
