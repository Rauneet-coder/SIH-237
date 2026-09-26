const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const crypto = require('node:crypto');
const User = require('../src/models/User');
const Document = require('../src/models/Document');
const keyAgentClient = require('../src/services/keyAgentClient');
const keyEnvelopeService = require('../src/services/keyEnvelopeService');
const documentService = require('../src/services/documentService');
const cryptoService = require('../src/services/cryptoService');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_test_encryption';

before(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI);
  }
  await User.deleteMany({});
  await Document.deleteMany({});
});

after(async () => {
  await User.deleteMany({});
  await Document.deleteMany({});
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

describe('Phase 3: Single Document Encryption (AES-256-GCM) & ML-KEM Key Envelopes', () => {
  let sender;
  let alice;
  let bob;
  let samplePlaintext;

  before(async () => {
    // 1. Provision sender and recipients in Key Agent and Database
    const aliceKeys = await keyAgentClient.provisionRecipient('recipient_alice');
    const bobKeys = await keyAgentClient.provisionRecipient('recipient_bob');
    const senderKeys = await keyAgentClient.provisionRecipient('sender_hq');

    const dummyRsa = cryptoService.generateKeyPair(2048);

    sender = await User.create({
      username: 'sender_hq',
      email: 'hq@mod.gov.in',
      password: 'hashed_password',
      role: 'DOCUMENT_OWNER',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: senderKeys.mlKemPublicKey,
      mlDsaPublicKey: senderKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    alice = await User.create({
      username: 'recipient_alice',
      email: 'alice@mod.gov.in',
      password: 'hashed_password',
      role: 'RECIPIENT',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: aliceKeys.mlKemPublicKey,
      mlDsaPublicKey: aliceKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    bob = await User.create({
      username: 'recipient_bob',
      email: 'bob@mod.gov.in',
      password: 'hashed_password',
      role: 'RECIPIENT',
      publicKey: dummyRsa.publicKey,
      mlKemPublicKey: bobKeys.mlKemPublicKey,
      mlDsaPublicKey: bobKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE'
    });

    samplePlaintext = Buffer.from('%PDF-1.4 Ministry of Defence Classified Strategic Assessment 2026 %EOF');
  });

  it('should encrypt document exactly ONCE and generate distinct ML-KEM envelopes per recipient', async () => {
    const doc = await documentService.uploadAndEncryptDocument({
      title: 'MoD Strategic Directive 2026',
      fileBuffer: samplePlaintext,
      fileName: 'strategic_directive.pdf',
      senderId: sender._id,
      recipientIds: [alice._id, bob._id],
      classification: 'TOP_SECRET'
    });

    assert.ok(doc._id);
    assert.ok(doc.documentId);
    assert.equal(doc.classification, 'TOP_SECRET');
    assert.equal(doc.fileHash, cryptoService.computeHash(samplePlaintext));

    // Verify Encrypt Once: single encrypted blob exists
    assert.ok(doc.encryptedBlob, 'Single encrypted blob must exist');
    assert.ok(doc.iv);
    assert.ok(doc.authTag);

    // Verify per-recipient ML-KEM key envelopes
    assert.ok(doc.keyEnvelopes.length >= 2, 'Must have key envelopes for recipients');

    const aliceEnv = doc.keyEnvelopes.find((e) => e.recipientId.toString() === alice._id.toString());
    const bobEnv = doc.keyEnvelopes.find((e) => e.recipientId.toString() === bob._id.toString());

    assert.ok(aliceEnv, 'Alice must have an ML-KEM envelope');
    assert.ok(bobEnv, 'Bob must have an ML-KEM envelope');

    // Distinct capsules and wrapped keys
    assert.notEqual(aliceEnv.kemCiphertext, bobEnv.kemCiphertext);
    assert.notEqual(aliceEnv.wrappedDek, bobEnv.wrappedDek);
    assert.equal(aliceEnv.kemAlgorithm, 'ML-KEM-1024');
    assert.equal(bobEnv.kemAlgorithm, 'ML-KEM-1024');
  });

  it('should allow Alice to decapsulate DEK via Key Agent and decrypt document successfully', async () => {
    const doc = await Document.findOne({ title: 'MoD Strategic Directive 2026' });

    const result = await documentService.decryptDocumentForRecipient({
      docId: doc._id,
      recipientId: alice._id,
      recipientUsername: 'recipient_alice'
    });

    assert.ok(result.decryptedBuffer);
    assert.ok(result.decryptedBuffer.includes('%PDF-1.4'));
    assert.ok(result.decryptedBuffer.includes('Strategic Assessment 2026'));
  });

  it('should allow Bob to decapsulate DEK via Key Agent and decrypt document successfully', async () => {
    const doc = await Document.findOne({ title: 'MoD Strategic Directive 2026' });

    const result = await documentService.decryptDocumentForRecipient({
      docId: doc._id,
      recipientId: bob._id,
      recipientUsername: 'recipient_bob'
    });

    assert.ok(result.decryptedBuffer);
    assert.ok(result.decryptedBuffer.includes('%PDF-1.4'));
    assert.ok(result.decryptedBuffer.includes('Strategic Assessment 2026'));
  });

  it('should fail decryption if ML-KEM envelope is tampered with', async () => {
    const doc = await Document.findOne({ title: 'MoD Strategic Directive 2026' });
    const aliceEnv = doc.keyEnvelopes.find((e) => e.recipientId.toString() === alice._id.toString());

    // Tamper with wrappedDek
    const tamperedEnv = {
      ...aliceEnv.toObject(),
      wrappedDek: Buffer.from('tampered_wrapped_dek_bytes_xyz12345').toString('base64')
    };

    await assert.rejects(
      () =>
        keyEnvelopeService.unwrapEnvelope({
          envelope: tamperedEnv,
          recipientUsername: 'recipient_alice',
          recipientId: alice._id.toString(),
          documentId: doc.documentId,
          documentHash: doc.fileHash
        }),
      /unwrap failed/
    );
  });

  it('should fail decryption if document ciphertext or authTag is tampered', async () => {
    const doc = await Document.findOne({ title: 'MoD Strategic Directive 2026' });
    const originalTag = doc.authTag;

    // Tamper auth tag in database
    doc.authTag = '00112233445566778899aabbccddeeff';
    await doc.save();

    await assert.rejects(
      () =>
        documentService.decryptDocumentForRecipient({
          docId: doc._id,
          recipientId: alice._id,
          recipientUsername: 'recipient_alice'
        }),
      /decryption failed/
    );

    // Restore authTag
    doc.authTag = originalTag;
    await doc.save();
  });
});
