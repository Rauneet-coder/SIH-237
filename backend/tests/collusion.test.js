const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  DEFAULT_CODE_LENGTH,
  generateBiasVector,
  generateRecipientCodeword,
  computeAccusationScore,
  traceTraitors,
  simulateCollusion,
  deriveSessionKey,
  embedForensicFingerprint,
  extractForensicFingerprint
} = require('../src/services/collusionService');

describe('Collusion-Resistant Fingerprinting & Traitor Tracing Service', () => {
  const docId = 'doc_test_12345';

  test('should generate deterministic bias vector within cutoffs', () => {
    const biases1 = generateBiasVector(docId, 128);
    const biases2 = generateBiasVector(docId, 128);

    assert.equal(biases1.length, 128);
    assert.deepEqual(biases1, biases2);

    for (const p of biases1) {
      assert.ok(p >= 0.15 && p <= 0.85);
    }
  });

  test('should generate distinct fingerprint codewords for different recipients', () => {
    const biases = generateBiasVector(docId, DEFAULT_CODE_LENGTH);
    const cwAlice = generateRecipientCodeword(docId, 'user_alice', biases);
    const cwBob = generateRecipientCodeword(docId, 'user_bob', biases);
    const cwCharlie = generateRecipientCodeword(docId, 'user_charlie', biases);

    assert.equal(cwAlice.length, DEFAULT_CODE_LENGTH);
    assert.equal(cwBob.length, DEFAULT_CODE_LENGTH);
    assert.notEqual(cwAlice, cwBob);
    assert.notEqual(cwBob, cwCharlie);
  });

  test('should derive distinct HKDF session keys bound to recipient and sequence', () => {
    const masterKey = crypto.randomBytes(32);

    const key1 = deriveSessionKey({
      masterKey,
      docId,
      recipientId: 'user_alice',
      sequenceNumber: 1
    });

    const key2 = deriveSessionKey({
      masterKey,
      docId,
      recipientId: 'user_bob',
      sequenceNumber: 2
    });

    const key3 = deriveSessionKey({
      masterKey,
      docId,
      recipientId: 'user_alice',
      sequenceNumber: 3
    });

    assert.equal(key1.length, 32);
    assert.equal(key2.length, 32);
    assert.notEqual(key1.toString('hex'), key2.toString('hex'));
    assert.notEqual(key1.toString('hex'), key3.toString('hex'));
  });

  test('should embed and extract forensic fingerprint payload correctly', () => {
    const documentContent = Buffer.from('TOP SECRET: Operation Trident Protocol');
    const metadata = {
      codeword: '1011001010101',
      recipientId: 'user_alice_456',
      sequenceNumber: 42
    };

    const watermarked = embedForensicFingerprint(documentContent, metadata);
    assert.ok(watermarked.length > documentContent.length);

    const extracted = extractForensicFingerprint(watermarked);
    assert.ok(extracted);
    assert.equal(extracted.codeword, metadata.codeword);
    assert.equal(extracted.rec, metadata.recipientId);
    assert.equal(extracted.seq, metadata.sequenceNumber);
  });

  test('should successfully trace and unmask colluders from a forged hybrid watermark', () => {
    const biases = generateBiasVector(docId, DEFAULT_CODE_LENGTH);

    // Setup 5 recipients: Alice, Bob (colluders), Charlie, David, Eve (innocents)
    const candidates = [
      { recipientId: 'alice', username: 'Alice', email: 'alice@mod.gov.in' },
      { recipientId: 'bob', username: 'Bob', email: 'bob@mod.gov.in' },
      { recipientId: 'charlie', username: 'Charlie', email: 'charlie@mod.gov.in' },
      { recipientId: 'david', username: 'David', email: 'david@mod.gov.in' },
      { recipientId: 'eve', username: 'Eve', email: 'eve@mod.gov.in' }
    ].map((cand) => ({
      ...cand,
      codeword: generateRecipientCodeword(docId, cand.recipientId, biases)
    }));

    // Alice and Bob collude by combining their watermarks via interleaving
    const colluders = [candidates[0].codeword, candidates[1].codeword];
    const hybridWatermark = simulateCollusion(colluders, 'interleaving');

    assert.equal(hybridWatermark.length, DEFAULT_CODE_LENGTH);

    // Run traitor tracing algorithm
    const report = traceTraitors({
      suspectWatermark: hybridWatermark,
      candidates,
      biases
    });

    assert.equal(report.collusionDetected, true);
    assert.ok(report.accusedRecipients.length >= 1);

    const accusedIds = report.accusedRecipients.map((r) => r.recipientId);
    // Both Alice and Bob should be identified as the prime suspects
    assert.ok(accusedIds.includes('alice') || accusedIds.includes('bob'));

    // Check that colluders score significantly higher than innocent recipients
    const aliceScore = report.rankedCandidates.find((r) => r.recipientId === 'alice').score;
    const bobScore = report.rankedCandidates.find((r) => r.recipientId === 'bob').score;
    const charlieScore = report.rankedCandidates.find((r) => r.recipientId === 'charlie').score;
    const davidScore = report.rankedCandidates.find((r) => r.recipientId === 'david').score;

    assert.ok(aliceScore > charlieScore);
    assert.ok(bobScore > davidScore);
  });
});
