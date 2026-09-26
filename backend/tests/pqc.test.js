const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const pqcService = require('../src/services/pqcService');

describe('NIST Post-Quantum Cryptography Service (FIPS 203 & FIPS 204)', () => {
  it('should initialize PQC modules successfully', async () => {
    await pqcService.init();
    assert.ok(true);
  });

  describe('ML-KEM-1024 Key Encapsulation Mechanism', () => {
    it('should generate valid ML-KEM-1024 keypair', async () => {
      const keys = await pqcService.generateKemKeypair();
      assert.ok(keys.publicKey, 'Public key must exist');
      assert.ok(keys.secretKey, 'Secret key must exist');
      assert.equal(keys.publicKeyBytes.length, 1568, 'ML-KEM-1024 public key must be 1568 bytes');
      assert.equal(keys.secretKeyBytes.length, 3168, 'ML-KEM-1024 secret key must be 3168 bytes');
    });

    it('should encapsulate and decapsulate shared secret accurately', async () => {
      const recipientKeys = await pqcService.generateKemKeypair();

      // Encapsulate on sender side
      const encap = await pqcService.encapsulate(recipientKeys.publicKey);
      assert.ok(encap.cipherText);
      assert.ok(encap.sharedSecret);
      assert.equal(encap.sharedSecretBytes.length, 32, 'Shared secret must be 32 bytes (256-bit)');

      // Decapsulate on recipient side
      const decap = await pqcService.decapsulate(encap.cipherText, recipientKeys.secretKey);
      assert.equal(decap.sharedSecret, encap.sharedSecret, 'Recovered shared secret must match encapsulated secret');
      assert.ok(decap.sharedSecretBytes.equals(encap.sharedSecretBytes));
    });

    it('should fail or yield mismatched secret if wrong secret key is used', async () => {
      const recipientKeys = await pqcService.generateKemKeypair();
      const attackerKeys = await pqcService.generateKemKeypair();

      const encap = await pqcService.encapsulate(recipientKeys.publicKey);
      const decap = await pqcService.decapsulate(encap.cipherText, attackerKeys.secretKey);

      assert.notEqual(
        decap.sharedSecret,
        encap.sharedSecret,
        'Decapsulation with attacker key must NOT recover correct shared secret'
      );
    });
  });

  describe('ML-DSA-65 Digital Signature Algorithm', () => {
    it('should generate valid ML-DSA-65 keypair', async () => {
      const keys = await pqcService.generateDsaKeypair();
      assert.ok(keys.publicKey);
      assert.ok(keys.secretKey);
      assert.equal(keys.publicKeyBytes.length, 1952, 'ML-DSA-65 public key must be 1952 bytes');
      assert.equal(keys.secretKeyBytes.length, 4032, 'ML-DSA-65 secret key must be 4032 bytes');
    });

    it('should sign canonical event and verify signature successfully', async () => {
      const keys = await pqcService.generateDsaKeypair();
      const canonicalEventDigest = Buffer.from(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'hex'
      );

      const { signature } = await pqcService.sign(canonicalEventDigest, keys.secretKey);
      assert.ok(signature, 'Signature must be generated');

      const isValid = await pqcService.verify(signature, canonicalEventDigest, keys.publicKey);
      assert.equal(isValid, true, 'Valid signature must verify as true');
    });

    it('should reject signature if message/digest has been tampered with', async () => {
      const keys = await pqcService.generateDsaKeypair();
      const originalDigest = Buffer.from('event-digest-version-1');
      const tamperedDigest = Buffer.from('event-digest-version-2-tampered');

      const { signature } = await pqcService.sign(originalDigest, keys.secretKey);
      const isValid = await pqcService.verify(signature, tamperedDigest, keys.publicKey);

      assert.equal(isValid, false, 'Tampered digest must fail verification');
    });

    it('should reject signature if verified against a different public key', async () => {
      const legitimateKeys = await pqcService.generateDsaKeypair();
      const impostorKeys = await pqcService.generateDsaKeypair();
      const digest = Buffer.from('canonical-event-digest');

      const { signature } = await pqcService.sign(digest, legitimateKeys.secretKey);
      const isValid = await pqcService.verify(signature, digest, impostorKeys.publicKey);

      assert.equal(isValid, false, 'Verification with impostor public key must fail');
    });
  });
});
