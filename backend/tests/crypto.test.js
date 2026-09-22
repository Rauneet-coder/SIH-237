const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const cryptoService = require('../src/services/cryptoService');

describe('Native Node.js Crypto Service Tests', () => {
  test('should generate valid RSA keypair with PEM encoding', () => {
    const keyPair = cryptoService.generateKeyPair(2048);
    assert.ok(keyPair.publicKey.includes('-----BEGIN PUBLIC KEY-----'));
    assert.ok(keyPair.publicKey.includes('-----END PUBLIC KEY-----'));
    assert.ok(keyPair.privateKey.includes('-----BEGIN PRIVATE KEY-----'));
    assert.ok(keyPair.privateKey.includes('-----END PRIVATE KEY-----'));
  });

  test('should generate 32-byte symmetric key', () => {
    const symKey = cryptoService.generateSymmetricKey();
    assert.equal(symKey.length, 32);
    assert.ok(Buffer.isBuffer(symKey));
  });

  test('should encrypt and decrypt document correctly with AES-256-GCM', () => {
    const symKey = cryptoService.generateSymmetricKey();
    const documentContent = 'CONFIDENTIAL: Tactical Movement Order Alpha-9. Immediate Execution.';
    const originalBuffer = Buffer.from(documentContent, 'utf-8');

    const encrypted = cryptoService.encryptDocument(originalBuffer, symKey);
    assert.ok(encrypted.encryptedBlob);
    assert.ok(encrypted.iv);
    assert.ok(encrypted.authTag);
    assert.notEqual(encrypted.encryptedBlob, documentContent);

    const decrypted = cryptoService.decryptDocument(
      encrypted.encryptedBlob,
      symKey,
      encrypted.iv,
      encrypted.authTag
    );
    assert.equal(decrypted.toString('utf-8'), documentContent);
  });

  test('should fail AES-256-GCM decryption if authTag is tampered', () => {
    const symKey = cryptoService.generateSymmetricKey();
    const documentContent = 'Top Secret Operations Protocol';
    const encrypted = cryptoService.encryptDocument(documentContent, symKey);

    // Tamper with the authTag
    const tamperedTag = encrypted.authTag.slice(0, -2) + (encrypted.authTag.slice(-2) === 'aa' ? 'bb' : 'aa');

    assert.throws(
      () => {
        cryptoService.decryptDocument(
          encrypted.encryptedBlob,
          symKey,
          encrypted.iv,
          tamperedTag
        );
      },
      /Unsupported state or unable to authenticate data/i
    );
  });

  test('should wrap and unwrap symmetric key for recipient with RSA-OAEP', () => {
    const recipientKeys = cryptoService.generateKeyPair(2048);
    const symKey = cryptoService.generateSymmetricKey();

    const wrappedKey = cryptoService.encryptSymmetricKey(symKey, recipientKeys.publicKey);
    assert.ok(wrappedKey);
    assert.notEqual(wrappedKey, symKey.toString('base64'));

    const unwrappedKey = cryptoService.decryptSymmetricKey(wrappedKey, recipientKeys.privateKey);
    assert.deepEqual(unwrappedKey, symKey);
  });

  test('should fail to unwrap symmetric key if wrong private key is used', () => {
    const recipientKeys = cryptoService.generateKeyPair(2048);
    const wrongKeys = cryptoService.generateKeyPair(2048);
    const symKey = cryptoService.generateSymmetricKey();

    const wrappedKey = cryptoService.encryptSymmetricKey(symKey, recipientKeys.publicKey);

    assert.throws(() => {
      cryptoService.decryptSymmetricKey(wrappedKey, wrongKeys.privateKey);
    });
  });

  test('should compute deterministic SHA-256 hash', () => {
    const data = 'SIH26237 Provenance Chain Genesis Block';
    const hash1 = cryptoService.computeHash(data);
    const hash2 = cryptoService.computeHash(data);

    assert.equal(hash1.length, 64);
    assert.equal(hash1, hash2);
  });

  test('should sign data and verify valid signature', () => {
    const authorityKeys = cryptoService.generateKeyPair(2048);
    const payload = 'Seq:1|PrevHash:00000|Doc:doc123|Recipient:user456|Action:DECRYPT_ATTEMPT';

    const signature = cryptoService.signPayload(payload, authorityKeys.privateKey);
    assert.ok(signature);

    const isValid = cryptoService.verifySignature(payload, signature, authorityKeys.publicKey);
    assert.equal(isValid, true);

    // Tampered payload fails verification
    const isTamperedValid = cryptoService.verifySignature(
      payload + 'TAMPERED',
      signature,
      authorityKeys.publicKey
    );
    assert.equal(isTamperedValid, false);
  });
});
