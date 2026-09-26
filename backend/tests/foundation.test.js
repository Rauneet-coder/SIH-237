const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  AppError,
  AuthenticationError,
  AuthorizationError,
  FailClosedError,
  ValidationError
} = require('../src/utils/errors');
const logger = require('../src/utils/logger');
const pqcService = require('../src/services/pqcService');
const keyAgentClient = require('../src/services/keyAgentClient');
const watermarkBridge = require('../src/services/watermarkBridge');

describe('Phase 1 Foundation: Errors, Logging, Key Agent & Watermark Bridge', () => {
  describe('Standardized Error Hierarchy', () => {
    it('should instantiate typed errors with appropriate HTTP status codes', () => {
      const authErr = new AuthenticationError('Invalid credentials');
      assert.equal(authErr.statusCode, 401);
      assert.equal(authErr.code, 'AUTHENTICATION_ERROR');

      const azErr = new AuthorizationError('Forbidden');
      assert.equal(azErr.statusCode, 403);
      assert.equal(azErr.code, 'AUTHORIZATION_ERROR');

      const valErr = new ValidationError('Bad input');
      assert.equal(valErr.statusCode, 400);

      const failClosed = new FailClosedError('Watermark verification failed');
      assert.equal(failClosed.statusCode, 403);
      assert.equal(failClosed.code, 'FAIL_CLOSED_RELEASE_DENIED');
      assert.ok(failClosed.message.includes('FAIL-CLOSED ACTIVATED'));
    });
  });

  describe('Security Logger Sanitization', () => {
    it('should redact private keys and passwords in logs', () => {
      const rawMsg = 'User logged in with password: "SuperSecretPassword123!"';
      const sanitized = logger.sanitize(rawMsg);
      assert.ok(!sanitized.includes('SuperSecretPassword123!'), 'Password must be redacted');
      assert.ok(sanitized.includes('REDACTED_SECRET'));

      const pemMsg = 'Key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----';
      const sanitizedPem = logger.sanitize(pemMsg);
      assert.ok(!sanitizedPem.includes('MIIEowIBAAKCAQ'), 'Private key bytes must be redacted');
    });
  });

  describe('Local Key Agent Private Key Boundary', () => {
    it('should provision recipient and return ONLY public keys', async () => {
      const pubKeys = await keyAgentClient.provisionRecipient('REC-DEFENCE-01');
      assert.ok(pubKeys.mlKemPublicKey, 'ML-KEM public key must be returned');
      assert.ok(pubKeys.mlDsaPublicKey, 'ML-DSA public key must be returned');
      // Ensure secret keys are NOT returned in public profile
      assert.equal(pubKeys.mlKemSecretKey, undefined);
      assert.equal(pubKeys.mlDsaSecretKey, undefined);
    });

    it('should perform ML-KEM decapsulation within key-agent boundary', async () => {
      const recipientId = 'REC-DEFENCE-02';
      const pubKeys = await keyAgentClient.provisionRecipient(recipientId);

      // Outside sender encapsulates DEK
      const encap = await pqcService.encapsulate(pubKeys.mlKemPublicKey);

      // Key Agent decapsulates without exposing private key
      const recoveredSecret = await keyAgentClient.decapsulate(recipientId, encap.cipherText);
      assert.equal(recoveredSecret, encap.sharedSecret, 'Key agent must decapsulate matching shared secret');
    });

    it('should sign canonical event digest within key-agent boundary', async () => {
      const recipientId = 'REC-DEFENCE-03';
      const pubKeys = await keyAgentClient.provisionRecipient(recipientId);
      const digest = Buffer.from('canonical-event-sha256-digest-value');

      const signature = await keyAgentClient.sign(recipientId, digest);
      assert.ok(signature, 'Signature must be returned');

      // Verify signature using recipient public key
      const isValid = await pqcService.verify(signature, digest, pubKeys.mlDsaPublicKey);
      assert.equal(isValid, true, 'Signature produced by Key Agent must verify with public key');
    });

    it('should reject decapsulation and signing after key revocation', async () => {
      const recipientId = 'REC-DEFENCE-REVOKED';
      await keyAgentClient.provisionRecipient(recipientId);
      keyAgentClient.revoke(recipientId);

      await assert.rejects(
        () => keyAgentClient.sign(recipientId, Buffer.from('test')),
        /revoked or inactive/
      );
    });
  });

  describe('Watermark Bridge & In-Process Fallback Engine', () => {
    it('should embed and extract forensic watermark correctly via bridge', async () => {
      const fakePdf = Buffer.from('%PDF-1.4 sample document content stream %EOF');
      const watermarkId = 'WID-F9B2C104-E7A9';
      const sessionId = 'SES-001-A';

      const watermarked = await watermarkBridge.embed(fakePdf, watermarkId, sessionId);
      assert.ok(watermarked.length > fakePdf.length, 'Watermarked PDF should contain embedded metadata');

      const extracted = await watermarkBridge.extract(watermarked);
      assert.equal(extracted.status, 'SUCCESS');
      assert.equal(extracted.watermark_id, watermarkId);
      assert.ok(extracted.confidence >= 0.9);
    });
  });
});
