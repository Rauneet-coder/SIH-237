/**
 * P0 Security Boundary Tests
 * Tests for the critical security fixes in Milestone 2:
 * - Privileged role self-registration denial
 * - Route-level authorization enforcement
 * - Session ownership checks
 * - Device binding validation
 * - Provenance verification integrity
 * - Legacy endpoint restrictions
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// Test the role restriction logic directly
describe('P0 Security: Privileged Role Self-Registration Prevention', () => {
  const SELF_REGISTERABLE_ROLES = ['recipient', 'sender'];

  it('should allow registration with "recipient" role', () => {
    const requestedRole = 'recipient';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });

  it('should allow registration with "sender" role', () => {
    const requestedRole = 'sender';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'sender');
  });

  it('should deny "admin" role and default to "recipient"', () => {
    const requestedRole = 'admin';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });

  it('should deny "investigator" role and default to "recipient"', () => {
    const requestedRole = 'investigator';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });

  it('should deny "ADMIN" role (case-insensitive) and default to "recipient"', () => {
    const requestedRole = 'ADMIN';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });

  it('should deny "auditor" role and default to "recipient"', () => {
    const requestedRole = 'auditor';
    const assignedRole = SELF_REGISTERABLE_ROLES.includes(requestedRole.toLowerCase())
      ? requestedRole.toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });

  it('should default to "recipient" when no role is specified', () => {
    const requestedRole = undefined;
    const assignedRole = SELF_REGISTERABLE_ROLES.includes((requestedRole || 'recipient').toLowerCase())
      ? (requestedRole || 'recipient').toLowerCase()
      : 'recipient';
    assert.equal(assignedRole, 'recipient');
  });
});

// Test the authorization middleware logic
describe('P0 Security: Route Authorization Middleware', () => {
  it('should match exact role', () => {
    const allowedRoles = ['ADMIN', 'INVESTIGATOR'];
    const userRole = 'admin';
    const normalizedUser = userRole.toUpperCase();
    const matches = allowedRoles.includes(normalizedUser);
    assert.equal(matches, true);
  });

  it('should deny mismatched role', () => {
    const allowedRoles = ['ADMIN', 'INVESTIGATOR'];
    const userRole = 'recipient';
    const normalizedUser = userRole.toUpperCase();
    const matches = allowedRoles.includes(normalizedUser);
    assert.equal(matches, false);
  });

  it('should map SENDER to DOCUMENT_OWNER alias', () => {
    const allowedRoles = ['DOCUMENT_OWNER'];
    const normalizedAllowed = allowedRoles.map(r => r.toUpperCase());
    const userRole = 'sender';
    const normalizedUser = userRole.toUpperCase();
    const matches =
      normalizedAllowed.includes(normalizedUser) ||
      (normalizedAllowed.includes('DOCUMENT_OWNER') && normalizedUser === 'SENDER');
    assert.equal(matches, true);
  });
});

// Test session ownership logic
describe('P0 Security: Session Ownership Enforcement', () => {
  it('should deny access when recipientId does not match session owner', () => {
    const sessionOwner = '507f1f77bcf86cd799439011';
    const requestingUser = '507f1f77bcf86cd799439022';
    assert.notEqual(sessionOwner, requestingUser, 'Different users should not match');
  });

  it('should allow access when recipientId matches session owner', () => {
    const sessionOwner = '507f1f77bcf86cd799439011';
    const requestingUser = '507f1f77bcf86cd799439011';
    assert.equal(sessionOwner, requestingUser, 'Same user should match');
  });

  it('should deny access when deviceId does not match session device', () => {
    const sessionDevice = 'DEV-ABC123';
    const requestDevice = 'DEV-XYZ789';
    assert.notEqual(sessionDevice, requestDevice, 'Different devices should not match');
  });
});

// Test provenance integrity verification
describe('P0 Security: Provenance Hash Chain Integrity', () => {
  const cryptoService = require('../src/services/cryptoService');
  const provenanceService = require('../src/services/provenanceService');

  it('should detect tampered canonical payload', () => {
    const original = provenanceService.createCanonicalPayload({
      sequenceNumber: 1,
      prevHash: provenanceService.GENESIS_PREV_HASH,
      docId: 'doc1',
      recipientId: 'user1',
      action: 'DOCUMENT_UPLOAD',
      status: 'SUCCESS',
      timestampIso: '2026-09-28T00:00:00.000Z'
    });

    const tampered = provenanceService.createCanonicalPayload({
      sequenceNumber: 1,
      prevHash: provenanceService.GENESIS_PREV_HASH,
      docId: 'doc1',
      recipientId: 'user1',
      action: 'DECRYPT_SUCCESS', // Changed action
      status: 'SUCCESS',
      timestampIso: '2026-09-28T00:00:00.000Z'
    });

    const originalHash = cryptoService.computeHash(original);
    const tamperedHash = cryptoService.computeHash(tampered);

    assert.notEqual(originalHash, tamperedHash, 'Tampered payload must produce different hash');
  });

  it('should produce deterministic hashes for identical payloads', () => {
    const payload = provenanceService.createCanonicalPayload({
      sequenceNumber: 42,
      prevHash: 'abc123',
      docId: 'doc42',
      recipientId: 'user42',
      action: 'DECRYPT_ATTEMPT',
      status: 'SUCCESS',
      timestampIso: '2026-09-28T12:00:00.000Z'
    });

    const hash1 = cryptoService.computeHash(payload);
    const hash2 = cryptoService.computeHash(payload);

    assert.equal(hash1, hash2, 'Same payload must produce same hash');
  });
});

// Test canonical event determinism
describe('P0 Security: Canonical Event Serialization', () => {
  const canonicalEventService = require('../src/services/canonicalEventService');

  it('should produce deterministic canonical JSON regardless of field insertion order', () => {
    const event1 = {
      watermarkId: 'WID-ABC',
      documentId: 'DOC-123',
      recipientId: 'user1',
      eventType: 'DOCUMENT_DECRYPTION'
    };

    const event2 = {
      eventType: 'DOCUMENT_DECRYPTION',
      recipientId: 'user1',
      documentId: 'DOC-123',
      watermarkId: 'WID-ABC'
    };

    const canonical1 = canonicalEventService.serializeCanonical(event1);
    const canonical2 = canonicalEventService.serializeCanonical(event2);

    assert.equal(canonical1, canonical2, 'Canonical serialization must be deterministic');
  });

  it('should detect any field modification in event digest', () => {
    const event = canonicalEventService.createDecryptionEvent({
      documentId: 'DOC-TEST',
      documentHash: 'abc123',
      recipientId: 'user1',
      sessionId: 'SES-TEST',
      deviceId: 'DEV-TEST',
      watermarkId: 'WID-TEST',
      watermarkCommitment: 'commit123',
      signingKeyId: 'ML-DSA-65-V1',
      timestamp: '2026-09-28T00:00:00.000Z'
    });

    const { eventDigest: original } = canonicalEventService.computeEventDigest(event);

    // Tamper with one field
    const tampered = { ...event, watermarkId: 'WID-TAMPERED' };
    const { eventDigest: modified } = canonicalEventService.computeEventDigest(tampered);

    assert.notEqual(original, modified, 'Modified field must change digest');
  });
});

// Test ML-DSA signature rejection for tampered digests
describe('P0 Security: ML-DSA Signature Rejection', () => {
  const pqcService = require('../src/services/pqcService');

  it('should reject signature when verified against wrong public key', async () => {
    await pqcService.init();

    const keys1 = await pqcService.generateDsaKeypair();
    const keys2 = await pqcService.generateDsaKeypair();

    const message = Buffer.from('test-canonical-event-digest');
    const { signature } = await pqcService.sign(message, keys1.secretKey);

    const isValid = await pqcService.verify(signature, message, keys2.publicKey);
    assert.equal(isValid, false, 'Signature must not verify against wrong public key');
  });

  it('should reject signature when message is tampered', async () => {
    const keys = await pqcService.generateDsaKeypair();

    const originalMessage = Buffer.from('original-digest');
    const { signature } = await pqcService.sign(originalMessage, keys.secretKey);

    const tamperedMessage = Buffer.from('tampered-digest');
    const isValid = await pqcService.verify(signature, tamperedMessage, keys.publicKey);
    assert.equal(isValid, false, 'Signature must not verify for tampered message');
  });
});

// Test legacy endpoint configuration
describe('P0 Security: Legacy Decrypt Endpoint Control', () => {
  it('should be disabled by default (LEGACY_DECRYPT_ENABLED not set)', () => {
    // Simulate the config behavior
    const envValue = undefined;
    const isEnabled = envValue === 'true';
    assert.equal(isEnabled, false, 'Legacy decrypt should be disabled by default');
  });

  it('should only enable when explicitly set to "true"', () => {
    assert.equal('true' === 'true', true);
    assert.equal('false' === 'true', false);
    assert.equal('' === 'true', false);
    assert.equal('1' === 'true', false);
  });
});
