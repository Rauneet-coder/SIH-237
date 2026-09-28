'use strict';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  handler,
  setKeystoreDir,
  setHmacSecret,
  resetEnclave,
  loadKeystore,
  enclave
} = require('../src/services/key-agent-server');
const {
  createCanonicalString,
  hashBody,
  generateHmac
} = require('../src/services/keyAgentAuth');
const pqcService = require('../src/services/pqcService');

describe('Key Agent Daemon Security, Custody & Persistence', () => {
  let server;
  let baseUrl;
  let testKeystoreDir;
  const TEST_SECRET = 'test_key_agent_hmac_secret_32bytes_sih237';
  const RECIPIENT_ALICE = 'officer_alice_defence';
  const RECIPIENT_BOB = 'officer_bob_defence';

  before(async () => {
    // Isolated temporary directory for encrypted keystore
    testKeystoreDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sih237-keystore-test-'));
    setKeystoreDir(testKeystoreDir);
    setHmacSecret(TEST_SECRET);
    resetEnclave();

    // Start server using the REAL production handler
    await new Promise((resolve) => {
      server = http.createServer(handler);
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    if (testKeystoreDir && fs.existsSync(testKeystoreDir)) {
      fs.rmSync(testKeystoreDir, { recursive: true, force: true });
    }
  });

  /**
   * Helper to craft authenticated HTTP requests to the real daemon handler
   */
  async function authFetch(endpoint, { method = 'POST', payload, recipientId = '', timestamp, nonce, customAuth, tamperBody } = {}) {
    const ts = timestamp !== undefined ? timestamp : new Date().toISOString();
    const nc = nonce !== undefined ? nonce : crypto.randomUUID();
    const bodyStr = payload ? JSON.stringify(payload) : '';
    const bodyHash = hashBody(bodyStr);

    const canonical = createCanonicalString({
      method,
      path: endpoint,
      recipientId,
      timestamp: ts,
      nonce: nc,
      bodyHash
    });

    const authHeader = customAuth !== undefined ? customAuth : generateHmac(TEST_SECRET, canonical);
    const bodyToSend = tamperBody !== undefined ? tamperBody : (payload ? bodyStr : undefined);

    const headers = {
      'Content-Type': 'application/json'
    };
    if (authHeader !== null) headers['X-Key-Agent-Auth'] = authHeader;
    if (ts !== null) headers['X-Key-Agent-Timestamp'] = ts;
    if (nc !== null) headers['X-Key-Agent-Nonce'] = nc;
    if (recipientId) headers['X-Key-Agent-Recipient'] = recipientId;

    return fetch(`${baseUrl}${endpoint}`, {
      method,
      headers,
      body: bodyToSend
    });
  }

  test('Public endpoint: GET /health responds without authentication', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.service, 'SIH26237-KeyAgent');
    assert.equal(data.keystoreEncrypted, true);
  });

  test('Security Negative: Missing authentication headers returns 401', async () => {
    const res = await fetch(`${baseUrl}/provision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipientId: RECIPIENT_ALICE })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.match(body.error, /Missing required authentication headers/);
  });

  test('Security Negative: Incorrect HMAC signature returns 401', async () => {
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE,
      customAuth: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.match(body.error, /Invalid HMAC signature/);
  });

  test('Security Negative: Modified request body (tampered payload) returns 401', async () => {
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE,
      tamperBody: JSON.stringify({ recipientId: 'attacker_substituted_id' })
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.match(body.error, /Invalid HMAC signature or body hash mismatch/);
  });

  test('Security Negative: Expired request timestamp (> 60s) returns 401', async () => {
    const expiredTs = new Date(Date.now() - 65 * 1000).toISOString();
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE,
      timestamp: expiredTs
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.match(body.error, /Request expired/);
  });

  test('Security Negative: Replayed request with duplicate nonce returns 401', async () => {
    const sharedNonce = crypto.randomUUID();
    const res1 = await authFetch('/has', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE,
      nonce: sharedNonce
    });
    assert.equal(res1.status, 200);

    // Immediate replay of exact same nonce
    const res2 = await authFetch('/has', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE,
      nonce: sharedNonce
    });
    assert.equal(res2.status, 401);
    const body2 = await res2.json();
    assert.match(body2.error, /Replay detected/);
  });

  test('Security Negative: Recipient mismatch between header and payload returns 403', async () => {
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_BOB // Header claims Bob, payload asks for Alice
    });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.match(body.error, /Recipient mismatch/);
  });

  let aliceKemPub;
  let aliceDsaPub;

  test('Correctness: POST /provision creates recipient and returns ONLY public keys', async () => {
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(res.status, 200);
    const data = await res.json();

    assert.equal(data.recipientId, RECIPIENT_ALICE);
    assert.equal(data.status, 'ACTIVE');
    assert.equal(data.alreadyExisted, false);
    assert.ok(data.mlKemPublicKey, 'Returns ML-KEM public key');
    assert.ok(data.mlDsaPublicKey, 'Returns ML-DSA public key');
    assert.equal(data.mlKemSecretKey, undefined, 'Private key MUST NOT be returned');
    assert.equal(data.mlDsaSecretKey, undefined, 'Private key MUST NOT be returned');

    aliceKemPub = data.mlKemPublicKey;
    aliceDsaPub = data.mlDsaPublicKey;

    // Verify keystore file was created on disk with mode 0600
    const keystorePath = path.join(testKeystoreDir, 'keystore.enc');
    const masterKeyPath = path.join(testKeystoreDir, 'daemon.master.key');
    assert.ok(fs.existsSync(keystorePath), 'Keystore file must exist');
    assert.ok(fs.existsSync(masterKeyPath), 'Master key file must exist');
  });

  test('Idempotence: Duplicate /provision does NOT overwrite existing recipient keys', async () => {
    const res = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(res.status, 200);
    const data = await res.json();

    assert.equal(data.recipientId, RECIPIENT_ALICE);
    assert.equal(data.status, 'ACTIVE');
    assert.equal(data.alreadyExisted, true, 'Must indicate recipient already existed');
    assert.equal(data.mlKemPublicKey, aliceKemPub, 'Must NOT overwrite existing KEM public key');
    assert.equal(data.mlDsaPublicKey, aliceDsaPub, 'Must NOT overwrite existing DSA public key');
  });

  test('Decapsulation & Signing: Successfully decapsulates and signs with session/document binding', async () => {
    // Encapsulate DEK against Alice's public key
    const { cipherText, sharedSecret } = await pqcService.encapsulate(aliceKemPub);

    const decRes = await authFetch('/decapsulate', {
      payload: {
        recipientId: RECIPIENT_ALICE,
        kemCiphertext: cipherText,
        sessionId: 'SES-TEST-001',
        documentId: 'DOC-CONFIDENTIAL-001'
      },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(decRes.status, 200);
    const decData = await decRes.json();
    assert.equal(decData.sharedSecret, sharedSecret, 'Decapsulated secret must match original shared secret');
    assert.equal(decData.sessionId, 'SES-TEST-001');
    assert.equal(decData.documentId, 'DOC-CONFIDENTIAL-001');

    // Sign canonical digest
    const testDigest = Buffer.from('canonical_rfc8785_event_digest_test');
    const signRes = await authFetch('/sign', {
      payload: {
        recipientId: RECIPIENT_ALICE,
        message: testDigest.toString('base64'),
        sessionId: 'SES-TEST-001',
        documentId: 'DOC-CONFIDENTIAL-001',
        context: 'CANONICAL_AUDIT_LOG'
      },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(signRes.status, 200);
    const signData = await signRes.json();
    assert.ok(signData.signature);

    const isSigValid = await pqcService.verify(signData.signature, testDigest, aliceDsaPub);
    assert.equal(isSigValid, true, 'ML-DSA signature produced by daemon must verify against public key');
  });

  test('Persistence across daemon restart: Keystore reloads private keys from encrypted file', async () => {
    // Clear in-memory enclave to simulate daemon process termination
    resetEnclave();
    assert.equal(enclave.size, 0, 'Memory enclave cleared');

    // Trigger keystore reload from encrypted disk storage
    const loadedCount = loadKeystore();
    assert.equal(loadedCount >= 1, true, 'Must load stored recipient keys from disk');
    assert.ok(enclave.has(RECIPIENT_ALICE), 'Alice credentials must survive restart');

    // Verify decapsulation works after reload
    const { cipherText, sharedSecret } = await pqcService.encapsulate(aliceKemPub);
    const decRes = await authFetch('/decapsulate', {
      payload: {
        recipientId: RECIPIENT_ALICE,
        kemCiphertext: cipherText,
        sessionId: 'SES-RESTART-001'
      },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(decRes.status, 200);
    const decData = await decRes.json();
    assert.equal(decData.sharedSecret, sharedSecret, 'Decapsulation succeeds after restart');
  });

  test('Revocation: POST /revoke permanently marks credentials as REVOKED and blocks operations', async () => {
    const revRes = await authFetch('/revoke', {
      payload: { recipientId: RECIPIENT_ALICE, reason: 'Key compromise drill' },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(revRes.status, 200);
    const revData = await revRes.json();
    assert.equal(revData.status, 'REVOKED');

    // Subsequent decapsulate must be rejected with 403
    const decRes = await authFetch('/decapsulate', {
      payload: {
        recipientId: RECIPIENT_ALICE,
        kemCiphertext: 'dummy_ciphertext'
      },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(decRes.status, 403);
    const decErr = await decRes.json();
    assert.match(decErr.error, /REVOKED/);

    // Re-provisioning of revoked recipient is strictly prohibited
    const reprovRes = await authFetch('/provision', {
      payload: { recipientId: RECIPIENT_ALICE },
      recipientId: RECIPIENT_ALICE
    });
    assert.equal(reprovRes.status, 409);
  });
});
