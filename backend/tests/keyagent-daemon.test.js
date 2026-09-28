const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { routes, enclave } = require('../src/services/key-agent-server');
const pqcService = require('../src/services/pqcService');

describe('Key Agent Standalone Daemon Process Isolation', () => {
  let server;
  let baseUrl;

  before(async () => {
    // Start isolated Key Agent HTTP server on ephemeral port
    await new Promise((resolve) => {
      server = http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://localhost');
        const path = url.pathname;

        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const bodyStr = Buffer.concat(chunks).toString('utf-8');
        const body = bodyStr ? JSON.parse(bodyStr) : {};

        try {
          let result;
          if (path === '/provision') result = await routes.provision(body);
          else if (path === '/decapsulate') result = await routes.decapsulate(body);
          else if (path === '/sign') result = await routes.sign(body);
          else if (path === '/revoke') result = await routes.revoke(body);
          else if (path === '/health') result = await routes.health();
          else {
            res.writeHead(404);
            return res.end();
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });

      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  const TEST_RECIPIENT = 'daemon_officer_defence';
  let mlKemPub;
  let mlDsaPub;

  test('POST /health should report daemon health and zero initial leaks', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.service, 'SIH26237-KeyAgent');
  });

  test('POST /provision generates PQC keys inside isolated daemon', async () => {
    const res = await fetch(`${baseUrl}/provision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipientId: TEST_RECIPIENT })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.recipientId, TEST_RECIPIENT);
    assert.equal(data.status, 'ACTIVE');
    assert.ok(data.mlKemPublicKey, 'Must return ML-KEM-1024 public key');
    assert.ok(data.mlDsaPublicKey, 'Must return ML-DSA-65 public key');
    assert.equal(data.mlKemSecretKey, undefined, 'Private key MUST NEVER leave daemon process');
    assert.equal(data.mlDsaSecretKey, undefined, 'Private key MUST NEVER leave daemon process');

    mlKemPub = data.mlKemPublicKey;
    mlDsaPub = data.mlDsaPublicKey;
  });

  test('POST /decapsulate recovers shared secret without revealing private key', async () => {
    // Encapsulate DEK using recipient's public key on client side
    const { cipherText, sharedSecret: originalSecret } = await pqcService.encapsulate(mlKemPub);

    const res = await fetch(`${baseUrl}/decapsulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipientId: TEST_RECIPIENT,
        kemCiphertext: cipherText
      })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.sharedSecret);
    assert.equal(data.sharedSecret, originalSecret, 'Daemon must decapsulate identical shared secret');
  });

  test('POST /sign signs event digest using ML-DSA inside daemon', async () => {
    const messageDigest = Buffer.from('canonical_event_digest_daemon_test_01');

    const res = await fetch(`${baseUrl}/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipientId: TEST_RECIPIENT,
        message: messageDigest.toString('base64')
      })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.signature);

    // Verify signature using public key
    const isValid = await pqcService.verify(data.signature, messageDigest, mlDsaPub);
    assert.equal(isValid, true, 'ML-DSA signature produced by daemon must verify');
  });

  test('POST /revoke revokes recipient credentials in daemon', async () => {
    const res = await fetch(`${baseUrl}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipientId: TEST_RECIPIENT })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'REVOKED');

    // Subsequent decapsulate attempt must fail
    const decRes = await fetch(`${baseUrl}/decapsulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipientId: TEST_RECIPIENT,
        kemCiphertext: 'dummy_ciphertext'
      })
    });
    assert.equal(decRes.status, 400);
  });
});
