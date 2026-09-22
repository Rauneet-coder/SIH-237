const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const mongoose = require('mongoose');
const { connectDB, disconnectDB } = require('../src/config/db');
const User = require('../src/models/User');
const Document = require('../src/models/Document');
const ProvenanceLog = require('../src/models/ProvenanceLog');
const app = require('../src/server');

const TEST_DB_URI = 'mongodb://127.0.0.1:27017/sih237_integration_test';
let server;
let baseUrl;

describe('End-to-End API Integration Tests', () => {
  before(async () => {
    process.env.NODE_ENV = 'test';
    await connectDB(TEST_DB_URI);
    await User.deleteMany({});
    await Document.deleteMany({});
    await ProvenanceLog.deleteMany({});

    // Start server on an ephemeral port
    await new Promise((resolve) => {
      server = http.createServer(app);
      server.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await User.deleteMany({});
    await Document.deleteMany({});
    await ProvenanceLog.deleteMany({});
    await disconnectDB();
    await new Promise((resolve) => server.close(resolve));
  });

  let senderUser;
  let senderToken;
  let recipient1User;
  let recipient1PrivateKey;
  let recipient2User;
  let recipient2PrivateKey;
  let uploadedDocId;
  const sampleDocumentText = 'OPERATION CYBER-SHIELD: Authorized personnel only. Classified level Top-Secret.';

  test('GET /health should return 200 and valid status', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.runtime, 'Node.js');
  });

  test('POST /api/auth/register should register sender and generate RSA keys', async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'commander_alpha',
        email: 'alpha@defence.gov.in',
        password: 'SecurePassword123!',
        role: 'sender'
      })
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.user.id);
    assert.equal(data.user.role, 'sender');
    assert.ok(data.user.publicKey);
    assert.ok(data.privateKey);

    senderUser = data.user;
  });

  test('POST /api/auth/register should register recipients with unique RSA keys', async () => {
    // Recipient 1
    const res1 = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'officer_bravo',
        email: 'bravo@defence.gov.in',
        password: 'PasswordBravo123!',
        role: 'recipient'
      })
    });
    assert.equal(res1.status, 201);
    const data1 = await res1.json();
    recipient1User = data1.user;
    recipient1PrivateKey = data1.privateKey;

    // Recipient 2
    const res2 = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'officer_charlie',
        email: 'charlie@defence.gov.in',
        password: 'PasswordCharlie123!',
        role: 'recipient'
      })
    });
    assert.equal(res2.status, 201);
    const data2 = await res2.json();
    recipient2User = data2.user;
    recipient2PrivateKey = data2.privateKey;

    assert.notEqual(recipient1User.publicKey, recipient2User.publicKey);
  });

  test('POST /api/auth/login should authenticate sender and issue JWT', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'commander_alpha',
        password: 'SecurePassword123!'
      })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.token);
    senderToken = data.token;
  });

  test('POST /api/documents/upload should encrypt document with AES-256-GCM and wrap key for Recipient 1', async () => {
    const res = await fetch(`${baseUrl}/api/documents/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${senderToken}`
      },
      body: JSON.stringify({
        title: 'Operation Cyber-Shield Briefing',
        fileName: 'cyber_shield.pdf',
        fileContent: Buffer.from(sampleDocumentText).toString('base64'),
        isBase64: true,
        mimeType: 'application/pdf',
        recipientIds: [recipient1User.id]
      })
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.document.id);
    assert.equal(data.document.recipientCount, 1);
    assert.ok(data.document.fileHash);

    uploadedDocId = data.document.id;
  });

  test('POST /api/documents/:id/decrypt should successfully decrypt for authorized Recipient 1', async () => {
    // Login as recipient 1
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'officer_bravo',
        password: 'PasswordBravo123!'
      })
    });
    const { token: recipient1Token } = await loginRes.json();

    const decryptRes = await fetch(`${baseUrl}/api/documents/${uploadedDocId}/decrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${recipient1Token}`
      },
      body: JSON.stringify({
        privateKey: recipient1PrivateKey
      })
    });

    assert.equal(decryptRes.status, 200);
    const data = await decryptRes.json();
    assert.ok(data.decryptedData);

    const decryptedText = Buffer.from(data.decryptedData, 'base64').toString('utf-8');
    assert.equal(decryptedText, sampleDocumentText);
  });

  test('POST /api/documents/:id/decrypt should reject unauthorized Recipient 2 with 403 and log failure', async () => {
    // Login as recipient 2
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'officer_charlie',
        password: 'PasswordCharlie123!'
      })
    });
    const { token: recipient2Token } = await loginRes.json();

    const decryptRes = await fetch(`${baseUrl}/api/documents/${uploadedDocId}/decrypt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${recipient2Token}`
      },
      body: JSON.stringify({
        privateKey: recipient2PrivateKey
      })
    });

    assert.equal(decryptRes.status, 403);
    const data = await decryptRes.json();
    assert.ok(data.error.includes('Access denied'));
  });

  test('GET /api/provenance/verify should verify unbroken signed provenance chain', async () => {
    const res = await fetch(`${baseUrl}/api/provenance/verify`);
    assert.equal(res.status, 200);
    const data = await res.json();

    assert.equal(data.report.isValid, true);
    assert.ok(data.report.totalEntries >= 3); // UPLOAD + ATTEMPT + SUCCESS + FAILURE
    assert.equal(data.report.issues.length, 0);
    assert.ok(data.serverPublicKey);
  });

  test('GET /api/provenance/logs should return ordered audit logs with details', async () => {
    const res = await fetch(`${baseUrl}/api/provenance/logs`, {
      headers: {
        Authorization: `Bearer ${senderToken}`
      }
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.total >= 3);
    assert.ok(data.logs.length >= 3);

    // Verify sequential integrity of logs in response
    for (let i = 0; i < data.logs.length; i++) {
      assert.equal(data.logs[i].sequenceNumber, i + 1);
      assert.ok(data.logs[i].signature);
      assert.ok(data.logs[i].entryHash);
    }
  });
});
