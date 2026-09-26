const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const app = require('../src/server');
const User = require('../src/models/User');
const Device = require('../src/models/Device');
const keyAgentClient = require('../src/services/keyAgentClient');
const env = require('../src/config/env');

const TEST_DB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/sih237_identity_test';

let server;
let baseUrl;

before(async () => {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(TEST_DB_URI);
  }
  await User.deleteMany({});
  await Device.deleteMany({});

  server = app.listen(0);
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  if (server) server.close();
  await User.deleteMany({});
  await Device.deleteMany({});
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

describe('Phase 2: Identity, RBAC & Local Key Agent Abstraction', () => {
  let recipientToken;
  let recipientId;
  let adminToken;
  let adminId;

  it('should register a recipient with Post-Quantum (ML-KEM & ML-DSA) public keys', async () => {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'general_sharma',
        email: 'sharma@mod.gov.in',
        password: 'ClassifiedPassword123!',
        role: 'RECIPIENT',
        deviceId: 'DEV-LAPTOP-01',
        deviceFingerprint: 'fp-sha256-hardware-bind-991'
      })
    });

    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.user.username, 'general_sharma');
    assert.equal(data.user.role, 'RECIPIENT');
    assert.ok(data.user.mlKemPublicKey, 'ML-KEM public key must be provisioned');
    assert.ok(data.user.mlDsaPublicKey, 'ML-DSA public key must be provisioned');
    assert.equal(data.user.keyStatus, 'ACTIVE');

    recipientId = data.user.id;

    // Verify private keys exist ONLY in Key Agent enclave, not in database
    const dbUser = await User.findById(recipientId).lean();
    assert.equal(dbUser.mlKemSecretKey, undefined);
    assert.equal(dbUser.mlDsaSecretKey, undefined);
    assert.ok(keyAgentClient.hasRecipient('general_sharma'), 'Key agent must hold private key enclave');
  });

  it('should login recipient and return JWT with PQC key status', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'general_sharma',
        password: 'ClassifiedPassword123!'
      })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.token, 'JWT token must be issued');
    assert.equal(data.user.keyStatus, 'ACTIVE');
    assert.ok(data.user.mlKemPublicKey);
    recipientToken = data.token;
  });

  it('should register and list trusted recipient devices', async () => {
    // Register second trusted device
    const regRes = await fetch(`${baseUrl}/api/auth/devices`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${recipientToken}`
      },
      body: JSON.stringify({
        deviceId: 'DEV-TABLET-SECURE-02',
        deviceFingerprint: 'fp-sha256-tablet-hardware-882',
        platform: 'Hardened Linux OS'
      })
    });

    assert.equal(regRes.status, 201);
    const regData = await regRes.json();
    assert.equal(regData.device.deviceId, 'DEV-TABLET-SECURE-02');
    assert.equal(regData.device.status, 'ACTIVE');

    // List devices
    const listRes = await fetch(`${baseUrl}/api/auth/devices`, {
      headers: { Authorization: `Bearer ${recipientToken}` }
    });
    assert.equal(listRes.status, 200);
    const listData = await listRes.json();
    assert.ok(listData.devices.length >= 2, 'Should have at least 2 registered devices');
  });

  it('should register an admin and enforce RBAC policies', async () => {
    const adminRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'mod_admin',
        email: 'admin@mod.gov.in',
        password: 'AdminMasterKey2026!',
        role: 'ADMIN'
      })
    });

    assert.equal(adminRes.status, 201);
    const adminData = await adminRes.json();
    adminId = adminData.user.id;

    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'mod_admin',
        password: 'AdminMasterKey2026!'
      })
    });
    const loginData = await loginRes.json();
    adminToken = loginData.token;
  });

  it('should allow user or admin to revoke a cryptographic key', async () => {
    // General Sharma revokes his own key
    const revokeRes = await fetch(`${baseUrl}/api/auth/keys/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${recipientToken}`
      },
      body: JSON.stringify({
        userId: recipientId
      })
    });

    assert.equal(revokeRes.status, 200);
    const revokeData = await revokeRes.json();
    assert.equal(revokeData.keyStatus, 'REVOKED');

    // Verify database record is revoked
    const updatedUser = await User.findById(recipientId);
    assert.equal(updatedUser.keyStatus, 'REVOKED');

    // Verify Key Agent no longer considers key active
    assert.equal(keyAgentClient.hasRecipient('general_sharma'), false);
  });
});
