'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../src/models/User');
const Device = require('../src/models/Device');
const { login } = require('../src/controllers/authController');
const { migrateDeviceIndexes } = require('../src/config/deviceIndexes');

test('shared workstation logins preserve per-user enrollment and revocation', async () => {
  const dbName = `sih237_test_profile_login_${process.pid}`;
  await mongoose.connect(`mongodb://127.0.0.1:27017/${dbName}`, { autoIndex: false, serverSelectionTimeoutMS: 3000 });
  try {
    await Device.collection.createIndex({ deviceId: 1 }, { unique: true });
    const password = 'Test-only-profile-password';
    const hash = await bcrypt.hash(password, 4);
    const users = await User.create(['sender', 'recipient', 'investigator', 'admin'].map((role, i) => ({ username: `test_profile_${i}`, email: `profile${i}@example.test`, password: hash, role })));
    const invoke = async (user, inputPassword = password) => {
      let result; let failure;
      await login({ body: { username: user.username, password: inputPassword, deviceId: 'shared-test-workstation', deviceFingerprint: 'test-fingerprint' }, ip: '127.0.0.1' }, { json: value => { result = value; } }, error => { failure = error; });
      return { result, failure };
    };
    assert.ok((await invoke(users[0])).result?.token);
    assert.equal((await invoke(users[1])).failure?.code, 11000, 'reproduces legacy duplicate-device failure');
    await migrateDeviceIndexes(Device.collection);
    await migrateDeviceIndexes(Device.collection);
    for (const user of users) assert.ok((await invoke(user)).result?.token);
    assert.equal(await Device.countDocuments(), 4);
    await invoke(users[0]);
    assert.equal(await Device.countDocuments(), 4, 'repeat login reuses enrollment');
    await assert.rejects(Device.create({ userId: users[0]._id, deviceId: 'shared-test-workstation', deviceFingerprint: 'other' }), error => error.code === 11000);
    for (const status of ['SUSPENDED', 'REVOKED']) {
      await Device.updateOne({ userId: users[1]._id }, { status });
      assert.equal((await invoke(users[1])).failure?.statusCode, 403);
      assert.ok((await invoke(users[0])).result?.token);
    }
    assert.equal((await invoke(users[0], 'incorrect')).failure?.statusCode, 401);
  } finally {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  }
});
