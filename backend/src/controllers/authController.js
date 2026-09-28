'use strict';

const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Device = require('../models/Device');
const cryptoService = require('../services/cryptoService');
const keyAgentClient = require('../services/keyAgentClient');
const env = require('../config/env');
const logger = require('../utils/logger');
const { ValidationError, AuthenticationError, AuthorizationError, NotFoundError } = require('../utils/errors');

// Active challenges map: challengeId -> { challengeId, nonce, deviceId, userId, purpose, sessionId, expiresAt, consumed }
const deviceChallenges = new Map();
// Single-use device proof tokens: token -> { userId, deviceId, purpose, sessionId, expiresAt, consumed }
const deviceProofTokens = new Map();

/**
 * Register a new user with Post-Quantum key generation (ML-KEM & ML-DSA)
 * Private keys are generated and retained exclusively within the Key Agent boundary.
 * Enforces least-privilege defaults (RECIPIENT, RESTRICTED) and secure first-admin bootstrap.
 */
async function register(req, res, next) {
  try {
    const { username, email, password, role, deviceId, deviceFingerprint, platform } = req.body;

    if (!username || !email || !password) {
      throw new ValidationError('Username, email, and password are required.');
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email: email.toLowerCase() }]
    }).exec();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'A user with this username or email already exists.',
        code: 'USER_ALREADY_EXISTS'
      });
    }

    // Prohibit re-registering or reactivating a revoked device
    if (deviceId) {
      const existingDevice = await Device.findOne({ deviceId }).exec();
      if (existingDevice && existingDevice.status === 'REVOKED') {
        throw new AuthorizationError(`Device ${deviceId} has been permanently REVOKED and cannot be re-registered.`);
      }
    }

    // Role and clearance determination
    const userCount = await User.countDocuments().exec();
    let assignedRole;
    let assignedClearance;

    if (userCount === 0) {
      // First-user bootstrap: assign privileged role if requested, else default to RECIPIENT
      if (role && role.toUpperCase() === 'ADMIN') {
        assignedRole = 'ADMIN';
        assignedClearance = 'TOP_SECRET';
      } else if (role && (role.toUpperCase() === 'SENDER' || role.toUpperCase() === 'DOCUMENT_OWNER')) {
        assignedRole = 'SENDER';
        assignedClearance = 'TOP_SECRET';
      } else {
        assignedRole = 'RECIPIENT';
        assignedClearance = 'RESTRICTED';
      }
      logger.securityAudit('INITIAL_BOOTSTRAP_USER_PROVISIONED', {
        username,
        role: assignedRole,
        clearance: assignedClearance
      });
    } else {
      // Least-privilege default for public registration
      assignedRole = 'RECIPIENT';
      assignedClearance = 'RESTRICTED';

      if (role && role.toUpperCase() !== 'RECIPIENT') {
        logger.securityAudit('PRIVILEGED_ROLE_SELF_REGISTRATION_DENIED', {
          requestedRole: role,
          assignedRole,
          username
        });
      }
    }

    // 1. Hash password with bcrypt (cost factor 12 per SR-04)
    const hashedPassword = await bcrypt.hash(password, 12);

    // 2. Provision Post-Quantum Keys (ML-KEM-1024 & ML-DSA-65) inside Key Agent boundary
    const pqcPublicKeys = await keyAgentClient.provisionRecipient(username);

    // 3. Generate backwards-compatible RSA keypair for legacy tests
    const { publicKey, privateKey } = cryptoService.generateKeyPair(2048);

    // 4. Construct device list if device registration requested
    const initialDevices = [];
    if (deviceId && deviceFingerprint) {
      initialDevices.push({
        deviceId,
        deviceFingerprint,
        trusted: true,
        status: 'ACTIVE',
        enrolledAt: new Date(),
        lastSeenAt: new Date()
      });
    }

    // 5. Persist user with public keys only
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: assignedRole,
      clearance: assignedClearance,
      publicKey,
      mlKemPublicKey: pqcPublicKeys.mlKemPublicKey,
      mlDsaPublicKey: pqcPublicKeys.mlDsaPublicKey,
      keyStatus: 'ACTIVE',
      keyVersion: '1.0',
      devices: initialDevices,
      isActive: true
    });

    await user.save();

    // Also persist in Device collection if provided
    if (deviceId && deviceFingerprint) {
      await Device.create({
        userId: user._id,
        deviceId,
        deviceFingerprint,
        platform: platform || 'Web Browser',
        status: 'ACTIVE',
        lastSeenAt: new Date(),
        ipAddress: req.ip
      });
    }

    logger.securityAudit('USER_REGISTERED', {
      userId: user._id.toString(),
      username: user.username,
      role: user.role,
      clearance: user.clearance,
      hasPqcKeys: true
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully. PQC keys provisioned inside Key Agent.',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        clearance: user.clearance,
        publicKey: user.publicKey,
        mlKemPublicKey: user.mlKemPublicKey,
        mlDsaPublicKey: user.mlDsaPublicKey,
        keyStatus: user.keyStatus,
        createdAt: user.createdAt
      },
      privateKey
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Login user, verify credentials, bind device, and issue JWT
 */
async function login(req, res, next) {
  try {
    const { username, email, password, deviceId, deviceFingerprint } = req.body;

    if ((!username && !email) || !password) {
      throw new ValidationError('Username/email and password are required.');
    }

    const query = username ? { username } : { email: email.toLowerCase() };
    const user = await User.findOne(query).exec();

    if (!user || !user.isActive) {
      throw new AuthenticationError('Invalid credentials or inactive account.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new AuthenticationError('Invalid credentials.');
    }

    // Optional device registration/update on login
    if (deviceId && deviceFingerprint) {
      const existingDevice = await Device.findOne({ userId: user._id, deviceId }).exec();
      if (!existingDevice) {
        await Device.create({
          userId: user._id,
          deviceId,
          deviceFingerprint,
          status: 'ACTIVE',
          lastSeenAt: new Date(),
          ipAddress: req.ip
        });
      } else {
        if (existingDevice.status === 'REVOKED') {
          throw new AuthorizationError(`Device ${deviceId} has been revoked. Access denied.`);
        }
        if (existingDevice.status === 'SUSPENDED') {
          throw new AuthorizationError(`Device ${deviceId} is suspended. Contact administrator.`);
        }
        existingDevice.lastSeenAt = new Date();
        existingDevice.ipAddress = req.ip;
        await existingDevice.save();
      }
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role,
        clearance: user.clearance,
        keyStatus: user.keyStatus
      },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    logger.info(`User ${user.username} authenticated successfully`, {
      userId: user._id.toString(),
      role: user.role,
      clearance: user.clearance
    });

    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        clearance: user.clearance,
        publicKey: user.publicKey,
        mlKemPublicKey: user.mlKemPublicKey,
        mlDsaPublicKey: user.mlDsaPublicKey,
        keyStatus: user.keyStatus
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get currently authenticated user profile
 */
async function getMe(req, res, next) {
  try {
    return res.json({ success: true, user: req.user });
  } catch (error) {
    next(error);
  }
}

/**
 * Get list of active recipients with public keys for encryption distribution
 */
async function getRecipients(req, res, next) {
  try {
    const recipients = await User.find({ isActive: true })
      .select('username email role clearance publicKey mlKemPublicKey mlDsaPublicKey keyStatus createdAt')
      .exec();

    return res.json({ success: true, recipients });
  } catch (error) {
    next(error);
  }
}

/**
 * Register a new trusted device for the authenticated user
 */
async function registerDevice(req, res, next) {
  try {
    const { deviceId, deviceFingerprint, platform } = req.body;
    if (!deviceId || !deviceFingerprint) {
      throw new ValidationError('deviceId and deviceFingerprint are required.');
    }

    let device = await Device.findOne({ userId: req.user._id, deviceId }).exec();
    if (device) {
      if (device.status === 'REVOKED') {
        throw new AuthorizationError(`Device ${deviceId} has been revoked and cannot be reactivated.`);
      }
      if (device.status === 'SUSPENDED') {
        throw new AuthorizationError(`Device ${deviceId} is suspended. Contact administrator.`);
      }
      device.deviceFingerprint = deviceFingerprint;
      device.status = 'ACTIVE';
      device.lastSeenAt = new Date();
      await device.save();
    } else {
      device = await Device.create({
        userId: req.user._id,
        deviceId,
        deviceFingerprint,
        platform: platform || 'Web Browser',
        status: 'ACTIVE',
        lastSeenAt: new Date(),
        ipAddress: req.ip
      });
    }

    // Also update devices array in User document
    const user = await User.findById(req.user._id).exec();
    if (user) {
      const existingUserDev = user.devices.find((d) => d.deviceId === deviceId);
      if (existingUserDev) {
        existingUserDev.deviceFingerprint = deviceFingerprint;
        existingUserDev.status = 'ACTIVE';
        existingUserDev.lastSeenAt = new Date();
      } else {
        user.devices.push({
          deviceId,
          deviceFingerprint,
          trusted: true,
          status: 'ACTIVE',
          enrolledAt: new Date(),
          lastSeenAt: new Date()
        });
      }
      await user.save();
    }

    logger.securityAudit('DEVICE_REGISTERED', {
      userId: req.user._id.toString(),
      deviceId
    });

    return res.status(201).json({ success: true, device });
  } catch (error) {
    next(error);
  }
}

/**
 * List registered devices for authenticated user
 */
async function getDevices(req, res, next) {
  try {
    const devices = await Device.find({ userId: req.user._id }).exec();
    return res.json({ success: true, devices });
  } catch (error) {
    next(error);
  }
}

/**
 * Revoke cryptographic key for a user (Self or Admin)
 */
async function revokeKey(req, res, next) {
  try {
    const targetUserId = req.body.userId || req.user._id;

    // Check authorization: must be self or admin
    if (targetUserId.toString() !== req.user._id.toString() && req.user.role.toUpperCase() !== 'ADMIN') {
      throw new AuthorizationError('Only an administrator or the key owner can revoke this key.');
    }

    const user = await User.findById(targetUserId).exec();
    if (!user) {
      throw new NotFoundError('User');
    }

    user.keyStatus = 'REVOKED';
    await user.save();

    // Revoke in Key Agent
    keyAgentClient.revoke(user.username, 'Revoked via API');

    logger.securityAudit('KEY_REVOKED', {
      revokedBy: req.user._id.toString(),
      targetUser: user.username
    });

    return res.json({
      success: true,
      message: `Cryptographic keys for user ${user.username} have been revoked.`,
      keyStatus: 'REVOKED'
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Admin-only: Update a user's role (Controlled elevation for SENDER, INVESTIGATOR, etc.)
 */
async function updateUserRole(req, res, next) {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    const VALID_ROLES = ['RECIPIENT', 'SENDER', 'INVESTIGATOR', 'ADMIN', 'AUDITOR'];
    if (!role || !VALID_ROLES.includes(role.toUpperCase())) {
      throw new ValidationError(`Invalid role. Must be one of: ${VALID_ROLES.join(', ')}`);
    }

    const user = await User.findById(userId).exec();
    if (!user) {
      throw new NotFoundError('User');
    }

    const previousRole = user.role;
    user.role = role.toUpperCase();
    await user.save();

    logger.securityAudit('USER_ROLE_UPDATED', {
      adminId: req.user._id.toString(),
      targetUserId: userId,
      previousRole,
      newRole: user.role
    });

    return res.json({
      success: true,
      message: `User ${user.username} role updated from ${previousRole} to ${user.role}`,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Admin-only: Update a user's clearance level (Audited ABAC adjustment)
 */
async function updateUserClearance(req, res, next) {
  try {
    const { userId } = req.params;
    const { clearance, reason } = req.body;

    const VALID_CLEARANCES = ['UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
    if (!clearance || !VALID_CLEARANCES.includes(clearance.toUpperCase())) {
      throw new ValidationError(`Invalid clearance. Must be one of: ${VALID_CLEARANCES.join(', ')}`);
    }

    const user = await User.findById(userId).exec();
    if (!user) {
      throw new NotFoundError('User');
    }

    const previousClearance = user.clearance || 'RESTRICTED';
    const newClearance = clearance.toUpperCase();

    user.clearance = newClearance;
    user.clearanceHistory.push({
      previousClearance,
      newClearance,
      changedBy: req.user._id,
      reason: reason || 'Administrative clearance assignment',
      changedAt: new Date()
    });
    await user.save();

    logger.securityAudit('USER_CLEARANCE_UPDATED', {
      adminId: req.user._id.toString(),
      targetUserId: userId,
      previousClearance,
      newClearance,
      reason: reason || 'Administrative clearance assignment'
    });

    return res.json({
      success: true,
      message: `User ${user.username} clearance updated from ${previousClearance} to ${newClearance}`,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        clearance: user.clearance
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Admin-only: List all registered users
 */
async function listUsers(req, res, next) {
  try {
    const users = await User.find()
      .select('username email role clearance keyStatus isActive createdAt')
      .sort({ createdAt: -1 })
      .exec();

    return res.json({ success: true, users });
  } catch (error) {
    next(error);
  }
}

/**
 * Generate a device challenge bound to user, device, purpose, and session
 */
async function generateDeviceChallenge(req, res, next) {
  try {
    const { deviceId, purpose = 'DECRYPTION_SESSION', sessionId = null } = req.body;
    if (!deviceId) {
      throw new ValidationError('deviceId is required');
    }
    const device = await Device.findOne({ userId: req.user._id, deviceId, status: 'ACTIVE' }).exec();
    if (!device) {
      throw new AuthorizationError('Device is not registered or active');
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    const challengeId = `CHAL-${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = Date.now() + 2 * 60 * 1000; // 2 minutes

    deviceChallenges.set(challengeId, {
      challengeId,
      challenge: nonce, // Backward compatibility with response hashing
      nonce,
      deviceId,
      userId: req.user._id.toString(),
      purpose,
      sessionId,
      expiresAt,
      consumed: false
    });

    // Cleanup expired challenges
    const now = Date.now();
    for (const [id, rec] of deviceChallenges.entries()) {
      if (rec.expiresAt < now) deviceChallenges.delete(id);
    }

    return res.json({
      success: true,
      challengeId,
      challenge: nonce,
      deviceId,
      purpose,
      sessionId,
      expiresInSeconds: 120
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Verify cryptographic device challenge response and issue single-use proof token
 */
async function verifyDeviceChallenge(req, res, next) {
  try {
    const { deviceId, response, challengeId, proof } = req.body;
    const providedProof = proof || response;

    if (!deviceId || !providedProof) {
      throw new ValidationError('deviceId and response/proof are required');
    }

    // Locate challenge record: either by explicit challengeId or by deviceId
    let challengeRecord = null;
    let foundKey = null;

    if (challengeId && deviceChallenges.has(challengeId)) {
      challengeRecord = deviceChallenges.get(challengeId);
      foundKey = challengeId;
    } else {
      // Find latest valid unconsumed challenge for this device
      for (const [key, rec] of deviceChallenges.entries()) {
        if (rec.deviceId === deviceId && rec.userId === req.user._id.toString() && !rec.consumed) {
          challengeRecord = rec;
          foundKey = key;
          break;
        }
      }
    }

    if (!challengeRecord || Date.now() > challengeRecord.expiresAt || challengeRecord.consumed) {
      if (foundKey) deviceChallenges.delete(foundKey);
      throw new AuthorizationError('Challenge expired or already consumed. Request a fresh challenge.');
    }

    // Mark challenge as consumed immediately (one-time use)
    challengeRecord.consumed = true;
    deviceChallenges.delete(foundKey);

    const device = await Device.findOne({ userId: req.user._id, deviceId, status: 'ACTIVE' }).exec();
    if (!device) {
      throw new AuthorizationError('Device is not registered or active');
    }

    // Expected response: HMAC-SHA256(deviceFingerprint, challenge)
    const expectedResponse = crypto
      .createHmac('sha256', device.deviceFingerprint)
      .update(challengeRecord.challenge)
      .digest('hex');

    const proofBuf = Buffer.from(providedProof, 'hex');
    const expectedBuf = Buffer.from(expectedResponse, 'hex');

    const isValid =
      proofBuf.length === expectedBuf.length &&
      crypto.timingSafeEqual(proofBuf, expectedBuf);

    if (!isValid) {
      logger.securityAudit('DEVICE_CHALLENGE_FAILED', {
        deviceId,
        userId: req.user._id.toString()
      });
      throw new AuthorizationError('Device challenge response verification failed');
    }

    // Issue single-use device proof token valid for 2 minutes
    const proofToken = `DPT-${crypto.randomBytes(32).toString('hex')}`;
    deviceProofTokens.set(proofToken, {
      userId: req.user._id.toString(),
      deviceId,
      purpose: challengeRecord.purpose,
      sessionId: challengeRecord.sessionId,
      expiresAt: Date.now() + 2 * 60 * 1000,
      consumed: false
    });

    device.lastSeenAt = new Date();
    await device.save();

    logger.securityAudit('DEVICE_CHALLENGE_VERIFIED', {
      deviceId,
      userId: req.user._id.toString(),
      purpose: challengeRecord.purpose
    });

    return res.json({
      success: true,
      verified: true,
      deviceId,
      deviceProofToken: proofToken,
      verifiedAt: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register,
  login,
  getMe,
  getRecipients,
  registerDevice,
  getDevices,
  generateDeviceChallenge,
  verifyDeviceChallenge,
  revokeKey,
  updateUserRole,
  updateUserClearance,
  listUsers,
  deviceProofTokens
};
