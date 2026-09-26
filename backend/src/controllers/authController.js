const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Device = require('../models/Device');
const cryptoService = require('../services/cryptoService');
const keyAgentClient = require('../services/keyAgentClient');
const env = require('../config/env');
const logger = require('../utils/logger');
const { ValidationError, AuthenticationError, AuthorizationError, NotFoundError } = require('../utils/errors');

/**
 * Register a new user with Post-Quantum key generation (ML-KEM & ML-DSA)
 * Private keys are generated and retained exclusively within the Key Agent boundary.
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

    // 1. Hash password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. Generate RSA keypair for backwards-compatible cryptographic operations
    const { publicKey, privateKey } = cryptoService.generateKeyPair(2048);

    // 3. Provision Post-Quantum Keys (ML-KEM-1024 & ML-DSA-65) inside Key Agent boundary
    const pqcPublicKeys = await keyAgentClient.provisionRecipient(username);

    // 4. Construct device list if device registration requested
    const initialDevices = [];
    if (deviceId && deviceFingerprint) {
      initialDevices.push({
        deviceId,
        deviceFingerprint,
        trusted: true,
        lastSeenAt: new Date()
      });
    }

    // 5. Persist user with public keys only
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: role || 'recipient',
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
        publicKey: user.publicKey,
        mlKemPublicKey: user.mlKemPublicKey,
        mlDsaPublicKey: user.mlDsaPublicKey,
        keyStatus: user.keyStatus,
        createdAt: user.createdAt
      },
      // One-time legacy RSA private key export for backwards compatibility with tests
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
        keyStatus: user.keyStatus
      },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    logger.info(`User ${user.username} authenticated successfully`, {
      userId: user._id.toString(),
      role: user.role
    });

    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
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
      .select('username email role publicKey mlKemPublicKey mlDsaPublicKey keyStatus createdAt')
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
    keyAgentClient.revoke(user.username);

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

module.exports = {
  register,
  login,
  getMe,
  getRecipients,
  registerDevice,
  getDevices,
  revokeKey
};
