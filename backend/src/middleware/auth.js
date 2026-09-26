const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Device = require('../models/Device');
const env = require('../config/env');
const { AuthenticationError, AuthorizationError } = require('../utils/errors');

/**
 * Middleware to authenticate requests using JWT Bearer token
 */
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Authentication required. Please provide a Bearer token.');
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, env.JWT_SECRET);

    const user = await User.findById(decoded.id).select('-password').exec();
    if (!user || !user.isActive) {
      throw new AuthenticationError('User not found or account is inactive.');
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Authentication token has expired.',
        code: 'TOKEN_EXPIRED'
      });
    }
    if (error instanceof AuthenticationError) {
      return res.status(error.statusCode).json({
        success: false,
        error: error.message,
        code: error.code
      });
    }
    return res.status(401).json({
      success: false,
      error: 'Invalid authentication token.',
      code: 'INVALID_TOKEN'
    });
  }
}

/**
 * Middleware to restrict route access to specific roles (case-insensitive)
 * @param {string[]} roles
 */
function authorizeRoles(...roles) {
  const normalizedAllowedRoles = roles.map((r) => r.toUpperCase());

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Unauthenticated user.',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const userRole = (req.user.role || '').toUpperCase();

    // Map common aliases (e.g. SENDER -> DOCUMENT_OWNER)
    const matches =
      normalizedAllowedRoles.includes(userRole) ||
      (normalizedAllowedRoles.includes('DOCUMENT_OWNER') && userRole === 'SENDER') ||
      (normalizedAllowedRoles.includes('SENDER') && userRole === 'DOCUMENT_OWNER');

    if (!matches) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Requires one of roles: [${roles.join(', ')}]`,
        code: 'AUTHORIZATION_DENIED'
      });
    }
    next();
  };
}

/**
 * Middleware to validate device binding for decryption and high-security endpoints
 */
async function validateDeviceBinding(req, res, next) {
  try {
    const deviceId = req.headers['x-device-id'] || req.body.deviceId;
    if (!deviceId) {
      // If no device ID supplied, pass through (or require based on strict policy)
      return next();
    }

    const device = await Device.findOne({
      userId: req.user._id,
      deviceId
    }).exec();

    if (device && device.status === 'REVOKED') {
      throw new AuthorizationError(`Device ${deviceId} has been revoked.`);
    }

    req.device = device;
    next();
  } catch (error) {
    next(error);
  }
}

module.exports = {
  authenticate,
  authorizeRoles,
  validateDeviceBinding
};
