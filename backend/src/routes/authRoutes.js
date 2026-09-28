const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate, authorizeRoles } = require('../middleware/auth');

// Public endpoints (no auth required per SR-02)
router.post('/register', authController.register);
router.post('/login', authController.login);

// Authenticated profile endpoint
router.get('/me', authenticate, authController.getMe);

// Recipient listing for document distribution: sender, admin
router.get(
  '/recipients',
  authenticate,
  authorizeRoles('SENDER', 'DOCUMENT_OWNER', 'ADMIN'),
  authController.getRecipients
);

// Device binding & challenge-response possession routes
router.post('/devices', authenticate, authController.registerDevice);
router.get('/devices', authenticate, authController.getDevices);
router.post('/devices/challenge', authenticate, authController.generateDeviceChallenge);
router.post('/devices/verify', authenticate, authController.verifyDeviceChallenge);

// Key lifecycle & revocation routes
router.post('/keys/revoke', authenticate, authController.revokeKey);

// Admin-only role and clearance management
router.post(
  '/users/:userId/role',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.updateUserRole
);
router.patch(
  '/users/:userId/role',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.updateUserRole
);

router.post(
  '/users/:userId/clearance',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.updateUserClearance
);
router.patch(
  '/users/:userId/clearance',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.updateUserClearance
);

// Admin-only user listing
router.get(
  '/users',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.listUsers
);

module.exports = router;
