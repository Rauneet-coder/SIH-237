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

// Device binding routes
router.post('/devices', authenticate, authController.registerDevice);
router.get('/devices', authenticate, authController.getDevices);

// Key lifecycle & revocation routes
router.post('/keys/revoke', authenticate, authController.revokeKey);

// Admin-only role management
router.post(
  '/users/:userId/role',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.updateUserRole
);

// Admin-only user listing
router.get(
  '/users',
  authenticate,
  authorizeRoles('ADMIN'),
  authController.listUsers
);

module.exports = router;
