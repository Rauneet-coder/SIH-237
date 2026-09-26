const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/me', authenticate, authController.getMe);
router.get('/recipients', authenticate, authController.getRecipients);

// Device binding routes
router.post('/devices', authenticate, authController.registerDevice);
router.get('/devices', authenticate, authController.getDevices);

// Key lifecycle & revocation routes
router.post('/keys/revoke', authenticate, authController.revokeKey);

module.exports = router;
