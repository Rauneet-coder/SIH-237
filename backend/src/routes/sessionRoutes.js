const express = require('express');
const router = express.Router();
const sessionController = require('../controllers/sessionController');
const { authenticate, authorizeRoles, validateDeviceBinding } = require('../middleware/auth');

// Create a new decryption session: recipient only
router.post(
  '/',
  authenticate,
  authorizeRoles('RECIPIENT', 'SENDER', 'DOCUMENT_OWNER', 'ADMIN'),
  validateDeviceBinding,
  sessionController.createSession
);

// Prepare (execute fail-closed pipeline): recipient only
router.post(
  '/:sessionId/prepare',
  authenticate,
  validateDeviceBinding,
  sessionController.prepareSession
);

// Get session status: session owner or admin
router.get(
  '/:sessionId/status',
  authenticate,
  sessionController.getSessionStatus
);

// Controlled document render: session owner only (fail-closed protected)
router.get(
  '/:sessionId/render',
  authenticate,
  validateDeviceBinding,
  sessionController.getControlledDocument
);

module.exports = router;
