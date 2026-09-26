const express = require('express');
const router = express.Router();
const sessionController = require('../controllers/sessionController');
const { authenticate } = require('../middleware/auth');

router.post('/', authenticate, sessionController.createSession);
router.post('/:sessionId/prepare', authenticate, sessionController.prepareSession);
router.get('/:sessionId/status', authenticate, sessionController.getSessionStatus);
router.get('/:sessionId/render', authenticate, sessionController.getControlledDocument);

module.exports = router;
