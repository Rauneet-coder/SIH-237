const express = require('express');
const router = express.Router();
const provenanceController = require('../controllers/provenanceController');
const { authenticate } = require('../middleware/auth');

// Public verification and key export endpoints
router.get('/verify', provenanceController.verifyProvenanceChain);
router.get('/server-key', provenanceController.getServerPublicKey);

// Authenticated provenance query endpoint
router.get('/logs', authenticate, provenanceController.listLogs);

module.exports = router;
