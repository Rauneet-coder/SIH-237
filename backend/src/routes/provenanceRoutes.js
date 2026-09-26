const express = require('express');
const router = express.Router();
const provenanceController = require('../controllers/provenanceController');
const { authenticate } = require('../middleware/auth');

// Public verification and key export endpoints
router.get('/verify', provenanceController.verifyProvenanceChain);
router.get('/server-key', provenanceController.getServerPublicKey);

// Authenticated provenance query endpoint
router.get('/logs', authenticate, provenanceController.listLogs);

// Hyperledger Fabric Endpoints
router.get('/fabric/status', authenticate, provenanceController.getFabricStatus);
router.get('/fabric/events/:eventId', authenticate, provenanceController.getFabricEvent);
router.get('/fabric/watermark/:watermarkQuery', authenticate, provenanceController.queryFabricByWatermark);
router.get('/fabric/document/:documentId', authenticate, provenanceController.queryFabricByDocument);
router.get('/fabric/recipient/:recipientId', authenticate, provenanceController.queryFabricByRecipient);
router.get('/fabric/verify/:eventId', authenticate, provenanceController.verifyFabricEvent);

module.exports = router;
