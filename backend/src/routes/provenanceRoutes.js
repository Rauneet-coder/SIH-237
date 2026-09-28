const express = require('express');
const router = express.Router();
const provenanceController = require('../controllers/provenanceController');
const { authenticate, authorizeRoles } = require('../middleware/auth');

// Public verification and key export endpoints (auditable transparency)
router.get('/verify', provenanceController.verifyProvenanceChain);
router.get('/server-key', provenanceController.getServerPublicKey);

// Authenticated provenance query endpoint: admin, investigator, auditor
router.get(
  '/logs',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.listLogs
);

// Hyperledger Fabric Endpoints: admin, investigator, auditor
router.get(
  '/fabric/status',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.getFabricStatus
);

router.get(
  '/fabric/events/:eventId',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.getFabricEvent
);

router.get(
  '/fabric/watermark/:watermarkQuery',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN'),
  provenanceController.queryFabricByWatermark
);

router.get(
  '/fabric/document/:documentId',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.queryFabricByDocument
);

router.get(
  '/fabric/recipient/:recipientId',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.queryFabricByRecipient
);

router.get(
  '/fabric/verify/:eventId',
  authenticate,
  authorizeRoles('ADMIN', 'INVESTIGATOR', 'AUDITOR'),
  provenanceController.verifyFabricEvent
);

module.exports = router;
