const express = require('express');
const multer = require('multer');
const router = express.Router();
const forensicController = require('../controllers/forensicController');
const { authenticate, authorizeRoles } = require('../middleware/auth');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB
  }
});

// Watermark extraction: investigator, admin, auditor, sender
router.post(
  '/extract',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN', 'AUDITOR', 'SENDER', 'DOCUMENT_OWNER'),
  upload.single('file'),
  forensicController.extractWatermark
);

// Cryptographic forensic verification on Fabric ledger
router.post(
  '/verify',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN', 'AUDITOR'),
  forensicController.verifyForensicEvidence
);

// One-shot leak investigation (Extract + Verify on Ledger)
router.post(
  '/investigate',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN', 'AUDITOR'),
  upload.single('file'),
  forensicController.investigateLeak
);

module.exports = router;
