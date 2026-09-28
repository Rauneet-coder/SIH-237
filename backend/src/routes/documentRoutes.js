const express = require('express');
const multer = require('multer');
const router = express.Router();
const documentController = require('../controllers/documentController');
const collusionController = require('../controllers/collusionController');
const { authenticate, authorizeRoles, validateDeviceBinding } = require('../middleware/auth');
const env = require('../config/env');

// Multer memory storage for in-memory encryption processing
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB maximum document limit
  }
});

// Document upload: sender and admin only
router.post(
  '/upload',
  authenticate,
  authorizeRoles('SENDER', 'DOCUMENT_OWNER', 'ADMIN'),
  upload.single('file'),
  documentController.uploadDocument
);

// List documents: all authenticated users (scoped by role in controller)
router.get('/', authenticate, documentController.listDocuments);

// Get document details: all authenticated users (scoped in controller)
router.get('/:id', authenticate, documentController.getDocument);

// Legacy decrypt endpoint: DISABLED in secure mode.
// This endpoint returns raw plaintext without session watermark, ML-DSA signature,
// or ledger commit. Use the session API (/api/sessions) for secure decryption.
if (env.LEGACY_DECRYPT_ENABLED) {
  router.post('/:id/decrypt', authenticate, validateDeviceBinding, documentController.decryptDocument);
} else {
  router.post('/:id/decrypt', authenticate, (req, res) => {
    return res.status(403).json({
      success: false,
      error: 'Legacy decrypt endpoint is disabled in secure mode. Use the session-based decryption API at /api/sessions for secure document access with watermarking, signing, and ledger commitment.',
      code: 'LEGACY_DECRYPT_DISABLED',
      sessionApiUrl: '/api/sessions'
    });
  });
}

// Collusion-resistant traitor tracing & simulation: investigator and admin only
router.post(
  '/:id/trace',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN'),
  upload.single('file'),
  collusionController.traceCollusion
);

router.post(
  '/:id/simulate-collusion',
  authenticate,
  authorizeRoles('INVESTIGATOR', 'ADMIN'),
  collusionController.simulateCollusionAttack
);

module.exports = router;
