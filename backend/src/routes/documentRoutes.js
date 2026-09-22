const express = require('express');
const multer = require('multer');
const router = express.Router();
const documentController = require('../controllers/documentController');
const { authenticate } = require('../middleware/auth');

// Multer memory storage for in-memory encryption processing
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB maximum document limit
  }
});

router.post('/upload', authenticate, upload.single('file'), documentController.uploadDocument);
router.get('/', authenticate, documentController.listDocuments);
router.get('/:id', authenticate, documentController.getDocument);
router.post('/:id/decrypt', authenticate, documentController.decryptDocument);

module.exports = router;
