const Document = require('../models/Document');
const documentService = require('../services/documentService');

/**
 * Handle document upload and multi-recipient hybrid encryption
 */
async function uploadDocument(req, res, next) {
  try {
    const { title } = req.body;
    let recipientIds = req.body.recipientIds;

    if (typeof recipientIds === 'string') {
      try {
        recipientIds = JSON.parse(recipientIds);
      } catch (e) {
        recipientIds = [recipientIds];
      }
    }

    if (!Array.isArray(recipientIds) || recipientIds.length === 0) {
      return res.status(400).json({ error: 'recipientIds must be a non-empty array of user IDs.' });
    }

    let fileBuffer;
    let fileName = 'document.pdf';
    let mimeType = 'application/pdf';

    if (req.file) {
      fileBuffer = req.file.buffer;
      fileName = req.file.originalname;
      mimeType = req.file.mimetype;
    } else if (req.body.fileContent) {
      // Allow base64 or raw string in json body for testing/API clients
      fileBuffer = Buffer.from(req.body.fileContent, req.body.isBase64 ? 'base64' : 'utf-8');
      if (req.body.fileName) fileName = req.body.fileName;
      if (req.body.mimeType) mimeType = req.body.mimeType;
    } else {
      return res.status(400).json({ error: 'A file attachment or fileContent is required.' });
    }

    const document = await documentService.uploadAndEncryptDocument({
      title,
      fileBuffer,
      fileName,
      mimeType,
      senderId: req.user._id,
      recipientIds
    });

    return res.status(201).json({
      message: 'Document encrypted and distributed successfully.',
      document: {
        id: document._id,
        title: document.title,
        fileName: document.fileName,
        fileSize: document.fileSize,
        fileHash: document.fileHash,
        mimeType: document.mimeType,
        recipientCount: document.recipientKeys.length,
        createdAt: document.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * List documents accessible to the current user (as sender or authorized recipient)
 */
async function listDocuments(req, res, next) {
  try {
    const userId = req.user._id;

    // Investigators and admins can view all documents, normal users view their sent or received documents
    let query;
    if (['admin', 'investigator'].includes(req.user.role)) {
      query = {};
    } else {
      query = {
        $or: [{ senderId: userId }, { 'recipientKeys.recipientId': userId }]
      };
    }

    const documents = await Document.find(query)
      .populate('senderId', 'username email')
      .populate('recipientKeys.recipientId', 'username email')
      .select('-encryptedBlob -iv -authTag')
      .sort({ createdAt: -1 })
      .exec();

    return res.json({ documents });
  } catch (error) {
    next(error);
  }
}

/**
 * Get document details and recipient's wrapped key
 */
async function getDocument(req, res, next) {
  try {
    const { id } = req.params;
    const document = await Document.findById(id)
      .populate('senderId', 'username email')
      .populate('recipientKeys.recipientId', 'username email')
      .exec();

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    // Check authorization
    const isSender = document.senderId._id.equals(req.user._id);
    const recipientKey = document.recipientKeys.find((rk) =>
      rk.recipientId._id ? rk.recipientId._id.equals(req.user._id) : rk.recipientId.equals(req.user._id)
    );
    const isPrivileged = ['admin', 'investigator'].includes(req.user.role);

    if (!isSender && !recipientKey && !isPrivileged) {
      return res.status(403).json({ error: 'Access denied: not authorized to view this document.' });
    }

    return res.json({
      document: {
        id: document._id,
        title: document.title,
        fileName: document.fileName,
        fileSize: document.fileSize,
        fileHash: document.fileHash,
        mimeType: document.mimeType,
        sender: document.senderId,
        recipientCount: document.recipientKeys.length,
        myEncryptedKey: recipientKey ? recipientKey.encryptedSymmetricKey : null,
        createdAt: document.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Decrypt document using recipient's RSA private key with automatic attribution logging
 */
async function decryptDocument(req, res, next) {
  try {
    const { id } = req.params;
    const { privateKey } = req.body;

    if (!privateKey) {
      return res.status(400).json({ error: 'Recipient RSA privateKey (PEM string) is required to decrypt.' });
    }

    const { document, decryptedBuffer } = await documentService.decryptDocumentForRecipient({
      docId: id,
      recipientId: req.user._id,
      recipientPrivateKeyPem: privateKey
    });

    // If client requested raw binary stream download
    if (req.query.download === 'true') {
      res.setHeader('Content-Type', document.mimeType || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${document.fileName}"`);
      return res.send(decryptedBuffer);
    }

    // Default response: JSON with base64 payload and metadata
    return res.json({
      message: 'Document decrypted successfully. Decryption event logged immutably.',
      documentId: document._id,
      fileName: document.fileName,
      mimeType: document.mimeType,
      fileHash: document.fileHash,
      decryptedData: decryptedBuffer.toString('base64'),
      isBase64: true
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  uploadDocument,
  listDocuments,
  getDocument,
  decryptDocument
};
