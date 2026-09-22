const mongoose = require('mongoose');

const recipientKeySchema = new mongoose.Schema(
  {
    recipientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    encryptedSymmetricKey: {
      type: String,
      required: true // RSA-OAEP encrypted AES-256 key (Base64)
    }
  },
  { _id: false }
);

const documentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true
    },
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    fileName: {
      type: String,
      required: true
    },
    mimeType: {
      type: String,
      default: 'application/pdf'
    },
    fileSize: {
      type: Number,
      required: true
    },
    fileHash: {
      type: String,
      required: true // SHA-256 of original plaintext
    },
    encryptedBlob: {
      type: String,
      required: true // AES-256-GCM ciphertext (Base64)
    },
    iv: {
      type: String,
      required: true // 12-byte IV (Hex)
    },
    authTag: {
      type: String,
      required: true // 16-byte GCM authentication tag (Hex)
    },
    recipientKeys: [recipientKeySchema]
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Document', documentSchema);
