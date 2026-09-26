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
      required: true // Legacy RSA-OAEP encrypted AES-256 key (Base64)
    }
  },
  { _id: false }
);

const keyEnvelopeSchema = new mongoose.Schema(
  {
    recipientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    kemAlgorithm: {
      type: String,
      default: 'ML-KEM-1024'
    },
    kemCiphertext: {
      type: String,
      required: true // Base64 ML-KEM encapsulation capsule
    },
    wrappedDek: {
      type: String,
      required: true // Base64 wrapped AES DEK
    },
    wrappingNonce: {
      type: String,
      required: true // Hex 12-byte wrapping nonce
    },
    wrappingTag: {
      type: String,
      required: true // Hex 16-byte wrapping auth tag
    },
    keyVersion: {
      type: String,
      default: '1.0'
    }
  },
  { _id: false }
);

const documentSchema = new mongoose.Schema(
  {
    documentId: {
      type: String,
      unique: true,
      sparse: true,
      index: true
    },
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
      required: true, // SHA-256 of original plaintext
      index: true
    },
    // AES-256-GCM Single Ciphertext
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
    classification: {
      type: String,
      enum: ['RESTRICTED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
      default: 'CONFIDENTIAL'
    },
    version: {
      type: Number,
      default: 1
    },
    // Legacy RSA recipient keys for backward compatibility
    recipientKeys: [recipientKeySchema],
    // Post-Quantum ML-KEM Key Envelopes
    keyEnvelopes: [keyEnvelopeSchema]
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Document', documentSchema);
