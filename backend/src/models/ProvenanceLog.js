const mongoose = require('mongoose');

const provenanceLogSchema = new mongoose.Schema(
  {
    sequenceNumber: {
      type: Number,
      required: true,
      unique: true,
      index: true
    },
    docId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Document',
      required: true,
      index: true
    },
    recipientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    action: {
      type: String,
      required: true,
      enum: ['DOCUMENT_UPLOAD', 'DECRYPT_ATTEMPT', 'DECRYPT_SUCCESS', 'DECRYPT_FAILURE']
    },
    status: {
      type: String,
      required: true,
      enum: ['SUCCESS', 'FAILURE']
    },
    timestamp: {
      type: Date,
      required: true,
      default: Date.now
    },
    prevHash: {
      type: String,
      required: true // 64-char SHA-256 hex string; genesis is 64 zeros
    },
    entryHash: {
      type: String,
      required: true // 64-char SHA-256 hex string of canonical payload
    },
    signature: {
      type: String,
      required: true // Base64 digital signature by server private key
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('ProvenanceLog', provenanceLogSchema);
