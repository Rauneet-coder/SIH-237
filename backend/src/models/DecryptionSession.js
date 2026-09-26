const mongoose = require('mongoose');

const decryptionSessionSchema = new mongoose.Schema(
  {
    sessionId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    documentId: {
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
    deviceId: {
      type: String,
      required: true
    },
    sessionNonce: {
      type: String,
      required: true // 32-byte CSPRNG hex
    },
    status: {
      type: String,
      enum: [
        'CREATED',
        'AUTHORIZED',
        'DECRYPTED',
        'WATERMARKED',
        'SIGNED',
        'COMMITTED',
        'RELEASED',
        'FAILED',
        'REVOKED'
      ],
      default: 'CREATED'
    },
    // Forensic Watermarking Metadata
    watermarkId: {
      type: String,
      default: null,
      index: true
    },
    watermarkCommitment: {
      type: String,
      default: null
    },
    // Canonical Signed Event Record
    canonicalEvent: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    eventDigest: {
      type: String,
      default: null
    },
    signature: {
      type: String, // ML-DSA signature in Base64
      default: null
    },
    signingKeyId: {
      type: String,
      default: null
    },
    // Distributed Ledger Transaction Reference
    ledgerTxId: {
      type: String,
      default: null
    },
    ledgerBlockNumber: {
      type: Number,
      default: null
    },
    // Temporal and Audit
    startedAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: {
      type: Date,
      required: true
    },
    failureReason: {
      type: String,
      default: null
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('DecryptionSession', decryptionSessionSchema);
