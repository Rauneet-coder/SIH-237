const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    password: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: [
        'sender',
        'recipient',
        'investigator',
        'admin',
        'auditor',
        'ADMIN',
        'DOCUMENT_OWNER',
        'RECIPIENT',
        'INVESTIGATOR',
        'AUDITOR'
      ],
      default: 'recipient'
    },
    // Legacy RSA-2048 Public Key (SPKI PEM)
    publicKey: {
      type: String,
      required: true
    },
    privateKeyReference: {
      type: String,
      default: null
    },
    // Post-Quantum NIST FIPS 203 & 204 Public Keys
    mlKemPublicKey: {
      type: String, // Base64 encoded ML-KEM-1024 Public Key
      default: null
    },
    mlDsaPublicKey: {
      type: String, // Base64 encoded ML-DSA-65 Public Key
      default: null
    },
    keyStatus: {
      type: String,
      enum: ['ACTIVE', 'REVOKED', 'SUSPENDED'],
      default: 'ACTIVE'
    },
    keyVersion: {
      type: String,
      default: '1.0'
    },
    // Registered Devices for Decryption Binding
    devices: [
      {
        deviceId: { type: String, required: true },
        deviceFingerprint: { type: String, required: true },
        trusted: { type: Boolean, default: true },
        lastSeenAt: { type: Date, default: Date.now }
      }
    ],
    isActive: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);

// Method to normalize role checking (case-insensitive)
userSchema.methods.hasRole = function (roleName) {
  return this.role.toUpperCase() === roleName.toUpperCase();
};

module.exports = mongoose.model('User', userSchema);
