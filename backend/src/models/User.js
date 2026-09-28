'use strict';

const mongoose = require('mongoose');

const VALID_ROLES = [
  'RECIPIENT',
  'SENDER',
  'INVESTIGATOR',
  'ADMIN',
  'AUDITOR',
  'DOCUMENT_OWNER',
  // Backward compatibility aliases
  'recipient',
  'sender',
  'investigator',
  'admin',
  'auditor'
];

const VALID_CLEARANCES = [
  'UNCLASSIFIED',
  'RESTRICTED',
  'CONFIDENTIAL',
  'SECRET',
  'TOP_SECRET'
];

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
      enum: VALID_ROLES,
      default: 'RECIPIENT'
    },
    // Security Clearance Level for ABAC Policy Enforcement (Default: Least Privilege)
    clearance: {
      type: String,
      enum: VALID_CLEARANCES,
      default: 'RESTRICTED'
    },
    // Audit metadata for clearance changes
    clearanceHistory: [
      {
        previousClearance: String,
        newClearance: String,
        changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        reason: String,
        changedAt: { type: Date, default: Date.now }
      }
    ],
    // Legacy RSA-2048 Public Key (SPKI PEM)
    publicKey: {
      type: String,
      required: false,
      default: null
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
        status: { type: String, enum: ['ACTIVE', 'SUSPENDED', 'REVOKED'], default: 'ACTIVE' },
        enrolledAt: { type: Date, default: Date.now },
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

// Pre-save hook: Normalize roles and clearances to uppercase canonical representations
userSchema.pre('save', function (next) {
  if (this.role) {
    this.role = this.role.toUpperCase();
  }
  if (this.clearance) {
    this.clearance = this.clearance.toUpperCase();
  }
  next();
});

// Method to normalize role checking (case-insensitive)
userSchema.methods.hasRole = function (roleName) {
  if (!this.role || !roleName) return false;
  const current = this.role.toUpperCase();
  const target = roleName.toUpperCase();
  if (current === target) return true;
  if (target === 'DOCUMENT_OWNER' && current === 'SENDER') return true;
  if (target === 'SENDER' && current === 'DOCUMENT_OWNER') return true;
  return false;
};

module.exports = mongoose.model('User', userSchema);
