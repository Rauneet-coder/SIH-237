const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    deviceId: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    deviceFingerprint: {
      type: String,
      required: true
    },
    platform: {
      type: String,
      default: 'Unknown'
    },
    status: {
      type: String,
      enum: ['ACTIVE', 'SUSPENDED', 'REVOKED'],
      default: 'ACTIVE'
    },
    lastSeenAt: {
      type: Date,
      default: Date.now
    },
    ipAddress: {
      type: String,
      default: null
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Device', deviceSchema);
