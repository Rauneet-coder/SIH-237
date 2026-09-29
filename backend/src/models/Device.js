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

// A workstation can be enrolled independently for multiple authenticated users.
deviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

module.exports = mongoose.model('Device', deviceSchema);
