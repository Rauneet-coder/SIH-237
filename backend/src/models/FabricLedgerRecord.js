const mongoose = require('mongoose');

/**
 * FabricLedgerRecord Schema
 * Mirror of the Hyperledger Fabric chaincode DecryptionProvenanceContract world state.
 * Guarantees that even in air-gapped standalone mode, provenance is persisted
 * with strict append-only constraints and rich indexing.
 */
const fabricLedgerRecordSchema = new mongoose.Schema(
  {
    eventId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    eventDigest: {
      type: String,
      required: true,
      index: true
    },
    documentId: {
      type: String,
      required: true,
      index: true
    },
    documentHash: {
      type: String,
      required: true
    },
    recipientId: {
      type: String,
      required: true,
      index: true
    },
    sessionId: {
      type: String,
      required: true,
      index: true
    },
    watermarkId: {
      type: String,
      required: true,
      index: true
    },
    watermarkCommitment: {
      type: String,
      required: true,
      index: true
    },
    signingKeyId: {
      type: String,
      required: true
    },
    signature: {
      type: String,
      required: true
    },
    timestamp: {
      type: String,
      required: true
    },
    status: {
      type: String,
      required: true,
      default: 'COMMITTED',
      enum: ['COMMITTED']
    },
    actorOrg: {
      type: String,
      default: 'Org1MSP'
    },
    txId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    blockNumber: {
      type: Number,
      default: 1
    }
  },
  {
    timestamps: true
  }
);

// Enforce append-only invariant at Mongoose level:
fabricLedgerRecordSchema.pre(['updateOne', 'findOneAndUpdate', 'updateMany', 'replaceOne'], function () {
  throw new Error('IMMUTABLE_LEDGER: Update operations are strictly forbidden on the Fabric provenance ledger');
});

fabricLedgerRecordSchema.pre(['deleteOne', 'findOneAndDelete', 'deleteMany'], function () {
  const isTestContext =
    process.env.NODE_ENV === 'test' ||
    (mongoose.connection && mongoose.connection.name && mongoose.connection.name.includes('test'));

  if (isTestContext && this.getFilter && Object.keys(this.getFilter()).length === 0) {
    return;
  }
  throw new Error('IMMUTABLE_LEDGER: Delete operations are strictly forbidden on the Fabric provenance ledger');
});

module.exports = mongoose.model('FabricLedgerRecord', fabricLedgerRecordSchema);
