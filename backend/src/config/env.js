const dotenv = require('dotenv');
const cryptoService = require('../services/cryptoService');

dotenv.config();

// Ensure the server has an RSA keypair for legacy/server-level provenance logs
let serverPrivateKey = process.env.SERVER_PRIVATE_KEY
  ? process.env.SERVER_PRIVATE_KEY.replace(/\\n/g, '\n')
  : null;
let serverPublicKey = process.env.SERVER_PUBLIC_KEY
  ? process.env.SERVER_PUBLIC_KEY.replace(/\\n/g, '\n')
  : null;

if (!serverPrivateKey || !serverPublicKey) {
  const generated = cryptoService.generateKeyPair(2048);
  serverPrivateKey = generated.privateKey;
  serverPublicKey = generated.publicKey;
}

const env = {
  PORT: parseInt(process.env.PORT || '8000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  MONGODB_URI: process.env.MONGODB_URI || process.env.MONGODB_URL || 'mongodb://127.0.0.1:27017/sih237',
  JWT_SECRET: process.env.JWT_SECRET || 'dev_secret_sih26237_change_in_production_key_32chars',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  SERVER_PRIVATE_KEY: serverPrivateKey,
  SERVER_PUBLIC_KEY: serverPublicKey,
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  LOG_LEVEL: process.env.LOG_LEVEL || 'INFO',
  OFFLINE_MODE: process.env.OFFLINE_MODE !== 'false',

  // Watermark Service Interface
  WATERMARK_SERVICE_URL: process.env.WATERMARK_SERVICE_URL || 'http://127.0.0.1:8001',
  WATERMARK_TIMEOUT_MS: parseInt(process.env.WATERMARK_TIMEOUT_MS || '5000', 10),

  // Key Agent Interface (Private key boundary)
  KEY_AGENT_URL: process.env.KEY_AGENT_URL || 'http://127.0.0.1:8002',

  // Hyperledger Fabric Configuration
  FABRIC_ENABLED: process.env.FABRIC_ENABLED === 'true',
  FABRIC_CHANNEL: process.env.FABRIC_CHANNEL || 'provenance-channel',
  FABRIC_CHAINCODE: process.env.FABRIC_CHAINCODE || 'provenance',
  FABRIC_GATEWAY_PEER: process.env.FABRIC_GATEWAY_PEER || 'peer0.org1.example.com',
  FABRIC_MSP_ID: process.env.FABRIC_MSP_ID || 'Org1MSP',

  // Document Storage Vault
  ENCRYPTED_STORAGE_DIR: process.env.ENCRYPTED_STORAGE_DIR || './storage/encrypted'
};

module.exports = env;
