const dotenv = require('dotenv');
const cryptoService = require('../services/cryptoService');

dotenv.config();

// Ensure the server has an RSA keypair for signing provenance logs
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
  PORT: process.env.PORT || 8000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  MONGODB_URI: process.env.MONGODB_URI || process.env.MONGODB_URL || 'mongodb://127.0.0.1:27017/sih237',
  JWT_SECRET: process.env.JWT_SECRET || 'dev_secret_sih26237_change_in_production_key_32chars',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
  SERVER_PRIVATE_KEY: serverPrivateKey,
  SERVER_PUBLIC_KEY: serverPublicKey,
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*'
};

module.exports = env;
