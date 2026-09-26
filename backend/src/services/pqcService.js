const { CryptoError, KeyEnvelopeError } = require('../utils/errors');
const logger = require('../utils/logger');

let mlKemInstance = null;
let mlDsaInstance = null;

/**
 * Lazily load @noble/post-quantum ES modules in CommonJS
 */
async function getPqcModules() {
  if (!mlKemInstance || !mlDsaInstance) {
    try {
      const kemMod = await import('@noble/post-quantum/ml-kem.js');
      const dsaMod = await import('@noble/post-quantum/ml-dsa.js');
      mlKemInstance = kemMod.ml_kem1024;
      mlDsaInstance = dsaMod.ml_dsa65;
    } catch (err) {
      logger.error('Failed to load NIST Post-Quantum Cryptography modules', { error: err.message });
      throw new CryptoError(`PQC module initialization failed: ${err.message}`);
    }
  }
  return { mlKem: mlKemInstance, mlDsa: mlDsaInstance };
}

/**
 * Convert Buffer, ArrayBuffer, or Base64 string to Uint8Array
 */
function toUint8Array(input, name = 'input') {
  if (input instanceof Uint8Array) {
    return input;
  }
  if (Buffer.isBuffer(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (typeof input === 'string') {
    return new Uint8Array(Buffer.from(input, 'base64'));
  }
  throw new CryptoError(`Invalid input type for ${name}: expected Buffer, Uint8Array, or Base64 string`);
}

/**
 * Post-Quantum Cryptographic Service for SIH-237
 * Conforms strictly to NIST FIPS 203 (ML-KEM-1024) and FIPS 204 (ML-DSA-65)
 */
const pqcService = {
  /**
   * Pre-warm PQC cryptographic module loading
   */
  async init() {
    await getPqcModules();
    logger.info('NIST Post-Quantum Cryptography (ML-KEM-1024 & ML-DSA-65) initialized');
  },

  /**
   * Generate an ML-KEM-1024 keypair for key encapsulation
   * @returns {Promise<{ publicKey: string, secretKey: string, publicKeyBytes: Buffer, secretKeyBytes: Buffer }>}
   */
  async generateKemKeypair() {
    try {
      const { mlKem } = await getPqcModules();
      const keys = mlKem.keygen();
      return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        secretKey: Buffer.from(keys.secretKey).toString('base64'),
        publicKeyBytes: Buffer.from(keys.publicKey),
        secretKeyBytes: Buffer.from(keys.secretKey)
      };
    } catch (err) {
      throw new CryptoError(`ML-KEM key generation failed: ${err.message}`);
    }
  },

  /**
   * Encapsulate shared secret using recipient's ML-KEM public key
   * @param {string|Buffer|Uint8Array} recipientPublicKey
   * @returns {Promise<{ cipherText: string, sharedSecret: string, cipherTextBytes: Buffer, sharedSecretBytes: Buffer }>}
   */
  async encapsulate(recipientPublicKey) {
    try {
      const { mlKem } = await getPqcModules();
      const pkBytes = toUint8Array(recipientPublicKey, 'recipientPublicKey');
      const { cipherText, sharedSecret } = mlKem.encapsulate(pkBytes);
      return {
        cipherText: Buffer.from(cipherText).toString('base64'),
        sharedSecret: Buffer.from(sharedSecret).toString('base64'),
        cipherTextBytes: Buffer.from(cipherText),
        sharedSecretBytes: Buffer.from(sharedSecret)
      };
    } catch (err) {
      throw new KeyEnvelopeError(`ML-KEM encapsulation failed: ${err.message}`);
    }
  },

  /**
   * Decapsulate shared secret using recipient's ML-KEM secret key
   * (Invoked inside Key Agent boundary)
   * @param {string|Buffer|Uint8Array} cipherText
   * @param {string|Buffer|Uint8Array} secretKey
   * @returns {Promise<{ sharedSecret: string, sharedSecretBytes: Buffer }>}
   */
  async decapsulate(cipherText, secretKey) {
    try {
      const { mlKem } = await getPqcModules();
      const ctBytes = toUint8Array(cipherText, 'cipherText');
      const skBytes = toUint8Array(secretKey, 'secretKey');
      const sharedSecret = mlKem.decapsulate(ctBytes, skBytes);
      return {
        sharedSecret: Buffer.from(sharedSecret).toString('base64'),
        sharedSecretBytes: Buffer.from(sharedSecret)
      };
    } catch (err) {
      throw new KeyEnvelopeError(`ML-KEM decapsulation failed: ${err.message}`);
    }
  },

  /**
   * Generate an ML-DSA-65 keypair for digital signatures
   * @returns {Promise<{ publicKey: string, secretKey: string, publicKeyBytes: Buffer, secretKeyBytes: Buffer }>}
   */
  async generateDsaKeypair() {
    try {
      const { mlDsa } = await getPqcModules();
      const keys = mlDsa.keygen();
      return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        secretKey: Buffer.from(keys.secretKey).toString('base64'),
        publicKeyBytes: Buffer.from(keys.publicKey),
        secretKeyBytes: Buffer.from(keys.secretKey)
      };
    } catch (err) {
      throw new CryptoError(`ML-DSA key generation failed: ${err.message}`);
    }
  },

  /**
   * Sign message/digest using recipient's ML-DSA private key
   * (Invoked inside Key Agent boundary)
   * @param {string|Buffer|Uint8Array} message
   * @param {string|Buffer|Uint8Array} secretKey
   * @returns {Promise<{ signature: string, signatureBytes: Buffer }>}
   */
  async sign(message, secretKey) {
    try {
      const { mlDsa } = await getPqcModules();
      const msgBytes = toUint8Array(message, 'message');
      const skBytes = toUint8Array(secretKey, 'secretKey');
      const signature = mlDsa.sign(msgBytes, skBytes);
      return {
        signature: Buffer.from(signature).toString('base64'),
        signatureBytes: Buffer.from(signature)
      };
    } catch (err) {
      throw new CryptoError(`ML-DSA signing failed: ${err.message}`);
    }
  },

  /**
   * Verify ML-DSA digital signature
   * @param {string|Buffer|Uint8Array} signature
   * @param {string|Buffer|Uint8Array} message
   * @param {string|Buffer|Uint8Array} publicKey
   * @returns {Promise<boolean>}
   */
  async verify(signature, message, publicKey) {
    try {
      const { mlDsa } = await getPqcModules();
      const sigBytes = toUint8Array(signature, 'signature');
      const msgBytes = toUint8Array(message, 'message');
      const pkBytes = toUint8Array(publicKey, 'publicKey');
      return mlDsa.verify(sigBytes, msgBytes, pkBytes);
    } catch (err) {
      logger.warn('ML-DSA verification threw error (treating as invalid)', { error: err.message });
      return false;
    }
  }
};

module.exports = pqcService;
