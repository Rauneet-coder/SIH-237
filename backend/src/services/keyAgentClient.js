const pqcService = require('./pqcService');
const { CryptoError, AuthorizationError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Local Key Agent Boundary Simulation
 * In an air-gapped defence environment, this boundary represents a dedicated
 * Hardware Security Module (HSM) or isolated local daemon on the user workstation.
 *
 * CRITICAL SECURITY INVARIANT:
 * Private keys NEVER leave this boundary. The backend application receives only:
 * - Public keys (during registration)
 * - Decapsulated shared secrets (during authorized DEK recovery)
 * - Digital signatures (during canonical event signing)
 */

class KeyAgentStore {
  constructor() {
    // In-memory isolated vault representing secure key-agent enclave
    this._enclave = new Map();
  }

  /**
   * Provision a new recipient in the Key Agent
   * @param {string} recipientId
   * @returns {Promise<{ mlKemPublicKey: string, mlDsaPublicKey: string }>}
   */
  async provisionRecipient(recipientId) {
    const kemKeys = await pqcService.generateKemKeypair();
    const dsaKeys = await pqcService.generateDsaKeypair();

    this._enclave.set(recipientId, {
      recipientId,
      mlKemSecretKey: kemKeys.secretKey,
      mlKemPublicKey: kemKeys.publicKey,
      mlDsaSecretKey: dsaKeys.secretKey,
      mlDsaPublicKey: dsaKeys.publicKey,
      status: 'ACTIVE',
      provisionedAt: new Date().toISOString()
    });

    logger.securityAudit('KEY_AGENT_PROVISION', {
      recipientId,
      status: 'ACTIVE'
    });

    // Return strictly public keys
    return {
      mlKemPublicKey: kemKeys.publicKey,
      mlDsaPublicKey: dsaKeys.publicKey
    };
  }

  /**
   * Check if recipient keys exist and are active
   */
  hasRecipient(recipientId) {
    const entry = this._enclave.get(recipientId);
    return !!entry && entry.status === 'ACTIVE';
  }

  /**
   * Request ML-KEM decapsulation inside the Key Agent boundary
   * @param {string} recipientId
   * @param {string} kemCiphertext
   * @returns {Promise<string>} sharedSecret (Base64)
   */
  async decapsulate(recipientId, kemCiphertext) {
    const entry = this._enclave.get(recipientId);
    if (!entry) {
      throw new AuthorizationError(`Key Agent: no cryptographic credentials for ${recipientId}`);
    }
    if (entry.status !== 'ACTIVE') {
      throw new AuthorizationError(`Key Agent: keys for ${recipientId} are revoked or inactive`);
    }

    const result = await pqcService.decapsulate(kemCiphertext, entry.mlKemSecretKey);

    logger.securityAudit('KEY_AGENT_DECAPSULATE', {
      recipientId,
      result: 'SUCCESS'
    });

    return result.sharedSecret;
  }

  /**
   * Request ML-DSA digital signature inside the Key Agent boundary
   * @param {string} recipientId
   * @param {string|Buffer} canonicalDigest
   * @returns {Promise<string>} signature (Base64)
   */
  async sign(recipientId, canonicalDigest) {
    const entry = this._enclave.get(recipientId);
    if (!entry) {
      throw new AuthorizationError(`Key Agent: no cryptographic credentials for ${recipientId}`);
    }
    if (entry.status !== 'ACTIVE') {
      throw new AuthorizationError(`Key Agent: keys for ${recipientId} are revoked or inactive`);
    }

    const { signature } = await pqcService.sign(canonicalDigest, entry.mlDsaSecretKey);

    logger.securityAudit('KEY_AGENT_SIGN', {
      recipientId,
      digestPrefix: canonicalDigest.toString('hex').slice(0, 16)
    });

    return signature;
  }

  /**
   * Revoke recipient keys in Key Agent
   */
  revoke(recipientId) {
    const entry = this._enclave.get(recipientId);
    if (entry) {
      entry.status = 'REVOKED';
      logger.securityAudit('KEY_AGENT_REVOCATION', { recipientId });
    }
  }
}

// Global Key Agent client instance
const keyAgentClient = new KeyAgentStore();

module.exports = keyAgentClient;
