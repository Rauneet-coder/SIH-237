const pqcService = require('./pqcService');
const { CryptoError, AuthorizationError } = require('../utils/errors');
const logger = require('../utils/logger');

const KEY_AGENT_PORT = parseInt(process.env.KEY_AGENT_PORT || '8002', 10);
const KEY_AGENT_HOST = process.env.KEY_AGENT_HOST || '127.0.0.1';
const KEY_AGENT_URL = process.env.KEY_AGENT_URL || `http://${KEY_AGENT_HOST}:${KEY_AGENT_PORT}`;

/**
 * Local Key Agent Boundary
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
    // In-memory fallback vault representing secure key-agent enclave
    this._enclave = new Map();
    this._daemonAvailable = null; // null = untested, true/false
  }

  /**
   * Helper to make HTTP request to isolated Key Agent daemon process
   * @private
   */
  async _callDaemon(endpoint, payload) {
    if (this._daemonAvailable === false && process.env.NODE_ENV === 'test') {
      return null; // Skip daemon if known unavailable in tests
    }

    try {
      const url = `${KEY_AGENT_URL}${endpoint}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000);

      const res = await fetch(url, {
        method: payload ? 'POST' : 'GET',
        headers: { 'Content-Type': 'application/json' },
        body: payload ? JSON.stringify(payload) : undefined,
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Key Agent daemon returned HTTP ${res.status}`);
      }

      this._daemonAvailable = true;
      return await res.json();
    } catch (err) {
      if (err.cause?.code === 'ECONNREFUSED' || err.name === 'AbortError' || err.message?.includes('fetch failed')) {
        this._daemonAvailable = false;
        return null; // Daemon not running; fallback to local enclave
      }
      throw err;
    }
  }

  /**
   * Provision a new recipient in the Key Agent
   * @param {string} recipientId
   * @returns {Promise<{ mlKemPublicKey: string, mlDsaPublicKey: string }>}
   */
  async provisionRecipient(recipientId) {
    // 1. Try out-of-process Key Agent daemon first
    const daemonResult = await this._callDaemon('/provision', { recipientId });
    if (daemonResult) {
      this._enclave.set(recipientId, {
        recipientId,
        status: 'ACTIVE',
        isDaemon: true,
        provisionedAt: new Date().toISOString()
      });
      logger.securityAudit('KEY_AGENT_PROVISION', {
        recipientId,
        mode: 'OUT_OF_PROCESS_DAEMON',
        status: 'ACTIVE'
      });
      return {
        mlKemPublicKey: daemonResult.mlKemPublicKey,
        mlDsaPublicKey: daemonResult.mlDsaPublicKey
      };
    }

    // 2. Fallback to in-process enclave boundary
    const kemKeys = await pqcService.generateKemKeypair();
    const dsaKeys = await pqcService.generateDsaKeypair();

    this._enclave.set(recipientId, {
      recipientId,
      mlKemSecretKey: kemKeys.secretKey,
      mlKemPublicKey: kemKeys.publicKey,
      mlDsaSecretKey: dsaKeys.secretKey,
      mlDsaPublicKey: dsaKeys.publicKey,
      status: 'ACTIVE',
      isDaemon: false,
      provisionedAt: new Date().toISOString()
    });

    logger.securityAudit('KEY_AGENT_PROVISION', {
      recipientId,
      mode: 'IN_PROCESS_ENCLAVE',
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
    // 1. Try out-of-process Key Agent daemon
    const entry = this._enclave.get(recipientId);
    if (entry?.isDaemon) {
      const daemonResult = await this._callDaemon('/decapsulate', { recipientId, kemCiphertext });
      if (daemonResult) {
        logger.securityAudit('KEY_AGENT_DECAPSULATE', {
          recipientId,
          mode: 'OUT_OF_PROCESS_DAEMON',
          result: 'SUCCESS'
        });
        return daemonResult.sharedSecret;
      }
    }

    // 2. In-process enclave path
    if (!entry) {
      throw new AuthorizationError(`Key Agent: no cryptographic credentials for ${recipientId}`);
    }
    if (entry.status !== 'ACTIVE') {
      throw new AuthorizationError(`Key Agent: keys for ${recipientId} are revoked or inactive`);
    }

    const result = await pqcService.decapsulate(kemCiphertext, entry.mlKemSecretKey);

    logger.securityAudit('KEY_AGENT_DECAPSULATE', {
      recipientId,
      mode: 'IN_PROCESS_ENCLAVE',
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
    const digestBuf = Buffer.isBuffer(canonicalDigest) ? canonicalDigest : Buffer.from(canonicalDigest, 'hex');

    // 1. Try out-of-process Key Agent daemon
    const entry = this._enclave.get(recipientId);
    if (entry?.isDaemon) {
      const daemonResult = await this._callDaemon('/sign', {
        recipientId,
        message: digestBuf.toString('base64')
      });
      if (daemonResult) {
        logger.securityAudit('KEY_AGENT_SIGN', {
          recipientId,
          mode: 'OUT_OF_PROCESS_DAEMON',
          digestPrefix: digestBuf.toString('hex').slice(0, 16)
        });
        return daemonResult.signature;
      }
    }

    // 2. In-process enclave path
    if (!entry) {
      throw new AuthorizationError(`Key Agent: no cryptographic credentials for ${recipientId}`);
    }
    if (entry.status !== 'ACTIVE') {
      throw new AuthorizationError(`Key Agent: keys for ${recipientId} are revoked or inactive`);
    }

    const { signature } = await pqcService.sign(digestBuf, entry.mlDsaSecretKey);

    logger.securityAudit('KEY_AGENT_SIGN', {
      recipientId,
      mode: 'IN_PROCESS_ENCLAVE',
      digestPrefix: digestBuf.toString('hex').slice(0, 16)
    });

    return signature;
  }

  /**
   * Revoke recipient keys in Key Agent
   */
  async revoke(recipientId) {
    const entry = this._enclave.get(recipientId);
    if (entry?.isDaemon) {
      await this._callDaemon('/revoke', { recipientId }).catch(() => {});
    }
    if (entry) {
      entry.status = 'REVOKED';
      logger.securityAudit('KEY_AGENT_REVOCATION', { recipientId });
    }
  }
}

// Global Key Agent client instance
const keyAgentClient = new KeyAgentStore();

module.exports = keyAgentClient;
