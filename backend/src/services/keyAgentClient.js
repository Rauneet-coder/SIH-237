'use strict';

const crypto = require('node:crypto');
const pqcService = require('./pqcService');
const env = require('../config/env');
const { CryptoError, AuthorizationError } = require('../utils/errors');
const logger = require('../utils/logger');
const { createCanonicalString, hashBody, generateHmac } = require('./keyAgentAuth');

const KEY_AGENT_URL = env.KEY_AGENT_URL || 'http://127.0.0.1:8002';
const KEY_AGENT_HMAC_SECRET = env.KEY_AGENT_HMAC_SECRET || 'dev_key_agent_hmac_secret_32bytes_sih237';
const KEY_AGENT_SECURE_MODE = env.KEY_AGENT_SECURE_MODE;

/**
 * Local Key Agent Boundary Client
 * In an air-gapped defence environment, this boundary represents a dedicated
 * Hardware Security Module (HSM) or isolated local daemon on the user workstation.
 *
 * CRITICAL SECURITY INVARIANT:
 * Private keys NEVER leave the Key Agent process. The backend application receives only:
 * - Public keys (during registration / rotation)
 * - Decapsulated shared secrets (during authorized DEK recovery)
 * - Digital signatures (during canonical event signing)
 */
class KeyAgentStore {
  constructor() {
    // In-memory registry tracking recipient metadata and fallback enclave
    this._enclave = new Map();
    this._daemonAvailable = null; // null = untested, true/false
  }

  /**
   * Helper to make authenticated HTTP request to isolated Key Agent daemon process
   * @private
   */
  async _callDaemon(endpoint, payload, recipientId = '') {
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const method = payload ? 'POST' : 'GET';
    const bodyStr = payload ? JSON.stringify(payload) : '';
    const bodyHash = hashBody(bodyStr);

    const canonicalString = createCanonicalString({
      method,
      path: endpoint,
      recipientId,
      timestamp,
      nonce,
      bodyHash
    });

    const hmacSig = generateHmac(KEY_AGENT_HMAC_SECRET, canonicalString);

    try {
      const url = `${KEY_AGENT_URL}${endpoint}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Key-Agent-Auth': hmacSig,
          'X-Key-Agent-Timestamp': timestamp,
          'X-Key-Agent-Nonce': nonce,
          'X-Key-Agent-Recipient': recipientId
        },
        body: payload ? bodyStr : undefined,
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
      const isConnectionIssue =
        err.cause?.code === 'ECONNREFUSED' ||
        err.name === 'AbortError' ||
        err.message?.includes('fetch failed');

      if (isConnectionIssue) {
        this._daemonAvailable = false;
        if (KEY_AGENT_SECURE_MODE) {
          throw new CryptoError(
            `Key Agent daemon is unreachable on ${KEY_AGENT_URL}. In secure mode, in-process key fallback is disabled.`
          );
        }
        return null; // Fallback to local enclave only in insecure development mode
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
    const daemonResult = await this._callDaemon('/provision', { recipientId }, recipientId);
    if (daemonResult) {
      this._enclave.set(recipientId, {
        recipientId,
        status: daemonResult.status || 'ACTIVE',
        isDaemon: true,
        mlKemPublicKey: daemonResult.mlKemPublicKey,
        mlDsaPublicKey: daemonResult.mlDsaPublicKey,
        version: daemonResult.version || 1,
        provisionedAt: new Date().toISOString()
      });
      logger.securityAudit('KEY_AGENT_PROVISION', {
        recipientId,
        mode: 'OUT_OF_PROCESS_DAEMON',
        status: 'ACTIVE',
        alreadyExisted: !!daemonResult.alreadyExisted
      });
      return {
        mlKemPublicKey: daemonResult.mlKemPublicKey,
        mlDsaPublicKey: daemonResult.mlDsaPublicKey
      };
    }

    // 2. In-process enclave boundary (allowed only when secure mode is explicitly false)
    if (KEY_AGENT_SECURE_MODE) {
      throw new CryptoError('Key Agent daemon unavailable; in-process key fallback is disabled in secure mode.');
    }

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
   * Check if recipient keys exist and are active in client cache
   * Synchronous for compatibility with callers
   */
  hasRecipient(recipientId) {
    const entry = this._enclave.get(recipientId);
    return Boolean(entry && entry.status === 'ACTIVE');
  }

  /**
   * Check daemon if not in local cache (async)
   */
  async checkRecipientActive(recipientId) {
    const entry = this._enclave.get(recipientId);
    if (entry && entry.status === 'ACTIVE') return true;

    try {
      const daemonResult = await this._callDaemon('/has', { recipientId }, recipientId);
      if (daemonResult && daemonResult.exists) {
        this._enclave.set(recipientId, {
          recipientId,
          status: 'ACTIVE',
          isDaemon: true
        });
        return true;
      }
    } catch {
      // Best-effort check
    }

    return false;
  }

  /**
   * Request ML-KEM decapsulation inside the Key Agent boundary
   * @param {string} recipientId
   * @param {string} kemCiphertext
   * @param {string} [sessionId]
   * @param {string} [documentId]
   * @returns {Promise<string>} sharedSecret (Base64)
   */
  async decapsulate(recipientId, kemCiphertext, sessionId = null, documentId = null) {
    const entry = this._enclave.get(recipientId);

    // 1. Try out-of-process Key Agent daemon
    if (entry?.isDaemon || this._daemonAvailable !== false) {
      const daemonResult = await this._callDaemon(
        '/decapsulate',
        { recipientId, kemCiphertext, sessionId, documentId },
        recipientId
      );
      if (daemonResult) {
        logger.securityAudit('KEY_AGENT_DECAPSULATE', {
          recipientId,
          mode: 'OUT_OF_PROCESS_DAEMON',
          sessionId,
          documentId,
          result: 'SUCCESS'
        });
        return daemonResult.sharedSecret;
      }
    }

    // 2. In-process enclave path (insecure development only)
    if (KEY_AGENT_SECURE_MODE) {
      throw new AuthorizationError(`Key Agent daemon required in secure mode for ${recipientId}`);
    }
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
      sessionId,
      documentId,
      result: 'SUCCESS'
    });

    return result.sharedSecret;
  }

  /**
   * Request ML-DSA digital signature inside the Key Agent boundary
   * @param {string} recipientId
   * @param {string|Buffer} canonicalDigest
   * @param {string} [sessionId]
   * @param {string} [documentId]
   * @param {string} [context]
   * @returns {Promise<string>} signature (Base64)
   */
  async sign(recipientId, canonicalDigest, sessionId = null, documentId = null, context = null) {
    const digestBuf = Buffer.isBuffer(canonicalDigest) ? canonicalDigest : Buffer.from(canonicalDigest, 'hex');
    const entry = this._enclave.get(recipientId);

    // 1. Try out-of-process Key Agent daemon
    if (entry?.isDaemon || this._daemonAvailable !== false) {
      const daemonResult = await this._callDaemon(
        '/sign',
        {
          recipientId,
          message: digestBuf.toString('base64'),
          sessionId,
          documentId,
          context
        },
        recipientId
      );
      if (daemonResult) {
        logger.securityAudit('KEY_AGENT_SIGN', {
          recipientId,
          mode: 'OUT_OF_PROCESS_DAEMON',
          sessionId,
          documentId,
          digestPrefix: digestBuf.toString('hex').slice(0, 16)
        });
        return daemonResult.signature;
      }
    }

    // 2. In-process enclave path (insecure development only)
    if (KEY_AGENT_SECURE_MODE) {
      throw new AuthorizationError(`Key Agent daemon required in secure mode for ${recipientId}`);
    }
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
      sessionId,
      documentId,
      digestPrefix: digestBuf.toString('hex').slice(0, 16)
    });

    return signature;
  }

  /**
   * Rotate recipient keys in Key Agent
   */
  async rotate(recipientId) {
    const entry = this._enclave.get(recipientId);
    if (entry?.isDaemon || this._daemonAvailable !== false) {
      const result = await this._callDaemon('/rotate', { recipientId }, recipientId);
      if (result) {
        entry.mlKemPublicKey = result.mlKemPublicKey;
        entry.mlDsaPublicKey = result.mlDsaPublicKey;
        entry.version = result.version;
        logger.securityAudit('KEY_AGENT_ROTATION', { recipientId, version: result.version });
        return result;
      }
    }
    throw new CryptoError(`Key rotation unavailable for ${recipientId}`);
  }

  /**
   * Revoke recipient keys in Key Agent
   */
  async revoke(recipientId, reason = 'Unspecified') {
    const entry = this._enclave.get(recipientId);
    if (entry?.isDaemon || this._daemonAvailable !== false) {
      await this._callDaemon('/revoke', { recipientId, reason }, recipientId).catch(() => {});
    }
    if (entry) {
      entry.status = 'REVOKED';
      logger.securityAudit('KEY_AGENT_REVOCATION', { recipientId, reason });
    }
  }
}

// Global Key Agent client instance
const keyAgentClient = new KeyAgentStore();

module.exports = keyAgentClient;
