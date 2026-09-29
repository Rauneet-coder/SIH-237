#!/usr/bin/env node

/**
 * SIH26237 — Key Agent Service
 * 
 * Isolated local daemon managing recipient ML-KEM-1024 and ML-DSA-65 private keys.
 * Implements the security boundary described in the HLD: private keys NEVER
 * leave this process. The backend communicates via authenticated HTTP API.
 * 
 * SECURITY INVARIANTS:
 * 1. This service exposes only:
 *    - Public keys (during provisioning / rotation)
 *    - Decapsulated shared secrets (during authorized DEK recovery)
 *    - Digital signatures (during canonical event signing)
 * 2. Recipient private keys are persisted exclusively in a protected local
 *    keystore encrypted with AES-256-GCM (POSIX mode 0600) and NEVER stored in
 *    the application database or shared with the backend.
 * 3. All operational endpoints require HMAC-SHA256 authenticated requests with
 *    freshness window (+/-60s), replay prevention (single-use nonces), and
 *    recipient/session binding.
 * 4. Provisioning is idempotent: existing recipient keys are NEVER silently overwritten.
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createCanonicalString, hashBody, verifyHmac } = require('./keyAgentAuth');

// Service configuration
const PORT = parseInt(process.env.KEY_AGENT_PORT || '8002', 10);
let hmacSecret = process.env.KEY_AGENT_HMAC_SECRET || 'dev_key_agent_hmac_secret_32bytes_sih237';
let keystoreDir = path.resolve(
  process.env.KEY_AGENT_KEYSTORE_PATH || path.join(__dirname, '../../storage/key-agent-keystore')
);

const MAX_BODY_BYTES = 1024 * 1024; // 1 MB limit
const TIMESTAMP_TOLERANCE_MS = 60 * 1000; // 60 seconds

// In-memory enclave cache
const enclave = new Map();

// Sliding window cache for replay protection: Map<nonce, expiryEpochMs>
const seenNonces = new Map();

let pqcService = null;
let masterKey = null;

/**
 * Clean up expired nonces from sliding replay cache
 */
function pruneExpiredNonces() {
  const now = Date.now();
  for (const [nonce, expiresAt] of seenNonces.entries()) {
    if (expiresAt <= now) {
      seenNonces.delete(nonce);
    }
  }
}

/**
 * Configure HMAC secret (useful for tests)
 */
function setHmacSecret(secret) {
  hmacSecret = secret;
}

/**
 * Configure keystore directory (useful for tests)
 */
function setKeystoreDir(dir) {
  keystoreDir = path.resolve(dir);
  masterKey = null;
}

/**
 * Reset in-memory enclave and nonces (useful for tests)
 */
function resetEnclave() {
  enclave.clear();
  seenNonces.clear();
}

/**
 * Ensure keystore directory and retrieve/create daemon master key (mode 0600)
 */
function getOrCreateMasterKey() {
  if (masterKey) return masterKey;

  if (!fs.existsSync(keystoreDir)) {
    fs.mkdirSync(keystoreDir, { recursive: true, mode: 0o700 });
  }

  const keyFilePath = path.join(keystoreDir, 'daemon.master.key');
  if (fs.existsSync(keyFilePath)) {
    masterKey = fs.readFileSync(keyFilePath);
    if (masterKey.length !== 32) {
      throw new Error(`Invalid daemon master key length: expected 32 bytes, got ${masterKey.length}`);
    }
  } else {
    masterKey = crypto.randomBytes(32);
    fs.writeFileSync(keyFilePath, masterKey, { mode: 0o600 });
    try {
      fs.chmodSync(keyFilePath, 0o600);
    } catch {
      // Best-effort chmod for cross-platform support
    }
  }

  return masterKey;
}

/**
 * Save current enclave to disk encrypted with AES-256-GCM
 */
function saveKeystore() {
  const mk = getOrCreateMasterKey();
  const plainObj = {};
  for (const [k, v] of enclave.entries()) {
    plainObj[k] = v;
  }

  const plaintext = Buffer.from(JSON.stringify(plainObj), 'utf8');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', mk, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope = {
    format: 'SIH237_KEYSTORE_AES256GCM_V1',
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    updatedAt: new Date().toISOString()
  };

  const finalPath = path.join(keystoreDir, 'keystore.enc');
  const tmpPath = `${finalPath}.${crypto.randomBytes(6).toString('hex')}.tmp`;

  fs.writeFileSync(tmpPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(tmpPath, 0o600);
  } catch {
    // Best-effort
  }
  fs.renameSync(tmpPath, finalPath);
}

/**
 * Load enclave from encrypted disk keystore if present
 */
function loadKeystore() {
  try {
    const mk = getOrCreateMasterKey();
    const filePath = path.join(keystoreDir, 'keystore.enc');
    if (!fs.existsSync(filePath)) {
      return 0;
    }

    const raw = fs.readFileSync(filePath, 'utf8');
    const envelope = JSON.parse(raw);
    if (envelope.format !== 'SIH237_KEYSTORE_AES256GCM_V1') {
      throw new Error(`Unsupported keystore envelope format: ${envelope.format}`);
    }

    const iv = Buffer.from(envelope.iv, 'hex');
    const tag = Buffer.from(envelope.tag, 'hex');
    const ciphertext = Buffer.from(envelope.ciphertext, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', mk, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const parsed = JSON.parse(plaintext.toString('utf8'));

    enclave.clear();
    for (const [recipientId, data] of Object.entries(parsed)) {
      enclave.set(recipientId, data);
    }

    return enclave.size;
  } catch (err) {
    console.error('[KeyAgent] Failed to load keystore from disk:', err.message);
    throw err;
  }
}

/**
 * Lazily load PQC modules
 */
async function getPqc() {
  if (!pqcService) {
    const kemMod = await import('@noble/post-quantum/ml-kem.js');
    const dsaMod = await import('@noble/post-quantum/ml-dsa.js');
    pqcService = {
      mlKem: kemMod.ml_kem1024,
      mlDsa: dsaMod.ml_dsa65
    };
  }
  return pqcService;
}

/**
 * Convert various input types to Uint8Array
 */
function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (Buffer.isBuffer(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof input === 'string') return new Uint8Array(Buffer.from(input, 'base64'));
  throw new Error('Invalid input type: expected Buffer, Uint8Array, or Base64 string');
}

/**
 * Read request body with size boundary enforcement
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytesReceived = 0;

    req.on('data', chunk => {
      bytesReceived += chunk.length;
      if (bytesReceived > MAX_BODY_BYTES) {
        req.destroy();
        const err = new Error('Payload too large: exceeds 1MB limit');
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf-8');
      try {
        const parsed = rawBody ? JSON.parse(rawBody) : {};
        resolve({ parsed, rawBody });
      } catch {
        const err = new Error('Invalid JSON body');
        err.statusCode = 400;
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

/**
 * Send JSON response helper
 */
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

/**
 * Route handlers
 */
const routes = {
  /**
   * POST /provision — Idempotently provision ML-KEM + ML-DSA keypairs
   * Existing active credentials are NEVER overwritten.
   */
  async provision(body) {
    const { recipientId } = body;
    if (!recipientId) throw new Error('recipientId is required');

    const existing = enclave.get(recipientId);
    if (existing) {
      if (existing.status === 'REVOKED' && !body.force) {
        const err = new Error(`Recipient ${recipientId} credentials are REVOKED; re-provisioning prohibited`);
        err.statusCode = 409;
        throw err;
      }

      // Idempotent: return existing active public keys
      return {
        recipientId,
        mlKemPublicKey: existing.mlKemPublicKey,
        mlDsaPublicKey: existing.mlDsaPublicKey,
        version: existing.version || 1,
        status: existing.status,
        alreadyExisted: true
      };
    }

    const { mlKem, mlDsa } = await getPqc();
    const kemKeys = mlKem.keygen();
    const dsaKeys = mlDsa.keygen();

    const record = {
      recipientId,
      mlKemSecretKey: Buffer.from(kemKeys.secretKey).toString('base64'),
      mlKemPublicKey: Buffer.from(kemKeys.publicKey).toString('base64'),
      mlDsaSecretKey: Buffer.from(dsaKeys.secretKey).toString('base64'),
      mlDsaPublicKey: Buffer.from(dsaKeys.publicKey).toString('base64'),
      version: 1,
      status: 'ACTIVE',
      provisionedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    enclave.set(recipientId, record);
    saveKeystore();

    return {
      recipientId,
      mlKemPublicKey: record.mlKemPublicKey,
      mlDsaPublicKey: record.mlDsaPublicKey,
      version: 1,
      status: 'ACTIVE',
      alreadyExisted: false
    };
  },

  /**
   * POST /rotate — Explicit key rotation for an existing recipient
   */
  async rotate(body) {
    const { recipientId } = body;
    if (!recipientId) throw new Error('recipientId is required');

    const existing = enclave.get(recipientId);
    if (!existing) {
      const err = new Error(`Cannot rotate keys: recipient ${recipientId} does not exist`);
      err.statusCode = 404;
      throw err;
    }
    if (existing.status === 'REVOKED') {
      const err = new Error(`Cannot rotate keys: recipient ${recipientId} is REVOKED`);
      err.statusCode = 400;
      throw err;
    }

    const { mlKem, mlDsa } = await getPqc();
    const kemKeys = mlKem.keygen();
    const dsaKeys = mlDsa.keygen();

    const newVersion = (existing.version || 1) + 1;
    existing.mlKemSecretKey = Buffer.from(kemKeys.secretKey).toString('base64');
    existing.mlKemPublicKey = Buffer.from(kemKeys.publicKey).toString('base64');
    existing.mlDsaSecretKey = Buffer.from(dsaKeys.secretKey).toString('base64');
    existing.mlDsaPublicKey = Buffer.from(dsaKeys.publicKey).toString('base64');
    existing.version = newVersion;
    existing.updatedAt = new Date().toISOString();

    saveKeystore();

    return {
      recipientId,
      mlKemPublicKey: existing.mlKemPublicKey,
      mlDsaPublicKey: existing.mlDsaPublicKey,
      version: newVersion,
      status: 'ACTIVE'
    };
  },

  /**
   * POST /decapsulate — ML-KEM decapsulation bound to session/document context
   */
  async decapsulate(body) {
    const { recipientId, kemCiphertext, sessionId, documentId } = body;
    if (!recipientId) throw new Error('recipientId is required');
    if (!kemCiphertext) throw new Error('kemCiphertext is required');

    const entry = enclave.get(recipientId);
    if (!entry) {
      const err = new Error(`No credentials for: ${recipientId}`);
      err.statusCode = 404;
      throw err;
    }
    if (entry.status !== 'ACTIVE') {
      const err = new Error(`Keys for ${recipientId} are ${entry.status}`);
      err.statusCode = 403;
      throw err;
    }

    const { mlKem } = await getPqc();
    const ctBytes = toUint8Array(kemCiphertext);
    const skBytes = toUint8Array(entry.mlKemSecretKey);
    const sharedSecret = mlKem.decapsulate(ctBytes, skBytes);

    return {
      sharedSecret: Buffer.from(sharedSecret).toString('base64'),
      recipientId,
      sessionId: sessionId || null,
      documentId: documentId || null
    };
  },

  /**
   * POST /sign — ML-DSA signing bound to session/document context
   */
  async sign(body) {
    const { recipientId, message, sessionId, documentId, context } = body;
    if (!recipientId) throw new Error('recipientId is required');
    if (!message) throw new Error('message is required');

    const entry = enclave.get(recipientId);
    if (!entry) {
      const err = new Error(`No credentials for: ${recipientId}`);
      err.statusCode = 404;
      throw err;
    }
    if (entry.status !== 'ACTIVE') {
      const err = new Error(`Keys for ${recipientId} are ${entry.status}`);
      err.statusCode = 403;
      throw err;
    }

    const { mlDsa } = await getPqc();
    const msgBytes = toUint8Array(message);
    const skBytes = toUint8Array(entry.mlDsaSecretKey);
    const signature = mlDsa.sign(msgBytes, skBytes);

    return {
      signature: Buffer.from(signature).toString('base64'),
      recipientId,
      sessionId: sessionId || null,
      documentId: documentId || null,
      context: context || null
    };
  },

  /**
   * POST /revoke — Mark recipient keys as REVOKED (preserved on disk for audit)
   */
  async revoke(body) {
    const { recipientId, reason } = body;
    if (!recipientId) throw new Error('recipientId is required');

    const entry = enclave.get(recipientId);
    if (entry) {
      entry.status = 'REVOKED';
      entry.revokedAt = new Date().toISOString();
      entry.revocationReason = reason || 'Unspecified';
      saveKeystore();
      return { recipientId, status: 'REVOKED', revokedAt: entry.revokedAt };
    }

    const err = new Error(`Recipient ${recipientId} not found`);
    err.statusCode = 404;
    throw err;
  },

  /**
   * GET /has — Check recipient presence and active status
   */
  async has(body) {
    const { recipientId } = body;
    const entry = enclave.get(recipientId);
    return {
      recipientId,
      exists: !!entry && entry.status === 'ACTIVE',
      status: entry ? entry.status : 'NOT_FOUND',
      version: entry ? entry.version : null
    };
  },

  /**
   * GET /health — Service health check
   */
  async health() {
    return {
      status: 'ok',
      service: 'SIH26237-KeyAgent',
      enclaveSize: enclave.size,
      keystoreEncrypted: true,
      timestamp: new Date().toISOString()
    };
  }
};

/**
 * HTTP server request handler with strict HMAC verification and replay protection
 */
async function handler(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathName = url.pathname.replace(/\/$/, '') || '/';

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Key-Agent-Auth, X-Key-Agent-Timestamp, X-Key-Agent-Nonce, X-Key-Agent-Recipient');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health endpoint is public
  if (pathName === '/health' && req.method === 'GET') {
    const healthData = await routes.health();
    sendJson(res, 200, healthData);
    return;
  }

  try {
    // 1. Read body and enforce size bounds
    let parsedBody = {};
    let rawBody = '';

    if (req.method === 'POST') {
      const readResult = await readBody(req);
      parsedBody = readResult.parsed;
      rawBody = readResult.rawBody;
    } else if (req.method === 'GET' && url.searchParams.has('recipientId')) {
      parsedBody = { recipientId: url.searchParams.get('recipientId') };
    }

    // 2. Authenticate sensitive endpoints
    const authHeader = req.headers['x-key-agent-auth'];
    const timestampHeader = req.headers['x-key-agent-timestamp'];
    const nonceHeader = req.headers['x-key-agent-nonce'];
    const recipientHeader = req.headers['x-key-agent-recipient'];

    if (!authHeader || !timestampHeader || !nonceHeader) {
      sendJson(res, 401, {
        error: 'Missing required authentication headers (X-Key-Agent-Auth, X-Key-Agent-Timestamp, X-Key-Agent-Nonce)'
      });
      return;
    }

    // 3. Verify timestamp freshness
    const now = Date.now();
    const reqTimestamp = typeof timestampHeader === 'number'
      ? timestampHeader
      : Date.parse(timestampHeader);

    if (isNaN(reqTimestamp) || Math.abs(now - reqTimestamp) > TIMESTAMP_TOLERANCE_MS) {
      sendJson(res, 401, {
        error: `Request expired or timestamp skewed (> ${TIMESTAMP_TOLERANCE_MS / 1000}s)`
      });
      return;
    }

    // 4. Replay protection
    pruneExpiredNonces();
    if (seenNonces.has(nonceHeader)) {
      sendJson(res, 401, { error: 'Replay detected: nonce has already been consumed' });
      return;
    }
    seenNonces.set(nonceHeader, now + TIMESTAMP_TOLERANCE_MS + 5000);

    // 5. Verify HMAC
    const bodyHash = hashBody(rawBody);
    const canonicalString = createCanonicalString({
      method: req.method,
      path: pathName,
      recipientId: recipientHeader || '',
      timestamp: timestampHeader,
      nonce: nonceHeader,
      bodyHash
    });

    const isHmacValid = verifyHmac(hmacSecret, canonicalString, authHeader);
    if (!isHmacValid) {
      sendJson(res, 401, { error: 'Invalid HMAC signature or body hash mismatch' });
      return;
    }

    // 6. Verify recipient binding
    if (parsedBody.recipientId && recipientHeader && parsedBody.recipientId !== recipientHeader) {
      sendJson(res, 403, {
        error: `Recipient mismatch: header (${recipientHeader}) does not match payload (${parsedBody.recipientId})`
      });
      return;
    }

    // 7. Route dispatch
    let result;
    switch (pathName) {
      case '/provision':
        result = await routes.provision(parsedBody);
        break;
      case '/rotate':
        result = await routes.rotate(parsedBody);
        break;
      case '/decapsulate':
        result = await routes.decapsulate(parsedBody);
        break;
      case '/sign':
        result = await routes.sign(parsedBody);
        break;
      case '/revoke':
        result = await routes.revoke(parsedBody);
        break;
      case '/has':
        result = await routes.has(parsedBody);
        break;
      default:
        sendJson(res, 404, { error: `Unknown endpoint: ${pathName}` });
        return;
    }

    sendJson(res, 200, result);
  } catch (err) {
    const status = err.statusCode || 400;
    sendJson(res, status, { error: err.message });
  }
}

// Create HTTP server
const server = http.createServer(handler);

// Auto-start if invoked directly
if (require.main === module) {
  try {
    loadKeystore();
    console.log(`[KeyAgent] Loaded ${enclave.size} recipient keys from encrypted persistent keystore`);
  } catch (err) {
    console.warn(`[KeyAgent] Initializing fresh keystore at: ${keystoreDir}`);
  }

  server.listen(PORT, '127.0.0.1', async () => {
    await getPqc();
    console.log(`[KeyAgent] 🔐 Key Agent Service running on http://127.0.0.1:${PORT}`);
    console.log(`[KeyAgent] Keystore persistence: AES-256-GCM in ${keystoreDir}`);
    console.log(`[KeyAgent] Authentication: HMAC-SHA256 required on all operational endpoints`);
  });
}

module.exports = {
  server,
  enclave,
  routes,
  handler,
  getPqc,
  loadKeystore,
  saveKeystore,
  resetEnclave,
  setKeystoreDir,
  setHmacSecret,
  seenNonces
};
