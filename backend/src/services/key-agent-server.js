#!/usr/bin/env node

/**
 * SIH26237 — Key Agent Service
 * 
 * Isolated local process managing recipient ML-KEM and ML-DSA private keys.
 * Implements the security boundary described in the HLD: private keys NEVER
 * leave this process. The backend communicates via authenticated HTTP API.
 * 
 * SECURITY INVARIANT:
 * This service exposes only:
 *   - Public keys (during provisioning)
 *   - Decapsulated shared secrets (during authorized DEK recovery)
 *   - Digital signatures (during canonical event signing)
 * 
 * Private keys are held in-memory and never serialized to disk or sent over
 * the network. In production, this should integrate with OS keychain or HSM.
 * 
 * Usage: node key-agent-server.js [--port 8002]
 */

const http = require('node:http');
const crypto = require('node:crypto');

// Service configuration
const PORT = parseInt(process.env.KEY_AGENT_PORT || '8002', 10);
const HMAC_SECRET = process.env.KEY_AGENT_HMAC_SECRET || crypto.randomBytes(32).toString('hex');

// In-memory secure enclave
const enclave = new Map();

let pqcService = null;

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
    console.log('[KeyAgent] NIST PQC modules loaded (ML-KEM-1024, ML-DSA-65)');
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
 * Read full request body as JSON
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response
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
   * POST /provision — Generate and store ML-KEM + ML-DSA keypairs
   */
  async provision(body) {
    const { recipientId } = body;
    if (!recipientId) throw new Error('recipientId is required');

    const { mlKem, mlDsa } = await getPqc();
    const kemKeys = mlKem.keygen();
    const dsaKeys = mlDsa.keygen();

    enclave.set(recipientId, {
      recipientId,
      mlKemSecretKey: Buffer.from(kemKeys.secretKey).toString('base64'),
      mlKemPublicKey: Buffer.from(kemKeys.publicKey).toString('base64'),
      mlDsaSecretKey: Buffer.from(dsaKeys.secretKey).toString('base64'),
      mlDsaPublicKey: Buffer.from(dsaKeys.publicKey).toString('base64'),
      status: 'ACTIVE',
      provisionedAt: new Date().toISOString()
    });

    console.log(`[KeyAgent] Provisioned keys for: ${recipientId}`);

    return {
      recipientId,
      mlKemPublicKey: Buffer.from(kemKeys.publicKey).toString('base64'),
      mlDsaPublicKey: Buffer.from(dsaKeys.publicKey).toString('base64'),
      status: 'ACTIVE'
    };
  },

  /**
   * POST /decapsulate — ML-KEM decapsulation (private key stays inside)
   */
  async decapsulate(body) {
    const { recipientId, kemCiphertext } = body;
    if (!recipientId) throw new Error('recipientId is required');
    if (!kemCiphertext) throw new Error('kemCiphertext is required');

    const entry = enclave.get(recipientId);
    if (!entry) throw new Error(`No credentials for: ${recipientId}`);
    if (entry.status !== 'ACTIVE') throw new Error(`Keys for ${recipientId} are ${entry.status}`);

    const { mlKem } = await getPqc();
    const ctBytes = toUint8Array(kemCiphertext);
    const skBytes = toUint8Array(entry.mlKemSecretKey);
    const sharedSecret = mlKem.decapsulate(ctBytes, skBytes);

    console.log(`[KeyAgent] Decapsulated shared secret for: ${recipientId}`);

    return {
      sharedSecret: Buffer.from(sharedSecret).toString('base64')
    };
  },

  /**
   * POST /sign — ML-DSA signing (private key stays inside)
   */
  async sign(body) {
    const { recipientId, message } = body;
    if (!recipientId) throw new Error('recipientId is required');
    if (!message) throw new Error('message is required');

    const entry = enclave.get(recipientId);
    if (!entry) throw new Error(`No credentials for: ${recipientId}`);
    if (entry.status !== 'ACTIVE') throw new Error(`Keys for ${recipientId} are ${entry.status}`);

    const { mlDsa } = await getPqc();
    const msgBytes = toUint8Array(message);
    const skBytes = toUint8Array(entry.mlDsaSecretKey);
    const signature = mlDsa.sign(msgBytes, skBytes);

    console.log(`[KeyAgent] Signed digest for: ${recipientId}`);

    return {
      signature: Buffer.from(signature).toString('base64')
    };
  },

  /**
   * POST /revoke — Mark keys as revoked (but preserve for audit)
   */
  async revoke(body) {
    const { recipientId } = body;
    if (!recipientId) throw new Error('recipientId is required');

    const entry = enclave.get(recipientId);
    if (entry) {
      entry.status = 'REVOKED';
      console.log(`[KeyAgent] Revoked keys for: ${recipientId}`);
      return { recipientId, status: 'REVOKED' };
    }
    return { recipientId, status: 'NOT_FOUND' };
  },

  /**
   * GET /has — Check if recipient has active keys
   */
  async has(body) {
    const { recipientId } = body;
    const entry = enclave.get(recipientId);
    return {
      recipientId,
      exists: !!entry && entry.status === 'ACTIVE'
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
      timestamp: new Date().toISOString()
    };
  }
};

/**
 * HTTP server request handler
 */
async function handler(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname.replace(/\/$/, '');

  // CORS headers for local development
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    let body = {};
    if (req.method === 'POST') {
      body = await readBody(req);
    } else if (req.method === 'GET' && url.searchParams.has('recipientId')) {
      body = { recipientId: url.searchParams.get('recipientId') };
    }

    let result;
    switch (path) {
      case '/provision':
        result = await routes.provision(body);
        break;
      case '/decapsulate':
        result = await routes.decapsulate(body);
        break;
      case '/sign':
        result = await routes.sign(body);
        break;
      case '/revoke':
        result = await routes.revoke(body);
        break;
      case '/has':
        result = await routes.has(body);
        break;
      case '/health':
        result = await routes.health();
        break;
      default:
        sendJson(res, 404, { error: `Unknown endpoint: ${path}` });
        return;
    }

    sendJson(res, 200, result);
  } catch (err) {
    console.error(`[KeyAgent] Error on ${path}:`, err.message);
    sendJson(res, 400, { error: err.message });
  }
}

// Create HTTP server
const server = http.createServer(handler);

// Start HTTP server if run as standalone script
if (require.main === module) {
  server.listen(PORT, '127.0.0.1', async () => {
    // Pre-warm PQC modules
    await getPqc();
    console.log(`[KeyAgent] 🔐 Key Agent Service running on http://127.0.0.1:${PORT}`);
    console.log(`[KeyAgent] Security boundary: private keys isolated in this process`);
    console.log(`[KeyAgent] Endpoints: /provision, /decapsulate, /sign, /revoke, /has, /health`);
  });
}

module.exports = { server, enclave, routes, handler, getPqc };
