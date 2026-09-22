const crypto = require('node:crypto');

/**
 * Native Node.js Cryptographic Service for SIH26237
 * Uses built-in node:crypto for all operations:
 * - AES-256-GCM symmetric document encryption/decryption with authentication tags
 * - RSA-2048 keypair generation (SPKI/PKCS#8 PEM)
 * - RSA-OAEP (SHA-256) per-recipient symmetric key wrapping
 * - SHA-256 document hashing and hash-chaining
 * - RSA digital signature generation and verification for provenance logs
 */

/**
 * Generate a new RSA keypair (2048-bit by default)
 * @param {number} modulusLength - Key size in bits (default: 2048)
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded key strings
 */
function generateKeyPair(modulusLength = 2048) {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
}

/**
 * Generate a cryptographically secure 256-bit (32-byte) AES symmetric key
 * @returns {Buffer} 32-byte buffer
 */
function generateSymmetricKey() {
  return crypto.randomBytes(32);
}

/**
 * Encrypt document buffer using AES-256-GCM
 * @param {Buffer|string} documentBuffer - Plaintext file content
 * @param {Buffer} symmetricKey - 32-byte AES key
 * @returns {{ encryptedBlob: string, iv: string, authTag: string }} Base64/Hex outputs
 */
function encryptDocument(documentBuffer, symmetricKey) {
  if (!Buffer.isBuffer(documentBuffer)) {
    documentBuffer = Buffer.from(documentBuffer);
  }
  // Standard 96-bit (12-byte) IV for GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

  const encrypted = Buffer.concat([cipher.update(documentBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedBlob: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Decrypt document buffer using AES-256-GCM and verify authentication tag
 * @param {string|Buffer} encryptedBlob - Base64 string or Buffer of ciphertext
 * @param {Buffer} symmetricKey - 32-byte AES key
 * @param {string} ivHex - Hex encoded IV
 * @param {string} authTagHex - Hex encoded 16-byte authentication tag
 * @returns {Buffer} Decrypted plaintext buffer
 */
function decryptDocument(encryptedBlob, symmetricKey, ivHex, authTagHex) {
  const ciphertextBuffer = Buffer.isBuffer(encryptedBlob)
    ? encryptedBlob
    : Buffer.from(encryptedBlob, 'base64');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
  return decrypted;
}

/**
 * Wrap (encrypt) the AES symmetric key for a specific recipient using RSA-OAEP (SHA-256)
 * @param {Buffer} symmetricKey - 32-byte AES key
 * @param {string} recipientPublicKeyPem - Recipient's public key PEM
 * @returns {string} Base64 encoded encrypted symmetric key
 */
function encryptSymmetricKey(symmetricKey, recipientPublicKeyPem) {
  const encryptedKey = crypto.publicEncrypt(
    {
      key: recipientPublicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    symmetricKey
  );
  return encryptedKey.toString('base64');
}

/**
 * Unwrap (decrypt) the AES symmetric key using recipient's private key with RSA-OAEP
 * @param {string} encryptedKeyBase64 - Base64 encoded ciphertext of symmetric key
 * @param {string} recipientPrivateKeyPem - Recipient's private key PEM
 * @returns {Buffer} 32-byte AES symmetric key buffer
 */
function decryptSymmetricKey(encryptedKeyBase64, recipientPrivateKeyPem) {
  const encryptedBuffer = Buffer.from(encryptedKeyBase64, 'base64');
  const decryptedKey = crypto.privateDecrypt(
    {
      key: recipientPrivateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedBuffer
  );
  return decryptedKey;
}

/**
 * Calculate SHA-256 hex digest of data
 * @param {Buffer|string} data - Input content
 * @returns {string} 64-character lowercase hex string
 */
function computeHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Digitally sign data using server's private key (SHA-256 with RSA)
 * @param {string|Buffer} data - Payload to sign
 * @param {string} privateKeyPem - Server's private key PEM
 * @returns {string} Base64 encoded signature
 */
function signPayload(data, privateKeyPem) {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

/**
 * Verify a digital signature against payload and public key
 * @param {string|Buffer} data - Original payload that was signed
 * @param {string} signatureBase64 - Base64 encoded signature
 * @param {string} publicKeyPem - Public key PEM
 * @returns {boolean} True if signature is cryptographically valid
 */
function verifySignature(data, signatureBase64, publicKeyPem) {
  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(publicKeyPem, Buffer.from(signatureBase64, 'base64'));
  } catch (err) {
    return false;
  }
}

module.exports = {
  generateKeyPair,
  generateSymmetricKey,
  encryptDocument,
  decryptDocument,
  encryptSymmetricKey,
  decryptSymmetricKey,
  computeHash,
  signPayload,
  verifySignature
};
