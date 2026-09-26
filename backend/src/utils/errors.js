/**
 * SIH-237 Standardized Typed Error Hierarchy
 * All operational and security errors inherit from AppError.
 * Enables fail-closed error handling and clean API error mapping.
 */

class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed', details = null) {
    super(message, 401, 'AUTHENTICATION_ERROR', details);
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Access denied: insufficient privileges', details = null) {
    super(message, 403, 'AUTHORIZATION_ERROR', details);
  }
}

class NotFoundError extends AppError {
  constructor(resource = 'Resource', details = null) {
    super(`${resource} not found`, 404, 'NOT_FOUND_ERROR', details);
  }
}

class ValidationError extends AppError {
  constructor(message = 'Input validation failed', details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

class CryptoError extends AppError {
  constructor(message = 'Cryptographic operation failed', details = null) {
    super(message, 500, 'CRYPTO_ERROR', details);
  }
}

class KeyEnvelopeError extends CryptoError {
  constructor(message = 'Key envelope generation or decapsulation failed', details = null) {
    super(message, details);
    this.code = 'KEY_ENVELOPE_ERROR';
    this.statusCode = 400;
  }
}

class WatermarkError extends AppError {
  constructor(message = 'Watermark processing failed', details = null) {
    super(message, 500, 'WATERMARK_ERROR', details);
  }
}

class LedgerError extends AppError {
  constructor(message = 'Hyperledger Fabric transaction failed', details = null) {
    super(message, 502, 'LEDGER_ERROR', details);
  }
}

class FailClosedError extends AppError {
  constructor(reason = 'Security invariant violated. Release denied.', details = null) {
    super(`FAIL-CLOSED ACTIVATED: ${reason}`, 403, 'FAIL_CLOSED_RELEASE_DENIED', details);
  }
}

module.exports = {
  AppError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  CryptoError,
  KeyEnvelopeError,
  WatermarkError,
  LedgerError,
  FailClosedError
};
