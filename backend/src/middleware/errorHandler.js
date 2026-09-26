const { AppError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Centralized Express error handler
 * Sanitizes errors in production, logs security events, and handles typed errors.
 */
function errorHandler(err, req, res, next) {
  const isAppError = err instanceof AppError;
  const statusCode = err.statusCode || (res.statusCode !== 200 ? res.statusCode : 500);
  const errorCode = err.code || (statusCode >= 500 ? 'INTERNAL_SERVER_ERROR' : 'REQUEST_ERROR');

  // Log error using structured logger
  if (statusCode >= 500) {
    logger.error(`Unhandled Exception on ${req.method} ${req.originalUrl}: ${err.message}`, {
      code: errorCode,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      ...(process.env.NODE_ENV !== 'production' ? { stack: err.stack } : {})
    });
  } else {
    logger.warn(`Client Error on ${req.method} ${req.originalUrl}: ${err.message}`, {
      code: errorCode,
      status: statusCode
    });
  }

  // Safe response sanitization
  const response = {
    success: false,
    error: isAppError || process.env.NODE_ENV !== 'production' ? err.message : 'Internal Server Error',
    code: errorCode,
    status: statusCode,
    timestamp: new Date().toISOString(),
    ...(err.details ? { details: err.details } : {})
  };

  res.status(statusCode).json(response);
}

module.exports = errorHandler;
