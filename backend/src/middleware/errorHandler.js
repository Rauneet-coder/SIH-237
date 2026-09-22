/**
 * Centralized Express error handler
 */
function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || (res.statusCode !== 200 ? res.statusCode : 500);

  if (statusCode >= 500 && process.env.NODE_ENV !== 'test') {
    console.error(`[Server Error] ${err.stack || err.message}`);
  }

  res.status(statusCode).json({
    error: err.message || 'Internal Server Error',
    status: statusCode,
    timestamp: new Date().toISOString()
  });
}

module.exports = errorHandler;
