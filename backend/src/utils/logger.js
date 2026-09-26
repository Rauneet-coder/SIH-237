/**
 * SIH-237 Structured Security Logger
 * Provides audit logging, context tagging, and automatic redaction of sensitive
 * cryptographic material, credentials, and plaintext payloads.
 */

const SENSITIVE_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
  /(password|secret|token|bearer|dek|symmetricKey|privateKey)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-\.\+/=]{8,})[\"']?/gi,
  /(BEGIN PRIVATE KEY|END PRIVATE KEY)/gi
];

function sanitize(message) {
  if (typeof message !== 'string') {
    try {
      message = JSON.stringify(message);
    } catch {
      message = String(message);
    }
  }

  let sanitized = message;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, (match, prefix) => {
      if (prefix) return `${prefix}: "[REDACTED_SECRET]"`;
      return '[REDACTED_KEY_MATERIAL]';
    });
  }
  return sanitized;
}

const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  SECURITY_AUDIT: 4
};

const CURRENT_LEVEL = process.env.LOG_LEVEL
  ? LOG_LEVELS[process.env.LOG_LEVEL.toUpperCase()] || LOG_LEVELS.INFO
  : LOG_LEVELS.INFO;

function log(level, message, context = {}) {
  if (LOG_LEVELS[level] < CURRENT_LEVEL && level !== 'SECURITY_AUDIT') {
    return;
  }

  const timestamp = new Date().toISOString();
  const sanitizedContext = JSON.parse(sanitize(context));
  const sanitizedMsg = sanitize(message);

  const entry = {
    timestamp,
    level,
    message: sanitizedMsg,
    ...(Object.keys(sanitizedContext).length > 0 ? { context: sanitizedContext } : {})
  };

  const formatted = `[${timestamp}] [${level}] ${sanitizedMsg} ${
    Object.keys(sanitizedContext).length > 0 ? JSON.stringify(sanitizedContext) : ''
  }`;

  if (level === 'ERROR' || level === 'SECURITY_AUDIT') {
    console.error(formatted);
  } else if (level === 'WARN') {
    console.warn(formatted);
  } else {
    console.log(formatted);
  }

  return entry;
}

const logger = {
  debug: (msg, ctx) => log('DEBUG', msg, ctx),
  info: (msg, ctx) => log('INFO', msg, ctx),
  warn: (msg, ctx) => log('WARN', msg, ctx),
  error: (msg, ctx) => log('ERROR', msg, ctx),
  securityAudit: (action, ctx) => log('SECURITY_AUDIT', `AUDIT_EVENT: ${action}`, ctx),
  sanitize
};

module.exports = logger;
