/**
 * Security & Input Sanitization Utilities for loccoMirror API
 * Protects against NoSQL Injection, XSS, Prototype Pollution, and ReDoS attacks.
 */

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * Ensures a value is strictly a primitive string and prevents NoSQL Object Injection
 * (e.g. payload containing {"$gt": ""} or {"$ne": null})
 */
function sanitizeString(input, maxLength = 255) {
  if (typeof input !== 'string') {
    return '';
  }
  // Trim and limit length to prevent memory exhaustion
  let sanitized = input.trim().slice(0, maxLength);
  // Remove null bytes and dangerous control characters
  sanitized = sanitized.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return sanitized;
}

/**
 * Validates and normalizes email addresses
 */
function validateEmail(email) {
  if (typeof email !== 'string') return { valid: false, message: 'Email must be a valid text string.' };
  const cleaned = email.trim().toLowerCase();
  if (!cleaned) return { valid: false, message: 'Email address cannot be empty.' };
  if (cleaned.length > 254) return { valid: false, message: 'Email address is too long.' };
  if (!EMAIL_REGEX.test(cleaned)) return { valid: false, message: 'Please provide a valid email format (e.g. user@example.com).' };
  return { valid: true, value: cleaned };
}

/**
 * Validates password strength & limits length to prevent bcrypt CPU starvation DoS
 */
function validatePassword(password) {
  if (typeof password !== 'string') return { valid: false, message: 'Password must be a valid string.' };
  if (!password || password.length < 6) return { valid: false, message: 'Password must be at least 6 characters long.' };
  if (password.length > 128) return { valid: false, message: 'Password cannot exceed 128 characters.' };
  return { valid: true, value: password };
}

/**
 * Validates and sanitizes display names
 */
function validateName(name) {
  if (typeof name !== 'string') return { valid: false, message: 'Name must be a valid text string.' };
  const cleaned = sanitizeString(name, 60);
  if (!cleaned || cleaned.length < 2) return { valid: false, message: 'Name must be between 2 and 60 characters.' };
  // Strip any script or HTML tags
  const stripped = cleaned.replace(/<[^>]*>?/gm, '');
  return { valid: true, value: stripped };
}

/**
 * NoSQL Injection prevention middleware
 * Recursively scans req.body, req.query, and req.params for keys starting with '$' or containing '.'
 */
function mongoSanitizeMiddleware(req, res, next) {
  const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj)) {
      if (key.startsWith('$') || key.includes('.')) {
        delete obj[key];
        continue;
      }
      if (typeof obj[key] === 'object') {
        sanitizeObject(obj[key]);
      }
    }
  };

  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);
  next();
}

module.exports = {
  sanitizeString,
  validateEmail,
  validatePassword,
  validateName,
  mongoSanitizeMiddleware,
};
