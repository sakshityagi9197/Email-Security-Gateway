/**
 * Utility helper functions
 */

/**
 * Debounce function to limit rate of function calls
 * @param {Function} func - Function to debounce
 * @param {number} wait - Milliseconds to wait
 * @returns {Function} Debounced function
 */
export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} { valid: boolean, message: string, strength: string }
 */
export function validatePasswordStrength(password) {
  if (!password) {
    return { valid: false, message: 'Password is required', strength: 'none' };
  }

  if (password.length < 12) {
    return { valid: false, message: 'Password must be at least 12 characters', strength: 'weak' };
  }

  let strength = 0;
  const checks = [
    { regex: /[A-Z]/, message: 'uppercase letter' },
    { regex: /[a-z]/, message: 'lowercase letter' },
    { regex: /[0-9]/, message: 'number' },
    { regex: /[^A-Za-z0-9]/, message: 'special character' },
  ];

  const missing = [];
  checks.forEach((check) => {
    if (check.regex.test(password)) {
      strength++;
    } else {
      missing.push(check.message);
    }
  });

  if (missing.length > 0) {
    return {
      valid: false,
      message: `Password must contain: ${missing.join(', ')}`,
      strength: strength === 3 ? 'medium' : 'weak',
    };
  }

  // Check for common patterns
  const commonPatterns = ['password', '12345', 'qwerty', 'admin', 'letmein'];
  const lowerPassword = password.toLowerCase();
  if (commonPatterns.some((pattern) => lowerPassword.includes(pattern))) {
    return {
      valid: false,
      message: 'Password contains common patterns',
      strength: 'weak',
    };
  }

  // Calculate final strength
  let finalStrength = 'medium';
  if (password.length >= 16 && strength === 4) {
    finalStrength = 'strong';
  } else if (password.length >= 20) {
    finalStrength = 'very-strong';
  }

  return {
    valid: true,
    message: 'Password is strong',
    strength: finalStrength,
  };
}

/**
 * Validate JSON or YAML string
 * @param {string} text - Text to validate
 * @returns {Object} { valid: boolean, message: string, parsed: any }
 */
export function validateJsonYaml(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    return { valid: true, message: 'Empty is valid', parsed: undefined };
  }

  // Try JSON first
  try {
    const parsed = JSON.parse(trimmed);
    return { valid: true, message: 'Valid JSON', parsed };
  } catch (jsonErr) {
    // Try YAML
    try {
      // Dynamic import for js-yaml
      if (typeof window !== 'undefined' && window.jsyaml) {
        const parsed = window.jsyaml.load(trimmed);
        return { valid: true, message: 'Valid YAML', parsed };
      }
      return { valid: false, message: 'JSON/YAML parser not available', parsed: null };
    } catch (yamlErr) {
      return {
        valid: false,
        message: `Invalid JSON/YAML: ${jsonErr.message}`,
        parsed: null,
      };
    }
  }
}

/**
 * Validate file size
 * @param {File} file - File to validate
 * @param {number} maxSizeMB - Maximum size in megabytes
 * @returns {Object} { valid: boolean, message: string }
 */
export function validateFileSize(file, maxSizeMB = 25) {
  if (!file) {
    return { valid: false, message: 'No file provided' };
  }

  const maxBytes = maxSizeMB * 1024 * 1024;
  if (file.size > maxBytes) {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    return {
      valid: false,
      message: `File too large: ${sizeMB}MB (max ${maxSizeMB}MB)`,
    };
  }

  return { valid: true, message: 'File size OK' };
}

/**
 * Sanitize HTML string using simple escaping
 * @param {string} text - Text to sanitize
 * @returns {string} Sanitized text
 */
export function sanitizeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Truncate text with ellipsis
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
export function truncate(text, maxLength = 50) {
  if (!text || text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

/**
 * Rate limiter class
 */
export class RateLimiter {
  constructor(maxAttempts = 3, windowMs = 60000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = [];
  }

  attempt() {
    const now = Date.now();
    // Remove old attempts outside the window
    this.attempts = this.attempts.filter((time) => now - time < this.windowMs);

    if (this.attempts.length >= this.maxAttempts) {
      const oldestAttempt = this.attempts[0];
      const waitTime = this.windowMs - (now - oldestAttempt);
      return {
        allowed: false,
        waitTime: Math.ceil(waitTime / 1000),
        message: `Too many attempts. Please wait ${Math.ceil(waitTime / 1000)} seconds.`,
      };
    }

    this.attempts.push(now);
    return { allowed: true, remaining: this.maxAttempts - this.attempts.length };
  }

  reset() {
    this.attempts = [];
  }
}

/**
 * Generate a random CSRF token
 * @returns {string} Random token
 */
export function generateCsrfToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Get or create CSRF token
 * @returns {string} CSRF token
 */
export function getCsrfToken() {
  let token = sessionStorage.getItem('csrf_token');
  if (!token) {
    token = generateCsrfToken();
    sessionStorage.setItem('csrf_token', token);
  }
  return token;
}

/**
 * Format bytes to human readable
 * @param {number} bytes - Bytes to format
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted string
 */
export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
