/**
 * Secret and Credential Exposure Detector.
 * Scans strings, logs, and telemetry for leaked environment variables, API keys,
 * database credentials, private keys, and high-entropy tokens.
 */

// Comprehensive Pattern Catalog
const SECRET_PATTERNS = [
  // 1. AWS Credentials
  {
    type: 'AWS_KEY',
    regex: /(?:AWS_KEY|AWS_ACCESS_KEY_ID|AWS_ACCESS_KEY|aws_access_key_id)\s*[:=]\s*["']?([A-Za-z0-9_/+=-]{16,40})["']?|\b(AKIA[0-9A-Z]{16})\b/i,
    severity: 'critical',
    score: 95
  },
  {
    type: 'AWS_SECRET',
    regex: /(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY|aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    severity: 'critical',
    score: 95
  },

  // 2. Database Passwords & Connection Strings
  {
    type: 'DATABASE_PASSWORD',
    regex: /(?:DATABASE_PASSWORD|DB_PASSWORD|DB_PASS|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD)\s*[:=]\s*["']?([^'"\s\r\n]{4,})["']?/i,
    severity: 'critical',
    score: 95
  },
  {
    type: 'POSTGRES_PASSWORD',
    regex: /(?:POSTGRES_PASSWORD|PGPASSWORD)\s*[:=]\s*["']?([^'"\s\r\n]{4,})["']?/i,
    severity: 'critical',
    score: 95
  },
  {
    type: 'DATABASE_URL',
    regex: /(?:DATABASE_URL|DB_URL|POSTGRES_URL)\s*[:=]\s*["']?((?:postgres|postgresql|mysql|mssql):\/\/[^\s'"\r\n]+)["']?|(?:postgres|postgresql|mysql|mssql):\/\/[a-zA-Z0-9_\-]+:[^@\s'"\r\n]+@[^\s'"\r\n]+/i,
    severity: 'critical',
    score: 95
  },
  {
    type: 'MONGODB_URI',
    regex: /(?:MONGODB_URI|MONGO_URL)\s*[:=]\s*["']?(mongodb(?:\+srv)?:\/\/[^\s'"\r\n]+)["']?|mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_\-]+:[^@\s'"\r\n]+@[^\s'"\r\n]+/i,
    severity: 'critical',
    score: 95
  },

  // 3. Cryptographic Private Keys & Certificates
  {
    type: 'RSA_PRIVATE_KEY',
    regex: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----/i,
    severity: 'critical',
    score: 100
  },
  {
    type: 'SSH_PRIVATE_KEY',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----/i,
    severity: 'critical',
    score: 100
  },
  {
    type: 'PRIVATE_KEY',
    regex: /-----BEGIN (?:EC|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----[\s\S]*?-----END (?:EC|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----|-----BEGIN (?:EC|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----|(?:PRIVATE_KEY|PRIVATEKEY)\s*[:=]\s*["']?([A-Za-z0-9_/+=-]{32,})["']?/i,
    severity: 'critical',
    score: 100
  },
  {
    type: 'BEGIN_CERTIFICATE',
    regex: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----|-----BEGIN CERTIFICATE-----/i,
    severity: 'critical',
    score: 85
  },

  // 4. API Keys & SaaS Tokens
  {
    type: 'GITHUB_TOKEN',
    regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b|(?:GITHUB_TOKEN|GH_TOKEN)\s*[:=]\s*["']?([a-zA-Z0-9_]{20,})["']?/i,
    severity: 'high',
    score: 85
  },
  {
    type: 'STRIPE_KEY',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,})\b|(?:STRIPE_KEY|STRIPE_SECRET_KEY|STRIPE_SECRET)\s*[:=]\s*["']?([a-zA-Z0-9_]{24,})["']?/i,
    severity: 'high',
    score: 85
  },
  {
    type: 'SLACK_TOKEN',
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b|(?:SLACK_TOKEN|SLACK_BOT_TOKEN)\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})["']?/i,
    severity: 'high',
    score: 80
  },
  {
    type: 'JWT_SECRET',
    regex: /(?:JWT_SECRET|JWT_KEY|JWT_SECRET_KEY)\s*[:=]\s*["']?([^'"\s\r\n]{8,})["']?/i,
    severity: 'high',
    score: 80
  },
  {
    type: 'API_TOKEN',
    regex: /(?:API_TOKEN|API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN)\s*[:=]\s*["']?([^'"\s\r\n]{12,})["']?/i,
    severity: 'high',
    score: 75
  }
];

/**
 * Calculates Shannon entropy of a string to detect high-entropy pseudorandom keys.
 * H = - sum(p * log2(p))
 */
function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Computes 1-indexed line and column numbers from character index.
 */
function calculateLocation(text, index) {
  const upToIndex = text.slice(0, index);
  const lines = upToIndex.split('\n');
  const line = lines.length;
  const col = lines[lines.length - 1].length + 1;
  return `line ${line}, col ${col}`;
}

/**
 * Formats a sanitized excerpt that redacts the actual secret value.
 * Shows variable prefix if available and masks secret payload with asterisks.
 */
function formatSanitizedExcerpt(fullMatch, secretType) {
  if (!fullMatch) return `${secretType}=***[REDACTED]`;

  if (fullMatch.includes('=')) {
    const parts = fullMatch.split('=');
    const varName = parts[0].trim();
    return `${varName}=***[REDACTED]`;
  }
  if (fullMatch.includes(':')) {
    const parts = fullMatch.split(':');
    const varName = parts[0].trim();
    return `${varName}: ***[REDACTED]`;
  }
  if (fullMatch.startsWith('-----BEGIN')) {
    return `${fullMatch.slice(0, 27)}...[REDACTED PRIVATE KEY]`;
  }

  const prefix = fullMatch.slice(0, 4);
  return `${prefix}***[REDACTED]`;
}

/**
 * Detects secrets and credentials in the provided input string.
 *
 * @param {string} input_string - Raw input string to inspect
 * @param {Object} [context={}] - Optional metadata regarding source
 * @returns {Array<{ secret_type: string, location: string, severity: 'critical'|'high'|'medium', excerpt: string, score: number }>}
 */
function detectSecrets(input_string, context = {}) {
  if (!input_string || typeof input_string !== 'string') {
    return [];
  }

  const detected = [];
  const foundIndices = new Set();

  // 1. Scan for catalog patterns
  for (const pattern of SECRET_PATTERNS) {
    const globalRegex = new RegExp(pattern.regex.source, 'gi');
    let match;

    while ((match = globalRegex.exec(input_string)) !== null) {
      const matchIndex = match.index;
      // Prevent overlapping duplicate matches at the exact same position
      if (foundIndices.has(matchIndex)) continue;
      foundIndices.add(matchIndex);

      const location = calculateLocation(input_string, matchIndex);
      const excerpt = formatSanitizedExcerpt(match[0], pattern.type);

      detected.push({
        secret_type: pattern.type,
        location,
        severity: pattern.severity,
        score: pattern.score,
        excerpt
      });
    }
  }

  // 2. High-Entropy Scanner for generic assignments
  const genericAssignmentRegex = /(?:secret|token|credential|key|auth|api)[\w.-]*\s*[:=]\s*["']?([a-zA-Z0-9_/+=-]{24,})["']?/gi;
  let genericMatch;
  while ((genericMatch = genericAssignmentRegex.exec(input_string)) !== null) {
    const matchIndex = genericMatch.index;
    if (foundIndices.has(matchIndex)) continue;

    const value = genericMatch[1];
    if (value && calculateShannonEntropy(value) >= 4.2) {
      foundIndices.add(matchIndex);
      const location = calculateLocation(input_string, matchIndex);
      const excerpt = formatSanitizedExcerpt(genericMatch[0], 'API_TOKEN');

      detected.push({
        secret_type: 'API_TOKEN',
        location,
        severity: 'high',
        score: 80,
        excerpt
      });
    }
  }

  return detected;
}

module.exports = {
  detectSecrets,
  calculateShannonEntropy,
  SECRET_PATTERNS
};
