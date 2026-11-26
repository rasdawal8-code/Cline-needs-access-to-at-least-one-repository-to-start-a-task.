/**
 * GOTU Environment Configuration
 * Validates all required environment variables on startup.
 * No secrets are hardcoded here — all come from the process environment.
 */

import { createRequire } from 'module';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Defaults (non-secret, safe to have defaults) ───────────────────────────
const DEFAULTS = {
  PORT: '4000',
  HOST: '127.0.0.1',
  NODE_ENV: 'development',
  SESSION_TTL_SECONDS: '86400',       // 24 hours
  RATE_LIMIT_MAX: '100',
  RATE_LIMIT_WINDOW_MS: '60000',
  JOB_LEASE_DURATION_MS: '60000',     // 60 seconds
  JOB_HEARTBEAT_INTERVAL_MS: '15000', // 15 seconds
  JOB_REAPER_INTERVAL_MS: '30000',    // 30 seconds
  JOB_MAX_CONCURRENT: '3',
  LOG_LEVEL: 'info',
  DATA_DIR: path.resolve(__dirname, '../../../data'),
  MFA_REQUIRED: 'false',
};

function get(key, required = false) {
  const val = process.env[key] ?? DEFAULTS[key];
  if (required && !val) {
    throw new Error(`[GOTU] Required environment variable missing: ${key}`);
  }
  return val;
}

// ─── Key bootstrap ──────────────────────────────────────────────────────────
// If keys are not set, generate ephemeral keys and warn loudly.
// In production, these MUST be set as environment variables.

function loadOrGenerateKey(envVar, saltFile, label) {
  const dataDir = get('DATA_DIR');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  if (process.env[envVar]) {
    const raw = Buffer.from(process.env[envVar], 'hex');
    if (raw.length !== 32) throw new Error(`${envVar} must be 64 hex chars (32 bytes)`);
    return raw;
  }

  // Development: derive from a local salt file
  const saltPath = path.join(dataDir, saltFile);
  let salt;
  if (fs.existsSync(saltPath)) {
    salt = fs.readFileSync(saltPath);
  } else {
    salt = crypto.randomBytes(32);
    fs.writeFileSync(saltPath, salt, { mode: 0o600 });
    console.warn(`[GOTU] WARNING: Generated ephemeral ${label} key salt at ${saltPath}.`);
    console.warn(`[GOTU] WARNING: Set ${envVar}=<64-hex-chars> in production.`);
  }

  // Derive a consistent key from the salt
  return crypto.scryptSync(`gotu-dev-${label}`, salt, 32);
}

// ─── Exported config object ──────────────────────────────────────────────────
let _config = null;

export function loadConfig() {
  if (_config) return _config;

  const dataDir = get('DATA_DIR');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  const encryptionKey = loadOrGenerateKey('GOTU_ENCRYPTION_KEY', '.enc.salt', 'encryption');
  const auditHmacKey  = loadOrGenerateKey('GOTU_AUDIT_HMAC_KEY',  '.audit.salt', 'audit-hmac');
  const sessionSecret = process.env.GOTU_SESSION_SECRET
    ?? (process.env.NODE_ENV === 'production'
        ? (() => { throw new Error('[GOTU] GOTU_SESSION_SECRET must be set in production'); })()
        : 'gotu-dev-session-secret-change-in-production-min-32-chars');

  _config = {
    port:               parseInt(get('PORT'), 10),
    host:               get('HOST'),
    nodeEnv:            get('NODE_ENV'),
    isProduction:       get('NODE_ENV') === 'production',
    logLevel:           get('LOG_LEVEL'),
    dataDir,
    dbPath:             path.join(dataDir, 'gotu.db'),
    sessionSecret,
    sessionTtl:         parseInt(get('SESSION_TTL_SECONDS'), 10),
    rateLimitMax:       parseInt(get('RATE_LIMIT_MAX'), 10),
    rateLimitWindowMs:  parseInt(get('RATE_LIMIT_WINDOW_MS'), 10),
    jobLeaseDurationMs: parseInt(get('JOB_LEASE_DURATION_MS'), 10),
    jobHeartbeatMs:     parseInt(get('JOB_HEARTBEAT_INTERVAL_MS'), 10),
    jobReaperMs:        parseInt(get('JOB_REAPER_INTERVAL_MS'), 10),
    jobMaxConcurrent:   parseInt(get('JOB_MAX_CONCURRENT'), 10),
    mfaRequired:        get('MFA_REQUIRED') === 'true',
    encryptionKey,      // Buffer(32) — AES-256-GCM for sensitive columns
    auditHmacKey,       // Buffer(32) — HMAC-SHA256 for audit log integrity
  };

  return _config;
}
