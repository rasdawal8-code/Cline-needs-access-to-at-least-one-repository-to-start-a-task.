/**
 * GOTU MFA Module
 * TOTP via speakeasy. MFA secrets are stored encrypted (AES-256-GCM).
 * Backup codes are hashed with Argon2id before storage.
 */

import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { randomUUID } from 'crypto';
import { hashPassword, verifyPassword } from './passwords.js';
import { encrypt, decrypt } from '../config/crypto.js';
import { loadConfig } from '../config/env.js';
import { getDb } from '../config/database.js';

const BACKUP_CODE_COUNT = 10;

/**
 * Generate a new TOTP secret for a user.
 * Returns the secret (base32) and an otpauth URL for QR display.
 * Does NOT save to DB yet — call saveMfaSecret() after user confirms.
 */
export function generateMfaSecret(username) {
  const secret = speakeasy.generateSecret({
    name:   `GOTU (${username})`,
    issuer: 'GOTU Intelligence',
    length: 32,
  });
  return {
    base32:     secret.base32,
    otpauthUrl: secret.otpauth_url,
  };
}

/**
 * Generate a QR code data URL for the TOTP otpauth URL.
 */
export async function generateQrCode(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl);
}

/**
 * Verify a TOTP token against a base32 secret.
 * Uses a 1-step window (allows 30s clock drift).
 */
export function verifyTotp(base32Secret, token) {
  return speakeasy.totp.verify({
    secret:   base32Secret,
    encoding: 'base32',
    token:    token.replace(/\s/g, ''),
    window:   1,
  });
}

/**
 * Generate backup codes (plaintext, one-time use).
 * Returns array of plaintext codes — show once to user, then hash and store.
 */
export function generateBackupCodes() {
  return Array.from({ length: BACKUP_CODE_COUNT }, () =>
    randomUUID().replace(/-/g, '').slice(0, 10).toUpperCase()
  );
}

/**
 * Hash all backup codes for storage.
 * @returns {Promise<string[]>} array of Argon2id hashes
 */
export async function hashBackupCodes(codes) {
  return Promise.all(codes.map(code => hashPassword(code)));
}

/**
 * Verify a backup code against stored hashes (tries each; invalidates matched one).
 * Returns true if a valid code was found and consumed.
 */
export async function consumeBackupCode(userId, candidateCode) {
  const config = loadConfig();
  const db = getDb();

  const user = db.prepare('SELECT mfa_backup_codes FROM users WHERE id = ?').get(userId);
  if (!user?.mfa_backup_codes) return false;

  const hashes = JSON.parse(decrypt(user.mfa_backup_codes, config.encryptionKey));
  let matchedIndex = -1;

  for (let i = 0; i < hashes.length; i++) {
    if (hashes[i] === null) continue; // already consumed
    if (await verifyPassword(hashes[i], candidateCode)) {
      matchedIndex = i;
      break;
    }
  }

  if (matchedIndex === -1) return false;

  // Invalidate the used code
  hashes[matchedIndex] = null;
  const updated = encrypt(JSON.stringify(hashes), config.encryptionKey);
  db.prepare('UPDATE users SET mfa_backup_codes = ? WHERE id = ?').run(updated, userId);

  return true;
}

/**
 * Enable MFA for a user: encrypt and store secret + backup code hashes.
 */
export async function enableMfa(userId, base32Secret, backupCodes) {
  const config = loadConfig();
  const db = getDb();

  const encryptedSecret = encrypt(base32Secret, config.encryptionKey);
  const hashes = await hashBackupCodes(backupCodes);
  const encryptedCodes = encrypt(JSON.stringify(hashes), config.encryptionKey);

  db.prepare(`
    UPDATE users SET
      mfa_secret       = ?,
      mfa_backup_codes = ?,
      mfa_enabled      = 1,
      updated_at       = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = ?
  `).run(encryptedSecret, encryptedCodes, userId);
}

/**
 * Get the decrypted TOTP secret for a user.
 */
export function getMfaSecret(userId) {
  const config = loadConfig();
  const db = getDb();
  const user = db.prepare('SELECT mfa_secret FROM users WHERE id = ? AND mfa_enabled = 1').get(userId);
  if (!user?.mfa_secret) return null;
  return decrypt(user.mfa_secret, config.encryptionKey);
}
