/**
 * GOTU Cryptographic Utilities
 * AES-256-GCM column-level encryption and HMAC utilities.
 * Keys come from config — never hardcoded.
 */

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // 96-bit IV for GCM
const TAG_LENGTH = 16;  // 128-bit auth tag

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Returns a JSON blob: { iv, tag, ct } all base64-encoded.
 * @param {string} plaintext
 * @param {Buffer} key - 32-byte key
 * @returns {string} JSON blob
 */
export function encrypt(plaintext, key) {
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    iv:  iv.toString('base64'),
    tag: tag.toString('base64'),
    ct:  ct.toString('base64'),
  });
}

/**
 * Decrypt a blob produced by encrypt().
 * Throws if the key is wrong or data is tampered.
 * @param {string} blob - JSON string from encrypt()
 * @param {Buffer} key - 32-byte key
 * @returns {string} plaintext
 */
export function decrypt(blob, key) {
  if (blob === null || blob === undefined) return null;
  const { iv, tag, ct } = JSON.parse(blob);
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ct, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

/**
 * Compute HMAC-SHA256 over a canonical JSON representation of an audit record.
 * All fields are included — none omitted.
 * @param {object} record - Audit record WITHOUT the hmac field
 * @param {Buffer} key - 32-byte HMAC key
 * @returns {string} hex HMAC
 */
export function computeAuditHmac(record, key) {
  const canonical = JSON.stringify({
    id:          record.id,
    seq:         record.seq,
    prev_hash:   record.prev_hash,
    user_id:     record.user_id,
    action:      record.action,
    resource:    record.resource,
    resource_id: record.resource_id,
    detail:      record.detail,       // already-encrypted blob
    ip:          record.ip,
    user_agent:  record.user_agent,
    timestamp:   record.timestamp,
  });
  return crypto.createHmac('sha256', key).update(canonical, 'utf8').digest('hex');
}

/**
 * Compute SHA-256 of a canonical audit record string (for hash chain).
 * Input is the full JSON including the hmac field.
 * @param {object} record - Complete audit record including hmac
 * @returns {string} hex SHA-256
 */
export function hashAuditRecord(record) {
  const canonical = JSON.stringify({
    id:          record.id,
    seq:         record.seq,
    prev_hash:   record.prev_hash,
    user_id:     record.user_id,
    action:      record.action,
    resource:    record.resource,
    resource_id: record.resource_id,
    detail:      record.detail,
    ip:          record.ip,
    user_agent:  record.user_agent,
    timestamp:   record.timestamp,
    hmac:        record.hmac,
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Generate a cryptographically random hex string of the given byte length.
 */
export function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // Still do comparison to avoid timing leak on length
    crypto.timingSafeEqual(Buffer.alloc(1), Buffer.alloc(1));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
