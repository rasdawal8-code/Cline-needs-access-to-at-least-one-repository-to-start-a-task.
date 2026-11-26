/**
 * GOTU Audit Logger
 * Append-only audit log with HMAC-SHA256 per record and SHA-256 hash chain.
 * Every sensitive detail field is AES-256-GCM encrypted.
 * Records cannot be modified or deleted (enforced by DB triggers + HMAC chain).
 */

import { randomUUID } from 'crypto';
import { getDb } from '../config/database.js';
import { loadConfig } from '../config/env.js';
import { computeAuditHmac, hashAuditRecord, encrypt } from '../config/crypto.js';

const GENESIS_HASH = '0'.repeat(64);

/**
 * Write an audit event.
 * @param {object} opts
 * @param {string|null} opts.userId
 * @param {string} opts.action     - e.g. 'auth.login', 'investigation.start'
 * @param {string} opts.resource   - e.g. 'user', 'investigation'
 * @param {string|null} opts.resourceId
 * @param {object|null} opts.detail  - Additional context (will be encrypted)
 * @param {string} opts.ip
 * @param {string} opts.userAgent
 */
export function writeAuditLog({
  userId = null,
  action,
  resource,
  resourceId = null,
  detail = null,
  ip,
  userAgent,
}) {
  const config = loadConfig();
  const db = getDb();

  const id        = randomUUID();
  const timestamp = new Date().toISOString();

  // Encrypt sensitive detail field
  const encryptedDetail = detail
    ? encrypt(JSON.stringify(detail), config.encryptionKey)
    : null;

  // Get the last record for hash chain
  const lastRecord = db.prepare(
    'SELECT seq, hmac, id, prev_hash, user_id, action, resource, resource_id, detail, ip, user_agent, timestamp FROM audit_log ORDER BY seq DESC LIMIT 1'
  ).get();

  const seq = lastRecord ? lastRecord.seq + 1 : 1;
  const prevHash = lastRecord ? hashAuditRecord(lastRecord) : GENESIS_HASH;

  const record = {
    id,
    seq,
    prev_hash: prevHash,
    user_id:     userId,
    action,
    resource,
    resource_id: resourceId,
    detail:      encryptedDetail,
    ip,
    user_agent:  userAgent,
    timestamp,
  };

  const hmac = computeAuditHmac(record, config.auditHmacKey);

  db.prepare(`
    INSERT INTO audit_log
      (id, seq, prev_hash, user_id, action, resource, resource_id, detail, ip, user_agent, timestamp, hmac)
    VALUES
      (@id, @seq, @prev_hash, @user_id, @action, @resource, @resource_id, @detail, @ip, @user_agent, @timestamp, @hmac)
  `).run({ ...record, hmac });

  return id;
}

/**
 * Convenience wrapper for route handlers that have req.ip and req.headers.
 */
export function auditFromRequest(req, action, resource, resourceId = null, detail = null) {
  return writeAuditLog({
    userId:     req.user?.id ?? null,
    action,
    resource,
    resourceId,
    detail,
    ip:         req.ip ?? req.socket?.remoteAddress ?? 'unknown',
    userAgent:  req.headers?.['user-agent'] ?? 'unknown',
  });
}
