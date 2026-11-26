/**
 * GOTU User Management
 * Registration, lookup, account lockout.
 */

import { randomUUID } from 'crypto';
import { getDb } from '../config/database.js';
import { hashPassword } from './passwords.js';

const MAX_FAILED_ATTEMPTS = 10;
const LOCKOUT_DURATION_MINUTES = 15;

/**
 * Create a new user.
 * @returns {object} Created user record
 */
export async function createUser({ username, email = null, password, role = 'analyst' }) {
  const db = getDb();
  const id = randomUUID();
  const passwordHash = await hashPassword(password);

  db.prepare(`
    INSERT INTO users (id, username, email, password_hash, role)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, username.trim(), email?.trim() ?? null, passwordHash, role);

  return getUserById(id);
}

export function getUserById(id) {
  return getDb().prepare(
    'SELECT id, username, email, role, mfa_enabled, failed_login_attempts, locked_until, created_at FROM users WHERE id = ?'
  ).get(id);
}

export function getUserByUsername(username) {
  return getDb().prepare(
    'SELECT * FROM users WHERE username = ? COLLATE NOCASE'
  ).get(username.trim());
}

/**
 * Record a failed login attempt. Locks account after MAX_FAILED_ATTEMPTS.
 */
export function recordFailedLogin(userId) {
  const db = getDb();
  const user = db.prepare('SELECT failed_login_attempts FROM users WHERE id = ?').get(userId);
  const newCount = (user?.failed_login_attempts ?? 0) + 1;

  if (newCount >= MAX_FAILED_ATTEMPTS) {
    const lockUntil = new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000).toISOString();
    db.prepare(`
      UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
      WHERE id = ?
    `).run(newCount, lockUntil, userId);
  } else {
    db.prepare(`
      UPDATE users SET failed_login_attempts = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
      WHERE id = ?
    `).run(newCount, userId);
  }
}

/**
 * Reset failed login count after successful authentication.
 */
export function resetFailedLogin(userId) {
  getDb().prepare(`
    UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id = ?
  `).run(userId);
}

/**
 * Returns true if the account is currently locked out.
 */
export function isAccountLocked(user) {
  if (!user.locked_until) return false;
  if (new Date(user.locked_until) > new Date()) return true;
  // Lock expired — reset
  resetFailedLogin(user.id);
  return false;
}

export function listUsers(limit = 100) {
  return getDb().prepare(
    'SELECT id, username, email, role, mfa_enabled, created_at FROM users ORDER BY created_at DESC LIMIT ?'
  ).all(limit);
}
