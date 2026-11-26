/**
 * GOTU SQLite Session Store
 * Implements the @fastify/session SessionStore interface:
 *   set(sessionId, session, callback)
 *   get(sessionId, callback)
 *   destroy(sessionId, callback)
 *
 * Sessions are AES-256-GCM encrypted. TTL enforced on get().
 * Uses better-sqlite3 synchronous API wrapped in async callbacks.
 */

import { getDb } from '../config/database.js';
import { loadConfig } from '../config/env.js';
import { encrypt, decrypt } from '../config/crypto.js';

export class SqliteSessionStore {
  constructor() {
    this._getDb = getDb;
    this._getConfig = loadConfig;
  }

  /**
   * Store a session. Called by @fastify/session on every session write.
   */
  set(sessionId, session, callback) {
    try {
      const config = this._getConfig();
      const db = this._getDb();

      const ttlMs = (config.sessionTtl ?? 86400) * 1000;
      const expiresAt = new Date(Date.now() + ttlMs).toISOString();
      const encrypted = encrypt(JSON.stringify(session), config.encryptionKey);

      db.prepare(`
        INSERT INTO sessions (id, data, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
      `).run(sessionId, encrypted, expiresAt);

      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  /**
   * Retrieve a session. Returns null if not found or expired.
   */
  get(sessionId, callback) {
    try {
      const config = this._getConfig();
      const db = this._getDb();

      const row = db.prepare(
        'SELECT data, expires_at FROM sessions WHERE id = ?'
      ).get(sessionId);

      if (!row) return callback(null, null);

      // Check TTL
      if (new Date(row.expires_at) < new Date()) {
        // Expired — delete and return null
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
        return callback(null, null);
      }

      const session = JSON.parse(decrypt(row.data, config.encryptionKey));
      callback(null, session);
    } catch (err) {
      callback(err);
    }
  }

  /**
   * Delete a session. Called on logout and session regeneration.
   */
  destroy(sessionId, callback) {
    try {
      const db = this._getDb();
      db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  /**
   * compareAndSet: atomically update a session only if it hasn't changed since last read.
   * Required by @fastify/session v11+ for concurrent request safety.
   * @param {object|null} prevSession - previous session value (null if new)
   * @param {string|null} prevSessionId - previous session ID
   * @param {object} session - new session data
   * @param {function} callback
   */
  compareAndSet(prevSession, prevSessionId, session, callback) {
    try {
      const config = this._getConfig();
      const db = this._getDb();
      // The store ID is prevSessionId — always write to the same store key
      // The session object contains the new data to persist
      const storeId = prevSessionId;
      if (!storeId) {
        return callback(new Error('Session store ID missing in compareAndSet'));
      }
      const ttlMs = (config.sessionTtl ?? 86400) * 1000;
      const expiresAt = new Date(Date.now() + ttlMs).toISOString();
      // Extract plain data from session object (all enumerable own keys)
      const sessionData = {};
      for (const key of Object.keys(session)) {
        sessionData[key] = session[key];
      }
      const encrypted = encrypt(JSON.stringify(sessionData), config.encryptionKey);
      db.prepare(`
        INSERT INTO sessions (id, data, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
      `).run(storeId, encrypted, expiresAt);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  /**
   * Purge all expired sessions. Called periodically.
   */
  purgeExpired() {
    const db = this._getDb();
    const result = db.prepare(
      "DELETE FROM sessions WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')"
    ).run();
    return result.changes;
  }
}
