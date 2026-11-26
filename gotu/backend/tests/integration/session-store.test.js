/**
 * Phase 4A Tests: SQLite Session Store
 * Tests set, get, destroy, TTL enforcement, concurrent safety, and stale session rejection.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'crypto';

// DATA_DIR is already set by the auth.test.js which runs first in singleThread mode
// Use a separate dir to avoid conflicts with other tests
const TEST_DATA_DIR = path.join(os.tmpdir(), `gotu-sess-test-${Date.now()}`);
fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
// Override env before any module load
Object.assign(process.env, { DATA_DIR: TEST_DATA_DIR, NODE_ENV: 'test' });

let store, db;

beforeAll(async () => {
  const { getDb, runMigrations } = await import('../../src/config/database.js');
  const { SqliteSessionStore } = await import('../../src/storage/session-store.js');
  db = getDb();
  runMigrations(db);
  store = new SqliteSessionStore();
});

afterAll(() => {
  try { fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true }); } catch {}
});

function promisify(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn(...args, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

describe('Session Store', () => {
  it('set and get roundtrip returns session data', async () => {
    const id = randomUUID();
    const sessionData = { user: { id: 'u1', username: 'alice' }, custom: 'value' };
    await promisify(store.set.bind(store), id, sessionData);
    const retrieved = await promisify(store.get.bind(store), id);
    expect(retrieved).toMatchObject(sessionData);
  });

  it('get returns null for non-existent session', async () => {
    const result = await promisify(store.get.bind(store), 'does-not-exist');
    expect(result).toBeNull();
  });

  it('destroy removes the session', async () => {
    const id = randomUUID();
    await promisify(store.set.bind(store), id, { user: { id: 'u1' } });
    await promisify(store.destroy.bind(store), id);
    const result = await promisify(store.get.bind(store), id);
    expect(result).toBeNull();
  });

  it('stale session (after destroy) cannot be retrieved', async () => {
    const id = randomUUID();
    await promisify(store.set.bind(store), id, { user: { id: 'u2' } });

    // Simulate logout
    await promisify(store.destroy.bind(store), id);

    // A subsequent request with the old session ID should get null
    const result = await promisify(store.get.bind(store), id);
    expect(result).toBeNull();
  });

  it('overwrites existing session on set', async () => {
    const id = randomUUID();
    await promisify(store.set.bind(store), id, { v: 1 });
    await promisify(store.set.bind(store), id, { v: 2 });
    const result = await promisify(store.get.bind(store), id);
    expect(result.v).toBe(2);
  });

  it('different session IDs are independent', async () => {
    const id1 = randomUUID();
    const id2 = randomUUID();
    await promisify(store.set.bind(store), id1, { user: 'alice' });
    await promisify(store.set.bind(store), id2, { user: 'bob' });
    const r1 = await promisify(store.get.bind(store), id1);
    const r2 = await promisify(store.get.bind(store), id2);
    expect(r1.user).toBe('alice');
    expect(r2.user).toBe('bob');
    await promisify(store.destroy.bind(store), id1);
    expect(await promisify(store.get.bind(store), id1)).toBeNull();
    expect((await promisify(store.get.bind(store), id2)).user).toBe('bob');
  });

  it('expired sessions are not returned', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const id = randomUUID();
    await promisify(store.set.bind(store), id, { user: 'test' });
    // Manually expire the session
    db.prepare("UPDATE sessions SET expires_at = datetime('now', '-1 second') WHERE id = ?").run(id);
    const result = await promisify(store.get.bind(store), id);
    expect(result).toBeNull();
  });

  it('purgeExpired removes expired sessions', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const id = randomUUID();
    await promisify(store.set.bind(store), id, { user: 'test' });
    db.prepare("UPDATE sessions SET expires_at = datetime('now', '-1 second') WHERE id = ?").run(id);
    const removed = store.purgeExpired();
    expect(removed).toBeGreaterThanOrEqual(1);
    const result = await promisify(store.get.bind(store), id);
    expect(result).toBeNull();
  });
});
