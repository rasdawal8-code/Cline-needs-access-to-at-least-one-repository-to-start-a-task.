import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import { randomUUID } from 'crypto';

function makeTestDb() {
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  db.exec(`CREATE TABLE jobs (id TEXT PRIMARY KEY, queue TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','claimed','running','completed','failed','retrying','paused')), priority INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, run_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), lease_token TEXT, lease_expires_at TEXT, last_heartbeat_at TEXT, checkpoint TEXT, error TEXT, started_at TEXT, completed_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))`);
  return db;
}

function enqueue(db, queue, payload = {}, opts = {}) {
  const id = randomUUID();
  db.prepare('INSERT INTO jobs (id, queue, payload, priority, max_attempts) VALUES (?, ?, ?, ?, ?)').run(id, queue, JSON.stringify(payload), opts.priority ?? 0, opts.maxAttempts ?? 3);
  return id;
}

function claimNext(db, queue) {
  const txn = db.transaction(() => {
    const job = db.prepare(`SELECT * FROM jobs WHERE queue = ? AND status IN ('pending','retrying') AND run_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now') ORDER BY priority DESC, created_at ASC LIMIT 1`).get(queue);
    if (!job) return null;
    const leaseToken = randomUUID();
    const leaseExpiry = new Date(Date.now() + 60000).toISOString();
    const updated = db.prepare(`UPDATE jobs SET status='claimed', lease_token=?, lease_expires_at=?, started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), attempts=attempts+1 WHERE id=? AND status IN ('pending','retrying')`).run(leaseToken, leaseExpiry, job.id);
    if (updated.changes === 0) return null;
    return { ...job, lease_token: leaseToken };
  });
  return txn.immediate();
}

describe('Job Queue — atomic claim', () => {
  it('claims a pending job', () => {
    const db = makeTestDb();
    enqueue(db, 'q');
    const job = claimNext(db, 'q');
    expect(job).not.toBeNull();
    const row = db.prepare('SELECT status, attempts FROM jobs WHERE id = ?').get(job.id);
    expect(row.status).toBe('claimed');
    expect(row.attempts).toBe(1);
  });
  it('returns null on empty queue', () => {
    const db = makeTestDb();
    expect(claimNext(db, 'empty')).toBeNull();
  });
  it('claims only one at a time', () => {
    const db = makeTestDb();
    enqueue(db, 'q'); enqueue(db, 'q');
    const j1 = claimNext(db, 'q');
    const j2 = claimNext(db, 'q');
    expect(j1.id).not.toBe(j2.id);
    expect(claimNext(db, 'q')).toBeNull();
  });
  it('respects priority', () => {
    const db = makeTestDb();
    const low  = enqueue(db, 'q', {}, { priority: 0 });
    const high = enqueue(db, 'q', {}, { priority: 10 });
    expect(claimNext(db, 'q').id).toBe(high);
  });
  it('reaper reclaims expired leases', () => {
    const db = makeTestDb();
    enqueue(db, 'q');
    const job = claimNext(db, 'q');
    db.prepare(`UPDATE jobs SET lease_expires_at = datetime('now', '-1 second') WHERE id = ?`).run(job.id);
    db.prepare(`UPDATE jobs SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'retrying' END, lease_token = NULL, lease_expires_at = NULL WHERE queue = ? AND status IN ('claimed','running') AND lease_expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')`).run('q');
    const row = db.prepare('SELECT status FROM jobs WHERE id = ?').get(job.id);
    expect(row.status).toBe('retrying');
  });
  it('wrong lease cannot complete job', () => {
    const db = makeTestDb();
    enqueue(db, 'q');
    const job = claimNext(db, 'q');
    const r = db.prepare(`UPDATE jobs SET status='completed' WHERE id=? AND lease_token=?`).run(job.id, 'wrong');
    expect(r.changes).toBe(0);
    expect(db.prepare('SELECT status FROM jobs WHERE id = ?').get(job.id).status).toBe('claimed');
  });
});
