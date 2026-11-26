/**
 * Phase 4A Tests: Audit Log — HMAC integrity and hash chain
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'crypto';

const TEST_DIR = path.join(os.tmpdir(), `gotu-audit-test-${randomUUID()}`);
fs.mkdirSync(TEST_DIR, { recursive: true });
process.env.DATA_DIR = TEST_DIR;
process.env.NODE_ENV = 'test';

let db, writeAuditLog, verifyAuditLog;

beforeAll(async () => {
  const dbMod = await import('../../src/config/database.js');
  db = dbMod.getDb();
  dbMod.runMigrations(db);
  ({ writeAuditLog } = await import('../../src/audit/logger.js'));
  ({ verifyAuditLog } = await import('../../src/audit/verify.js'));
});

afterAll(() => {
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

function writeEntry(overrides = {}) {
  return writeAuditLog({
    userId:     'user-123',
    action:     'test.action',
    resource:   'test',
    resourceId: 'res-1',
    detail:     { key: 'value' },
    ip:         '127.0.0.1',
    userAgent:  'TestAgent/1.0',
    ...overrides,
  });
}

describe('Audit Log — HMAC and hash chain', () => {
  it('writes entries and verifies clean chain', async () => {
    writeEntry();
    writeEntry({ action: 'test.action2' });
    writeEntry({ action: 'test.action3' });
    const result = await verifyAuditLog();
    expect(result.ok).toBe(true);
    expect(result.total).toBeGreaterThanOrEqual(3);
  });

  it('detects modification of a record', async () => {
    writeEntry({ action: 'tamper.test' });
    // Directly modify a record in the DB (bypassing the trigger is not possible,
    // but we simulate what happens if the trigger is dropped)
    // Instead we verify HMAC detects modification by checking the verifier logic directly
    const { computeAuditHmac } = await import('../../src/config/crypto.js');
    const { loadConfig } = await import('../../src/config/env.js');
    const config = loadConfig();
    const rec = db.prepare('SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    // Tamper with the in-memory representation
    const tampered = { ...rec, action: 'tampered.action' };
    const recomputedHmac = computeAuditHmac(tampered, config.auditHmacKey);
    // The HMAC will differ from stored
    expect(recomputedHmac).not.toBe(rec.hmac);
  });

  it('trigger blocks UPDATE on audit_log', () => {
    writeEntry({ action: 'update.block.test' });
    const rec = db.prepare('SELECT id FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    expect(() => {
      db.prepare("UPDATE audit_log SET action = 'hacked' WHERE id = ?").run(rec.id);
    }).toThrow(/immutable/i);
  });

  it('trigger blocks DELETE on audit_log', () => {
    writeEntry({ action: 'delete.block.test' });
    const rec = db.prepare('SELECT id FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    expect(() => {
      db.prepare('DELETE FROM audit_log WHERE id = ?').run(rec.id);
    }).toThrow(/cannot be deleted/i);
  });

  it('detail field is encrypted (not plaintext in DB)', () => {
    const secretValue = 'very-secret-detail-' + randomUUID();
    writeEntry({ detail: { secret: secretValue } });
    const rec = db.prepare('SELECT detail FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    expect(rec.detail).not.toContain(secretValue);
    // It should be a JSON blob with iv, tag, ct
    const parsed = JSON.parse(rec.detail);
    expect(parsed.iv).toBeTruthy();
    expect(parsed.ct).toBeTruthy();
  });

  it('seq is monotonically increasing', () => {
    const before = db.prepare('SELECT MAX(seq) as maxseq FROM audit_log').get().maxseq ?? 0;
    writeEntry({ action: 'seq.test.1' });
    writeEntry({ action: 'seq.test.2' });
    const after = db.prepare('SELECT MAX(seq) as maxseq FROM audit_log').get().maxseq;
    expect(after).toBeGreaterThan(before + 1);
  });
});
