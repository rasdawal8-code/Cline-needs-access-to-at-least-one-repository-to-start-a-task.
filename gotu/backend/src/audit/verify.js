/**
 * GOTU Audit Log Verifier
 * Run as: node src/audit/verify.js
 * Verifies HMAC integrity and hash chain continuity of the audit log.
 * Detects: modification, deletion, and reordering of records.
 */

import { getDb, runMigrations } from '../config/database.js';
import { loadConfig } from '../config/env.js';
import { computeAuditHmac, hashAuditRecord } from '../config/crypto.js';

const GENESIS_HASH = '0'.repeat(64);

export async function verifyAuditLog() {
  const config = loadConfig();
  const db = getDb();

  const records = db.prepare(
    'SELECT * FROM audit_log ORDER BY seq ASC'
  ).all();

  if (records.length === 0) {
    return { ok: true, total: 0, errors: [], message: 'Audit log is empty.' };
  }

  const errors = [];
  let prevHash = GENESIS_HASH;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    // 1. Check sequence continuity
    const expectedSeq = i + 1;
    if (rec.seq !== expectedSeq) {
      errors.push({
        type: 'SEQUENCE_GAP',
        message: `Sequence gap at index ${i}: expected seq ${expectedSeq}, found ${rec.seq}`,
        seq: rec.seq,
      });
    }

    // 2. Verify prev_hash matches previous record's hash
    if (rec.prev_hash !== prevHash) {
      errors.push({
        type: 'CHAIN_BROKEN',
        message: `Hash chain broken at seq ${rec.seq}: prev_hash does not match previous record`,
        seq: rec.seq,
        expected: prevHash,
        found: rec.prev_hash,
      });
    }

    // 3. Verify HMAC
    const { hmac: storedHmac, ...recordWithoutHmac } = rec;
    const expectedHmac = computeAuditHmac(recordWithoutHmac, config.auditHmacKey);
    if (storedHmac !== expectedHmac) {
      errors.push({
        type: 'HMAC_MISMATCH',
        message: `HMAC mismatch at seq ${rec.seq}: record has been modified`,
        seq: rec.seq,
      });
    }

    prevHash = hashAuditRecord(rec);
  }

  const ok = errors.length === 0;
  return {
    ok,
    total:   records.length,
    firstAt: records[0]?.timestamp,
    lastAt:  records[records.length - 1]?.timestamp,
    errors,
    message: ok
      ? `Audit log verified: ${records.length} records, chain intact.`
      : `Audit log has ${errors.length} integrity error(s).`,
  };
}

// CLI entrypoint
if (process.argv[1]?.endsWith('verify.js')) {
  runMigrations(getDb());
  verifyAuditLog().then(result => {
    console.log(result.message);
    if (!result.ok) {
      console.error('Errors:', JSON.stringify(result.errors, null, 2));
      process.exit(1);
    }
    process.exit(0);
  }).catch(err => {
    console.error('Verification failed:', err.message);
    process.exit(2);
  });
}
