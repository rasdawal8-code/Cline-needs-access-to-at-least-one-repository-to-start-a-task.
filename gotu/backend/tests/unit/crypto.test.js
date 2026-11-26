/**
 * Phase 4A Tests: Cryptographic utilities
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { encrypt, decrypt, computeAuditHmac, hashAuditRecord, safeEqual } from '../../src/config/crypto.js';

const KEY = crypto.randomBytes(32);
const HMAC_KEY = crypto.randomBytes(32);

describe('AES-256-GCM Encryption', () => {
  it('encrypts and decrypts correctly', () => {
    const plaintext = 'classified intelligence data';
    const blob = encrypt(plaintext, KEY);
    expect(decrypt(blob, KEY)).toBe(plaintext);
  });

  it('produces different ciphertexts each call (random IV)', () => {
    const blob1 = encrypt('same data', KEY);
    const blob2 = encrypt('same data', KEY);
    expect(blob1).not.toBe(blob2);
  });

  it('the blob does not contain the plaintext', () => {
    const blob = encrypt('super-secret-value-12345', KEY);
    expect(blob).not.toContain('super-secret-value-12345');
  });

  it('throws on wrong key', () => {
    const blob = encrypt('secret', KEY);
    const wrongKey = crypto.randomBytes(32);
    expect(() => decrypt(blob, wrongKey)).toThrow();
  });

  it('throws on tampered ciphertext', () => {
    const blob = encrypt('secret', KEY);
    const parsed = JSON.parse(blob);
    // Flip a byte in the ciphertext
    const ctBuf = Buffer.from(parsed.ct, 'base64');
    ctBuf[0] ^= 0xFF;
    parsed.ct = ctBuf.toString('base64');
    expect(() => decrypt(JSON.stringify(parsed), KEY)).toThrow();
  });

  it('throws on tampered auth tag', () => {
    const blob = encrypt('secret', KEY);
    const parsed = JSON.parse(blob);
    const tagBuf = Buffer.from(parsed.tag, 'base64');
    tagBuf[0] ^= 0xFF;
    parsed.tag = tagBuf.toString('base64');
    expect(() => decrypt(JSON.stringify(parsed), KEY)).toThrow();
  });

  it('handles null input gracefully', () => {
    expect(encrypt(null, KEY)).toBeNull();
    expect(decrypt(null, KEY)).toBeNull();
  });

  it('round-trips JSON', () => {
    const data = { nested: { value: [1, 2, 3] }, flag: true };
    const blob = encrypt(JSON.stringify(data), KEY);
    const restored = JSON.parse(decrypt(blob, KEY));
    expect(restored).toEqual(data);
  });
});

describe('Audit HMAC', () => {
  const makeRecord = (overrides = {}) => ({
    id:          'test-id-123',
    seq:         1,
    prev_hash:   '0'.repeat(64),
    user_id:     'user-abc',
    action:      'auth.login',
    resource:    'user',
    resource_id: 'user-abc',
    detail:      '{"encrypted":"blob"}',
    ip:          '1.2.3.4',
    user_agent:  'TestAgent/1.0',
    timestamp:   '2026-01-01T00:00:00.000Z',
    ...overrides,
  });

  it('produces consistent HMAC for same input', () => {
    const record = makeRecord();
    const hmac1 = computeAuditHmac(record, HMAC_KEY);
    const hmac2 = computeAuditHmac(record, HMAC_KEY);
    expect(hmac1).toBe(hmac2);
  });

  it('detects modification of any field', () => {
    const record = makeRecord();
    const originalHmac = computeAuditHmac(record, HMAC_KEY);
    const fields = ['user_id', 'action', 'resource', 'resource_id', 'detail', 'ip', 'user_agent', 'timestamp'];
    for (const field of fields) {
      const tampered = { ...record, [field]: record[field] + '_tampered' };
      expect(computeAuditHmac(tampered, HMAC_KEY)).not.toBe(originalHmac);
    }
  });

  it('detects wrong HMAC key', () => {
    const record = makeRecord();
    const hmac1 = computeAuditHmac(record, HMAC_KEY);
    const hmac2 = computeAuditHmac(record, crypto.randomBytes(32));
    expect(hmac1).not.toBe(hmac2);
  });

  it('hash chain: different records produce different hashes', () => {
    const r1 = { ...makeRecord(), hmac: 'hmac1' };
    const r2 = { ...makeRecord({ seq: 2 }), hmac: 'hmac2' };
    expect(hashAuditRecord(r1)).not.toBe(hashAuditRecord(r2));
  });
});

describe('safeEqual', () => {
  it('returns true for equal strings', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
  });
  it('returns false for different strings', () => {
    expect(safeEqual('abc', 'xyz')).toBe(false);
  });
  it('returns false for different lengths', () => {
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
  it('handles non-strings', () => {
    expect(safeEqual(null, 'abc')).toBe(false);
  });
});
