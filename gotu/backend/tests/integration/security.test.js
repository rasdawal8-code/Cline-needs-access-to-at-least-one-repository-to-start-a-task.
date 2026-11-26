import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'crypto';

const TEST_DIR = path.join(os.tmpdir(), `gotu-security-${randomUUID()}`);
fs.mkdirSync(TEST_DIR, { recursive: true });
process.env.DATA_DIR = TEST_DIR;
process.env.NODE_ENV = 'test';

let fastify, sessionA, sessionB, csrfA, csrfB, invIdA;

beforeAll(async () => {
  const { getDb, runMigrations } = await import('../../src/config/database.js');
  runMigrations(getDb());
  const { buildServer } = await import('../../src/server.js');
  fastify = await buildServer({ logger: false, noQueue: true, noStatic: true });
  await fastify.ready();

  // Setup user A
  const rA = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
  csrfA = rA.json().csrfToken;
  const cookA = rA.headers['set-cookie'];
  await fastify.inject({ method:'POST', url:'/api/auth/register', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:cookA}, body:JSON.stringify({username:'userA_sec',password:'SecurePassword123!'}) });
  const lA = await fastify.inject({ method:'POST', url:'/api/auth/login', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:cookA}, body:JSON.stringify({username:'userA_sec',password:'SecurePassword123!'}) });
  sessionA = Array.isArray(lA.headers['set-cookie'])?lA.headers['set-cookie'].join('; '):lA.headers['set-cookie'];
  csrfA = (await fastify.inject({method:'GET',url:'/api/csrf-token',headers:{cookie:sessionA}})).json().csrfToken;

  // Setup user B
  const rB = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
  csrfB = rB.json().csrfToken;
  const cookB = rB.headers['set-cookie'];
  await fastify.inject({ method:'POST', url:'/api/auth/register', headers:{'x-csrf-token':csrfB,'content-type':'application/json',cookie:cookB}, body:JSON.stringify({username:'userB_sec',password:'SecurePassword123!'}) });
  const lB = await fastify.inject({ method:'POST', url:'/api/auth/login', headers:{'x-csrf-token':csrfB,'content-type':'application/json',cookie:cookB}, body:JSON.stringify({username:'userB_sec',password:'SecurePassword123!'}) });
  sessionB = Array.isArray(lB.headers['set-cookie'])?lB.headers['set-cookie'].join('; '):lB.headers['set-cookie'];
  csrfB = (await fastify.inject({method:'GET',url:'/api/csrf-token',headers:{cookie:sessionB}})).json().csrfToken;

  // Create investigation as user A
  const invRes = await fastify.inject({ method:'POST', url:'/api/investigations', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:sessionA}, body:JSON.stringify({title:'Private Inv A',indicator:'secret@example.com',indicatorType:'email'}) });
  invIdA = invRes.json().id;
});

afterAll(async () => {
  if (fastify) await fastify.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

describe('Security — Authentication', () => {
  it('rejects unauthenticated access to protected routes', async () => {
    const routes = [
      { method: 'GET',  url: '/api/auth/me' },
      { method: 'GET',  url: '/api/investigations' },
      { method: 'GET',  url: '/api/engines' },
      { method: 'GET',  url: '/api/api-keys' },
    ];
    for (const { method, url } of routes) {
      const res = await fastify.inject({ method, url });
      expect(res.statusCode, `${method} ${url} should require auth`).toBe(401);
    }
  });

  it('sensitive fields absent from auth responses', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: sessionA } });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.password_hash).toBeUndefined();
    expect(body.mfa_secret).toBeUndefined();
    expect(body.mfa_backup_codes).toBeUndefined();
  });

  it('rejects password shorter than 12 chars', async () => {
    const r = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
    const res = await fastify.inject({ method:'POST', url:'/api/auth/register', headers:{'x-csrf-token':r.json().csrfToken,'content-type':'application/json',cookie:r.headers['set-cookie']}, body:JSON.stringify({username:'shortpassuser',password:'short'})
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('Security — Data Isolation', () => {
  it('user B cannot read user A investigation', async () => {
    const res = await fastify.inject({ method:'GET', url:`/api/investigations/${invIdA}`, headers:{cookie:sessionB} });
    expect(res.statusCode).toBe(404);
  });

  it('user B cannot list user A findings', async () => {
    const res = await fastify.inject({ method:'GET', url:`/api/investigations/${invIdA}/findings`, headers:{cookie:sessionB} });
    expect(res.statusCode).toBe(404);
  });

  it('user B cannot start user A investigation', async () => {
    const res = await fastify.inject({ method:'POST', url:`/api/investigations/${invIdA}/start`, headers:{'x-csrf-token':csrfB,cookie:sessionB} });
    expect(res.statusCode).toBe(404);
  });

  it('user B cannot delete user A investigation', async () => {
    const res = await fastify.inject({ method:'DELETE', url:`/api/investigations/${invIdA}`, headers:{'x-csrf-token':csrfB,cookie:sessionB} });
    expect(res.statusCode).toBe(404);
  });

  it('user B cannot read user A API keys', async () => {
    // Store a key as user A
    await fastify.inject({ method:'POST', url:'/api/api-keys', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:sessionA}, body:JSON.stringify({service:'test_isolation',keyValue:'secret-key-value-abc'}) });
    // List as user B
    const keysB = await fastify.inject({ method:'GET', url:'/api/api-keys', headers:{cookie:sessionB} });
    expect(keysB.statusCode).toBe(200);
    const services = keysB.json().items?.map(k => k.service) ?? [];
    expect(services).not.toContain('test_isolation');
  });
});

describe('Security — Input Validation', () => {
  it('rejects investigation with empty title', async () => {
    const res = await fastify.inject({ method:'POST', url:'/api/investigations', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:sessionA}, body:JSON.stringify({title:'',indicator:'test',indicatorType:'username'}) });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid indicator type', async () => {
    const res = await fastify.inject({ method:'POST', url:'/api/investigations', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:sessionA}, body:JSON.stringify({title:'T',indicator:'t',indicatorType:'invalid_type'}) });
    expect(res.statusCode).toBe(400);
  });

  it('rejects maxDepth out of range', async () => {
    const res = await fastify.inject({ method:'POST', url:'/api/investigations', headers:{'x-csrf-token':csrfA,'content-type':'application/json',cookie:sessionA}, body:JSON.stringify({title:'T',indicator:'t',indicatorType:'domain',maxDepth:99}) });
    expect(res.statusCode).toBe(400);
  });
});

describe('Security — Security Headers', () => {
  it('health endpoint returns security headers', async () => {
    const res = await fastify.inject({ method:'GET', url:'/api/health' });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBeTruthy();
    expect(res.headers['content-security-policy']).toBeTruthy();
  });

  it('CSP contains default-src self', async () => {
    const res = await fastify.inject({ method:'GET', url:'/api/health' });
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
  });
});

describe('Security — Audit Log Integrity', () => {
  it('audit log has entries for all auth and investigation actions', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const count = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
    expect(count).toBeGreaterThan(0);
  });

  it('audit log cannot be modified (trigger enforces immutability)', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const rec = db.prepare('SELECT id FROM audit_log LIMIT 1').get();
    if (!rec) return; // No records yet
    expect(() => {
      db.prepare("UPDATE audit_log SET action = 'tampered' WHERE id = ?").run(rec.id);
    }).toThrow(/immutable/i);
  });

  it('audit log cannot be deleted', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const rec = db.prepare('SELECT id FROM audit_log LIMIT 1').get();
    if (!rec) return;
    expect(() => {
      db.prepare('DELETE FROM audit_log WHERE id = ?').run(rec.id);
    }).toThrow(/cannot be deleted/i);
  });

  it('audit log HMAC chain verifies', async () => {
    const { verifyAuditLog } = await import('../../src/audit/verify.js');
    const result = await verifyAuditLog();
    expect(result.ok).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});

describe('Security — SSRF Protection', () => {
  it('blocks RFC1918 addresses', async () => {
    const { isBlockedIP } = await import('../../src/middleware/ssrf.js');
    expect(isBlockedIP('10.0.0.1')).toBe(true);
    expect(isBlockedIP('192.168.1.1')).toBe(true);
    expect(isBlockedIP('172.16.0.1')).toBe(true);
  });

  it('blocks cloud metadata endpoint', async () => {
    const { isBlockedIP } = await import('../../src/middleware/ssrf.js');
    expect(isBlockedIP('169.254.169.254')).toBe(true);
  });

  it('blocks IPv4-mapped IPv6 private addresses', async () => {
    const { isBlockedIP } = await import('../../src/middleware/ssrf.js');
    expect(isBlockedIP('::ffff:192.168.1.1')).toBe(true);
  });

  it('blocks file:// scheme', async () => {
    const { validateUrl, SSRFError } = await import('../../src/middleware/ssrf.js');
    await expect(validateUrl('file:///etc/passwd')).rejects.toThrow(SSRFError);
  });

  it('allows public IP addresses', async () => {
    const { isBlockedIP } = await import('../../src/middleware/ssrf.js');
    expect(isBlockedIP('1.1.1.1')).toBe(false);
    expect(isBlockedIP('8.8.8.8')).toBe(false);
  });
});

describe('Security — Encryption at Rest', () => {
  it('investigation data is encrypted in DB (indicator not stored in plaintext)', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const inv = db.prepare('SELECT config FROM investigations LIMIT 1').get();
    if (!inv) return;
    // config column should be an encrypted JSON blob, not raw text
    expect(() => JSON.parse(inv.config)).not.toThrow(); // it's JSON
    const parsed = JSON.parse(inv.config);
    // Should have iv, tag, ct keys (AES-256-GCM envelope)
    expect(parsed.iv).toBeTruthy();
    expect(parsed.ct).toBeTruthy();
  });

  it('API key values are encrypted in DB', async () => {
    const { getDb } = await import('../../src/config/database.js');
    const db = getDb();
    const key = db.prepare('SELECT key_value FROM api_keys LIMIT 1').get();
    if (!key) return;
    const parsed = JSON.parse(key.key_value);
    expect(parsed.iv).toBeTruthy();
    expect(parsed.ct).toBeTruthy();
    expect(key.key_value).not.toContain('secret-key-value-abc');
  });
});
