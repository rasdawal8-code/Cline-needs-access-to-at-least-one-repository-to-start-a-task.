import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'crypto';

const TEST_DIR = path.join(os.tmpdir(), `gotu-auth-test-${randomUUID()}`);
fs.mkdirSync(TEST_DIR, { recursive: true });
process.env.DATA_DIR = TEST_DIR;
process.env.NODE_ENV = 'test';

let fastify;

beforeAll(async () => {
  const { getDb, runMigrations } = await import('../../src/config/database.js');
  runMigrations(getDb());
  const { buildServer } = await import('../../src/server.js');
  fastify = await buildServer({ logger: false, noQueue: true, noStatic: true });
  await fastify.ready();
});

afterAll(async () => {
  if (fastify) await fastify.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

// Get a CSRF token and the session cookie required to validate it
async function getSession() {
  const res = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
  const csrf = res.json().csrfToken;
  const cookie = Array.isArray(res.headers['set-cookie'])
    ? res.headers['set-cookie'].join('; ')
    : res.headers['set-cookie'];
  return { csrf, cookie };
}

async function inject(method, url, { csrf, cookie, body } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (csrf) headers['x-csrf-token'] = csrf;
  if (cookie) headers['cookie'] = cookie;
  return fastify.inject({ method, url, headers, body: body ? JSON.stringify(body) : undefined });
}

describe('Auth — Register', () => {
  it('registers a new user successfully', async () => {
    const { csrf, cookie } = await getSession();
    const res = await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'testuser1', password: 'SecurePassword123!', email: 'test@example.com' } });
    expect(res.statusCode).toBe(201);
    expect(res.json().username).toBe('testuser1');
    expect(res.json().id).toBeTruthy();
    expect(res.json().password_hash).toBeUndefined();
  });

  it('rejects duplicate username', async () => {
    const s1 = await getSession();
    await inject('POST', '/api/auth/register', { csrf: s1.csrf, cookie: s1.cookie, body: { username: 'dupuser2', password: 'SecurePassword123!' } });
    // Get a fresh session token for the second request
    const s2 = await getSession();
    const res = await inject('POST', '/api/auth/register', { csrf: s2.csrf, cookie: s2.cookie, body: { username: 'dupuser2', password: 'AnotherSecure123!' } });
    expect(res.statusCode).toBe(409);
  });

  it('rejects short passwords', async () => {
    const { csrf, cookie } = await getSession();
    const res = await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'newuser99', password: 'short' } });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid username characters', async () => {
    const { csrf, cookie } = await getSession();
    const res = await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'user spaces', password: 'SecurePassword123!' } });
    expect(res.statusCode).toBe(400);
  });
});

describe('Auth — Login', () => {
  it('logs in with correct credentials and sets session cookie', async () => {
    const { csrf, cookie } = await getSession();
    await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'loginuser', password: 'SecurePassword123!' } });
    const res = await inject('POST', '/api/auth/login', { csrf, cookie, body: { username: 'loginuser', password: 'SecurePassword123!' } });
    expect(res.statusCode).toBe(200);
    expect(res.json().username).toBe('loginuser');
    expect(res.headers['set-cookie']).toBeTruthy();
  });

  it('rejects wrong password', async () => {
    const { csrf, cookie } = await getSession();
    await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'wpuser', password: 'SecurePassword123!' } });
    const res = await inject('POST', '/api/auth/login', { csrf, cookie, body: { username: 'wpuser', password: 'Wrong999!' } });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('Invalid credentials');
  });

  it('rejects non-existent user with same error message', async () => {
    const { csrf, cookie } = await getSession();
    const res = await inject('POST', '/api/auth/login', { csrf, cookie, body: { username: 'ghost9999', password: 'SomePassword123!' } });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('Invalid credentials');
  });
});

describe('Auth — Session protection', () => {
  it('/api/auth/me returns 401 without session', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/api/auth/me' });
    expect(res.statusCode).toBe(401);
  });

  it('/api/auth/me returns user info with valid session', async () => {
    const { csrf, cookie } = await getSession();
    await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'meuser', password: 'SecurePassword123!', email: 'me@example.com' } });
    const loginRes = await inject('POST', '/api/auth/login', { csrf, cookie, body: { username: 'meuser', password: 'SecurePassword123!' } });
    const sessionCookie = Array.isArray(loginRes.headers['set-cookie'])
      ? loginRes.headers['set-cookie'].join('; ')
      : loginRes.headers['set-cookie'];
    const meRes = await fastify.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: sessionCookie } });
    expect(meRes.statusCode).toBe(200);
    expect(meRes.json().username).toBe('meuser');
    expect(meRes.json().email).toBe('me@example.com');
    expect(meRes.json().password_hash).toBeUndefined();
    expect(meRes.json().mfa_secret).toBeUndefined();
  });

  it('logout destroys session — subsequent /me returns 401', async () => {
    const { csrf, cookie } = await getSession();
    await inject('POST', '/api/auth/register', { csrf, cookie, body: { username: 'logoutuser', password: 'SecurePassword123!' } });
    const loginRes = await inject('POST', '/api/auth/login', { csrf, cookie, body: { username: 'logoutuser', password: 'SecurePassword123!' } });
    const sessionCookie = Array.isArray(loginRes.headers['set-cookie'])
      ? loginRes.headers['set-cookie'].join('; ')
      : loginRes.headers['set-cookie'];
    await fastify.inject({ method: 'POST', url: '/api/auth/logout', headers: { 'x-csrf-token': csrf, cookie: sessionCookie } });
    const meRes = await fastify.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: sessionCookie } });
    expect(meRes.statusCode).toBe(401);
  });

  it('data isolation: user A cannot access user B session', async () => {
    const s1 = await getSession();
    const s2 = await getSession();
    await inject('POST', '/api/auth/register', { csrf: s1.csrf, cookie: s1.cookie, body: { username: 'userA', password: 'SecurePassword123!' } });
    await inject('POST', '/api/auth/register', { csrf: s2.csrf, cookie: s2.cookie, body: { username: 'userB', password: 'SecurePassword123!' } });
    const loginA = await inject('POST', '/api/auth/login', { csrf: s1.csrf, cookie: s1.cookie, body: { username: 'userA', password: 'SecurePassword123!' } });
    const cookieA = Array.isArray(loginA.headers['set-cookie'])?loginA.headers['set-cookie'].join('; '):loginA.headers['set-cookie'];
    // userA cookie should return userA, not userB
    const meA = await fastify.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: cookieA } });
    expect(meA.statusCode).toBe(200);
    expect(meA.json().username).toBe('userA');
  });
});

describe('System', () => {
  it('health check returns ok', async () => {
    const res = await fastify.inject({ method: 'GET', url: '/api/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('ok');
  });
});
