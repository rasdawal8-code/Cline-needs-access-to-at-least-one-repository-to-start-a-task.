import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { randomUUID } from 'crypto';

const TEST_DIR = path.join(os.tmpdir(), `gotu-inv-test-${randomUUID()}`);
fs.mkdirSync(TEST_DIR, { recursive: true });
process.env.DATA_DIR = TEST_DIR;
process.env.NODE_ENV = 'test';

let fastify, sessionCookie, csrf;

beforeAll(async () => {
  const { getDb, runMigrations } = await import('../../src/config/database.js');
  runMigrations(getDb());
  const { buildServer } = await import('../../src/server.js');
  fastify = await buildServer({ logger: false, noQueue: true, noStatic: true });
  await fastify.ready();
  // Register and login a test user
  const r = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
  csrf = r.json().csrfToken;
  const cook = r.headers['set-cookie'];
  await fastify.inject({ method: 'POST', url: '/api/auth/register', headers: { 'x-csrf-token': csrf, 'content-type': 'application/json', cookie: cook }, body: JSON.stringify({ username: 'invuser', password: 'SecurePassword123!' }) });
  const loginRes = await fastify.inject({ method: 'POST', url: '/api/auth/login', headers: { 'x-csrf-token': csrf, 'content-type': 'application/json', cookie: cook }, body: JSON.stringify({ username: 'invuser', password: 'SecurePassword123!' }) });
  sessionCookie = Array.isArray(loginRes.headers['set-cookie']) ? loginRes.headers['set-cookie'].join('; ') : loginRes.headers['set-cookie'];
  // Get a fresh CSRF token bound to the post-login session
  const csrfRes2 = await fastify.inject({ method: 'GET', url: '/api/csrf-token', headers: { cookie: sessionCookie } });
  csrf = csrfRes2.json().csrfToken;
});

afterAll(async () => {
  if (fastify) await fastify.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

async function api(method, url, body) {
  const headers = { 'x-csrf-token': csrf, cookie: sessionCookie };
  if (body) headers['content-type'] = 'application/json';
  return fastify.inject({ method, url, headers, body: body ? JSON.stringify(body) : undefined });
}

describe('Investigations — CRUD', () => {
  let invId;

  it('creates an investigation', async () => {
    const res = await api('POST', '/api/investigations', { title: 'Test Investigation', indicator: 'testuser123', indicatorType: 'username' });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.id).toBeTruthy();
    expect(body.title).toBe('Test Investigation');
    expect(body.status).toBe('pending');
    expect(body.indicator).toBe('testuser123');
    invId = body.id;
  });

  it('lists investigations for the user', async () => {
    const res = await api('GET', '/api/investigations');
    expect(res.statusCode).toBe(200);
    expect(res.json().total).toBeGreaterThan(0);
    expect(res.json().items[0].id).toBe(invId);
  });

  it('gets a single investigation', async () => {
    const res = await api('GET', `/api/investigations/${invId}`);
    expect(res.statusCode).toBe(200);
    expect(res.json().id).toBe(invId);
  });

  it('returns 404 for other user investigation', async () => {
    const res = await api('GET', '/api/investigations/nonexistent-id');
    expect(res.statusCode).toBe(404);
  });

  it('creates a root lead automatically', async () => {
    const res = await api('GET', `/api/investigations/${invId}/leads`);
    expect(res.statusCode).toBe(200);
    expect(res.json().total).toBe(1);
    expect(res.json().items[0].value).toBe('testuser123');
    expect(res.json().items[0].type).toBe('username');
  });
});

describe('Investigations — State Machine', () => {
  let invId;

  it('creates a pending investigation', async () => {
    const res = await api('POST', '/api/investigations', { title: 'State Test', indicator: 'example.com', indicatorType: 'domain' });
    invId = res.json().id;
    expect(res.json().status).toBe('pending');
  });

  it('starts (pending -> running)', async () => {
    const res = await api('POST', `/api/investigations/${invId}/start`);
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('running');
  });

  it('pauses (running -> paused)', async () => {
    const res = await api('POST', `/api/investigations/${invId}/pause`);
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('paused');
  });

  it('resumes (paused -> running)', async () => {
    const res = await api('POST', `/api/investigations/${invId}/resume`);
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('running');
  });

  it('stops (running -> stopped)', async () => {
    const res = await api('POST', `/api/investigations/${invId}/stop`);
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('stopped');
  });

  it('rejects invalid transition (stopped -> paused)', async () => {
    const res = await api('POST', `/api/investigations/${invId}/pause`);
    expect(res.statusCode).toBe(409);
  });

  it('deletes a stopped investigation', async () => {
    const res = await api('DELETE', `/api/investigations/${invId}`);
    expect(res.statusCode).toBe(204);
  });

  it('rejects deletion of running investigation', async () => {
    const r = await api('POST', '/api/investigations', { title: 'Running Del Test', indicator: 'foo@bar.com', indicatorType: 'email' });
    const id = r.json().id;
    await api('POST', `/api/investigations/${id}/start`);
    const res = await api('DELETE', `/api/investigations/${id}`);
    expect(res.statusCode).toBe(409);
    // cleanup
    await api('POST', `/api/investigations/${id}/stop`);
    await api('DELETE', `/api/investigations/${id}`);
  });
});

describe('Investigations — Data isolation', () => {
  it('user B cannot read user A investigation', async () => {
    // Create investigation as invuser (session already logged in)
    const res = await api('POST', '/api/investigations', { title: 'Private Inv', indicator: 'private.com', indicatorType: 'domain' });
    const invId = res.json().id;
    // Create user B and try to access user A investigation
    const rB = await fastify.inject({ method: 'GET', url: '/api/csrf-token' });
    const csrfB = rB.json().csrfToken;
    const cookB = rB.headers['set-cookie'];
    await fastify.inject({ method: 'POST', url: '/api/auth/register', headers: { 'x-csrf-token': csrfB, 'content-type': 'application/json', cookie: cookB }, body: JSON.stringify({ username: 'attackerB', password: 'SecurePassword123!' }) });
    const loginB = await fastify.inject({ method: 'POST', url: '/api/auth/login', headers: { 'x-csrf-token': csrfB, 'content-type': 'application/json', cookie: cookB }, body: JSON.stringify({ username: 'attackerB', password: 'SecurePassword123!' }) });
    const cookieB = Array.isArray(loginB.headers['set-cookie']) ? loginB.headers['set-cookie'].join('; ') : loginB.headers['set-cookie'];
    const steal = await fastify.inject({ method: 'GET', url: `/api/investigations/${invId}`, headers: { cookie: cookieB } });
    expect(steal.statusCode).toBe(404);
  });
});
