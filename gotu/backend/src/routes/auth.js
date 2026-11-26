/**
 * GOTU Auth Routes
 */

import { z } from 'zod/v4';
import { createUser, getUserByUsername, getUserById, recordFailedLogin, resetFailedLogin, isAccountLocked } from '../auth/users.js';
import { verifyPassword } from '../auth/passwords.js';
import { generateMfaSecret, generateQrCode, verifyTotp, enableMfa, getMfaSecret, generateBackupCodes, consumeBackupCode } from '../auth/mfa.js';
import { auditFromRequest } from '../audit/logger.js';
import { loadConfig } from '../config/env.js';

const RegisterSchema = z.object({
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_-]+$/),
  password: z.string().min(12).max(128),
  email: z.email().optional(),
});
const LoginSchema = z.object({ username: z.string().min(1), password: z.string().min(1) });
const MfaTokenSchema = z.object({ token: z.string().min(6).max(8) });
const BackupCodeSchema = z.object({ code: z.string().min(6).max(16) });

export default async function authRoutes(fastify) {

  fastify.post('/api/auth/register', async (req, reply) => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed', issues: parsed.error.issues });
    const { username, password, email } = parsed.data;
    if (getUserByUsername(username)) {
      auditFromRequest(req, 'auth.register.failed', 'user', null, { reason: 'username_taken' });
      return reply.code(409).send({ error: 'Username already taken' });
    }
    const user = await createUser({ username, password, email });
    auditFromRequest(req, 'auth.register', 'user', user.id, { username });
    return reply.code(201).send({ id: user.id, username: user.username, role: user.role });
  });

  fastify.post('/api/auth/login', async (req, reply) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed' });
    const { username, password } = parsed.data;
    const config = loadConfig();
    const user = getUserByUsername(username);
    if (!user) {
      await new Promise(r => setTimeout(r, 300));
      auditFromRequest(req, 'auth.login.failed', 'user', null, { reason: 'user_not_found' });
      return reply.code(401).send({ error: 'Invalid credentials' });
    }
    if (isAccountLocked(user)) {
      auditFromRequest(req, 'auth.login.locked', 'user', user.id, {});
      return reply.code(429).send({ error: 'Account temporarily locked. Try again later.' });
    }
    const valid = await verifyPassword(user.password_hash, password);
    if (!valid) {
      recordFailedLogin(user.id);
      auditFromRequest(req, 'auth.login.failed', 'user', user.id, { reason: 'wrong_password' });
      return reply.code(401).send({ error: 'Invalid credentials' });
    }
    resetFailedLogin(user.id);
    if (user.mfa_enabled || config.mfaRequired) {
      req.session.set('mfaPending', { userId: user.id, username: user.username, role: user.role });
      await req.session.regenerate(['mfaPending']);
      auditFromRequest(req, 'auth.login.mfa_required', 'user', user.id, {});
      return reply.send({ mfaRequired: true });
    }
    req.session.set('user', { id: user.id, username: user.username, role: user.role });
    await req.session.regenerate(['user']);
    auditFromRequest(req, 'auth.login', 'user', user.id, { username });
    return reply.send({ id: user.id, username: user.username, role: user.role });
  });

  fastify.post('/api/auth/mfa/verify', async (req, reply) => {
    const mfaPending = req.session.get('mfaPending');
    if (!mfaPending) return reply.code(401).send({ error: 'No pending MFA session' });
    const parsed = MfaTokenSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed' });
    const secret = getMfaSecret(mfaPending.userId);
    if (!secret) return reply.code(500).send({ error: 'MFA configuration error' });
    const valid = verifyTotp(secret, parsed.data.token);
    if (!valid) {
      auditFromRequest(req, 'auth.mfa.verify.failed', 'user', mfaPending.userId, {});
      return reply.code(401).send({ error: 'Invalid MFA token' });
    }
    req.session.set('user', mfaPending);
    await req.session.regenerate(['user']);
    auditFromRequest(req, 'auth.mfa.verify', 'user', mfaPending.userId, {});
    return reply.send({ id: mfaPending.userId, username: mfaPending.username, role: mfaPending.role });
  });

  fastify.post('/api/auth/mfa/backup', async (req, reply) => {
    const mfaPending = req.session.get('mfaPending');
    if (!mfaPending) return reply.code(401).send({ error: 'No pending MFA session' });
    const parsed = BackupCodeSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed' });
    const consumed = await consumeBackupCode(mfaPending.userId, parsed.data.code);
    if (!consumed) {
      auditFromRequest(req, 'auth.mfa.backup.failed', 'user', mfaPending.userId, {});
      return reply.code(401).send({ error: 'Invalid or already used backup code' });
    }
    req.session.set('user', mfaPending);
    await req.session.regenerate(['user']);
    auditFromRequest(req, 'auth.mfa.backup.used', 'user', mfaPending.userId, {});
    return reply.send({ id: mfaPending.userId, username: mfaPending.username, role: mfaPending.role });
  });

  fastify.post('/api/auth/mfa/enroll', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const { base32, otpauthUrl } = generateMfaSecret(user.username);
    const qrCodeDataUrl = await generateQrCode(otpauthUrl);
    req.session.set('mfaEnrollSecret', base32);
    auditFromRequest(req, 'auth.mfa.enroll.started', 'user', user.id, {});
    return reply.send({ qrCode: qrCodeDataUrl, manualEntry: base32 });
  });

  fastify.post('/api/auth/mfa/confirm', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const pendingSecret = req.session.get('mfaEnrollSecret');
    if (!pendingSecret) return reply.code(400).send({ error: 'No pending MFA enrollment.' });
    const parsed = MfaTokenSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed' });
    const valid = verifyTotp(pendingSecret, parsed.data.token);
    if (!valid) {
      auditFromRequest(req, 'auth.mfa.confirm.failed', 'user', user.id, {});
      return reply.code(401).send({ error: 'Token incorrect' });
    }
    const backupCodes = generateBackupCodes();
    await enableMfa(user.id, pendingSecret, backupCodes);
    req.session.set('mfaEnrollSecret', undefined);
    auditFromRequest(req, 'auth.mfa.enabled', 'user', user.id, {});
    return reply.send({ message: 'MFA enabled.', backupCodes });
  });

  fastify.post('/api/auth/logout', async (req, reply) => {
    const user = req.session.get('user');
    auditFromRequest(req, 'auth.logout', 'user', user?.id ?? null, {});
    await req.session.destroy();
    return reply.send({ message: 'Logged out' });
  });

  fastify.get('/api/auth/me', { preHandler: [requireAuth] }, async (req, reply) => {
    const sessionUser = req.session.get('user');
    const user = getUserById(sessionUser.id);
    if (!user) return reply.code(404).send({ error: 'User not found' });
    return reply.send({ id: user.id, username: user.username, email: user.email, role: user.role, mfaEnabled: user.mfa_enabled === 1 });
  });
}

export async function requireAuth(req, reply) {
  const user = req.session?.get('user');
  if (!user) return reply.code(401).send({ error: 'Authentication required' });
  req.user = user;
}

export function requireRole(...roles) {
  return async function(req, reply) {
    await requireAuth(req, reply);
    if (reply.sent) return;
    if (!roles.includes(req.user?.role)) return reply.code(403).send({ error: 'Insufficient permissions' });
  };
}
