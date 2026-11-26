/**
 * GOTU API Key Management Routes
 * POST /api/api-keys       — store encrypted key
 * GET  /api/api-keys       — list configured services
 * DELETE /api/api-keys/:id — remove key
 */
import { z } from 'zod/v4';
import { randomUUID } from 'crypto';
import { getDb } from '../config/database.js';
import { encrypt, decrypt } from '../config/crypto.js';
import { loadConfig } from '../config/env.js';
import { requireAuth } from './auth.js';
import { auditFromRequest } from '../audit/logger.js';

const CreateApiKeySchema = z.object({
  service: z.string().min(1).max(50),
  keyValue: z.string().min(1).max(2000),
  label: z.string().max(100).optional(),
});

export default async function apiKeyRoutes(fastify) {

  fastify.post('/api/api-keys', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = CreateApiKeySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed', issues: parsed.error.issues });
    const config = loadConfig();
    const db = getDb();
    const user = req.session.get('user');
    const { service, keyValue, label } = parsed.data;
    const encKey = encrypt(keyValue, config.encryptionKey);
    const id = randomUUID();
    db.prepare(
      'INSERT INTO api_keys (id, user_id, service, label, key_value) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, service) DO UPDATE SET key_value = excluded.key_value, label = excluded.label'
    ).run(id, user.id, service, label ?? null, encKey);
    auditFromRequest(req, 'api_key.set', 'api_key', null, { service });
    return reply.code(201).send({ message: `API key for ${service} stored securely.` });
  });

  fastify.get('/api/api-keys', { preHandler: [requireAuth] }, async (req, reply) => {
    const db = getDb();
    const user = req.session.get('user');
    const keys = db.prepare('SELECT id, service, label, created_at FROM api_keys WHERE user_id = ? ORDER BY service').all(user.id);
    return reply.send({ items: keys });
  });

  fastify.delete('/api/api-keys/:id', { preHandler: [requireAuth] }, async (req, reply) => {
    const db = getDb();
    const user = req.session.get('user');
    const row = db.prepare('SELECT id, service FROM api_keys WHERE id = ? AND user_id = ?').get(req.params.id, user.id);
    if (!row) return reply.code(404).send({ error: 'API key not found' });
    db.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').run(row.id, user.id);
    auditFromRequest(req, 'api_key.delete', 'api_key', row.id, { service: row.service });
    return reply.code(204).send();
  });
}
