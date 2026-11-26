/**
 * GOTU Investigation Routes — Phase 4B
 */

import { z } from 'zod/v4';
import { randomUUID } from 'crypto';
import crypto from 'crypto';
import { getDb } from '../config/database.js';
import { encrypt, decrypt } from '../config/crypto.js';
import { loadConfig } from '../config/env.js';
import { requireAuth } from './auth.js';
import { auditFromRequest } from '../audit/logger.js';
import { enqueueInvestigation, abortInvestigation } from '../jobs/investigation-worker.js';

const CreateInvestigationSchema = z.object({
  title: z.string().min(1).max(200),
  indicator: z.string().min(1).max(2000),
  indicatorType: z.enum(['username','email','domain','url','name','image','organization','ip','phone','other']),
  maxDepth: z.number().int().min(1).max(5).optional().default(2),
  maxDurationSeconds: z.number().int().min(60).max(3600).optional().default(600),
  maxApiCalls: z.number().int().min(10).max(5000).optional().default(500),
  requireLeadApproval: z.boolean().optional().default(false),
});

const VALID_TRANSITIONS = {
  pending:   ['running', 'stopped'],
  running:   ['paused', 'stopped', 'completed', 'failed'],
  paused:    ['running', 'stopped'],
  stopped:   [],
  completed: [],
  failed:    ['running'],
};

function getInvestigationOwnedBy(id, userId) {
  return getDb().prepare('SELECT * FROM investigations WHERE id = ? AND user_id = ?').get(id, userId);
}

function decryptInvestigation(inv, key) {
  if (!inv) return null;
  return {
    ...inv,
    config: inv.config ? JSON.parse(decrypt(inv.config, key)) : {},
    summary: inv.summary ? decrypt(inv.summary, key) : null,
  };
}

function leadFingerprint(type, value) {
  return crypto.createHash('sha256').update(`${type}:${value.toLowerCase().trim()}`).digest('hex');
}

export default async function investigationRoutes(fastify) {

  fastify.post('/api/investigations', { preHandler: [requireAuth] }, async (req, reply) => {
    const parsed = CreateInvestigationSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'Validation failed', issues: parsed.error.issues });
    const config = loadConfig();
    const db = getDb();
    const user = req.session.get('user');
    const data = parsed.data;
    const id = randomUUID();
    const encryptedConfig = encrypt(JSON.stringify({ maxDepth: data.maxDepth, maxDurationSeconds: data.maxDurationSeconds, maxApiCalls: data.maxApiCalls, requireLeadApproval: data.requireLeadApproval }), config.encryptionKey);
    db.prepare('INSERT INTO investigations (id, user_id, title, indicator, indicator_type, config, max_depth, max_duration_s, max_api_calls, require_lead_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, user.id, data.title, data.indicator, data.indicatorType, encryptedConfig, data.maxDepth, data.maxDurationSeconds, data.maxApiCalls, data.requireLeadApproval ? 1 : 0);
    const fp = leadFingerprint(data.indicatorType, data.indicator);
    db.prepare("INSERT OR IGNORE INTO investigation_leads (id, investigation_id, type, value, fingerprint, depth, status) VALUES (?, ?, ?, ?, ?, 0, 'pending')").run(randomUUID(), id, data.indicatorType, data.indicator, fp);
    auditFromRequest(req, 'investigation.create', 'investigation', id, { title: data.title });
    const inv = db.prepare('SELECT * FROM investigations WHERE id = ?').get(id);
    return reply.code(201).send(decryptInvestigation(inv, config.encryptionKey));
  });

  fastify.get('/api/investigations', { preHandler: [requireAuth] }, async (req, reply) => {
    const config = loadConfig();
    const db = getDb();
    const user = req.session.get('user');
    const limit = Math.min(parseInt(req.query.limit ?? '50', 10), 200);
    const offset = parseInt(req.query.offset ?? '0', 10);
    const rows = db.prepare('SELECT i.*, (SELECT COUNT(*) FROM findings WHERE investigation_id = i.id) AS finding_count, (SELECT COUNT(*) FROM investigation_leads WHERE investigation_id = i.id) AS lead_count FROM investigations i WHERE i.user_id = ? ORDER BY i.created_at DESC LIMIT ? OFFSET ?').all(user.id, limit, offset);
    const total = db.prepare('SELECT COUNT(*) AS n FROM investigations WHERE user_id = ?').get(user.id).n;
    return reply.send({ total, limit, offset, items: rows.map(r => decryptInvestigation(r, config.encryptionKey)) });
  });

  fastify.get('/api/investigations/:id', { preHandler: [requireAuth] }, async (req, reply) => {
    const config = loadConfig();
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    return reply.send(decryptInvestigation(inv, config.encryptionKey));
  });

  async function transitionState(req, reply, targetStatus) {
    const user = req.session.get('user');
    const db = getDb();
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const allowed = VALID_TRANSITIONS[inv.status] ?? [];
    if (!allowed.includes(targetStatus)) return reply.code(409).send({ error: `Cannot transition from '${inv.status}' to '${targetStatus}'`, currentStatus: inv.status });
    const now = new Date().toISOString();
    // Use separate update to avoid SQL quoting issues with CASE WHEN
    const setStarted = targetStatus === 'running' && !inv.started_at;
    const setCompleted = ['completed','stopped','failed'].includes(targetStatus);
    if (setStarted && setCompleted) {
      db.prepare("UPDATE investigations SET status=?, started_at=?, completed_at=?, updated_at=? WHERE id=? AND user_id=?").run(targetStatus, now, now, now, inv.id, user.id);
    } else if (setStarted) {
      db.prepare("UPDATE investigations SET status=?, started_at=?, updated_at=? WHERE id=? AND user_id=?").run(targetStatus, now, now, inv.id, user.id);
    } else if (setCompleted) {
      db.prepare("UPDATE investigations SET status=?, completed_at=?, updated_at=? WHERE id=? AND user_id=?").run(targetStatus, now, now, inv.id, user.id);
    } else {
      db.prepare("UPDATE investigations SET status=?, updated_at=? WHERE id=? AND user_id=?").run(targetStatus, now, inv.id, user.id);
    }
    auditFromRequest(req, `investigation.${targetStatus}`, 'investigation', inv.id, { previousStatus: inv.status });
    // Start/resume background processing
    if (targetStatus === 'running') {
      enqueueInvestigation(inv.id, user.id);
    } else if (targetStatus === 'stopped') {
      abortInvestigation(inv.id);
    }
    return reply.send({ id: inv.id, status: targetStatus });
  }

  fastify.post('/api/investigations/:id/start',  { preHandler: [requireAuth] }, (r,p) => transitionState(r,p,'running'));
  fastify.post('/api/investigations/:id/pause',  { preHandler: [requireAuth] }, (r,p) => transitionState(r,p,'paused'));
  fastify.post('/api/investigations/:id/resume', { preHandler: [requireAuth] }, (r,p) => transitionState(r,p,'running'));
  fastify.post('/api/investigations/:id/stop',   { preHandler: [requireAuth] }, (r,p) => transitionState(r,p,'stopped'));

  fastify.get('/api/investigations/:id/leads', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const db = getDb();
    const rows = req.query.status
      ? db.prepare('SELECT * FROM investigation_leads WHERE investigation_id = ? AND status = ? ORDER BY created_at ASC').all(inv.id, req.query.status)
      : db.prepare('SELECT * FROM investigation_leads WHERE investigation_id = ? ORDER BY created_at ASC').all(inv.id);
    return reply.send({ total: rows.length, items: rows });
  });

  fastify.post('/api/investigations/:id/leads/:lid/approve', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const r = getDb().prepare("UPDATE investigation_leads SET status = 'approved' WHERE id = ? AND investigation_id = ? AND status = 'pending'").run(req.params.lid, inv.id);
    if (r.changes === 0) return reply.code(404).send({ error: 'Lead not found or not pending' });
    auditFromRequest(req, 'investigation.lead.approve', 'investigation_lead', req.params.lid, {});
    return reply.send({ id: req.params.lid, status: 'approved' });
  });

  fastify.post('/api/investigations/:id/leads/:lid/reject', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const r = getDb().prepare("UPDATE investigation_leads SET status = 'rejected' WHERE id = ? AND investigation_id = ? AND status = 'pending'").run(req.params.lid, inv.id);
    if (r.changes === 0) return reply.code(404).send({ error: 'Lead not found or not pending' });
    return reply.send({ id: req.params.lid, status: 'rejected' });
  });

  fastify.get('/api/investigations/:id/findings', { preHandler: [requireAuth] }, async (req, reply) => {
    const config = loadConfig();
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const rows = getDb().prepare('SELECT * FROM findings WHERE investigation_id = ? ORDER BY discovered_at DESC').all(inv.id);
    return reply.send({ total: rows.length, items: rows.map(f => ({ ...f, data: f.data ? JSON.parse(decrypt(f.data, config.encryptionKey)) : null })) });
  });

  fastify.get('/api/investigations/:id/graph', { preHandler: [requireAuth] }, async (req, reply) => {
    const config = loadConfig();
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const db = getDb();
    const entities = db.prepare('SELECT * FROM entities WHERE investigation_id = ?').all(inv.id);
    const relationships = db.prepare('SELECT * FROM relationships WHERE investigation_id = ?').all(inv.id);
    return reply.send({
      nodes: entities.map(e => ({ ...e, properties: e.properties ? JSON.parse(decrypt(e.properties, config.encryptionKey)) : {} })),
      edges: relationships.map(r => ({ ...r, evidence: r.evidence ? JSON.parse(decrypt(r.evidence, config.encryptionKey)) : [] })),
    });
  });

  fastify.get('/api/investigations/:id/timeline', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    const db = getDb();
    const leads = db.prepare("SELECT id, type, value, status, confidence, created_at AS timestamp, 'lead_discovered' AS event_type FROM investigation_leads WHERE investigation_id = ? ORDER BY created_at").all(inv.id);
    const engines = db.prepare("SELECT id, engine_id, status, created_at AS timestamp, 'engine_result' AS event_type FROM engine_results WHERE investigation_id = ? ORDER BY created_at").all(inv.id);
    const events = [...leads, ...engines].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return reply.send({ total: events.length, events });
  });

  fastify.delete('/api/investigations/:id', { preHandler: [requireAuth] }, async (req, reply) => {
    const user = req.session.get('user');
    const inv = getInvestigationOwnedBy(req.params.id, user.id);
    if (!inv) return reply.code(404).send({ error: 'Investigation not found' });
    if (['running','paused'].includes(inv.status)) return reply.code(409).send({ error: 'Stop the investigation before deleting' });
    getDb().prepare('DELETE FROM investigations WHERE id = ? AND user_id = ?').run(inv.id, user.id);
    auditFromRequest(req, 'investigation.delete', 'investigation', inv.id, { title: inv.title });
    return reply.code(204).send();
  });
}
