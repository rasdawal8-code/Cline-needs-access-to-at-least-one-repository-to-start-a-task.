/**
 * GOTU Engine Routes
 * GET /api/engines              — list all engines and status
 * GET /api/engines/:id          — single engine status
 * GET /api/engines/:id/status   — explicit status check
 */

import { requireAuth } from './auth.js';
import { getRegistry } from '../engines/registry.js';

export default async function engineRoutes(fastify) {

  fastify.get('/api/engines', { preHandler: [requireAuth] }, async (req, reply) => {
    const registry = getRegistry();
    return reply.send({ engines: registry.getAllStatuses() });
  });

  fastify.get('/api/engines/:id', { preHandler: [requireAuth] }, async (req, reply) => {
    const registry = getRegistry();
    const engine = registry.getById(req.params.id);
    if (!engine) return reply.code(404).send({ error: 'Engine not found' });
    return reply.send({
      id:   engine.id,
      name: engine.name,
      supportedInputTypes: engine.supportedInputTypes,
      requiredApiKeys:     engine.requiredApiKeys,
      status: engine.getStatus(),
    });
  });
}
