/**
 * GOTU Backend Server
 * Fastify 5 with security middleware stack.
 */

import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import csrf from '@fastify/csrf-protection';
import session from '@fastify/session';
import { loadConfig } from './config/env.js';
import { getDb, runMigrations, seedSourceProviders } from './config/database.js';
import { SqliteSessionStore } from './storage/session-store.js';
import authRoutes from './routes/auth.js';
import investigationRoutes from './routes/investigations.js';
import engineRoutes from './routes/engines.js';
import apiKeyRoutes from './routes/api-keys.js';
import { getInvestigationQueue } from './jobs/investigation-worker.js';
import fastifyStatic from '@fastify/static';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function buildServer(opts = {}) {
  const config = loadConfig();

  const fastify = Fastify({
    logger: opts.logger ?? {
      level: config.logLevel,
      transport: config.nodeEnv === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
    },
    trustProxy: true,
  });

  // ─── Security headers ──────────────────────────────────────────────────────
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc:  ["'self'"],
        scriptSrc:   ["'self'"],
        styleSrc:    ["'self'", "'unsafe-inline'"], // Needed for Tailwind inline; tighten in production
        imgSrc:      ["'self'", 'data:'],
        connectSrc:  ["'self'"],
        fontSrc:     ["'self'"],
        objectSrc:   ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    frameguard:   { action: 'deny' },
    hsts:         { maxAge: 31536000, includeSubDomains: true },
    noSniff:      true,
    referrerPolicy: { policy: 'no-referrer' },
  });

  // ─── Rate limiting ─────────────────────────────────────────────────────────
  await fastify.register(rateLimit, {
    global:  true,
    max:     config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    keyGenerator: (req) => req.ip,
    errorResponseBuilder: () => ({
      error: 'Too many requests. Please wait before trying again.',
    }),
  });

  // ─── Cookie support (required by @fastify/session) ────────────────────────
  await fastify.register(cookie, {
    secret: config.sessionSecret, // signs cookies
    parseOptions: {},
  });

  // ─── Sessions ──────────────────────────────────────────────────────────────
  const sessionStore = new SqliteSessionStore();

  await fastify.register(session, {
    secret:      config.sessionSecret,
    store:       sessionStore,
    cookie: {
      secure:   config.isProduction,
      httpOnly: true,
      sameSite: 'strict',
      maxAge:   config.sessionTtl * 1000,
      path:     '/',
    },
    saveUninitialized: false,
  });

  // ─── CSRF protection ──────────────────────────────────────────────────────
  // Note: CSRF token endpoint added for SPA use
  await fastify.register(csrf, { sessionPlugin: '@fastify/session' });

  // ─── CSRF token endpoint ──────────────────────────────────────────────────
  fastify.get('/api/csrf-token', async (req, reply) => {
    const token = reply.generateCsrf();
    return reply.send({ csrfToken: token });
  });

  // ─── Health check ─────────────────────────────────────────────────────────
  fastify.get('/api/health', async (req, reply) => {
    return reply.send({
      status: 'ok',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });

  // ─── Auth routes ──────────────────────────────────────────────────────────
  await fastify.register(authRoutes);

  // ─── Investigation routes ─────────────────────────────────────────────────
  await fastify.register(investigationRoutes);

  // ─── Engine routes ────────────────────────────────────────────────────────
  await fastify.register(engineRoutes);

  // ─── API key management routes ────────────────────────────────────────────
  await fastify.register(apiKeyRoutes);

  // ─── Serve React frontend (SPA) ───────────────────────────────────────────
  const frontendDist = path.resolve(__dirname, '../../frontend/dist');
  if (!opts.noStatic) {
    try {
      await fastify.register(fastifyStatic, {
        root:          frontendDist,
        prefix:        '/',
        decorateReply: true,
        wildcard:      false,
      });
    } catch (err) {
      fastify.log.warn('Frontend dist not found — serving API only: ' + err.message);
    }
  }

  // ─── Start investigation job queue ────────────────────────────────────────
  if (!opts.noQueue) {
    const invQueue = getInvestigationQueue();
    invQueue.start();
    fastify.addHook('onClose', async () => invQueue.stop());
  }

  // ─── Global error handler ──────────────────────────────────────────────────
  fastify.setErrorHandler(async (error, req, reply) => {
    // Don't leak internal error details to client
    const statusCode = error.statusCode ?? 500;
    if (statusCode >= 500) {
      fastify.log.error(error);
      return reply.code(500).send({ error: 'Internal server error' });
    }
    return reply.code(statusCode).send({ error: error.message });
  });

  // ─── 404 handler (SPA fallback + API 404) ────────────────────────────────
  fastify.setNotFoundHandler(async (req, reply) => {
    // API routes get a JSON 404
    if (req.url.startsWith('/api/')) {
      return reply.code(404).send({ error: 'Not found' });
    }
    // All other routes serve the React SPA index.html
    if (!opts.noStatic) {
      try {
        return reply.sendFile('index.html');
      } catch {}
    }
    return reply.code(404).send({ error: 'Not found' });
  });

  return fastify;
}

// ─── Main entrypoint ──────────────────────────────────────────────────────────
if (process.argv[1]?.endsWith('server.js')) {
  const config = loadConfig();

  // Initialize database
  const db = getDb();
  runMigrations(db);
  seedSourceProviders(db);

  // Start session store cleanup
  const sessionStore = new SqliteSessionStore();
  setInterval(() => sessionStore.purgeExpired(), 60 * 60 * 1000); // hourly

  buildServer()
    .then(async fastify => {
      await fastify.listen({ port: config.port, host: config.host });
      console.log(`[GOTU] Server running at http://${config.host}:${config.port}`);
    })
    .catch(err => {
      console.error('[GOTU] Server failed to start:', err.message);
      process.exit(1);
    });
}
