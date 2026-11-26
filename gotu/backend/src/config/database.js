/**
 * GOTU Database Module
 * better-sqlite3 with WAL mode.
 * All sensitive columns use AES-256-GCM encryption via the crypto module.
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { loadConfig } from './env.js';
import { MIGRATION_001 } from './schema.js';

let _db = null;

export function getDb() {
  if (_db) return _db;

  const config = loadConfig();
  const dbPath = config.dbPath;

  const dataDir = path.dirname(dbPath);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  }

  _db = new Database(dbPath, { fileMustExist: false });

  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  try { fs.chmodSync(dbPath, 0o600); } catch {}

  const integ = _db.pragma('integrity_check', { simple: true });
  if (integ !== 'ok') {
    throw new Error(`[GOTU] Database integrity check failed: ${integ}`);
  }

  return _db;
}

export function closeDb() {
  if (_db) { _db.close(); _db = null; }
}

export function runMigrations(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  )`);

  const applied = new Set(
    db.prepare('SELECT version FROM schema_migrations').all().map(r => r.version)
  );

  for (const { version, sql } of getMigrations()) {
    if (applied.has(version)) continue;
    db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (version) VALUES (?)').run(version);
    })();
    console.log(`[GOTU] Applied migration v${version}`);
  }
}

function getMigrations() {
  return [{ version: 1, sql: MIGRATION_001 }];
}

/**
 * Seed default source provider metadata.
 * Run once after migrations.
 */
export function seedSourceProviders(db) {
  const providers = [
    {
      id: 'github', name: 'GitHub', category: 'username',
      pricing_model: 'free', cost_per_1000_requests: null,
      free_allowance_per_month: null, rate_limit_per_second: null,
      rate_limit_per_month: 60000,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://docs.github.com/en/rest/overview/rate-limits',
      notes: 'Unauthenticated: 60/hr. With token: 5000/hr.',
    },
    {
      id: 'reddit', name: 'Reddit', category: 'username',
      pricing_model: 'free', cost_per_1000_requests: null,
      free_allowance_per_month: null, rate_limit_per_second: null,
      rate_limit_per_month: null,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://www.reddit.com/dev/api/',
      notes: 'Public JSON API. No key required for user lookups.',
    },
    {
      id: 'brave_search', name: 'Brave Search', category: 'search',
      pricing_model: 'prepaid', cost_per_1000_requests: 5.00,
      free_allowance_per_month: 1000, rate_limit_per_second: 50,
      rate_limit_per_month: null,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://api-dashboard.search.brave.com/documentation/pricing',
      notes: 'Prepaid credits. $5 free credit/month (~1000 requests). $5.00 per 1000 above that.',
    },
    {
      id: 'google_cse', name: 'Google Custom Search', category: 'search',
      pricing_model: 'freemium', cost_per_1000_requests: 5.00,
      free_allowance_per_month: 100, rate_limit_per_second: null,
      rate_limit_per_month: 100,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://developers.google.com/custom-search/v1/overview#pricing',
      notes: 'Free: 100 queries/day. Partial dork support only. Not a full Google search replacement.',
    },
    {
      id: 'hibp', name: 'Have I Been Pwned (Email Breach)', category: 'email',
      pricing_model: 'paid', cost_per_1000_requests: null,
      free_allowance_per_month: 0, rate_limit_per_second: null,
      rate_limit_per_month: null,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://haveibeenpwned.com/API/v3',
      notes: 'Requires paid API key (~$3.50/mo). Email breach lookups only. Never used for password checks.',
    },
    {
      id: 'courtlistener', name: 'CourtListener', category: 'legal',
      pricing_model: 'free', cost_per_1000_requests: null,
      free_allowance_per_month: 5000, rate_limit_per_second: null,
      rate_limit_per_month: 5000,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://www.courtlistener.com/api/rest/v3/',
      notes: 'US federal courts and SCOTUS opinions. Free: 5000 req/day. Distinct from PACER.',
    },
    {
      id: 'sec_edgar', name: 'SEC EDGAR', category: 'financial',
      pricing_model: 'free', cost_per_1000_requests: null,
      free_allowance_per_month: null, rate_limit_per_second: 10,
      rate_limit_per_month: null,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://efts.sec.gov/',
      notes: 'Completely free. No API key required. 10 req/sec limit.',
    },
    {
      id: 'opencorporates', name: 'OpenCorporates', category: 'business',
      pricing_model: 'freemium', cost_per_1000_requests: null,
      free_allowance_per_month: null, rate_limit_per_second: null,
      rate_limit_per_month: null,
      pricing_last_verified: '2026-11-01',
      pricing_source_url: 'https://api.opencorporates.com/documentation/API-Reference',
      notes: 'API key required. Free for open data use. 140+ jurisdictions.',
    },
  ];

  const insert = db.prepare(`
    INSERT OR IGNORE INTO source_providers
      (id, name, category, pricing_model, cost_per_1000_requests,
       free_allowance_per_month, rate_limit_per_second, rate_limit_per_month,
       pricing_last_verified, pricing_source_url, notes)
    VALUES
      (@id, @name, @category, @pricing_model, @cost_per_1000_requests,
       @free_allowance_per_month, @rate_limit_per_second, @rate_limit_per_month,
       @pricing_last_verified, @pricing_source_url, @notes)
  `);

  db.transaction(() => {
    for (const p of providers) insert.run(p);
  })();
}
