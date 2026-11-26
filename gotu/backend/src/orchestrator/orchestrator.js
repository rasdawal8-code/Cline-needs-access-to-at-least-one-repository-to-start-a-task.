import { randomUUID } from 'crypto';
import { getDb } from '../config/database.js';
import { loadConfig } from '../config/env.js';
import { encrypt } from '../config/crypto.js';
import { getRegistry } from '../engines/registry.js';
import { createHash } from 'crypto';

const CONFIDENCE_THRESHOLD = 0.5;
const CONFIDENCE_RANK = { confirmed: 1.0, probable: 0.75, possible: 0.5, unverified: 0.2 };

function leadFingerprint(type, value) {
  return createHash('sha256').update(`${type}:${value.toLowerCase().trim()}`).digest('hex');
}

function isPersonalIdentityLead(type) {
  return type === 'name' || type === 'phone';
}

export class InvestigationOrchestrator {
  constructor(investigationId, userId) {
    this.investigationId = investigationId;
    this.userId = userId;
    this._aborted = false;
  }

  get _config() { return loadConfig(); }
  get _db() { return getDb(); }
  get _registry() { return getRegistry(); }

  _getInvestigation() {
    return this._db.prepare(
      "SELECT * FROM investigations WHERE id = ? AND user_id = ?"
    ).get(this.investigationId, this.userId);
  }

  _updateApiCallsUsed(count) {
    this._db.prepare("UPDATE investigations SET api_calls_used = api_calls_used + ? WHERE id = ?").run(count, this.investigationId);
  }

  _checkBudget(inv) {
    if (this._aborted) return false;
    if (inv.api_calls_used >= inv.max_api_calls) return false;
    if (inv.started_at) {
      const elapsed = (Date.now() - new Date(inv.started_at).getTime()) / 1000;
      if (elapsed > inv.max_duration_s) return false;
    }
    return true;
  }

  abort() { this._aborted = true; }

  async runCycle(checkpoint = null) {
    const inv = this._getInvestigation();
    if (!inv || ['stopped','completed','failed'].includes(inv.status)) return false;
    if (!this._checkBudget(inv)) {
      this._db.prepare("UPDATE investigations SET status = 'completed', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(this.investigationId);
      return false;
    }

    const startDepth = checkpoint?.depth ?? 0;
    const maxDepth = inv.max_depth;
    let processedAny = false;

    for (let depth = startDepth; depth <= maxDepth; depth++) {
      if (!this._checkBudget(this._getInvestigation())) break;
      const leads = this._getPendingLeadsAtDepth(depth, !!inv.require_lead_approval);
      if (leads.length === 0) continue;
      processedAny = true;
      for (const lead of leads) {
        if (!this._checkBudget(this._getInvestigation())) break;
        await this._processLead(lead, inv);
      }
    }

    const remaining = this._db.prepare(
      "SELECT COUNT(*) AS n FROM investigation_leads WHERE investigation_id = ? AND status IN ('pending','approved','running')"
    ).get(this.investigationId).n;

    if (remaining === 0) {
      this._db.prepare(
        "UPDATE investigations SET status = 'completed', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?"
      ).run(this.investigationId);
      return false;
    }
    return processedAny;
  }

  _getPendingLeadsAtDepth(depth, requireApproval) {
    if (requireApproval && depth > 0) {
      return this._db.prepare(
        "SELECT * FROM investigation_leads WHERE investigation_id = ? AND depth = ? AND status = 'approved' LIMIT 20"
      ).all(this.investigationId, depth);
    }
    return this._db.prepare(
      "SELECT * FROM investigation_leads WHERE investigation_id = ? AND depth = ? AND status IN ('pending','approved') LIMIT 20"
    ).all(this.investigationId, depth);
  }

  async _processLead(lead, inv) {
    this._db.prepare("UPDATE investigation_leads SET status = 'running' WHERE id = ?").run(lead.id);
    const engines = this._registry.getForInputType(lead.type);
    const discoveries = [];

    for (const engine of engines) {
      const statusCheck = engine.getStatus();
      if (statusCheck.status === 'not_configured' || statusCheck.status === 'unsupported') {
        const erId = randomUUID();
        this._db.prepare(
          "INSERT INTO engine_results (id, investigation_id, lead_id, engine_id, status) VALUES (?, ?, ?, ?, 'skipped')"
        ).run(erId, this.investigationId, lead.id, engine.id);
        continue;
      }

      const erId = randomUUID();
      this._db.prepare(
        "INSERT INTO engine_results (id, investigation_id, lead_id, engine_id, status, started_at) VALUES (?, ?, ?, ?, 'running', strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
      ).run(erId, this.investigationId, lead.id, engine.id);

      try {
        const result = await engine.execute({
          indicatorType: lead.type,
          indicatorValue: lead.value,
          investigationId: this.investigationId,
        });
        this._updateApiCallsUsed(result.apiCallsUsed);
        const encRaw = encrypt(
          JSON.stringify({ findings: result.findings, leads: result.leads, errors: result.errors }),
          this._config.encryptionKey
        );
        this._db.prepare(
          "UPDATE engine_results SET status = 'completed', raw_data = ?, api_calls_used = ?, completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?"
        ).run(encRaw, result.apiCallsUsed, erId);

        for (const finding of result.findings) {
          const fId = randomUUID();
          const encData = encrypt(JSON.stringify(finding.data), this._config.encryptionKey);
          this._db.prepare(
            "INSERT INTO findings (id, investigation_id, lead_id, engine_id, type, data, confidence, source_url, source_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).run(fId, this.investigationId, lead.id, engine.id, finding.type, encData, finding.confidence, finding.sourceUrl ?? null, finding.sourceName ?? null);
        }
        discoveries.push(...result.leads);
      } catch (err) {
        this._db.prepare(
          "UPDATE engine_results SET status = 'failed', error = ?, completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?"
        ).run(err.message, erId);
      }
    }

    const nextDepth = lead.depth + 1;
    if (nextDepth <= inv.max_depth) {
      for (const dl of discoveries) {
        const confidenceScore = CONFIDENCE_RANK[dl.confidence] ?? 0;
        if (confidenceScore < CONFIDENCE_THRESHOLD) continue;
        const fp = leadFingerprint(dl.type, dl.value);
        const existing = this._db.prepare(
          "SELECT id FROM investigation_leads WHERE investigation_id = ? AND fingerprint = ?"
        ).get(this.investigationId, fp);
        if (existing) continue;
        this._db.prepare(
          "INSERT OR IGNORE INTO investigation_leads (id, investigation_id, parent_lead_id, type, value, fingerprint, depth, confidence, source_engine, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).run(randomUUID(), this.investigationId, lead.id, dl.type, dl.value, fp, nextDepth, dl.confidence, dl.sourceEngine, 'pending');
      }
    }
    this._db.prepare("UPDATE investigation_leads SET status = 'completed' WHERE id = ?").run(lead.id);
  }
}
