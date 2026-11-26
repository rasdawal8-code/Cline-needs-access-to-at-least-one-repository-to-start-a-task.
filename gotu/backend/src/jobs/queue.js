import { randomUUID } from 'crypto';
import { getDb } from '../config/database.js';
import { loadConfig } from '../config/env.js';
import { encrypt, decrypt } from '../config/crypto.js';

export class JobQueue {
  constructor(queueName, handler) {
    this.queueName = queueName;
    this.handler = handler;
    this._pollerInterval = null;
    this._reaperInterval = null;
    this._heartbeats = new Map();
    this._running = false;
  }
  get _config() { return loadConfig(); }
  get _db() { return getDb(); }

  enqueue(payload, { priority = 0, maxAttempts = 3, runAt = null } = {}) {
    const id = randomUUID();
    const enc = encrypt(JSON.stringify(payload), this._config.encryptionKey);
    const runAtStr = runAt ? runAt.toISOString() : new Date().toISOString();
    this._db.prepare('INSERT INTO jobs (id, queue, payload, priority, max_attempts, run_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, this.queueName, enc, priority, maxAttempts, runAtStr);
    return id;
  }

  claimNext() {
    const leaseDurationMs = this._config.jobLeaseDurationMs;
    const claimTxn = this._db.transaction(() => {
      const job = this._db.prepare('SELECT * FROM jobs WHERE queue = ? AND status IN (\'pending\', \'retrying\') AND run_at <= strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') ORDER BY priority DESC, created_at ASC LIMIT 1').get(this.queueName);
      if (!job) return null;
      const leaseToken = randomUUID();
      const leaseExpiry = new Date(Date.now() + leaseDurationMs).toISOString();
      const now = new Date().toISOString();
      const updated = this._db.prepare('UPDATE jobs SET status = \'claimed\', lease_token = ?, lease_expires_at = ?, started_at = CASE WHEN started_at IS NULL THEN ? ELSE started_at END, attempts = attempts + 1 WHERE id = ? AND status IN (\'pending\', \'retrying\')').run(leaseToken, leaseExpiry, now, job.id);
      if (updated.changes === 0) return null;
      return { ...job, lease_token: leaseToken };
    });
    const job = claimTxn.immediate();
    if (!job) return null;
    try {
      job.decodedPayload = JSON.parse(decrypt(job.payload, this._config.encryptionKey));
    } catch {
      this._markFailed(job.id, job.lease_token, 'Payload decryption failed');
      return null;
    }
    return job;
  }

  startHeartbeat(jobId, leaseToken) {
    const intervalMs = this._config.jobHeartbeatMs;
    const id = setInterval(() => {
      const leaseDurationMs = this._config.jobLeaseDurationMs;
      const updated = this._db.prepare('UPDATE jobs SET last_heartbeat_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'), lease_expires_at = ?, status = \'running\' WHERE id = ? AND lease_token = ? AND status IN (\'claimed\',\'running\')').run(new Date(Date.now() + leaseDurationMs).toISOString(), jobId, leaseToken);
      if (updated.changes === 0) { clearInterval(id); this._heartbeats.delete(jobId); }
    }, intervalMs);
    this._heartbeats.set(jobId, id);
  }

  stopHeartbeat(jobId) {
    const id = this._heartbeats.get(jobId);
    if (id) { clearInterval(id); this._heartbeats.delete(jobId); }
  }

  markCompleted(jobId, leaseToken) {
    this.stopHeartbeat(jobId);
    this._db.prepare('UPDATE jobs SET status = \'completed\', completed_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'), lease_token = NULL, lease_expires_at = NULL WHERE id = ? AND lease_token = ?').run(jobId, leaseToken);
  }

  _markFailed(jobId, leaseToken, errorMsg) {
    this.stopHeartbeat(jobId);
    this._db.prepare('UPDATE jobs SET status = \'failed\', error = ?, completed_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'), lease_token = NULL, lease_expires_at = NULL WHERE id = ?').run(errorMsg, jobId);
  }

  markFailed(jobId, leaseToken, errorMsg) { this._markFailed(jobId, leaseToken, errorMsg); }

  saveCheckpoint(jobId, leaseToken, checkpointData) {
    const enc = encrypt(JSON.stringify(checkpointData), this._config.encryptionKey);
    this._db.prepare('UPDATE jobs SET checkpoint = ? WHERE id = ? AND lease_token = ?').run(enc, jobId, leaseToken);
  }

  loadCheckpoint(job) {
    if (!job.checkpoint) return null;
    try { return JSON.parse(decrypt(job.checkpoint, this._config.encryptionKey)); } catch { return null; }
  }

  reclaimExpired() {
    return this._db.prepare('UPDATE jobs SET status = CASE WHEN attempts >= max_attempts THEN \'failed\' ELSE \'retrying\' END, lease_token = NULL, lease_expires_at = NULL, error = CASE WHEN attempts >= max_attempts THEN \'Max attempts reached\' ELSE \'Lease expired\' END, run_at = CASE WHEN attempts >= max_attempts THEN run_at ELSE strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\', \'+\' || (attempts * 30) || \' seconds\') END WHERE queue = ? AND status IN (\'claimed\', \'running\') AND lease_expires_at < strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\')').run(this.queueName).changes;
  }

  start() {
    if (this._running) return;
    this._running = true;
    const maxConcurrent = this._config.jobMaxConcurrent;
    let activeCount = 0;
    this._pollerInterval = setInterval(async () => {
      if (activeCount >= maxConcurrent) return;
      const job = this.claimNext();
      if (!job) return;
      activeCount++;
      this.startHeartbeat(job.id, job.lease_token);
      try {
        await this.handler(job.decodedPayload, job);
        this.markCompleted(job.id, job.lease_token);
      } catch (err) {
        this.stopHeartbeat(job.id);
        const shouldRetry = job.attempts < job.max_attempts;
        if (shouldRetry) {
          const delay = job.attempts * 30;
          this._db.prepare('UPDATE jobs SET status = \'retrying\', error = ?, lease_token = NULL, lease_expires_at = NULL, run_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\', \'+\' || ? || \' seconds\') WHERE id = ?').run(err.message, delay, job.id);
        } else {
          this._markFailed(job.id, job.lease_token, err.message);
        }
      } finally { activeCount--; }
    }, 2000);
    this._reaperInterval = setInterval(() => this.reclaimExpired(), this._config.jobReaperMs);
  }

  stop() {
    this._running = false;
    if (this._pollerInterval) { clearInterval(this._pollerInterval); this._pollerInterval = null; }
    if (this._reaperInterval) { clearInterval(this._reaperInterval); this._reaperInterval = null; }
    for (const [, id] of this._heartbeats) clearInterval(id);
    this._heartbeats.clear();
  }

  getJob(jobId) { return this._db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId); }

  listJobs(status = null, limit = 50) {
    if (status) return this._db.prepare('SELECT id, queue, status, attempts, max_attempts, priority, run_at, started_at, completed_at, error, created_at FROM jobs WHERE queue = ? AND status = ? ORDER BY created_at DESC LIMIT ?').all(this.queueName, status, limit);
    return this._db.prepare('SELECT id, queue, status, attempts, max_attempts, priority, run_at, started_at, completed_at, error, created_at FROM jobs WHERE queue = ? ORDER BY created_at DESC LIMIT ?').all(this.queueName, limit);
  }
}
