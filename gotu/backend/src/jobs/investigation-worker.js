/**
 * GOTU Investigation Worker
 * Job handler that runs the orchestrator for an investigation.
 * Started by the job queue when an investigation is in 'running' state.
 */

import { JobQueue } from './queue.js';
import { InvestigationOrchestrator } from '../orchestrator/orchestrator.js';
import { getDb } from '../config/database.js';

export const INVESTIGATION_QUEUE = 'investigations';

let _queue = null;
let _activeOrchestrators = new Map(); // investigationId -> orchestrator

export function getInvestigationQueue() {
  if (_queue) return _queue;
  _queue = new JobQueue(INVESTIGATION_QUEUE, handleInvestigationJob);
  return _queue;
}

async function handleInvestigationJob(payload, job) {
  const { investigationId, userId } = payload;
  const db = getDb();

  // Verify investigation is still in running state
  const inv = db.prepare('SELECT * FROM investigations WHERE id = ? AND user_id = ?')
    .get(investigationId, userId);

  if (!inv || !['running', 'paused'].includes(inv.status)) {
    // Investigation was stopped externally — do nothing
    return;
  }

  if (inv.status === 'paused') {
    // Re-queue for later
    throw new Error('Investigation is paused');
  }

  const orchestrator = new InvestigationOrchestrator(investigationId, userId);
  _activeOrchestrators.set(investigationId, orchestrator);

  try {
    // Load checkpoint if available
    const checkpoint = _queue.loadCheckpoint(job);
    let continueRunning = true;

    while (continueRunning && !orchestrator._aborted) {
      // Check if paused or stopped
      const current = db.prepare('SELECT status FROM investigations WHERE id = ?').get(investigationId);
      if (!current || current.status === 'stopped') {
        orchestrator.abort();
        break;
      }
      if (current.status === 'paused') {
        // Save checkpoint and exit — will resume when re-queued
        _queue.saveCheckpoint(job.id, job.lease_token, { depth: 0 });
        throw new Error('Investigation paused');
      }

      continueRunning = await orchestrator.runCycle(checkpoint);

      // Save progress checkpoint
      _queue.saveCheckpoint(job.id, job.lease_token, {
        depth: 0,
        timestamp: new Date().toISOString(),
      });
    }
  } finally {
    _activeOrchestrators.delete(investigationId);
  }
}

/**
 * Enqueue an investigation to run.
 * Called when investigation transitions to 'running'.
 */
export function enqueueInvestigation(investigationId, userId) {
  const queue = getInvestigationQueue();
  return queue.enqueue({ investigationId, userId }, { priority: 5, maxAttempts: 2 });
}

/**
 * Abort an active orchestrator (immediate stop).
 */
export function abortInvestigation(investigationId) {
  const orch = _activeOrchestrators.get(investigationId);
  if (orch) orch.abort();
}
