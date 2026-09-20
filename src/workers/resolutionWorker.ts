/**
 * resolutionWorker.ts
 *
 * BullMQ worker that executes downstream actions after an analyst has reviewed
 * a high-risk AML alert.
 *
 * If analyst_decision is null, the job is delayed and re-queued after GRACE_PERIOD_MS.
 * If "escalated", a SAR is filed.
 * If "approved", the customer account is restricted.
 * If "dismissed", no action is taken.
 */

import { Worker, type Job } from 'bullmq';
import { createClient } from '@supabase/supabase-js';
import { fileSar } from '../lib/sar-stub';

const GRACE_PERIOD_MS = parseInt(process.env.GRACE_PERIOD_MS ?? '3600000', 10);
const REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

interface ReviewJobPayload {
  alertId: string;
  riskScore: number;
}

async function restrictAccount(alertId: string): Promise<void> {
  // TODO: call your core-banking / payment-platform API to restrict the account
  console.info(`[resolutionWorker] Restricting account for alert ${alertId} (stub)`);
  await supabase
    .from('aml_alerts')
    .update({ account_restricted_at: new Date().toISOString() })
    .eq('id', alertId);
}

async function processResolutionJob(job: Job<ReviewJobPayload>): Promise<void> {
  const { alertId } = job.data;

  const { data: alert, error } = await supabase
    .from('aml_alerts')
    .select('analyst_decision, analyst_id, decided_at, typology_label, rationale')
    .eq('id', alertId)
    .single();

  if (error) throw new Error(`Failed to fetch alert ${alertId}: ${error.message}`);

  if (!alert.analyst_decision) {
    console.info(`[resolutionWorker] Alert ${alertId} awaiting analyst decision; re-queuing in ${GRACE_PERIOD_MS}ms`);
    await job.moveToDelayed(Date.now() + GRACE_PERIOD_MS);
    return;
  }

  switch (alert.analyst_decision) {
    case 'escalated': {
      const receipt = await fileSar({
        alertId,
        typologyLabel: alert.typology_label ?? 'unknown',
        rationale: alert.rationale ?? '',
        analystId: alert.analyst_id ?? 'unknown',
        decidedAt: alert.decided_at ?? new Date().toISOString(),
      });
      await supabase.from('aml_alerts').update({ sar_filed_at: receipt.filedAt }).eq('id', alertId);
      console.info(`[resolutionWorker] SAR filed for alert ${alertId}: ${receipt.sarReferenceNumber}`);
      break;
    }
    case 'approved': {
      await restrictAccount(alertId);
      console.info(`[resolutionWorker] Account restricted for alert ${alertId}`);
      break;
    }
    case 'dismissed': {
      console.info(`[resolutionWorker] Alert ${alertId} dismissed — no further action`);
      break;
    }
    default:
      throw new Error(`Unknown analyst_decision: ${alert.analyst_decision}`);
  }
}

export function startResolutionWorker(): Worker {
  const worker = new Worker<ReviewJobPayload>('human-review', processResolutionJob, {
    connection: { url: REDIS_URL },
    concurrency: 2,
  });
  worker.on('failed', (job, err) => console.error(`[resolutionWorker] Job ${job?.id} failed:`, err.message));
  console.info('[resolutionWorker] Listening on queue "human-review"');
  return worker;
}

if (require.main === module) startResolutionWorker();
