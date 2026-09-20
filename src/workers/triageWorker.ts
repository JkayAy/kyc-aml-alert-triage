/**
 * triageWorker.ts
 *
 * BullMQ worker that drives the AML alert triage pipeline.
 *
 * Pipeline stages (per alert):
 *   1. PII Redaction  — regex + NER, runs before any LLM call
 *   2. LLM Risk Scoring — Claude classifies against FATF typologies
 *   3. Persist finding — write alert + risk score to Supabase
 *   4. Route — if risk_score > AUTO_DISMISS_THRESHOLD, push to human review
 */

import Anthropic from '@anthropic-ai/sdk';
import { Worker, Queue, type Job } from 'bullmq';
import { createClient } from '@supabase/supabase-js';
import { z } from 'zod';
import { redact } from '../lib/redaction';

const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL ?? 'claude-3-7-sonnet-20250219';
const AUTO_DISMISS_THRESHOLD = parseFloat(process.env.AUTO_DISMISS_THRESHOLD ?? '0.30');
const QUEUE_NAME = process.env.TRIAGE_QUEUE_NAME ?? 'aml-triage';
const REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY! });
const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

const TYPOLOGIES = [
  'structuring', 'smurfing', 'layering', 'unusual_country_pair',
  'rapid_movement', 'shell_company', 'cash_intensive', 'trade_based', 'other',
] as const;

type Typology = typeof TYPOLOGIES[number];

const RiskScoringSchema = z.object({
  typology_label: z.enum(TYPOLOGIES),
  risk_score: z.number().min(0).max(1),
  rationale: z.string().max(2000),
});

type RiskScoring = z.infer<typeof RiskScoringSchema>;

export interface AlertJobPayload {
  externalId: string;
  rawText: string;
  receivedAt: string;
}

const RISK_TOOL_NAME = 'record_risk_assessment';

const riskTool: Anthropic.Tool = {
  name: RISK_TOOL_NAME,
  description: 'Record the risk assessment for an AML alert.',
  input_schema: {
    type: 'object',
    properties: {
      typology_label: {
        type: 'string',
        enum: TYPOLOGIES as unknown as string[],
        description: 'FATF typology that best describes the alert.',
      },
      risk_score: {
        type: 'number',
        description: 'Risk score between 0.0 (no risk) and 1.0 (highest risk).',
      },
      rationale: {
        type: 'string',
        description: 'Concise reasoning (max 2000 chars). Reference only redacted tokens.',
      },
    },
    required: ['typology_label', 'risk_score', 'rationale'],
  },
};

async function scoreRisk(redactedText: string): Promise<RiskScoring> {
  const response = await anthropic.messages.create({
    model: ANTHROPIC_MODEL,
    max_tokens: 1024,
    tools: [riskTool],
    tool_choice: { type: 'tool', name: RISK_TOOL_NAME },
    system: `You are an experienced AML compliance analyst. You will receive a redacted
transaction alert where PII has been replaced with tokens such as [PERSON_1], [IBAN_1].
Classify the alert against FATF money-laundering typologies and assign a risk score.
Be conservative: when in doubt, score higher to ensure human review.`,
    messages: [{ role: 'user', content: `Assess this AML alert:\n\n${redactedText}` }],
  });

  const toolBlock = response.content.find(
    (b): b is Anthropic.ToolUseBlock => b.type === 'tool_use',
  );
  if (!toolBlock) throw new Error('LLM did not return a tool call for risk scoring');
  return RiskScoringSchema.parse(toolBlock.input);
}

async function persistAlert(
  payload: AlertJobPayload,
  redactedText: string,
  redactionMap: Record<string, string>,
  scoring: RiskScoring,
): Promise<string> {
  const redactionMapEncrypted = Buffer.from(JSON.stringify(redactionMap));

  const { data, error } = await supabase
    .from('aml_alerts')
    .insert({
      external_id: payload.externalId,
      raw_text: payload.rawText,
      redacted_text: redactedText,
      redaction_map: redactionMapEncrypted,
      typology_label: scoring.typology_label,
      risk_score: scoring.risk_score,
      rationale: scoring.rationale,
    })
    .select('id')
    .single();

  if (error) throw new Error(`Failed to persist alert: ${error.message}`);
  return data.id as string;
}

async function appendAuditLog(
  alertId: string,
  eventType: string,
  payload: Record<string, unknown>,
): Promise<void> {
  await supabase.from('aml_audit_logs').insert({ alert_id: alertId, event_type: eventType, payload });
}

const humanReviewQueue = new Queue('human-review', { connection: { url: REDIS_URL } });

async function routeToHumanReview(alertId: string, riskScore: number): Promise<void> {
  await humanReviewQueue.add('review', { alertId, riskScore }, { attempts: 3 });
}

async function processAuditJob(job: Job<AlertJobPayload>): Promise<void> {
  const { externalId, rawText } = job.data;
  console.info(`[triageWorker] Processing alert ${externalId}`);

  await job.updateProgress(10);
  const { redactedText, redactionMap } = await redact(rawText);

  await job.updateProgress(40);
  const scoring = await scoreRisk(redactedText);
  console.info(`[triageWorker] Alert ${externalId} scored: ${scoring.typology_label} / ${scoring.risk_score}`);

  await job.updateProgress(70);
  const alertId = await persistAlert(job.data, redactedText, redactionMap, scoring);
  await appendAuditLog(alertId, 'scored', { typology_label: scoring.typology_label, risk_score: scoring.risk_score });

  await job.updateProgress(90);
  if (scoring.risk_score > AUTO_DISMISS_THRESHOLD) {
    await routeToHumanReview(alertId, scoring.risk_score);
    await appendAuditLog(alertId, 'routed', { queue: 'human-review', risk_score: scoring.risk_score });
    console.info(`[triageWorker] Alert ${alertId} routed to human review`);
  } else {
    await appendAuditLog(alertId, 'auto_dismissed', { risk_score: scoring.risk_score });
    console.info(`[triageWorker] Alert ${alertId} auto-dismissed`);
  }
  await job.updateProgress(100);
}

export function startWorker(): Worker {
  const worker = new Worker<AlertJobPayload>(QUEUE_NAME, processAuditJob, {
    connection: { url: REDIS_URL },
    concurrency: parseInt(process.env.WORKER_CONCURRENCY ?? '5', 10),
  });
  worker.on('failed', (job, err) => console.error(`[triageWorker] Job ${job?.id} failed:`, err.message));
  worker.on('completed', (job) => console.info(`[triageWorker] Job ${job.id} completed`));
  console.info(`[triageWorker] Listening on queue "${QUEUE_NAME}"`);
  return worker;
}

if (require.main === module) startWorker();
