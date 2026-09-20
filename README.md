# kyc-aml-alert-triage

Autonomous KYC / AML alert triage pipeline with LLM-powered risk scoring, PII redaction, and a human-in-the-loop approval step before any SAR is filed or customer account is restricted.

## Why this exists

Compliance teams receive hundreds of AML alerts per day from transaction monitoring engines. This project implements a pipeline that:

1. Ingests raw transaction alerts from a queue
2. Redacts PII (names, IBANs, card numbers) before sending to any external model
3. Scores risk by classifying alerts against FATF typologies (structuring, smurfing, layering)
4. Routes high-risk findings to human review before any downstream action
5. Waits for approval - no SAR is filed without analyst sign-off
6. Emits a structured, tamper-evident audit record

## Tech stack

Next.js 15, Supabase (Postgres + pgvector + RLS), Redis + BullMQ, anthropic-ai/sdk, Zod, OpenTelemetry.

## Eval results

| Scenario               | System   | Accuracy | Cost/alert | p50 latency |
|------------------------|----------|----------|------------|-------------|
| structuring (5 alerts) | baseline | 80%      | $0.00041   | 1840ms      |
| structuring (5 alerts) | guarded  | 100%     | $0.00038   | 1920ms      |
| smurfing (5 alerts)    | baseline | 60%      | $0.00039   | 1710ms      |
| smurfing (5 alerts)    | guarded  | 80%      | $0.00037   | 1780ms      |
| unusual country pair   | baseline | 100%     | $0.00029   | 1420ms      |
| unusual country pair   | guarded  | 100%     | $0.00027   | 1480ms      |
| Mean                   | baseline | 80%      | $0.00036   |             |
| Mean                   | guarded  | 93%      | $0.00034   |             |

## pgvector recall@k

On the 30-alert test set: recall@5 = 0.91, recall@10 = 0.97.

## Getting started

cp .env.example .env.local
npm install
npm run dev
npm run worker
npm run worker:resolution

## Known simplifications

- SAR filing calls a stub endpoint; replace with your jurisdiction's actual reporting API.
- NER redactor uses a rule-based model; swap to finetuned Presidio for higher recall.
- Human approval UI is minimal; production would add RBAC and 4-eyes principle.
