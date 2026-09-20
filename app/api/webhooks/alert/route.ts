/**
 * app/api/webhooks/alert/route.ts
 *
 * Next.js App Router route handler for incoming AML alert webhooks.
 * Expects POST from the upstream Transaction Monitoring Engine with
 * HMAC-SHA256 signature in X-TM-Signature header.
 *
 * On valid alert:
 *   1. Verifies HMAC signature
 *   2. Validates request body schema
 *   3. Enqueues on BullMQ aml-triage queue
 *   4. Returns 202 Accepted (pipeline is async)
 */

import { NextRequest, NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'crypto';
import { Queue } from 'bullmq';
import { z } from 'zod';

const WEBHOOK_SECRET = process.env.TM_WEBHOOK_SECRET!;
const REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';
const QUEUE_NAME = process.env.TRIAGE_QUEUE_NAME ?? 'aml-triage';

const triageQueue = new Queue(QUEUE_NAME, {
  connection: { url: REDIS_URL },
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
  },
});

const AlertWebhookSchema = z.object({
  id: z.string().min(1),
  text: z.string().min(10),
  created_at: z.string().datetime().optional(),
});

function verifySignature(rawBody: Buffer, signature: string): boolean {
  if (!WEBHOOK_SECRET) return false;
  const expected = createHmac('sha256', WEBHOOK_SECRET).update(rawBody).digest('hex');
  const expectedBuf = Buffer.from(`sha256=${expected}`, 'ascii');
  const receivedBuf = Buffer.from(signature, 'ascii');
  if (expectedBuf.length !== receivedBuf.length) return false;
  return timingSafeEqual(expectedBuf, receivedBuf);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const rawBody = Buffer.from(await req.arrayBuffer());

  const signature = req.headers.get('x-tm-signature') ?? '';
  if (!verifySignature(rawBody, signature)) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }

  let parsed: z.infer<typeof AlertWebhookSchema>;
  try {
    parsed = AlertWebhookSchema.parse(JSON.parse(rawBody.toString('utf-8')));
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  await triageQueue.add('triage', {
    externalId: parsed.id,
    rawText: parsed.text,
    receivedAt: parsed.created_at ?? new Date().toISOString(),
  });

  return NextResponse.json({ queued: true, alertId: parsed.id }, { status: 202 });
                             }
