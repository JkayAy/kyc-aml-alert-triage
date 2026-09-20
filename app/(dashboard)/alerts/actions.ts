'use server';

/**
 * app/(dashboard)/alerts/actions.ts
 *
 * Next.js Server Actions for the analyst review dashboard.
 * Human sign-off is mandatory — the resolution worker checks analyst_decision
 * before taking any consequential action (SAR filing, account restriction).
 */

import { cookies } from 'next/headers';
import { createServerClient } from '@supabase/ssr';
import { revalidatePath } from 'next/cache';
import { z } from 'zod';

async function getAnalystId(): Promise<string> {
  const cookieStore = cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() { return cookieStore.getAll(); },
        setAll(cookiesToSet) {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        },
      },
    },
  );
  const { data: { session }, error } = await supabase.auth.getSession();
  if (error || !session) throw new Error('Unauthenticated');
  return session.user.id;
}

const DecisionSchema = z.object({
  alertId: z.string().uuid(),
  decision: z.enum(['approved', 'escalated', 'dismissed']),
});

export async function recordDecision(
  alertId: string,
  decision: 'approved' | 'escalated' | 'dismissed',
): Promise<{ success: boolean; error?: string }> {
  const parsed = DecisionSchema.safeParse({ alertId, decision });
  if (!parsed.success) return { success: false, error: 'Invalid input' };

  let analystId: string;
  try {
    analystId = await getAnalystId();
  } catch {
    return { success: false, error: 'Unauthenticated' };
  }

  const { createClient } = await import('@supabase/supabase-js');
  const supabaseAdmin = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );

  const { error } = await supabaseAdmin
    .from('aml_alerts')
    .update({
      analyst_decision: decision,
      analyst_id: analystId,
      decided_at: new Date().toISOString(),
    })
    .eq('id', alertId)
    .is('analyst_decision', null);  // idempotency guard

  if (error) {
    console.error('[actions] recordDecision failed:', error.message);
    return { success: false, error: error.message };
  }

  await supabaseAdmin.from('aml_audit_logs').insert({
    alert_id: alertId,
    event_type: 'decided',
    payload: { decision, analyst_id: analystId },
  });

  revalidatePath('/alerts');
  return { success: true };
                    }
