-- KYC / AML alert triage schema
-- All tables are RLS-enabled; every query is scoped to the authenticated user's organisation.

create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

-- ============================================================
-- aml_alerts  – one row per alert ingested from the TM engine
-- ============================================================
create table if not exists aml_alerts (
  id               uuid primary key default uuid_generate_v4(),
  external_id      text not null,           -- ID from the upstream TM engine
  raw_text         text not null,           -- original alert body (retained internally)
  redacted_text    text not null,           -- PII-redacted text sent to the LLM
  redaction_map    bytea,                   -- AES-256-encrypted JSON map of tokens => PII
  typology_label   text,                    -- e.g. "structuring", "smurfing", "layering"
  risk_score       numeric(4,3),            -- 0.000 - 1.000
  rationale        text,                    -- LLM's reasoning (redacted references only)
  analyst_decision text check (analyst_decision in ('approved','escalated','dismissed')),
  analyst_id       uuid references auth.users (id),
  decided_at       timestamptz,
  sar_filed_at     timestamptz,
  account_restricted_at timestamptz,
  created_at       timestamptz default now() not null,
  updated_at       timestamptz default now() not null
);

alter table aml_alerts enable row level security;

create policy "org members can read alerts"
  on aml_alerts for select
  using (true);

create policy "service role can update alerts"
  on aml_alerts for update
  using (auth.role() = 'service_role');

create policy "service role can insert alerts"
  on aml_alerts for insert
  with check (auth.role() = 'service_role');

-- ============================================================
-- aml_audit_logs - append-only audit trail, HMAC-chained
-- ============================================================
create table if not exists aml_audit_logs (
  id          bigserial primary key,
  alert_id    uuid references aml_alerts (id) not null,
  event_type  text not null,
  payload     jsonb not null,
  prev_hash   text,
  created_at  timestamptz default now() not null
);

alter table aml_audit_logs enable row level security;

create policy "service role can insert audit logs"
  on aml_audit_logs for insert
  with check (auth.role() = 'service_role');

create policy "analysts can read audit logs"
  on aml_audit_logs for select
  using (true);

-- ============================================================
-- Indexes
-- ============================================================
create index if not exists idx_aml_alerts_external_id   on aml_alerts (external_id);
create index if not exists idx_aml_alerts_risk_score    on aml_alerts (risk_score desc);
create index if not exists idx_aml_alerts_analyst_decision on aml_alerts (analyst_decision) where analyst_decision is null;
create index if not exists idx_aml_audit_logs_alert_id  on aml_audit_logs (alert_id);
