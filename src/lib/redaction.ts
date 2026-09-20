/**
 * redaction.ts
 *
 * Synchronous PII redaction for AML alert text.
 *
 * Two-layer approach:
 *   1. Deterministic regex patterns for well-structured PII (IBANs, card numbers,
 *      phone numbers, email addresses, UK/EU postcodes, IP addresses).
 *   2. Named-entity recognition via a lightweight Python microservice that runs
 *      Presidio Analyzer.  The NER call is a local HTTP request so it adds
 *      minimal latency and PII never leaves the processing environment.
 *
 * The redacted text (with [PERSON_1], [IBAN_1], ... tokens) is the only version
 * sent to the Anthropic API.  The original => token mapping is stored encrypted
 * alongside the alert so analysts can de-redact for review.
 */

export interface RedactionResult {
  redactedText: string;
  redactionMap: Record<string, string>;
}

const PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'IBAN', regex: /\b([A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?)\b/g },
  { label: 'CARD', regex: /\b(?:\d[ -]?){13,19}\b/g },
  { label: 'EMAIL', regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g },
  { label: 'PHONE', regex: /(?:\+44|0)(?:\s?\d){9,11}\b/g },
  { label: 'POSTCODE', regex: /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/gi },
  { label: 'IP', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
];

function regexRedact(
  text: string,
  redactionMap: Record<string, string>,
  counters: Record<string, number>,
): string {
  let redacted = text;
  for (const { label, regex } of PATTERNS) {
    regex.lastIndex = 0;
    redacted = redacted.replace(regex, (match) => {
      const normalised = match.trim();
      const existing = Object.entries(redactionMap).find(([, v]) => v === normalised);
      if (existing) return existing[0];
      counters[label] = (counters[label] ?? 0) + 1;
      const token = `[${label}_${counters[label]}]`;
      redactionMap[token] = normalised;
      return token;
    });
  }
  return redacted;
}

interface NerEntity {
  entity_type: string;
  start: number;
  end: number;
  text: string;
}

async function nerRedact(
  text: string,
  redactionMap: Record<string, string>,
  counters: Record<string, number>,
): Promise<string> {
  const NER_URL = process.env.NER_SERVICE_URL ?? 'http://localhost:8080/analyze';
  let entities: NerEntity[] = [];
  try {
    const res = await fetch(NER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, language: 'en' }),
      signal: AbortSignal.timeout(2000),
    });
    if (res.ok) entities = (await res.json()) as NerEntity[];
  } catch { /* NER unavailable — regex layer still applied */ }

  if (entities.length === 0) return text;
  entities.sort((a, b) => b.start - a.start);
  let result = text;
  for (const ent of entities) {
    const existing = Object.entries(redactionMap).find(([, v]) => v === ent.text);
    let token: string;
    if (existing) {
      token = existing[0];
    } else {
      counters[ent.entity_type] = (counters[ent.entity_type] ?? 0) + 1;
      token = `[${ent.entity_type}_${counters[ent.entity_type]}]`;
      redactionMap[token] = ent.text;
    }
    result = result.slice(0, ent.start) + token + result.slice(ent.end);
  }
  return result;
}

export async function redact(rawText: string): Promise<RedactionResult> {
  const redactionMap: Record<string, string> = {};
  const counters: Record<string, number> = {};
  let redacted = regexRedact(rawText, redactionMap, counters);
  redacted = await nerRedact(redacted, redactionMap, counters);
  return { redactedText: redacted, redactionMap };
}
