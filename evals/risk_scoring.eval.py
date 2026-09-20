"""risk_scoring.eval.py

LLM eval harness for the KYC/AML triage pipeline's risk-scoring step.

Compares a *baseline* system (plain LLM call, no system prompt) against the
*guarded* system (system prompt + forced tool-use) on 15 labelled alert
fixtures across three FATF typologies.

Usage: python evals/risk_scoring.eval.py

CI gate: Exit code 1 if guarded accuracy < 0.80 or guarded accuracy < baseline.
"""

from __future__ import annotations
import json, os, time
from dataclasses import dataclass
from typing import Any
import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-7-sonnet-20250219")

PRICING: dict[str, tuple[float, float]] = {
    "claude-3-7-sonnet-20250219": (3.0, 15.0),
    "claude-3-5-haiku-20241022": (0.8, 4.0),
}

def token_cost(input_tok: int, output_tok: int) -> float:
    p_in, p_out = PRICING.get(MODEL, (3.0, 15.0))
    return (input_tok * p_in + output_tok * p_out) / 1_000_000

FIXTURES: list[dict[str, Any]] = [
    {"id": "struct-1", "text": "[PERSON_1] made 9 cash deposits of £2 800 each over 5 days at different branches.", "expected": "structuring"},
    {"id": "struct-2", "text": "Account [IBAN_1] received 12 transfers of £2 500 from 12 different [PERSON] accounts within 48 hours.", "expected": "structuring"},
    {"id": "struct-3", "text": "[PERSON_1] split a £25 000 property payment into 10 separate wire transfers of £2 490 each on consecutive days.", "expected": "structuring"},
    {"id": "struct-4", "text": "Customer deposited £2 700, £2 600 and £2 750 across three different branches on the same day.", "expected": "structuring"},
    {"id": "struct-5", "text": "Fifteen cash deposits ranging from £1 900 to £2 400 were made to [IBAN_1] within a single month, totalling £32 000.", "expected": "structuring"},
    {"id": "smurf-1", "text": "Five individuals, each depositing £3 000 in cash, subsequently transferred all funds to [IBAN_1] within 24 hours.", "expected": "smurfing"},
    {"id": "smurf-2", "text": "[PERSON_1], [PERSON_2] and [PERSON_3] each deposited £4 500 and immediately transferred to the same beneficiary account.", "expected": "smurfing"},
    {"id": "smurf-3", "text": "Network of 8 new accounts, each funded with exactly £2 800 cash, all transacting to a single [ORG_1] account.", "expected": "smurfing"},
    {"id": "smurf-4", "text": "Coordinated deposits: 6 customers, unrelated by stated relationship, simultaneously deposited cash amounts under £3 000 and merged funds to one account.", "expected": "smurfing"},
    {"id": "smurf-5", "text": "[PERSON_1] acted as intermediary, collecting cash from multiple unnamed individuals and consolidating into [IBAN_1].", "expected": "smurfing"},
    {"id": "country-1", "text": "Transfer of £45 000 from [IBAN_1] (jurisdiction A, high-risk list) to [IBAN_2] (jurisdiction B, sanctioned territory).", "expected": "unusual_country_pair"},
    {"id": "country-2", "text": "Customer with low-risk profile sent £8 000 to a correspondent bank in a jurisdiction flagged by FATF.", "expected": "unusual_country_pair"},
    {"id": "country-3", "text": "Rapid series of transfers routing through [COUNTRY_1], [COUNTRY_2] and [COUNTRY_3], all on FATF grey or black list.", "expected": "unusual_country_pair"},
    {"id": "country-4", "text": "[PERSON_1] received £120 000 from an offshore entity in a secrecy jurisdiction with no stated business relationship.", "expected": "unusual_country_pair"},
    {"id": "country-5", "text": "Wire of £55 000 to [ORG_1] registered in a high-risk jurisdiction; customer's stated business is entirely domestic.", "expected": "unusual_country_pair"},
]

TYPOLOGIES = ["structuring","smurfing","layering","unusual_country_pair","rapid_movement","shell_company","cash_intensive","trade_based","other"]

RISK_TOOL = {
    "name": "record_risk_assessment",
    "description": "Record the risk assessment for an AML alert.",
    "input_schema": {
        "type": "object",
        "properties": {
            "typology_label": {"type": "string", "enum": TYPOLOGIES},
            "risk_score": {"type": "number"},
            "rationale": {"type": "string"},
        },
        "required": ["typology_label", "risk_score", "rationale"],
    },
}

SYSTEM_PROMPT = """You are an experienced AML compliance analyst.
You will receive a redacted transaction alert where PII has been replaced with tokens.
Classify the alert against FATF money-laundering typologies and assign a risk score.
Be conservative: when in doubt, score higher to ensure human review."""

@dataclass
class RunResult:
    fixture_id: str
    system: str
    correct: bool
    cost_usd: float
    latency_s: float

def run_baseline(fixture: dict[str, Any]) -> RunResult:
    t0 = time.perf_counter()
    r = client.messages.create(
        model=MODEL, max_tokens=256,
        messages=[{"role": "user", "content": f"Classify this AML alert typology in one word:\n\n{fixture['text']}"}],
    )
    latency = time.perf_counter() - t0
    output = r.content[0].text.strip().lower()
    correct = fixture["expected"] in output
    return RunResult(fixture["id"], "baseline", correct, token_cost(r.usage.input_tokens, r.usage.output_tokens), latency)

def run_guarded(fixture: dict[str, Any]) -> RunResult:
    t0 = time.perf_counter()
    r = client.messages.create(
        model=MODEL, max_tokens=512, system=SYSTEM_PROMPT,
        tools=[RISK_TOOL], tool_choice={"type": "tool", "name": "record_risk_assessment"},
        messages=[{"role": "user", "content": f"Assess this AML alert:\n\n{fixture['text']}"}],
    )
    latency = time.perf_counter() - t0
    tool_block = next((b for b in r.content if b.type == "tool_use"), None)
    label = tool_block.input.get("typology_label", "") if tool_block else ""
    correct = label == fixture["expected"]
    return RunResult(fixture["id"], "guarded", correct, token_cost(r.usage.input_tokens, r.usage.output_tokens), latency)

def main() -> None:
    scenarios = ["structuring", "smurfing", "unusual_country_pair"]
    print(f"\n AML risk-scoring eval   model={MODEL}   fixtures={len(FIXTURES)}\n")

    baseline_results = [run_baseline(f) for f in FIXTURES]
    guarded_results  = [run_guarded(f)  for f in FIXTURES]

    sep = f"|{'-'*30}|{'-'*10}|{'-'*10}|{'-'*14}|{'-'*14}|"
    print(f"| {'Scenario':<28} | {'System':<8} | {'Accuracy':<8} | {'Cost/alert':<12} | {'p50 latency':<12} |")
    print(sep)

    for scenario in scenarios:
        for system, results in [("baseline", baseline_results), ("guarded", guarded_results)]:
            subset = [r for r in results if scenario in r.fixture_id.replace("-", "_")]
            if not subset: continue
            acc = sum(r.correct for r in subset) / len(subset)
            avg_cost = sum(r.cost_usd for r in subset) / len(subset)
            p50 = sorted(r.latency_s for r in subset)[len(subset) // 2]
            tag = "**guarded**" if system == "guarded" else system
            print(f"| {scenario + ' (' + str(len(subset)) + ' alerts)':<28} | {tag:<8} | {acc:.0%}      | ${avg_cost:<11.5f} | {p50*1000:.0f}ms         |")

    base_acc  = sum(r.correct for r in baseline_results) / len(baseline_results)
    guard_acc = sum(r.correct for r in guarded_results) / len(guarded_results)
    print(sep)
    print(f"| {'**Mean**':<28} | {'baseline':<8} | {base_acc:.0%}      | ${sum(r.cost_usd for r in baseline_results)/len(FIXTURES):<11.5f} |              |")
    print(f"| {'**Mean**':<28} | {'**guarded**':<8} | **{guard_acc:.0%}**   | ${sum(r.cost_usd for r in guarded_results)/len(FIXTURES):<11.5f} |              |")

    if guard_acc < 0.80 or guard_acc < base_acc:
        print(f"\n Guarded accuracy {guard_acc:.0%} failed the gate.")
        raise SystemExit(1)
    print(f"\n Guarded accuracy {guard_acc:.0%} — eval passed.")

if __name__ == "__main__":
    main()
