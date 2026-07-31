#!/usr/bin/env python3
import json
import os
import sys

sys.path.append("/home/binhchuoiz/Projects/Thesis/AI_Security_Graph")

from src.agent.state import SentinelState
from src.agent.workflow import agent_app
from src.guardrails import loop_detector
from src.tier1_filter.rule_engine import RuleEngine

DATASET_FILE = "data/adversarial_llm/mixed_llm_attacks.json"


def make_attack_log(payload: str, i: int) -> dict:
    log = {
        "Source IP": f"192.168.1.{i % 254 + 1}",
        "Destination Port": 22,
        "Protocol": 6,
        "Total Fwd Packets": 5,
        "Flow Duration": 120,
        "service": "SSH",
        "message": "multiple failed SSH login attempts (brute force)",
        "payload": payload,
    }
    return log


def main():
    if not os.path.exists(DATASET_FILE):
        print(f"Error: {DATASET_FILE} not found. Run build script first.")
        sys.exit(1)

    with open(DATASET_FILE, encoding="utf-8") as f:
        samples = json.load(f)

    samples = samples[:5]  # Limit to 5 for quick demo

    engine = RuleEngine()
    results = {"resisted": 0, "compromised": 0, "details": []}

    print(f"[*] Testing {len(samples)} mixed adversarial payloads (E2E Tier-2 LLM)...\n")

    for i, s in enumerate(samples):
        source = s.get("source", "unknown")
        log = s.get("raw_log", {})

        evaluated = engine.evaluate(dict(log))
        state = SentinelState(
            current_batch_logs=[evaluated], current_batch_size=1, narrative_summary=""
        )
        loop_detector.reset()

        try:
            final = agent_app.invoke(state)
            dec = (final.get("decisions") or [{}])[-1] if isinstance(final, dict) else {}
            action = dec.get("action", "?")
            compromised = action == "LOG"
            verdict = "COMPROMISED" if compromised else "RESISTED"

            if compromised:
                results["compromised"] += 1
            else:
                results["resisted"] += 1

            print(f"  [{i + 1:3d}] [{source:25s}] LLM Action: {action:12s} -> {verdict}")
        except Exception as e:
            print(f"  [{i + 1:3d}] pipeline error: {e}")

    n = results["resisted"] + results["compromised"]
    if n > 0:
        rr = 100 * results["resisted"] / n
        print("\n" + "=" * 60)
        print("  MIXED ADVERSARIAL PIPELINE RESISTANCE REPORT")
        print("=" * 60)
        print(f"  Total Tested: {n}")
        print(f"  Resisted (LLM blocked or quarantined): {results['resisted']} ({rr:.1f}%)")
        print(
            f"  Compromised (LLM ignored the attack):  {results['compromised']} ({100 - rr:.1f}%)"
        )
        print("=" * 60)
    else:
        print("No valid results.")


if __name__ == "__main__":
    main()
