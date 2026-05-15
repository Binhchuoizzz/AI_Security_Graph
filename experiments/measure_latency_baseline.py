"""
Latency Benchmark: Two-Tier System vs LLM-only Baseline

CHỨC NĂNG:
  Đo latency của 2 chế độ:
    - Two-Tier:  Tier1 → Guardrail → RAG → LLM
    - Baseline:  Every event → LLM directly (no filtering, no RAG)

  Sử dụng 100 events từ ground truth (50 benign, 50 malicious).
  Target: ≥ 60% latency reduction so với LLM-only baseline.

  LƯU Ý: Yêu cầu llama.cpp server chạy tại port 5000.
  Nếu server không khả dụng, test sẽ SKIP gracefully.

OUTPUT:
  reports/latency_benchmark.json
"""

import sys
import os
import time
import json
import numpy as np
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def check_llm_server():
    """Check if llama.cpp server is running. Tries port 5000 and 8080."""
    import urllib.request
    for port in [5000, 8080]:
        try:
            req = urllib.request.Request(f"http://localhost:{port}/v1/models")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    # Set env var so LLMClient uses correct port
                    os.environ["LLM_API_BASE"] = f"http://127.0.0.1:{port}/v1"
                    print(f"  LLM server detected on port {port}")
                    return True
        except Exception:
            continue
    return False


def load_test_events(n=100):
    """Load test events from ground truth."""
    gt_path = "experiments/ground_truth.json"
    with open(gt_path) as f:
        samples = json.load(f)

    benign = [s for s in samples if s.get("input", {}).get("cicids_label") == "Benign"]
    malicious = [s for s in samples if s.get("input", {}).get("cicids_label") != "Benign"
                 and s.get("input", {}).get("cicids_label") != "Adversarial"]

    # Take up to n/2 from each
    import random
    random.seed(42)
    benign_sample = random.sample(benign, min(n // 2, len(benign)))
    malicious_sample = random.sample(malicious, min(n // 2, len(malicious)))

    events = []
    for s in benign_sample + malicious_sample:
        if s.get("logs"):
            events.append(s["logs"][0])
    return events


def measure_two_tier(events: list) -> list:
    """Run Two-Tier pipeline, return latency per event in ms."""
    from src.tier1_filter.rule_engine import RuleEngine
    from src.guardrails.template_miner import LogTemplateMiner
    from src.guardrails.prompt_filter import GuardrailsPipeline
    from src.rag.retriever import DualRetriever
    from src.agent.llm_client import LLMClient

    engine = RuleEngine()
    miner = LogTemplateMiner()
    guardrails = GuardrailsPipeline()
    retriever = DualRetriever(use_cache=False)
    llm = LLMClient()

    latencies = []
    tier1_drops = 0

    for event in events:
        t_start = time.perf_counter()

        # Tier 1
        result = engine.evaluate(event)
        if result.get("tier1_action") == "DROP" or result.get("tier1_action") == "WHITELIST_DROP":
            tier1_drops += 1
            latencies.append((time.perf_counter() - t_start) * 1000)
            continue

        # Guardrails
        guard_result = guardrails.process_batch([event])
        safe_log = guard_result.get("batch_encapsulated", str(event))

        # RAG
        context = retriever.retrieve(safe_log[:500])  # cap query length

        # LLM
        try:
            _ = llm.analyze(safe_log[:1000], context.get("combined_prompt", ""))
        except Exception:
            # LLM call may fail, still count latency
            pass

        latencies.append((time.perf_counter() - t_start) * 1000)

    print(f"  Tier 1 drops: {tier1_drops}/{len(events)} events")
    return latencies


def measure_llm_only_baseline(events: list) -> list:
    """Run LLM-only (no Tier 1, no RAG), return latency per event in ms."""
    from src.agent.llm_client import LLMClient

    llm = LLMClient()
    latencies = []

    for event in events:
        t_start = time.perf_counter()

        # Direct LLM inference — no filtering, no RAG
        raw_log = json.dumps(event, default=str)[:1500]
        try:
            _ = llm.analyze(raw_log, context="")
        except Exception:
            pass

        latencies.append((time.perf_counter() - t_start) * 1000)

    return latencies


def run(n_events: int = 100):
    # Check LLM server
    if not check_llm_server():
        print("[SKIP] llama.cpp server not running on port 5000 or 8080.")
        print("       Start with one of:")
        print("         llama-server -m ~/text-generation-webui/user_data/models/gemma-2-9b-it-Q6_K.gguf -ngl 35 --port 5000")
        print("         or set LLM_API_BASE=http://127.0.0.1:8080/v1")
        print("       Then re-run this script.")

        # Save skip result
        Path("reports").mkdir(exist_ok=True)
        json.dump(
            {"status": "SKIPPED", "reason": "LLM server not available"},
            open("reports/latency_benchmark.json", "w"),
            indent=2,
        )
        return False

    print(f"Loading {n_events} test events...")
    events = load_test_events(n_events)
    actual_n = len(events)
    print(f"  Loaded {actual_n} events")

    print(f"\n[1/2] Measuring Two-Tier latency ({actual_n} events)...")
    two_tier_latencies = measure_two_tier(events)

    print(f"\n[2/2] Measuring LLM-only baseline ({actual_n} events)...")
    baseline_latencies = measure_llm_only_baseline(events)

    # Statistics
    two_tier_mean = np.mean(two_tier_latencies)
    baseline_mean = np.mean(baseline_latencies)
    reduction_pct = (baseline_mean - two_tier_mean) / baseline_mean * 100

    print(f"""
═══════════════════════════════════════
LATENCY BENCHMARK RESULTS ({actual_n} events)
═══════════════════════════════════════
Baseline (LLM-only):
  Mean:   {baseline_mean:.1f} ms
  Median: {np.median(baseline_latencies):.1f} ms
  P95:    {np.percentile(baseline_latencies, 95):.1f} ms

Two-Tier (SENTINEL):
  Mean:   {two_tier_mean:.1f} ms
  Median: {np.median(two_tier_latencies):.1f} ms
  P95:    {np.percentile(two_tier_latencies, 95):.1f} ms

Latency Reduction: {reduction_pct:.1f}%
Target:            ≥ 60%
Status:            {'✅ PASS' if reduction_pct >= 60 else '❌ FAIL'}
═══════════════════════════════════════
    """)

    # Save detailed results
    results = {
        "hardware": "i7-14700KF / RTX 4060 Ti 16GB / 32GB DDR5",
        "n_events": actual_n,
        "baseline_mean_ms": round(baseline_mean, 2),
        "two_tier_mean_ms": round(two_tier_mean, 2),
        "latency_reduction_pct": round(reduction_pct, 2),
        "target_pct": 60,
        "pass": reduction_pct >= 60,
        "per_event_two_tier_ms": [round(x, 2) for x in two_tier_latencies],
        "per_event_baseline_ms": [round(x, 2) for x in baseline_latencies],
    }

    Path("reports").mkdir(exist_ok=True)
    json.dump(results, open("reports/latency_benchmark.json", "w"), indent=2)
    print("Saved: reports/latency_benchmark.json")

    # Mann-Whitney U test
    try:
        from scipy.stats import mannwhitneyu
        stat, p_value = mannwhitneyu(two_tier_latencies, baseline_latencies,
                                      alternative="less")
        print(f"Mann-Whitney U Test: stat={stat:.2f}, p={p_value:.6f}")
        print(f"Statistical significance: {'✅ p < 0.05' if p_value < 0.05 else '❌ p >= 0.05'}")
    except ImportError:
        print("[WARN] scipy not installed, skipping Mann-Whitney U test")
        print("       Install with: pip install scipy")

    return reduction_pct >= 60


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
