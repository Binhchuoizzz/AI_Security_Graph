"""
Đánh giá Hiệu năng Độ trễ: Hệ thống 2 Lớp (Two-Tier) so với LLM-only

CHỨC NĂNG:
  Đo độ trễ của 2 chế độ:
    - Two-Tier:  Tier1 → Guardrail → RAG → LLM
    - Baseline:  Mỗi sự kiện → LLM trực tiếp (không lọc, không RAG)

  Sử dụng 100 sự kiện từ ground truth (50 benign, 50 malicious).
  Mục tiêu: Giảm thiểu độ trễ ≥ 60% so với baseline chỉ dùng LLM.

  LƯU Ý: Yêu cầu llama.cpp server chạy tại port 5000.
  Nếu server không hoạt động, kiểm thử sẽ được bỏ qua (SKIP) an toàn.

KẾT QUẢ ĐẦU RA:
  experiments/results/latency_benchmark.json
"""

import json
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def check_llm_server():
    """Kiểm tra máy chủ llama.cpp có đang chạy hay không. Thử kết nối với các port 5000 và 8080."""
    import urllib.request

    for port in [5000, 8080]:
        try:
            req = urllib.request.Request(f"http://localhost:{port}/v1/models")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    # Thiết lập biến môi trường để LLMClient sử dụng port chính xác
                    os.environ["LLM_API_BASE"] = f"http://127.0.0.1:{port}/v1"
                    print(f"  LLM server detected on port {port}")
                    return True
        except Exception:
            continue
    return False


def load_test_events(n=100):
    """Tải các sự kiện kiểm thử từ tập ground truth."""
    gt_path = "experiments/ground_truth.json"
    with open(gt_path) as f:
        samples = json.load(f)

    benign = [s for s in samples if s.get("input", {}).get("cicids_label") == "Benign"]
    malicious = [
        s
        for s in samples
        if s.get("input", {}).get("cicids_label") != "Benign"
        and s.get("input", {}).get("cicids_label") != "Adversarial"
    ]

    # Lấy tối đa n/2 mẫu từ mỗi nhóm
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
    """Chạy pipeline 2 Lớp và trả về độ trễ của từng sự kiện (tính bằng ms)."""
    from src.agent.llm_client import LLMClient
    from src.guardrails.prompt_filter import GuardrailsPipeline
    from src.guardrails.template_miner import LogTemplateMiner
    from src.rag.retriever import DualRetriever
    from src.tier1_filter.rule_engine import RuleEngine

    engine = RuleEngine()
    LogTemplateMiner()
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

        # Lớp bảo vệ
        guard_result = guardrails.process_batch([event])
        safe_log = guard_result.get("batch_encapsulated", str(event))

        # RAG
        context = retriever.retrieve(safe_log[:500])  # Giới hạn độ dài truy vấn

        # LLM
        try:
            _ = llm.invoke(
                [
                    {
                        "role": "user",
                        "content": str(context.get("combined_prompt", "")) + "\n" + safe_log[:1000],
                    }
                ]
            )
        except Exception:
            # Cuộc gọi LLM thất bại, vẫn tính thời gian xử lý
            pass

        latencies.append((time.perf_counter() - t_start) * 1000)

    print(f"  Tier 1 drops: {tier1_drops}/{len(events)} events")
    return latencies


def measure_llm_only_baseline(events: list) -> list:
    """Chạy chế độ chỉ dùng LLM (không có Tier 1, không có RAG) và trả về độ trễ (ms)."""
    from src.agent.llm_client import LLMClient

    llm = LLMClient()
    latencies = []

    for event in events:
        t_start = time.perf_counter()

        # Suy luận trực tiếp bằng LLM — không lọc, không RAG
        raw_log = json.dumps(event, default=str)[:1500]
        try:
            _ = llm.invoke([{"role": "user", "content": raw_log}])
        except Exception:
            pass

        latencies.append((time.perf_counter() - t_start) * 1000)

    return latencies


def run(n_events: int = 100):
    # Kiểm tra máy chủ LLM
    if not check_llm_server():
        print("[SKIP] llama.cpp server not running on port 5000 or 8080.")
        print("       Start with one of:")
        print(
            "         llama-server -m ~/text-generation-webui/user_data/models/gemma-2-9b-it-Q6_K.gguf -ngl 35 --port 5000"
        )
        print("         or set LLM_API_BASE=http://127.0.0.1:8080/v1")
        print("       Then re-run this script.")

        # Lưu kết quả bỏ qua (skip)
        Path("experiments/results").mkdir(exist_ok=True)
        json.dump(
            {"status": "SKIPPED", "reason": "LLM server not available"},
            open("experiments/results/latency_benchmark.json", "w"),
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

    # Thống kê
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
Status:            {"✅ PASS" if reduction_pct >= 60 else "❌ FAIL"}
═══════════════════════════════════════
    """)

    # Lưu kết quả chi tiết
    results = {
        "hardware": "i7-14700KF / RTX 4060 Ti 16GB / 32GB DDR5",
        "n_events": actual_n,
        "baseline_mean_ms": round(baseline_mean, 2),
        "two_tier_mean_ms": round(two_tier_mean, 2),
        "latency_reduction_pct": round(reduction_pct, 2),
        "target_pct": 60,
        "pass": bool(reduction_pct >= 60),
        "per_event_two_tier_ms": [round(x, 2) for x in two_tier_latencies],
        "per_event_baseline_ms": [round(x, 2) for x in baseline_latencies],
    }

    Path("experiments/results").mkdir(exist_ok=True)
    with open("experiments/results/latency_benchmark.json", "w") as fh:
        json.dump(results, fh, indent=2)
    print("Saved: experiments/results/latency_benchmark.json")

    # Kiểm định thống kê Mann-Whitney U
    try:
        from scipy.stats import mannwhitneyu

        stat, p_value = mannwhitneyu(two_tier_latencies, baseline_latencies, alternative="less")
        print(f"Mann-Whitney U Test: stat={stat:.2f}, p={p_value:.6f}")
        print(f"Statistical significance: {'✅ p < 0.05' if p_value < 0.05 else '❌ p >= 0.05'}")
    except ImportError:
        print("[WARN] scipy not installed, skipping Mann-Whitney U test")
        print("       Install with: pip install scipy")

    return reduction_pct >= 60


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
