"""
SENTINEL — Stress Ngữ cảnh: Token Input vs Số lượng Log (Context Budget Curve)
==============================================================================
Trả lời "log quá dài/nhiều thì tràn ngữ cảnh không, và biết tinh chỉnh thế nào":
đẩy số log tăng dần N ∈ {1..2000} và đo token đưa vào LLM theo HAI cách:

  - RAW (nối thẳng mọi log)            -> tăng TUYẾN TÍNH, vượt n_ctx rất nhanh.
  - COMPRESSED (Drain template mining) -> BÃO HÒA, bị chặn BẰNG THIẾT KẾ.

Chứng minh kiến trúc giữ ngữ cảnh trong ngân sách (token_budget=4000, n_ctx=8192)
bất kể số log, nên local LLM KHÔNG bị tràn vì "log quá nhiều". Tất định, KHÔNG LLM.

Chạy:  .venv/bin/python experiments/run_context_stress.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.token_monitor import N_CTX  # noqa: E402
from src.guardrails.template_miner import (  # noqa: E402
    LogTemplateMiner,
    TokenBudgetManager,
    load_config,
)

GT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "context_stress_results.json")
PLOT_PATH = os.path.join(os.path.dirname(__file__), "results", "plots", "context_stress.png")

N_LEVELS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000]


def load_log_pool(limit=2000):
    with open(GT_PATH) as f:
        gt = json.load(f)
    pool = []
    for s in gt:
        for log in s.get("logs", []):
            pool.append(log)
            if len(pool) >= limit:
                return pool
    return pool


def main():
    print("=" * 70)
    print("  SENTINEL — STRESS NGỮ CẢNH (token input vs số log, Drain compression)")
    print("=" * 70)

    cfg = load_config()
    token_budget = int(cfg.get("guardrails", {}).get("token_budget", 4000))
    pool = load_log_pool()
    print(f"[*] Pool log thật: {len(pool)} | n_ctx={N_CTX} | token_budget={token_budget}")

    rows = []
    for N in N_LEVELS:
        logs = [pool[i % len(pool)] for i in range(N)]

        raw_text = "\n".join(str(x) for x in logs)
        raw_tokens = TokenBudgetManager.estimate_tokens(raw_text)

        miner = LogTemplateMiner()
        for x in logs:
            miner.add_log_dict(x)
        compressed = miner.format_for_llm()
        comp_tokens = TokenBudgetManager.estimate_tokens(compressed)
        n_templates = len(miner.get_summary())
        ratio = miner.get_compression_ratio()

        rows.append(
            {
                "n_logs": N,
                "raw_tokens": raw_tokens,
                "compressed_tokens": comp_tokens,
                "n_templates": n_templates,
                "compression_ratio": round(ratio, 1),
                "raw_exceeds_nctx": raw_tokens > N_CTX,
                "compressed_within_budget": comp_tokens <= token_budget,
            }
        )
        flag = "⚠️ RAW TRÀN n_ctx" if raw_tokens > N_CTX else ""
        print(
            f"[N={N:>4}] raw={raw_tokens:>7} tok | compressed={comp_tokens:>5} tok "
            f"| {n_templates} template (nén {ratio:.0f}×) {flag}"
        )

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {"n_ctx": N_CTX, "token_budget": token_budget, "sweep": rows},
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"\n[+] Saved -> {OUT_JSON}")

    # ---- Plot ----
    try:
        import matplotlib.pyplot as plt

        ns = [r["n_logs"] for r in rows]
        raw = [r["raw_tokens"] for r in rows]
        comp = [r["compressed_tokens"] for r in rows]

        plt.figure(figsize=(10, 6))
        plt.plot(ns, raw, "o-", color="#C62828", label="RAW (nối thẳng log)", linewidth=2)
        plt.plot(ns, comp, "s-", color="#2E7D32", label="COMPRESSED (Drain template)", linewidth=2)
        plt.axhline(N_CTX, color="#1565C0", linestyle="--", linewidth=1.5, label=f"n_ctx = {N_CTX}")
        plt.axhline(
            token_budget,
            color="#EF6C00",
            linestyle=":",
            linewidth=1.5,
            label=f"token_budget = {token_budget}",
        )
        plt.xscale("log")
        plt.yscale("log")
        plt.xlabel("Số lượng log trong một batch (log scale)", fontsize=12)
        plt.ylabel("Token đưa vào LLM (log scale)", fontsize=12)
        plt.title("Ngân sách Ngữ cảnh: nén template giữ token bị chặn bất kể số log", fontsize=13)
        plt.grid(True, alpha=0.3, which="both")
        plt.legend(loc="center left", fontsize=10)
        os.makedirs(os.path.dirname(PLOT_PATH), exist_ok=True)
        plt.savefig(PLOT_PATH, dpi=300, bbox_inches="tight")
        print(f"[+] Plot -> {PLOT_PATH}")
    except Exception as e:
        print(f"[!] Plot skipped: {e}")


if __name__ == "__main__":
    main()
