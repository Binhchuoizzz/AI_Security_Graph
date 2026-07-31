"""
SENTINEL — Stress Ngữ cảnh: Token Input vs Số lượng Log (Context Budget Curve)
[Luận văn Ch.4 §Context-Budget Observability & Stress — token vs số log, nén Drain, tránh tràn n_ctx]
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
import random
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.unified_dataset import drop_authored  # noqa: E402
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


def load_log_pool(limit=2000, diverse=False):
    """Pool log để nén.

    `diverse=False` — lấy N log ĐẦU TIÊN của ground_truth. Vì tệp gom theo lớp, N log đầu
    gần như cùng một loại nên Drain gộp hết về **một** template: kết quả đo được là
    `n_templates = 1` ở MỌI mức N, kể cả N=1000. "Nén 1000×" đó là kịch bản DỄ NHẤT có thể,
    không phải đại diện cho log SOC thật.

    `diverse=True` — lấy MẪU RẢI ĐỀU trên toàn tệp để chạm mọi lớp tấn công. Đây mới là
    phép thử thật của khâu nén, và là con số phải báo cùng.
    """
    with open(GT_PATH) as f:
        gt = json.load(f)
    # Cùng dân số THẬT như mọi phép đo ground_truth khác — xem `drop_authored`. Payload đối
    # địch tự viết có hình thái rất khác log thật nên sẽ làm lệch tỉ lệ nén.
    gt, _ = drop_authored(gt)
    if not diverse:
        pool = []
        for s in gt:
            for log in s.get("logs", []):
                pool.append(log)
                if len(pool) >= limit:
                    return pool
        return pool

    # XÁO TRỘN CÓ SEED, không dùng bước nhảy. Bản nháp đầu dùng `gt[::stride]` với
    # `stride = len(gt) // (limit // 2)`; với 1.750 mẫu và limit 2.000 thì stride ra **1**,
    # tức không rải gì cả và pool "đa dạng" trùng khít pool đồng nhất — hai cột số giống hệt
    # nhau, đúng thứ phép thử này sinh ra để tránh. Xáo trộn không phụ thuộc cỡ tệp.
    order = list(range(len(gt)))
    random.Random(42).shuffle(order)
    pool = []
    for i in order:
        pool.extend(gt[i].get("logs", []))
        if len(pool) >= limit:
            break
    return pool[:limit]


def sweep(pool: list, token_budget: int, tag: str) -> list:
    """Chạy dải N trên một pool và trả các dòng kết quả."""
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
            f"  [{tag} N={N:>4}] raw={raw_tokens:>7} tok | compressed={comp_tokens:>5} tok "
            f"| {n_templates} template (nén {ratio:.0f}×) {flag}"
        )
    return rows


def main():
    print("=" * 70)
    print("  SENTINEL — STRESS NGỮ CẢNH (token input vs số log, Drain compression)")
    print("=" * 70)

    cfg = load_config()
    _tb = cfg.get("guardrails", {}).get("token_budget", 4000)
    token_budget = int(_tb) if isinstance(_tb, (int, float, str)) else 4000
    pool_h = load_log_pool(diverse=False)
    pool_d = load_log_pool(diverse=True)
    print(f"[*] n_ctx={N_CTX} | token_budget={token_budget}")
    print(f"[*] Pool ĐỒNG NHẤT: {len(pool_h)} log (kịch bản dễ nhất)")
    rows = sweep(pool_h, token_budget, "đồng nhất")
    print(f"[*] Pool ĐA DẠNG: {len(pool_d)} log (rải đều mọi lớp — phép thử thật)")
    rows_d = sweep(pool_d, token_budget, "đa dạng ")

    _tpl_h = max(r["n_templates"] for r in rows)
    _tpl_d = max(r["n_templates"] for r in rows_d)
    _worst_d = max(r["compressed_tokens"] for r in rows_d)

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(
            {
                "n_ctx": N_CTX,
                "token_budget": token_budget,
                # `sweep` giữ tên cũ cho tương thích ngược với các script đọc tệp này.
                "sweep": rows,
                "sweep_diverse": rows_d,
                "max_templates_homogeneous": _tpl_h,
                "max_templates_diverse": _tpl_d,
                "worst_compressed_tokens_diverse": _worst_d,
                "diverse_within_budget": _worst_d <= token_budget,
                "note": (
                    "PHẢI báo CẢ HAI. `sweep` dùng pool đồng nhất — ground_truth gom theo lớp "
                    "nên N log đầu gộp về 1 template, tức đo trên đầu vào DỄ NHẤT có thể. "
                    "`sweep_diverse` rải đều mọi lớp và là con số đại diện cho log SOC thật. "
                    "Chỉ trích số của pool đồng nhất là thổi phồng năng lực nén."
                ),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(
        f"\n[*] Template tối đa: đồng nhất {_tpl_h} · đa dạng {_tpl_d} | "
        f"nén xấu nhất (đa dạng) {_worst_d} tok / ngân sách {token_budget}"
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
