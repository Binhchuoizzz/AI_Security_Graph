"""Đo hiệu quả Bộ đệm Tầng 1.75 (Semantic Cache) trên truy vấn RAG của luồng thật.

[Luận văn Ch.4 — vế "Bộ đệm Semantic Cache Tầng 1.75" của RQ1]

VÌ SAO CÓ TỆP NÀY. RQ1 nêu đích danh ba cơ chế xả tải: bộ lọc Welford O(1), Cổng ML LightGBM
và **Bộ đệm Semantic Cache Tầng 1.75**. Hai cái đầu có phép đo riêng; cái thứ ba thì không —
`SemanticCache.get_hit_rate()` chỉ được đọc ké trong `run_ablation.py` như một dòng phụ. Một
cơ chế được nêu trong câu hỏi nghiên cứu mà không có phép đo là một lỗ hổng phải bịt.

ĐO TRÊN ĐÚNG THỨ HỆ THỐNG HỎI. Không tự bịa truy vấn: dựng lại chuỗi bằng chính
`build_rag_queries()` mà `node_rag_context` dùng, trên các sự kiện THỰC SỰ lọt qua Tier-1 và
Cổng ML. Cache chỉ có ý nghĩa trên phân bố truy vấn thật; đo trên truy vấn tự soạn thì tỉ lệ
trúng muốn bao nhiêu cũng được.

MỘT ĐIỀU PHẢI NÓI THẲNG. Khoá cache là `sha256(query_text)` — KHỚP CHÍNH XÁC, không phải
tương đồng embedding. Tên gọi "Semantic Cache" dễ khiến người đọc hiểu là khớp ngữ nghĩa;
báo cáo phải ghi rõ cơ chế thật, vì tỉ lệ trúng của khớp-chính-xác phụ thuộc hoàn toàn vào
mức lặp lại của truy vấn, và `build_rag_queries` cố tình chuẩn hoá đầu vào nên nhiều log
KHÁC nhau sinh ra cùng một truy vấn. Đó mới là nguồn của tỉ lệ trúng, và nói đúng nguồn thì
con số vẫn đẹp mà không phải khoác cho nó một cơ chế nó không có.

Chạy:  .venv/bin/python experiments/run_cache_efficiency.py [--limit 1500]
Ra:    experiments/results/cache_efficiency_results.json
"""

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

OUT = "experiments/results/cache_efficiency_results.json"


def collect_tier2_queries(limit: int) -> tuple[list[str], dict]:
    """Chạy Tier-1 + Cổng ML để lấy CHÍNH những truy vấn sẽ tới RAG."""
    from experiments.unified_dataset import build_stream
    from src.agent.nodes import build_rag_queries
    from src.tier1_filter.ml_gateway import MLGateway
    from src.tier1_filter.rule_engine import RuleEngine

    warmup, main, _apt, _n = build_stream()
    engine, gw = RuleEngine(), MLGateway()
    # `build_stream()` trả phần tử VỎ BỌC {source, log, expected_threat, label, t}; log thật
    # nằm ở `ev["log"]`. Truyền cả vỏ vào Tier-1 thì engine không thấy một trường nào nó
    # biết -> `tier1_score = 0` cho MỌI sự kiện -> DROP 100%, kể cả tấn công. Đo được: 0/2370
    # tấn công escalate. Bẫy này im lặng tuyệt đối vì không có ngoại lệ nào được ném ra.
    # Nguồn sự thật: `unified_dataset.score_stream()` — luôn gọi `engine.evaluate(ev["log"])`.
    for w in warmup:
        try:
            engine.evaluate(w["log"])
        except Exception:
            pass

    queries: list[str] = []
    funnel = {"scanned": 0, "tier1_drop": 0, "ml_gate": 0, "reached_rag": 0}
    for ev in main:
        if len(queries) >= limit:
            break
        funnel["scanned"] += 1
        try:
            log = ev["log"]
            if engine.evaluate(log).get("tier1_action") in ("DROP", "WHITELIST_DROP"):
                funnel["tier1_drop"] += 1
                continue
            if gw.evaluate(log)[0]:
                funnel["ml_gate"] += 1
                continue
            tq, cq = build_rag_queries([log])
            if not tq:
                continue
            funnel["reached_rag"] += 1
            queries.append(tq)
            # Truy vấn 2 chỉ chạy khi log CÓ payload và khác truy vấn kỹ thuật — sao chép
            # đúng điều kiện của node_rag_context, nếu không sẽ thổi phồng số lượt truy xuất.
            if cq and cq != tq:
                queries.append(cq)
        except Exception:
            continue
    return queries, funnel


def run(limit: int = 1500) -> dict:
    from src.rag.retriever import DualRetriever

    print(f"[*] Gom truy vấn RAG từ luồng thật (trần {limit} sự kiện tới RAG)…")
    queries, funnel = collect_tier2_queries(limit)
    if not queries:
        print("[!] Không có truy vấn nào tới RAG — không đo được.")
        return {}
    print(f"    {len(queries)} truy vấn · phễu: {funnel}")

    retriever = DualRetriever(use_cache=True)
    if retriever.cache:
        retriever.cache.clear()

    hit_ms: list[float] = []
    miss_ms: list[float] = []
    for q in queries:
        t0 = time.perf_counter()
        res = retriever.retrieve(q)
        dt = (time.perf_counter() - t0) * 1000
        (hit_ms if res.get("cache_hit") else miss_ms).append(dt)

    stats = retriever.cache.get_stats() if retriever.cache else {}
    n = len(queries)
    n_hit = len(hit_ms)
    mean_hit = statistics.fmean(hit_ms) if hit_ms else None
    mean_miss = statistics.fmean(miss_ms) if miss_ms else None

    results = {
        "n_queries": n,
        "n_distinct_queries": len(set(queries)),
        "funnel_to_rag": funnel,
        "hit_rate": round(n_hit / n, 4),
        "n_hits": n_hit,
        "n_misses": len(miss_ms),
        "mean_ms_hit": round(mean_hit, 3) if mean_hit is not None else None,
        "mean_ms_miss": round(mean_miss, 3) if mean_miss is not None else None,
        "speedup_x": round(mean_miss / mean_hit, 1) if (mean_hit and mean_miss) else None,
        "ms_saved_total": round((mean_miss - mean_hit) * n_hit, 1)
        if (mean_hit is not None and mean_miss is not None)
        else None,
        "cache_stats": stats,
        "key_strategy": "sha256(query_text) — KHỚP CHÍNH XÁC, không phải tương đồng embedding",
        "why_hits_happen": (
            "build_rag_queries() chuẩn hoá log về mô tả dịch vụ/cổng/kỹ thuật, nên nhiều "
            "sự kiện KHÁC nhau sinh cùng một chuỗi truy vấn. Tỉ lệ trúng đến từ đó, không "
            "phải từ so khớp ngữ nghĩa."
        ),
        "scope_note": (
            "Đây là tỉ lệ trúng trên truy vấn RAG của các ca ĐÃ lọt Tier-1 và Cổng ML — "
            "KHÔNG phải tỉ lệ xả tải toàn hệ. Xả tải toàn hệ xem latency_benchmark.json."
        ),
    }

    print(f"\n    Tỉ lệ trúng: {results['hit_rate']:.2%}  ({n_hit}/{n})")
    print(f"    Trúng {results['mean_ms_hit']} ms · trượt {results['mean_ms_miss']} ms")
    if results["speedup_x"]:
        print(f"    Nhanh hơn {results['speedup_x']}× · tiết kiệm {results['ms_saved_total']} ms")

    Path("experiments/results").mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[+] Đã lưu: {OUT}")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Đo hiệu quả bộ đệm RAG Tầng 1.75.")
    ap.add_argument("--limit", type=int, default=1500, help="Trần số sự kiện tới RAG.")
    a = ap.parse_args()
    run(a.limit)
