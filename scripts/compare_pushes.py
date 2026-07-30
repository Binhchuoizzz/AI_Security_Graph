"""So sánh nhiều lần đẩy cạnh nhau — trả lời "đẩy lần sau có nhẹ hơn không, nhờ cơ chế nào".

Ghép hai nguồn số ĐỘC LẬP cho mỗi lượt:
  - `audit.json`            — chấm từ tracer Tier-2 (chất lượng LLM/RAG, độ trễ, cache)
  - `pipeline_stats.*.json` — bộ đếm Tier-1 (cơ chế nào đã chặn), lấy hiệu SAU − TRƯỚC

Chạy:  .venv/bin/python scripts/compare_pushes.py p1_cold p2_warm p3_warm
"""

import json
import os
import sys

RUNS = "reports/runs"


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _stats(label: str) -> dict:
    """Bộ đếm của RIÊNG lượt này = ảnh chụp SAU trừ TRƯỚC (bộ đếm gốc là luỹ kế)."""
    b = _load(os.path.join(RUNS, label, "pipeline_stats.BEFORE.json"))
    a = _load(os.path.join(RUNS, label, "pipeline_stats.AFTER.json"))
    bo, ao = b.get("offload_counts") or {}, a.get("offload_counts") or {}
    d = {k: int(ao.get(k, 0)) - int(bo.get(k, 0)) for k in set(ao) | set(bo)}
    d["raw"] = int(a.get("raw_logs_total", 0)) - int(b.get("raw_logs_total", 0))
    return d


def _row(name: str, vals: list, base: list | None = None, pct: bool = False) -> str:
    cells = []
    for i, v in enumerate(vals):
        s = f"{v:,}" if isinstance(v, int) else (f"{v:.2f}" if isinstance(v, float) else str(v))
        if base and i > 0 and isinstance(v, int) and isinstance(base[0], int) and base[0]:
            delta = 100 * (v - base[0]) / base[0]
            s += f" ({delta:+.0f}%)"
        cells.append(f"{s:>22s}")
    return f"  {name:<34s}" + "".join(cells)


def main() -> int:
    labels = sys.argv[1:] or ["p1_cold", "p2_warm", "p3_warm"]
    audits = [_load(os.path.join(RUNS, x, "audit.json")) for x in labels]
    stats = [_stats(x) for x in labels]
    have = [i for i, a in enumerate(audits) if a]
    if not have:
        print("[!] chưa lượt nào có audit.json")
        return 1
    labels = [labels[i] for i in have]
    audits = [audits[i] for i in have]
    stats = [stats[i] for i in have]

    print("\n" + "=" * 106)
    print("SO SÁNH CÁC LẦN ĐẨY — cùng 5.000 sự kiện, lượt #1 nguội, các lượt sau GIỮ trí nhớ")
    print("=" * 106)
    print(f"  {'':<34s}" + "".join(f"{x:>22s}" for x in labels))
    print("  " + "-" * 102)

    raw = [s.get("raw", 0) for s in stats]
    print(_row("Sự kiện thô qua Tier-1", raw))

    print("\n  ── TẢI LÊN TIER-2 (điều cần chứng minh) ──")
    llm_ev = [s.get("escalated_to_llm", 0) for s in stats]
    batches = [a.get("n_records", 0) for a in audits]
    calls = [(a.get("llm") or {}).get("real_calls", 0) for a in audits]
    print(_row("Sự kiện phải nhờ LLM", llm_ev, base=llm_ev))
    print(_row("Lô Tier-2", batches, base=batches))
    print(_row("GỌI LLM THẬT", calls, base=calls))

    print("\n  ── CƠ CHẾ CHẶN Ở TIER-1 ──")
    for key, name in (
        ("t1_reputation_block", "Tiền sử IP ≥70 (bền)"),
        ("t1_blacklist_memory", "Trí nhớ blacklist (TTL 1h)"),
        ("t1_dynamic_rule", "Luật động từ Tác tử"),
        ("t1_waf_signature", "Chữ ký WAF"),
        ("t1_zscore", "Dị biệt Z-score"),
        ("t1_other", "Điểm tĩnh khác"),
    ):
        print(_row(name, [s.get(key, 0) for s in stats]))
    print(_row("Cổng ML tự quyết", [s.get("ml_gate_resolved", 0) for s in stats]))

    print("\n  ── CACHE PHÁN QUYẾT ──")
    for layer in ("exact", "feature"):
        print(
            _row(
                f"HIT lớp {layer}",
                [(a.get("llm") or {}).get("cache_layers", {}).get(layer, 0) for a in audits],
            )
        )

    print("\n  ── CHẤT LƯỢNG (mẫu co lại ở lượt warm — đọc kèm cỡ mẫu) ──")
    print(_row("Lô chấm được", [(a.get("llm") or {}).get("scorable", 0) for a in audits]))
    print(_row("Đúng kỹ thuật (exact)", [(a.get("llm") or {}).get("exact", 0) for a in audits]))
    print(_row("Lỗi parse JSON", [(a.get("llm") or {}).get("parse_errors", 0) for a in audits]))
    print(_row("Độ trễ p95 (s)", [(a.get("llm") or {}).get("latency_p95") or 0.0 for a in audits]))
    print(
        _row(
            "Rò rỉ nhãn vào prompt",
            [(a.get("leakage") or {}).get("attack_technique_id", 0) for a in audits],
        )
    )

    if len(calls) > 1 and calls[0]:
        drop = 100 * (calls[0] - calls[1]) / calls[0]
        # `{drop:+.1f}` in ra "+16.9%" cho một mức GIẢM 16,9% — dấu cộng đọc như thể tải
        # TĂNG. Đây là dòng kết luận của cả phép đo, và nó sẽ được chép thẳng vào luận văn,
        # nên phải nói bằng chữ chứ không để người đọc tự suy dấu.
        verb = "GIẢM" if drop > 0 else ("TĂNG" if drop < 0 else "KHÔNG ĐỔI")
        print("\n" + "=" * 106)
        print(
            f"  TẢI LLM đẩy #2 so với #1: gọi LLM thật {calls[0]} -> {calls[1]} "
            f"= {verb} {abs(drop):.1f}%"
        )
        print("=" * 106)
    return 0


if __name__ == "__main__":
    sys.exit(main())
