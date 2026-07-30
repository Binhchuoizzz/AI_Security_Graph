"""In PHÂN BỔ GIẢM TẢI của riêng một lượt đẩy = pipeline_stats SAU trừ TRƯỚC.

Bộ đếm trong `config/pipeline_stats.json` là LUỸ KẾ (giữ nguyên qua các lần khởi động lại,
đúng giao ước sẵn có của `raw_logs_total`). Nên số của một lượt chỉ ra được bằng phép trừ hai
ảnh chụp — `run_audit_cycle.sh` chụp giúp ở hai đầu lượt.

Chạy:  .venv/bin/python scripts/diff_pipeline_stats.py reports/runs/<nhãn>
"""

import json
import os
import sys

# Nhãn hiển thị cho từng khoá — giữ ở MỘT chỗ để báo cáo và mã không trôi khỏi nhau.
LABELS = {
    "t1_blacklist_memory": "Trí nhớ blacklist (Redis, TTL 1h)",
    "t1_reputation_block": "Tiền sử IP ≥70 (SQLite, vĩnh viễn)",
    "t1_reputation_escalate": "Tiền sử IP ≥50 → đẩy lên gate",
    "t1_waf_signature": "Chữ ký WAF",
    "t1_injection_signature": "Chữ ký prompt-injection",
    "t1_dynamic_rule": "Luật động từ Tác tử",
    "t1_apt_chain": "Chuỗi APT nổi lên",
    "t1_zscore": "Dị biệt Z-score (zero-day)",
    "t1_other": "Điểm tĩnh khác",
    "ml_gate_resolved": "Cổng ML tự quyết (KHÔNG cần LLM)",
    "escalated_to_llm": "Phải nhờ Tier-2 (LLM)",
}


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f) or {}
    except Exception:
        return {}


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    before = _load(os.path.join(out, "pipeline_stats.BEFORE.json"))
    after = _load(os.path.join(out, "pipeline_stats.AFTER.json"))
    if not after:
        print("[!] thiếu pipeline_stats.AFTER.json — bỏ qua phân bổ giảm tải")
        return 0

    b_raw = int(before.get("raw_logs_total", 0))
    a_raw = int(after.get("raw_logs_total", 0))
    b_off = before.get("offload_counts") or {}
    a_off = after.get("offload_counts") or {}

    n = a_raw - b_raw
    print("\n── PHÂN BỔ GIẢM TẢI (riêng lượt này) ────────────────────────────────")
    if n <= 0:
        print(f"  [!] raw_logs_total không tăng ({b_raw} -> {a_raw}) — subscriber có chạy không?")
        return 0
    print(f"  Sự kiện thô qua Tier-1: {n}")

    keys = sorted(set(a_off) | set(b_off))
    mech = [
        (k, int(a_off.get(k, 0)) - int(b_off.get(k, 0)))
        for k in keys
        if not k.startswith("action:")
    ]
    acts = [
        (k, int(a_off.get(k, 0)) - int(b_off.get(k, 0))) for k in keys if k.startswith("action:")
    ]

    print("\n  Hành động cuối của Tier-1:")
    for k, v in sorted(acts, key=lambda kv: -kv[1]):
        if v:
            print(f"    {k.split(':', 1)[1]:16s} {v:6d}  ({100 * v / n:5.1f}%)")

    print("\n  Cơ chế đã CHẶN (không lên Tier-2):")
    tot_stop = 0
    for k, v in sorted(mech, key=lambda kv: -kv[1]):
        if not v or k in ("ml_gate_resolved", "escalated_to_llm"):
            continue
        tot_stop += v
        print(f"    {LABELS.get(k, k):38s} {v:6d}  ({100 * v / n:5.1f}%)")
    print(f"    {'— tổng chặn ở Tier-1':38s} {tot_stop:6d}  ({100 * tot_stop / n:5.1f}%)")

    gate = dict(mech).get("ml_gate_resolved", 0)
    llm = dict(mech).get("escalated_to_llm", 0)
    esc = gate + llm
    print("\n  Trong số leo thang:")
    print(
        f"    {LABELS['ml_gate_resolved']:38s} {gate:6d}"
        + (f"  ({100 * gate / esc:5.1f}% ca leo thang)" if esc else "")
    )
    print(
        f"    {LABELS['escalated_to_llm']:38s} {llm:6d}"
        + (f"  ({100 * llm / esc:5.1f}% ca leo thang)" if esc else "")
    )
    print(f"\n  => Chỉ {llm}/{n} = {100 * llm / n:.2f}% lưu lượng thô chạm tới LLM")
    return 0


if __name__ == "__main__":
    sys.exit(main())
