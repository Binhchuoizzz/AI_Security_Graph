"""
SENTINEL — Phân Tích Độ Nhạy Ngưỡng Welford (Z-score Threshold Sensitivity)
===========================================================================
Trả lời câu hỏi phản biện: "Ngưỡng 3.5σ có phải chọn may rủi / tinh chỉnh
quá khớp (cherry-pick) không?". Ta QUÉT ngưỡng Z-score của bộ phát hiện dị biệt
Welford trên ĐÚNG luồng gộp thật của `evaluate_unified_stream.py` (Tier-1 ĐẦY ĐỦ,
KHÔNG LLM, tất định) và đo trade-off:

  - Tỷ lệ escalation (tải đẩy lên Tier-2)         -> chi phí điện toán LLM
  - Tỷ lệ báo động nhầm trên benign (FP rate)     -> nhiễu cho phân tích viên
  - Precision / Recall / F1 ở tầng lọc Tier-1
  - Zero-day Welford bắt được (trên 7)            -> năng lực phát hiện

Ngưỡng được làm tham số trong RuleEngine (`z_threshold`, mặc định 3.5 — hành vi
production KHÔNG đổi). Script này CHỈ ghi đè thuộc tính khi quét.

Chạy:  .venv/bin/python experiments/run_threshold_sensitivity.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.evaluate_unified_stream import (  # noqa: E402
    BENIGN_ACTIONS,
    _is_threat,
    build_stream,
    static_only_action,
)
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "threshold_sensitivity_results.json")

# Dải ngưỡng quét quanh điểm vận hành 3.5σ (3-sigma rule cổ điển ở giữa).
THRESHOLDS = [2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]


def eval_at_threshold(tau: float, warmup, main):
    """Chạy TOÀN BỘ luồng gộp qua Tier-1 với ngưỡng Welford = tau. Trả về metrics."""
    engine = RuleEngine()
    engine.z_threshold = tau

    cls = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    flagged_total = 0  # số sự kiện bị Tier-1 gắn cờ (escalate/actioned) = tải Tier-2
    total_events = 0
    zd_caught = 0
    zd_total = 0

    # Warmup: học baseline Welford từ benign (đóng góp TN/FP)
    for ev in warmup:
        res = engine.evaluate(ev["log"])
        flagged = _is_threat(res["tier1_action"])
        cls["fp" if flagged else "tn"] += 1
        flagged_total += 1 if flagged else 0
        total_events += 1

    for ev in main:
        src = ev["source"]
        if src == "cicids":
            res = engine.evaluate(ev["log"])
            flagged = _is_threat(res["tier1_action"])
            if ev["expected_threat"]:
                cls["tp" if flagged else "fn"] += 1
            else:
                cls["fp" if flagged else "tn"] += 1
            flagged_total += 1 if flagged else 0
            total_events += 1
        elif src == "dapt":
            res = engine.evaluate(ev["log"])
            flagged = _is_threat(res["tier1_action"])
            flagged_total += 1 if flagged else 0
            total_events += 1
        elif src == "zeroday":
            static_act = static_only_action(engine, ev["log"])
            res = engine.evaluate(ev["log"])
            zd_total += 1
            if static_act in BENIGN_ACTIONS and _is_threat(res["tier1_action"]):
                zd_caught += 1
            flagged_total += 1 if _is_threat(res["tier1_action"]) else 0
            total_events += 1

    tp, fp, tn, fn = cls["tp"], cls["fp"], cls["tn"], cls["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    escalation_rate = flagged_total / total_events if total_events else 0.0

    return {
        "z_threshold": tau,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "benign_fp_rate": round(fpr, 4),
        "escalation_rate": round(escalation_rate, 4),
        "zeroday_caught": zd_caught,
        "zeroday_total": zd_total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def main():
    print("=" * 74)
    print("  SENTINEL — ĐỘ NHẠY NGƯỠNG WELFORD (Z-score) trên luồng gộp thật, Tier-1")
    print("=" * 74)

    # Xây luồng gộp MỘT lần (tất định) rồi tái dùng cho mọi ngưỡng.
    warmup, main, _apt_truth, n_chains = build_stream()
    print(
        f"[*] Luồng: {len(warmup)} benign warmup | {len(main)} sự kiện chính "
        f"| {n_chains} chuỗi DAPT"
    )

    rows = []
    for tau in THRESHOLDS:
        r = eval_at_threshold(tau, warmup, main)
        rows.append(r)
        star = "  <- điểm vận hành" if abs(tau - 3.5) < 1e-9 else ""
        print(
            f"[τ={tau:>3.1f}σ] F1={r['f1']:.3f} P={r['precision']:.3f} R={r['recall']:.3f} "
            f"| FP(benign)={r['benign_fp_rate']:.3f} | escal={r['escalation_rate']:.3f} "
            f"| zero-day={r['zeroday_caught']}/{r['zeroday_total']}{star}"
        )

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump({"operating_point": 3.5, "sweep": rows}, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved -> {OUT_JSON}")


if __name__ == "__main__":
    main()
