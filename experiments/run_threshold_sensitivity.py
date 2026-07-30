"""
SENTINEL — Phân Tích Độ Nhạy Ngưỡng Welford (Z-score Threshold Sensitivity)
[Luận văn Ch.4 §Welford Threshold Sensitivity — biện minh chọn 3.5σ, chống cherry-pick]
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

from experiments.metrics_core import confusion_report  # noqa: E402
from experiments.unified_dataset import (  # noqa: E402
    build_stream,
    score_stream,
    warn_unhandled,
)
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "threshold_sensitivity_results.json")

# Dải ngưỡng quét quanh điểm vận hành 3.5σ (3-sigma rule cổ điển ở giữa).
THRESHOLDS = [2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]


def eval_at_threshold(tau: float, warmup, main):
    """Chạy TOÀN BỘ luồng gộp qua Tier-1 với ngưỡng Welford = tau. Trả về metrics.

    Dùng `score_stream()` DÙNG CHUNG với `evaluate_unified_stream.py`. Trước đây file này
    giữ một BẢN SAO của vòng chấm, và bản sao đó mang y hệt hai lỗi: bỏ sót nguồn
    `cicids_max`/`dapt_max` (~25.000 sự kiện biến mất khỏi ma trận) và chấm cả warmup vào
    lớp benign (test-on-train). Vì thế sweep từng cho đúng bộ số sai của bản gốc. Gộp về
    một hàm nên từ nay sửa một chỗ là cả hai script cùng đúng.
    """
    engine = RuleEngine()
    engine.z_threshold = tau

    scored = score_stream(engine, warmup, main, collect_zeroday=True)
    warn_unhandled(scored["excluded_by_source"])

    cls = scored["confusion"]
    tp, fp, tn, fn = cls["tp"], cls["fp"], cls["tn"], cls["fn"]
    rep = confusion_report(tp, fp, tn, fn)

    zd = scored["zeroday"]
    zd_caught = sum(1 for z in zd if z["caught_by_welford"])
    total_events = scored["n_stream_events"]

    return {
        "z_threshold": tau,
        "precision": rep["precision"],
        "recall": rep["recall"],
        "f1": rep["f1"],
        # MCC: chỉ số chính khi so các ngưỡng — không bị base rate làm nhiễu như F1.
        "mcc": rep["mcc"],
        "balanced_accuracy": rep["balanced_accuracy"],
        "benign_fp_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        # Tải đẩy lên Tier-2 = chi phí điện toán LLM của điểm vận hành này.
        "escalation_rate": round(scored["n_flagged"] / total_events, 4) if total_events else 0.0,
        "zeroday_caught": zd_caught,
        "zeroday_total": len(zd),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n_scored": rep["n_scored"],
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
            f"[τ={tau:>3.1f}σ] MCC={r['mcc']:.3f} F1={r['f1']:.3f} P={r['precision']:.3f} "
            f"R={r['recall']:.3f} | FP(benign)={r['benign_fp_rate']:.3f} "
            f"| escal={r['escalation_rate']:.3f} "
            f"| zero-day={r['zeroday_caught']}/{r['zeroday_total']}{star}"
        )

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump({"operating_point": 3.5, "sweep": rows}, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved -> {OUT_JSON}")


if __name__ == "__main__":
    main()
