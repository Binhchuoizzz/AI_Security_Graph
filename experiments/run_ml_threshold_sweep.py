"""SENTINEL — Độ nhạy NGƯỠNG CỔNG ML (chính sách 4 dải).

ĐỐI XỨNG với `run_threshold_sensitivity.py` (vốn quét ngưỡng Welford τ để bác bỏ nghi ngờ
"3.5σ là cherry-pick"). Cùng câu hỏi phản biện đó áp cho Cổng ML — *"0.85 / 0.65 / 0.40 lấy
ở đâu ra?"* — nhưng trước đây KHÔNG có phép đo nào trả lời. Script này lấp chỗ trống.

CHÍNH SÁCH ĐANG QUÉT (xem `src/guardrails/decision_policy.py`):
    C >= block     -> BLOCK_IP          (tự chặn, dứt khoát)
    escalate<=C<block -> ESCALATE       (đẩy LLM — đây là CHI PHÍ)
    alert <= C < escalate -> ALERT      (cảnh báo yếu)
    C < alert      -> DROP              (dừng ở Tier-1)

ĐÁNH ĐỔI ĐƯỢC ĐO
    block  ↑ -> auto-BLOCK sạch hơn nhưng ÍT ca tự quyết -> tải LLM TĂNG.
    escalate ↓ -> bypass nhiều hơn (đỡ LLM) nhưng ML phải quyết cả ca mơ hồ -> dễ sai.
    Chỉ số ĐẦU BẢNG là `auto_block_precision`: lệnh chặn tự động KHÔNG THỂ đảo, nên một
    ngưỡng làm nó tụt là ngưỡng không dùng được, dù F1 gộp có đẹp lên.

CHẠY TRỰC TIẾP TRÊN XÁC SUẤT: mỗi sự kiện chỉ suy luận MỘT lần, xác suất được lưu lại rồi
áp mọi ngưỡng lên cùng bộ xác suất đó. Nhờ vậy quét 10 cấu hình vẫn chỉ tốn 1 lượt inference,
và mọi ngưỡng nhìn ĐÚNG CÙNG một tập mẫu (khác biệt là do ngưỡng, không do nhiễu lấy mẫu).

Thuần ĐỌC, KHÔNG cần LLM. Chạy:
    .venv/bin/python experiments/run_ml_threshold_sweep.py
"""

import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.evaluate_ml_gate import _is_threat  # noqa: E402
from experiments.metrics_core import confusion_report, wilson_ci  # noqa: E402
from src.guardrails import decision_policy  # noqa: E402
from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "datatest.json")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "ml_threshold_sweep_results.json")

# Điểm vận hành hiện tại — mốc so sánh.
OPERATING = (
    decision_policy.ML_BLOCK_CONF,
    decision_policy.ML_ESCALATE_CONF,
    decision_policy.ML_ALERT_CONF,
)

# Quét quanh điểm vận hành. Giữ bất biến alert <= escalate <= block.
BLOCK_GRID = [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
ESCALATE_GRID = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75]
ALERT_FIXED = decision_policy.ML_ALERT_CONF


def collect_probabilities(gw: MLGateway, events: list) -> list[dict]:
    """Suy luận MỘT lần cho cả sweep: trả [(p_attack, nhãn thật, có bị abstain không)].

    Ca ML từ chối (thiếu phủ đặc trưng / OOD) được giữ lại với `abstain=True` — chúng
    KHÔNG phụ thuộc ngưỡng nên phải nằm ngoài ma trận nhầm lẫn ở mọi cấu hình, nhưng vẫn
    tính vào tải LLM.
    """
    out: list[dict] = []
    for ev in events:
        action, _r, _c, sec = gw.evaluate_detailed(ev)
        rec: dict[str, object] = {
            "is_threat": _is_threat(ev),
            "abstain": False,
            "p_attack": None,
        }
        if sec.get("skipped") or sec.get("ood_abstain"):
            rec["abstain"] = True
        elif action is not None or sec.get("reason") == "":
            # Cổng ML đã ra quyết định -> tái tạo p_attack từ độ tin cậy trả về.
            # `evaluate_detailed` trả confidence_benign cho DROP, confidence_attack cho
            # BLOCK/ALERT, nên phải quy về CÙNG một trục "xác suất tấn công".
            rec["p_attack"] = (1.0 - _c) if action == "DROP" else _c
        else:
            rec["p_attack"] = _c
        out.append(rec)
    return out


def eval_at(records: list[dict], block: float, escalate: float, alert: float) -> dict:
    """Áp một bộ ngưỡng lên bộ xác suất ĐÃ TÍNH SẴN."""
    tp = fp = tn = fn = 0
    n_llm = 0  # ca phải lên LLM = ESCALATE + abstain -> chi phí thật
    blk_tp = blk_fp = 0

    for r in records:
        if r["abstain"] or r["p_attack"] is None:
            n_llm += 1
            continue
        p = float(r["p_attack"])  # type: ignore[arg-type]
        threat = bool(r["is_threat"])
        if p >= block:
            pred, decided = True, True
            blk_tp += int(threat)
            blk_fp += int(not threat)
        elif p >= escalate:
            n_llm += 1  # dải ESCALATE = đẩy LLM, KHÔNG tính vào phân loại của ML
            continue
        elif p >= alert:
            pred, decided = True, True
        else:
            pred, decided = False, True

        if decided:
            if threat and pred:
                tp += 1
            elif (not threat) and pred:
                fp += 1
            elif (not threat) and (not pred):
                tn += 1
            else:
                fn += 1

    n = len(records)
    rep = confusion_report(tp, fp, tn, fn)
    n_decided = tp + fp + tn + fn
    n_blk = blk_tp + blk_fp
    return {
        "block": block,
        "escalate": escalate,
        "alert": alert,
        "is_operating_point": (block, escalate, alert) == OPERATING,
        "mcc": rep["mcc"],
        "f1": rep["f1"],
        "precision": rep["precision"],
        "recall": rep["recall"],
        # CHỈ SỐ ĐẦU BẢNG: lệnh chặn tự động không thể đảo -> ngưỡng nào làm nó tụt là loại.
        "auto_block_precision": round(blk_tp / n_blk, 4) if n_blk else None,
        "auto_block_precision_ci95": list(wilson_ci(blk_tp, n_blk)) if n_blk else None,
        "auto_block_n": n_blk,
        "auto_block_fp": blk_fp,
        "bypass_rate": round(n_decided / n, 4) if n else 0.0,
        "llm_load_rate": round(n_llm / n, 4) if n else 0.0,
        "n_llm_calls": n_llm,
    }


def main():
    ap = argparse.ArgumentParser(description="Quét ngưỡng Cổng ML (chống nghi ngờ cherry-pick)")
    ap.add_argument("--data", default=DATA_PATH)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=OUT_JSON)
    args = ap.parse_args()

    if not os.path.exists(args.data):
        print(f"[-] Không thấy data: {args.data} — chạy scripts/build_datatest.py trước.")
        sys.exit(1)
    with open(args.data, encoding="utf-8") as f:
        events = json.load(f)
    if args.limit:
        events = events[: args.limit]

    gw = MLGateway()
    if not gw.pipeline:
        print("[-] Không nạp được ml_lab/tier_2_model.pkl — bỏ qua.")
        sys.exit(1)

    print("=" * 96)
    print("  SENTINEL — ĐỘ NHẠY NGƯỠNG CỔNG ML (đối xứng với sweep Welford)")
    print("=" * 96)
    print(
        f"[*] Suy luận 1 lượt trên {len(events)} sự kiện, rồi áp mọi ngưỡng lên cùng bộ xác suất…"
    )
    records = collect_probabilities(gw, events)
    n_abstain = sum(1 for r in records if r["abstain"])
    print(f"[*] {n_abstain} ca ML từ chối quyết (không phụ thuộc ngưỡng)\n")

    rows = []
    # (a) quét ngưỡng BLOCK, giữ nguyên escalate/alert
    for b in BLOCK_GRID:
        rows.append(eval_at(records, b, decision_policy.ML_ESCALATE_CONF, ALERT_FIXED))
    # (b) quét ngưỡng ESCALATE, giữ nguyên block/alert
    for e in ESCALATE_GRID:
        if e <= decision_policy.ML_BLOCK_CONF:
            rows.append(eval_at(records, decision_policy.ML_BLOCK_CONF, e, ALERT_FIXED))

    hdr = (
        f"{'block':>6s} {'escal':>6s} {'MCC':>7s} {'F1':>7s} "
        f"{'autoBLK-P':>10s} {'n_BLK':>7s} {'FP':>5s} {'tải LLM':>9s}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        star = "  <- điểm vận hành" if r["is_operating_point"] else ""
        abp = f"{r['auto_block_precision']:.4f}" if r["auto_block_precision"] is not None else "—"
        print(
            f"{r['block']:>6.2f} {r['escalate']:>6.2f} {r['mcc']:>7.3f} {r['f1']:>7.3f} "
            f"{abp:>10s} {r['auto_block_n']:>7d} {r['auto_block_fp']:>5d} "
            f"{r['llm_load_rate']:>8.1%}{star}"
        )

    print(
        "\nĐỌC BẢNG: nâng `block` làm auto-BLOCK sạch hơn nhưng đẩy tải LLM lên; hạ `escalate`\n"
        "giảm tải LLM nhưng bắt ML quyết cả ca mơ hồ. Điểm vận hành hợp lệ khi\n"
        "auto_block_precision KHÔNG tụt trong khi tải LLM vẫn ở mức chấp nhận được —\n"
        "một cao nguyên phẳng quanh điểm vận hành là bằng chứng ngưỡng KHÔNG cherry-pick."
    )

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(
            {
                "operating_point": {
                    "block": OPERATING[0],
                    "escalate": OPERATING[1],
                    "alert": OPERATING[2],
                },
                "n_events": len(events),
                "n_abstain": n_abstain,
                "sweep": rows,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    print(f"\n[+] JSON: {args.out}")


if __name__ == "__main__":
    main()
