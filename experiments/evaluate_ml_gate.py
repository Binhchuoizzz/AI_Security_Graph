"""
SENTINEL — Đánh giá CỔNG ML (Tier-1, LightGBM) như một CHIỀU riêng của khung 5D.
=============================================================================
Cổng ML là chặng MÁY HỌC của Tier-1: chặn/cảnh báo tức thì các flow tấn công rõ ràng,
GIẢM TẢI cho Tier-2 (LLM). Trước đây khung 5D chỉ đo Tier-1 (rule/Welford) + LLM — CHƯA
đo riêng Cổng ML. Script này bổ sung, đo trên DATA CÂN BẰNG (`data/datatest.json`: ~933
attack / ~1000 benign) để F1 không bị lệch bởi skew.

Đo 2 nhóm chỉ số:
  A) HIỆU NĂNG PHÂN LOẠI + GIẢM TẢI (chiều Accuracy/Performance):
     F1/Precision/Recall (chỉ trên mẫu ML RA quyết định), bypass-rate (ML tự quyết,
     không cần LLM), abstain-rate (OOD -> escalate), skip-rate (payload-thuần), latency,
     majority_baseline (tỷ lệ attack — chống F1 gây ngộ nhận).
  B) KHÁNG NÉ-TRÁNH (chiều Security cho ML): bơm Inf + giá trị cực đoan vào mẫu tấn công,
     đo tỷ lệ lớp bảo mật KHÔNG bị lừa thành benign (block đúng, HOẶC abstain->escalate).

Thuần ĐỌC: không ghi audit/threat_memory/luật động (không làm bẩn hệ thống).

Chạy:
    .venv/bin/python experiments/evaluate_ml_gate.py            # dùng data/datatest.json
    .venv/bin/python experiments/evaluate_ml_gate.py --limit 300
"""

import argparse
import json
import os
import sys
import time
from typing import Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import (  # noqa: E402
    alert_burden,
    bootstrap_ci,
    calibration_report,
    confusion_report,
    per_class_report,
    throughput,
    weakest_classes,
    wilson_ci,
)
from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "datatest.json")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "ml_gate_results.json")

ATTACK_ACTIONS = {"BLOCK_IP", "ALERT"}
BENIGN_ACTIONS = {"LOG"}


def _is_threat(ev: dict) -> bool:
    """Nhãn thật của 1 event luồng gộp (đã enrich)."""
    src = ev.get("unified_source", "")
    if src in ("zeroday", "adversarial"):
        return True
    if src == "dapt":
        return bool(ev.get("apt_is_attack"))
    return bool(ev.get("expected_threat"))


def _has_flow_features(ev: dict) -> bool:
    req = ["Flow Duration", "Total Fwd Packets", "Flow Pkts/s"]
    return any(ev.get(r) not in ("", None, 0) for r in req)


def _f1(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return round(prec, 4), round(rec, 4), round(f1, 4), round(acc, 4)


def _f1_of_pairs(pairs) -> float:
    """F1 tính lại từ cặp (is_threat, pred_attack) — hàm thống kê cho bootstrap CI."""
    tp = sum(1 for t, p in pairs if t and p)
    fp = sum(1 for t, p in pairs if not t and p)
    fn = sum(1 for t, p in pairs if t and not p)
    pr = tp / (tp + fp) if (tp + fp) else 0.0
    rc = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0


def evaluate_classification(gw: MLGateway, events: list) -> dict:
    tp = fp = tn = fn = 0
    n_decided = n_abstain = n_skip = 0
    latencies = []
    n_threat = 0
    decided_records: list[dict] = []  # cho per-class + bootstrap CI
    wall_start = time.perf_counter()
    # Tách confusion THEO TỪNG HÀNH ĐỘNG (= theo dải tin cậy của chính sách 4 dải:
    # BLOCK_IP C>=0.85 · ALERT 0.40-0.65). Cần thiết vì chỉ số headline là độ chính xác
    # của auto-BLOCK — hành động DỨT KHOÁT, không thể đảo — chứ không phải F1 gộp (F1 gộp
    # tính cả dải ALERT low-priority nên bị kéo xuống). Trước đây số này chỉ nằm trong
    # báo cáo viết tay, KHÔNG được script xuất ra -> không tái lập được. Nay xuất ra JSON.
    per_action: dict[str, dict[str, int]] = {}
    cal_conf: list[float] = []
    cal_correct: list[bool] = []
    for ev in events:
        threat = _is_threat(ev)
        n_threat += int(threat)
        t0 = time.perf_counter()
        action, _r, conf, sec = gw.evaluate_detailed(ev)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        if sec.get("ood_abstain"):
            n_abstain += 1
            continue
        if action is None:
            # skip (payload-thuần / thiếu feature) hoặc dưới ngưỡng tự tin
            if sec.get("skipped"):
                n_skip += 1
            else:
                n_abstain += 1  # dưới ngưỡng -> cũng escalate LLM
            continue
        n_decided += 1
        pred_attack = action in ATTACK_ACTIONS
        cell = (
            "tp"
            if (threat and pred_attack)
            else "fp"
            if ((not threat) and pred_attack)
            else "tn"
            if ((not threat) and (not pred_attack))
            else "fn"
        )
        if cell == "tp":
            tp += 1
        elif cell == "fp":
            fp += 1
        elif cell == "tn":
            tn += 1
        else:
            fn += 1
        bucket = per_action.setdefault(action, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        bucket[cell] += 1
        # HIỆU CHUẨN: dải tự quyết của Cổng ML (0,85/0,65/0,40) chỉ hợp lệ nếu `confidence`
        # THẬT SỰ tương ứng với tần suất đúng. Thu cặp (độ tin cậy, đúng/sai) tại đây để
        # tính Brier/ECE — không tốn thêm lần suy luận nào vì giá trị đã có sẵn.
        cal_conf.append(conf or 0.0)
        cal_correct.append(cell in ("tp", "tn"))
        decided_records.append(
            {
                # Nhãn LỚP cụ thể chỉ có ở nguồn `cicids` (từ ground_truth); các nguồn khác
                # chỉ mang Attack/Benign. Suy biến về nhãn thô để bảng per-class vẫn dựng
                # được, chỉ là độ hạt thô hơn ở phần đó.
                "label": ev.get("gt_label") or ("Attack" if threat else "Benign"),
                "source": ev.get("unified_source", ""),
                "is_threat": threat,
                "flagged": pred_attack,
                "action": action,
            }
        )

    wall_elapsed = time.perf_counter() - wall_start
    total = len(events)
    prec, rec, f1, acc = _f1(tp, fp, tn, fn)
    majority = round(n_threat / total, 4) if total else 0.0
    rep = confusion_report(tp, fp, tn, fn)

    # Precision theo TỪNG dải hành động (bằng chứng cho chỉ số headline auto-BLOCK).
    by_action = {}
    for act, c in sorted(per_action.items()):
        n_pred_atk = c["tp"] + c["fp"]
        by_action[act] = {
            **c,
            "n_predicted_attack": n_pred_atk,
            "precision": round(c["tp"] / n_pred_atk, 4) if n_pred_atk else None,
        }
    _blk = by_action.get("BLOCK_IP", {})

    cls_report = per_class_report(decided_records)
    f1_ci = bootstrap_ci(
        [(r["is_threat"], r["flagged"]) for r in decided_records], _f1_of_pairs, seed=42
    )

    return {
        "total_events": total,
        "n_threat": n_threat,
        "majority_baseline_attack_rate": majority,
        "confusion_matrix_on_decided": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "f1_ci95_bootstrap": list(f1_ci),
        # MCC = chỉ số CHÍNH. Bằng 0 với mọi bộ đoán-một-lớp bất kể tỉ lệ lớp, nên không
        # bị base rate đánh lừa như F1/Accuracy. `zero_r_accuracy` là mốc ĐÚNG cho accuracy
        # (bộ phân loại hằng tốt nhất), khác `majority_baseline` (stub luôn hô "tấn công").
        "mcc": rep["mcc"],
        "balanced_accuracy": rep["balanced_accuracy"],
        "accuracy": acc,
        "zero_r_accuracy": rep["zero_r_accuracy"],
        "accuracy_beats_baseline": rep["accuracy_beats_baseline"],
        "specificity": rep["specificity"],
        # Bóc theo lớp: recall gộp che mất lớp bị bỏ sót sạch.
        "per_class": cls_report,
        "weakest_classes": weakest_classes(cls_report, k=3),
        # Thông lượng: trả lời "hệ chịu được bao nhiêu EPS?" — câu hỏi vận hành mà độ trễ
        # mỗi-sự-kiện không trả lời được, và là điều kiện cần cho tuyên bố "LLM cục bộ khả thi".
        "throughput_eps": throughput(total, wall_elapsed),
        "wall_seconds": round(wall_elapsed, 3),
        # Gánh nặng cảnh báo quy về đơn vị SOC thật dùng. LƯU Ý: tỉ lệ thuận với nhịp phát
        # của benchmark, KHÔNG phải nhịp lưu lượng của một mạng doanh nghiệp — phải nêu rõ
        # khi trích, hoặc chuẩn hoá lại theo EPS mục tiêu.
        "alert_burden_at_bench_rate": alert_burden(fp, tp + fp, wall_elapsed),
        "n_decided_by_ml": n_decided,
        "bypass_rate": round(n_decided / total, 4) if total else 0.0,
        "n_abstain_escalate": n_abstain,
        "abstain_rate": round(n_abstain / total, 4) if total else 0.0,
        "n_skip_payload": n_skip,
        "mean_latency_ms": round(sum(latencies) / len(latencies), 4) if latencies else 0.0,
        "metric_valid": (tp + fp + tn + fn) >= 30,
        # Bằng chứng cho headline: auto-BLOCK = dải C>=0.85, hành động dứt khoát.
        "by_action": by_action,
        "auto_block_precision": _blk.get("precision"),
        "auto_block_n": _blk.get("n_predicted_attack", 0),
        "auto_block_fp": _blk.get("fp", 0),
        # Hiệu chuẩn độ tin cậy — kiểm chứng chính GIẢ ĐỊNH nền của chính sách 4 dải.
        # `auto_block_precision` nói "khi đã chặn thì đúng bao nhiêu"; hiệu chuẩn nói
        # "con số tin cậy có nghĩa gì" — cái sau mới biện minh được cho việc CHỌN ngưỡng.
        "confidence_calibration": calibration_report(cal_conf, cal_correct),
    }


# Độ KHÓ của từng chế độ né-tránh — quyết định cách ĐỌC con số, nên phải đi kèm kết quả.
# `*_single` chỉ nhiễu MỘT đặc trưng (lấy theo thứ tự dict, thường còn chẳng phải đặc trưng
# mô hình dùng) nên đạt ~100% là chuyện TẦM THƯỜNG. Chỉ `extreme_broad` mới thực sự thử
# lớp phòng thủ. Vì thế KHÔNG có số gộp: trung bình 3 chế độ sẽ bị 2 chế độ dễ kéo lên.
EVASION_MODES: dict[str, str] = {
    "inf_single": "DỄ — bơm Infinity vào 1 đặc trưng; lớp sanitize bắt ngay",
    "extreme_single": "DỄ — 1 đặc trưng cực đoan; lớp clamp ±8σ chặn được",
    "extreme_broad": "KHÓ — TOÀN BỘ đặc trưng cực đoan; phép thử THẬT của lớp phòng thủ",
}


def _inject(ev: dict, mode: str) -> dict:
    """Sinh biến thể NÉ-TRÁNH từ 1 event flow (xem EVASION_MODES về độ khó)."""
    evil = dict(ev)
    numeric = [k for k, v in ev.items() if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if mode == "inf_single" and numeric:
        evil[numeric[0]] = "Infinity"
    elif mode == "extreme_single" and numeric:
        evil[numeric[0]] = 1e18
    elif mode == "extreme_broad":
        for k in numeric:
            evil[k] = 1e15
    return evil


def evaluate_evasion_resistance(gw: MLGateway, events: list) -> dict:
    """Với mỗi mẫu TẤN CÔNG mà ML vốn bắt được, thử 3 kiểu né-tránh. 'Kháng được' =
    ML KHÔNG bị lừa thành benign/LOG (vẫn BLOCK/ALERT, HOẶC abstain->escalate LLM)."""
    modes = list(EVASION_MODES)
    stats: dict[str, dict[str, Any]] = {
        m: {"attempts": 0, "resisted": 0, "flipped_benign": 0, "difficulty": EVASION_MODES[m]}
        for m in modes
    }
    base_caught = 0
    for ev in events:
        if not _is_threat(ev) or not _has_flow_features(ev):
            continue
        base_action, _r, _c, _s = gw.evaluate_detailed(ev)
        if base_action not in ATTACK_ACTIONS:
            continue  # chỉ thử né-tránh trên mẫu ML vốn ĐÃ bắt là tấn công
        base_caught += 1
        for m in modes:
            evil = _inject(ev, m)
            a, _r2, _c2, sec = gw.evaluate_detailed(evil)
            stats[m]["attempts"] += 1
            # An toàn: vẫn coi là tấn công HOẶC không tin ML (abstain/skip -> LLM).
            safe = (a in ATTACK_ACTIONS) or (a is None)
            if safe:
                stats[m]["resisted"] += 1
            else:
                stats[m]["flipped_benign"] += 1
    for m in modes:
        at = stats[m]["attempts"]
        stats[m]["resistance_rate"] = round(stats[m]["resisted"] / at, 4) if at else None
        stats[m]["resistance_ci95"] = list(wilson_ci(stats[m]["resisted"], at)) if at else None

    # KHÔNG trả `overall_resistance_rate` nữa — CÓ CHỦ ĐÍCH.
    # Trung bình 3 chế độ bị hai chế độ DỄ (nhiễu 1 đặc trưng, gần như luôn 100%) kéo lên,
    # tạo ra một con số ~99,6% nghe rất mạnh nhưng che mất chế độ KHÓ duy nhất. Chỉ số đáng
    # trích là `headline_hard_mode` — kết quả của phép thử thật.
    hard = stats.get("extreme_broad", {})
    return {
        "attack_samples_ml_caught": base_caught,
        "by_mode": stats,
        "headline_hard_mode": {
            "mode": "extreme_broad",
            "resistance_rate": hard.get("resistance_rate"),
            "resistance_ci95": hard.get("resistance_ci95"),
            "note": (
                "Chỉ số ĐÁNG TRÍCH cho chiều kháng né-tránh. Số gộp 3 chế độ đã bị BỎ vì "
                "hai chế độ nhiễu-một-đặc-trưng đạt ~100% một cách tầm thường và làm trung "
                "bình mất ý nghĩa."
            ),
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Đánh giá Cổng ML (Tier-1) + kháng né-tránh")
    ap.add_argument("--data", default=DATA_PATH, help="JSON luồng gộp đã enrich")
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

    print(f"[*] Đánh giá Cổng ML trên {len(events)} sự kiện ({args.data})…")
    cls = evaluate_classification(gw, events)
    eva = evaluate_evasion_resistance(gw, events)

    result = {"classification": cls, "evasion_resistance": eva}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 64)
    print("  KẾT QUẢ CỔNG ML (Tier-1) — chiều Accuracy/Performance/Security")
    print("=" * 64)
    print(f"  MCC={cls['mcc']} | BalAcc={cls['balanced_accuracy']}      <- chỉ số CHÍNH")
    print(
        f"  F1={cls['f1']} (CI95 {cls['f1_ci95_bootstrap']}) | "
        f"P={cls['precision']} | R={cls['recall']} | Spec={cls['specificity']}"
    )
    print(
        f"  Acc={cls['accuracy']} vs ZeroR={cls['zero_r_accuracy']} -> "
        f"{'vượt mốc' if cls['accuracy_beats_baseline'] else 'KHÔNG vượt mốc đoán hằng'}"
    )
    print(
        f"  Bypass (ML tự quyết)={cls['bypass_rate']:.1%} | "
        f"Abstain->LLM={cls['abstain_rate']:.1%} | Skip payload={cls['n_skip_payload']}"
    )
    print(
        f"  Majority baseline (đoán-toàn-attack)={cls['majority_baseline_attack_rate']:.1%} "
        f"| Latency TB={cls['mean_latency_ms']}ms | metric_valid={cls['metric_valid']}"
    )
    print(f"  Thông lượng={cls['throughput_eps']} sự kiện/s (tường {cls['wall_seconds']}s)")
    _cal = cls["confidence_calibration"]
    print(
        f"  HIỆU CHUẨN confidence: ECE={_cal['ece']} Brier={_cal['brier']} "
        f"(lệch lớn nhất {_cal['max_gap']})   <- biện minh cho việc CHỌN ngưỡng 4 dải"
    )
    if _cal["high_conf_n"]:
        print(
            f"    ↳ dải >=0.85 (tự động BLOCK): nói chắc {_cal['high_conf_mean_confidence']} "
            f"/ đúng thật {_cal['high_conf_accuracy']} trên n={_cal['high_conf_n']}"
        )
    print(f"  CM (trên mẫu ML quyết): {cls['confusion_matrix_on_decided']}")
    print(
        f"  Auto-BLOCK precision={cls['auto_block_precision']} "
        f"trên {cls['auto_block_n']} lệnh chặn, FP={cls['auto_block_fp']}   <- chỉ số MẠNH nhất"
    )
    if cls.get("weakest_classes"):
        print("  3 lớp YẾU NHẤT: " + ", ".join(f"{n}={v}" for n, v in cls["weakest_classes"]))
    print("  — Kháng né-tránh (Security cho ML), TÁCH theo độ khó:")
    for m, s in eva["by_mode"].items():
        print(
            f"      {m:15s}: {s['resisted']}/{s['attempts']} = {s['resistance_rate']} "
            f"CI95 {s['resistance_ci95']}"
        )
        print(f"      {'':15s}  ({s['difficulty']})")
    hm = eva["headline_hard_mode"]
    print(
        f"  >> Chỉ số đáng trích (chế độ KHÓ): {hm['resistance_rate']} CI95 {hm['resistance_ci95']}"
    )
    print("     (số gộp 3 chế độ đã BỎ — hai chế độ dễ làm trung bình mất ý nghĩa)")
    print(f"\n[+] JSON: {args.out}")


if __name__ == "__main__":
    main()
