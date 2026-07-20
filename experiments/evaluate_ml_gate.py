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


def evaluate_classification(gw: MLGateway, events: list) -> dict:
    tp = fp = tn = fn = 0
    n_decided = n_abstain = n_skip = 0
    latencies = []
    n_threat = 0
    # Tách confusion THEO TỪNG HÀNH ĐỘNG (= theo dải tin cậy của chính sách 4 dải:
    # BLOCK_IP C>=0.85 · ALERT 0.40-0.65). Cần thiết vì chỉ số headline là độ chính xác
    # của auto-BLOCK — hành động DỨT KHOÁT, không thể đảo — chứ không phải F1 gộp (F1 gộp
    # tính cả dải ALERT low-priority nên bị kéo xuống). Trước đây số này chỉ nằm trong
    # báo cáo viết tay, KHÔNG được script xuất ra -> không tái lập được. Nay xuất ra JSON.
    per_action: dict[str, dict[str, int]] = {}
    for ev in events:
        threat = _is_threat(ev)
        n_threat += int(threat)
        t0 = time.perf_counter()
        action, _r, _c, sec = gw.evaluate_detailed(ev)
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

    total = len(events)
    prec, rec, f1, acc = _f1(tp, fp, tn, fn)
    majority = round(n_threat / total, 4) if total else 0.0

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

    return {
        "total_events": total,
        "n_threat": n_threat,
        "majority_baseline_attack_rate": majority,
        "confusion_matrix_on_decided": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "accuracy": acc,
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
    }


def _inject(ev: dict, mode: str) -> dict:
    """Sinh biến thể NÉ-TRÁNH từ 1 event flow."""
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
    modes = ["inf_single", "extreme_single", "extreme_broad"]
    stats: dict[str, dict[str, Any]] = {
        m: {"attempts": 0, "resisted": 0, "flipped_benign": 0} for m in modes
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
    total_att = sum(stats[m]["attempts"] for m in modes)
    total_res = sum(stats[m]["resisted"] for m in modes)
    return {
        "attack_samples_ml_caught": base_caught,
        "by_mode": stats,
        "overall_resistance_rate": round(total_res / total_att, 4) if total_att else None,
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
    print(f"  F1={cls['f1']} | P={cls['precision']} | R={cls['recall']} | Acc={cls['accuracy']}")
    print(
        f"  Bypass (ML tự quyết)={cls['bypass_rate']:.1%} | "
        f"Abstain->LLM={cls['abstain_rate']:.1%} | Skip payload={cls['n_skip_payload']}"
    )
    print(
        f"  Majority baseline (đoán-toàn-attack)={cls['majority_baseline_attack_rate']:.1%} "
        f"| Latency TB={cls['mean_latency_ms']}ms | metric_valid={cls['metric_valid']}"
    )
    print(f"  CM (trên mẫu ML quyết): {cls['confusion_matrix_on_decided']}")
    print("  — Kháng né-tránh (Security cho ML):")
    for m, s in eva["by_mode"].items():
        print(f"      {m:15s}: resisted {s['resisted']}/{s['attempts']} = {s['resistance_rate']}")
    print(f"  Tổng resistance_rate = {eva['overall_resistance_rate']}")
    print(f"\n[+] JSON: {args.out}")


if __name__ == "__main__":
    main()
