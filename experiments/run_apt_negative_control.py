"""
SENTINEL — APT: Đối chứng ÂM tính + Khoảng tin cậy (Negative Control + CI)
=========================================================================
Bổ sung cho phần APT (vốn chỉ báo recall=1.0 trên n nhỏ, KHÔNG có đối chứng âm).
Hai câu hỏi của hội đồng:

  (a) "recall=1.0 trên n=? — có ý nghĩa thống kê không?"  -> báo Wilson 95% CI.
  (b) "Bộ phát hiện APT có BÁO NHẦM trên IP benign xuất hiện NHIỀU NGÀY không?"
      -> đối chứng âm: đếm IP có mặt ≥2 ngày phân biệt trong luồng nhưng KHÔNG phải
         APT thật, rồi xác nhận 0 IP nào kích hoạt check_apt_chain (specificity).

Cơ chế phân biệt nằm ở CỔNG GHI: chỉ sự kiện bị gắn cờ tấn công mới được ghi vào
kho APT; check_apt_chain bật khi đủ ≥2 NGÀY-TẤN-CÔNG phân biệt. Đối chứng âm chứng
minh: hiện diện đa-ngày benign KHÔNG đủ để bật cảnh báo.

Tier-1 + Memory, tất định, KHÔNG LLM.  Chạy:
    .venv/bin/python experiments/run_apt_negative_control.py
"""

import math
import os
import sqlite3
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.evaluate_unified_stream import BENIGN_PHASES, _safe_int, build_stream  # noqa: E402
from src.agent.threat_memory import ThreatMemoryStore  # noqa: E402

OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "apt_negative_control_results.json")
EVAL_DB = os.path.join(os.path.dirname(__file__), ".apt_negctrl_memory.db")


def wilson_ci(k, n, z=1.96):
    """Khoảng tin cậy Wilson cho tỷ lệ k/n (phù hợp n nhỏ, p ở biên)."""
    if n == 0:
        return (0.0, 0.0)
    phat = k / n
    denom = 1 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def main():
    print("=" * 70)
    print("  SENTINEL — APT: ĐỐI CHỨNG ÂM TÍNH + KHOẢNG TIN CẬY")
    print("=" * 70)

    if os.path.exists(EVAL_DB):
        os.remove(EVAL_DB)
    memory = ThreatMemoryStore(db_path=EVAL_DB)
    with sqlite3.connect(EVAL_DB) as c:
        c.execute("DELETE FROM threat_events")

    warmup, main_events, apt_truth, n_chains = build_stream()

    # Theo dõi: với mỗi IP -> tập NGÀY có mặt (mọi sự kiện) và tập NGÀY-TẤN-CÔNG.
    all_days = defaultdict(set)
    attack_days = defaultdict(set)
    fired = {}

    for ev in main_events:
        if ev["source"] != "dapt":
            continue
        ip = ev["ip"]
        day = _safe_int(ev.get("day"), 1)
        all_days[ip].add(day)
        is_attack = (ev.get("phase") not in BENIGN_PHASES) and (
            ev.get("label") not in BENIGN_PHASES
        )
        if not is_attack:
            continue  # CỔNG GHI: chỉ sự kiện tấn công mới vào kho APT
        attack_days[ip].add(day)
        before = memory.check_apt_chain(ip)
        memory.record_apt_event(
            src_ip=ip,
            dst_ip=ev.get("dst_ip", ""),
            apt_phase=ev.get("phase"),
            apt_day=day,
            label=ev.get("label", ""),
            timestamp=ev.get("timestamp", ""),
        )
        after = memory.check_apt_chain(ip)
        if (not before["is_apt"]) and after["is_apt"]:
            fired[ip] = after.get("chain_length", 0)

    # Dương tính thật = IP có tấn công ở ≥2 ngày (apt_truth, giao với IP thực sự thấy)
    seen_ips = set(all_days.keys())
    positives = apt_truth & seen_ips
    detected = positives & set(fired.keys())
    recall = len(detected) / len(positives) if positives else 0.0
    rec_lo, rec_hi = wilson_ci(len(detected), len(positives))

    # Âm tính = IP hiện diện ≥2 NGÀY phân biệt nhưng KHÔNG phải APT thật
    multiday_ips = {ip for ip, days in all_days.items() if len(days) >= 2}
    negatives = multiday_ips - apt_truth
    false_fires = negatives & set(fired.keys())
    specificity = 1.0 - (len(false_fires) / len(negatives)) if negatives else 1.0

    summary = {
        "n_chains": n_chains,
        "positives_apt_truth": len(positives),
        "detected": len(detected),
        "recall": round(recall, 4),
        "recall_wilson95_ci": [round(rec_lo, 4), round(rec_hi, 4)],
        "negatives_multiday_benign": len(negatives),
        "false_apt_firings": len(false_fires),
        "specificity": round(specificity, 4),
        "false_fire_ips": sorted(false_fires),
    }

    print(f"\n  DƯƠNG TÍNH (APT thật, tấn công ≥2 ngày): n = {len(positives)}")
    print(f"    Phát hiện: {len(detected)}/{len(positives)}  -> recall = {recall:.3f}")
    print(f"    Wilson 95% CI: [{rec_lo:.3f}, {rec_hi:.3f}]")
    print(f"\n  ÂM TÍNH (IP hiện diện ≥2 ngày nhưng KHÔNG phải APT): n = {len(negatives)}")
    print(f"    Báo nhầm APT (false fire): {len(false_fires)}")
    print(f"    Specificity = {specificity:.3f}")
    if false_fires:
        print(f"    [!] IP báo nhầm: {sorted(false_fires)}")
    else:
        print("    [+] KHÔNG có IP benign đa-ngày nào kích hoạt cảnh báo APT.")

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    import json

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved -> {OUT_JSON}")

    if os.path.exists(EVAL_DB):
        os.remove(EVAL_DB)


if __name__ == "__main__":
    main()
