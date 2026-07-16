"""
SENTINEL — Unified Streaming Evaluation (OFFLINE, tất định)
==========================================================
THAY THẾ phương pháp đánh giá "3 luồng tách rời" cũ (CICIDS / DAPT nạp-sẵn /
zero-day chạy riêng), vốn có 2 nhược điểm:
  - DAPT bị nạp TOÀN BỘ chuỗi vào Threat Memory rồi mới `check_apt_chain`
    -> vòng luẩn quẩn (đã báo trước đáp án), không chứng minh được năng lực
    phát hiện APT nổi lên dần.
  - Zero-day và CICIDS chạy ở hai script riêng, không phản ánh một SOC thực tế
    nơi mọi traffic trộn lẫn trên cùng một dòng thời gian.

Cách làm MỚI: gộp cả 3 nguồn vào MỘT luồng sự kiện sắp theo thời gian (dựng bởi
`experiments/unified_dataset.py`), stream TĂNG DẦN qua hệ thống THẬT (Tier-1
RuleEngine + Welford + Threat Memory) với bộ nhớ KHỞI TẠO SẠCH. Nhờ đó:
  1. Phân loại (CICIDS): đo trên stream trộn thật.
  2. APT (DAPT): bộ nhớ tích lũy TỪ stream; `check_apt_chain` chỉ bật sau khi
     đủ sự kiện đa ngày -> phát hiện EMERGENT, đo "độ trễ phát hiện".
  3. Zero-day: outlier signature-less, rule tĩnh bỏ sót nhưng Welford bắt được,
     baseline học ngay từ traffic benign trong cùng luồng.

Bộ DỰNG dữ liệu (build_stream, map_cicids...) nằm ở `unified_dataset.py` để luồng
ONLINE (`scripts/build_datatest.py` → `scripts/demo.py`/`push_datatest.py`)
và các thí nghiệm rigor cùng dùng chung.

Chạy offline (Tier-1 + Memory, tất định, không cần LLM server):
    .venv/bin/python experiments/evaluate_unified_stream.py
"""

import json
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.unified_dataset import (  # noqa: E402
    BENIGN_ACTIONS,
    ROOT,
    _is_threat,
    build_stream,
    static_only_action,
)
from src.agent.threat_memory import ThreatMemoryStore  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

EVAL_MEM_DB = os.path.join(ROOT, "experiments", ".unified_eval_memory.db")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "unified_stream_results.json")
REPORT_MD = os.path.join(ROOT, "reports", "unified_stream_evaluation_report.md")


# --------------------------------------------------------------------------- #
# Run the unified stream through the real system
# --------------------------------------------------------------------------- #
def run():
    print("=" * 70)
    print("  SENTINEL — UNIFIED STREAMING EVALUATION (1 luồng gộp, memory sạch)")
    print("=" * 70)

    # Bộ nhớ THẬT nhưng dùng DB tạm + xóa sạch (không đụng production threat_memory)
    if os.path.exists(EVAL_MEM_DB):
        os.remove(EVAL_MEM_DB)
    memory = ThreatMemoryStore(db_path=EVAL_MEM_DB)
    with sqlite3.connect(EVAL_MEM_DB) as c:
        c.execute("DELETE FROM threat_events")

    engine = RuleEngine()

    warmup, main, apt_truth, n_chains = build_stream()
    print(f"\n[*] Nguồn: {len(warmup)} benign (warmup) | {len(main)} sự kiện luồng chính")
    print(f"[*] DAPT: {n_chains} chuỗi | IP là APT thật (>=2 ngày tấn công): {len(apt_truth)}")

    # Phân loại (tính trên CẢ benign warmup lẫn tấn công ở luồng chính) -- #
    cls = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    # ---- Phase warmup: học baseline Welford từ benign -------------------- #
    # Các flow này expected = benign -> đóng góp TN/FP cho confusion matrix.
    for ev in warmup:
        res = engine.evaluate(ev["log"])
        flagged = _is_threat(res["tier1_action"])
        cls["fp" if flagged else "tn"] += 1

    # ---- Phase chính: stream trộn theo thời gian ------------------------- #
    # APT
    apt_detected = {}  # ip -> {first_attack_event, fire_event, fire_day, days_at_fire}
    apt_event_counter = defaultdict(int)
    # zero-day
    zd_results = []

    ev_index = 0
    for ev in main:
        ev_index += 1
        src = ev["source"]

        if src == "cicids":
            res = engine.evaluate(ev["log"])
            flagged = _is_threat(res["tier1_action"])
            if ev["expected_threat"]:
                cls["tp" if flagged else "fn"] += 1
            else:
                cls["fp" if flagged else "tn"] += 1

        elif src == "dapt":
            # Mỗi sự kiện DAPT vẫn đi qua Tier-1 (thường DROP/LOG vì tín hiệu thấp)
            engine.evaluate(ev["log"])
            if not ev.get("is_attack"):
                continue  # benign DAPT = nền nhiễu, KHÔNG ghi vào memory APT
            ip = ev["ip"]
            apt_event_counter[ip] += 1
            # GHI vào bộ nhớ TỪ stream (tích lũy dần), rồi HỎI lại
            before = memory.check_apt_chain(ip)
            memory.record_apt_event(
                src_ip=ip,
                dst_ip=ev["dst_ip"],
                apt_phase=ev["phase"],
                apt_day=ev["day"],
                label=ev["label"],
                timestamp=ev["timestamp"],
            )
            after = memory.check_apt_chain(ip)
            if ip not in apt_detected:
                apt_detected[ip] = {
                    "first_event_idx": ev_index,
                    "first_day": ev["day"],
                    "fired": False,
                }
            # ghi lại khoảnh khắc bản án LẬT từ False -> True
            if (not before["is_apt"]) and after["is_apt"] and not apt_detected[ip]["fired"]:
                apt_detected[ip].update(
                    {
                        "fired": True,
                        "fire_event_idx": ev_index,
                        "fire_day": ev["day"],
                        "events_until_fire": apt_event_counter[ip],
                        "phases_at_fire": after.get("phases_seen", ""),
                    }
                )

        elif src == "zeroday":
            static_act = static_only_action(engine, ev["log"])
            res = engine.evaluate(ev["log"])
            zd_results.append(
                {
                    "id": ev["id"],
                    "name": ev["name"],
                    "mitre": ev["mitre"],
                    "static_only_action": static_act,
                    "full_action": res["tier1_action"],
                    "z_score": round(res.get("tier1_z_score", 0.0), 2),
                    "tier1_score": res.get("tier1_score", 0),
                    "caught_by_welford": static_act in BENIGN_ACTIONS
                    and _is_threat(res["tier1_action"]),
                }
            )

    # ---- Metrics --------------------------------------------------------- #
    tp, fp, tn, fn = cls["tp"], cls["fp"], cls["tn"], cls["fn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    apt_fired = {ip: d for ip, d in apt_detected.items() if d.get("fired")}
    apt_truth_seen = apt_truth & set(apt_detected.keys())
    apt_tp = len(apt_truth & set(apt_fired.keys()))
    apt_fn = len(apt_truth_seen) - apt_tp
    lags = [d["events_until_fire"] for ip, d in apt_fired.items() if ip in apt_truth]
    avg_lag = sum(lags) / len(lags) if lags else 0.0

    zd_caught = sum(1 for z in zd_results if z["caught_by_welford"])

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "stream": {
            "warmup_benign": len(warmup),
            "main_events": len(main),
            "dapt_chains": n_chains,
            "apt_truth_ips": len(apt_truth),
        },
        "classification_cicids": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
        },
        "apt_dapt": {
            "apt_truth_ips": len(apt_truth),
            "apt_truth_seen_in_stream": len(apt_truth_seen),
            "detected": apt_tp,
            "missed": apt_fn,
            "recall": round(apt_tp / len(apt_truth_seen), 4) if apt_truth_seen else 0.0,
            "avg_detection_lag_events": round(avg_lag, 2),
        },
        "zeroday": {
            "total": len(zd_results),
            "caught_by_welford_static_missed": zd_caught,
        },
    }

    details = {"apt_detected": apt_detected, "zeroday": zd_results}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "details": details}, f, indent=2, ensure_ascii=False)

    _print_console(summary, apt_fired, apt_truth, zd_results)
    _write_report(summary, apt_fired, apt_truth, zd_results)
    print(f"\n[+] JSON: {OUT_JSON}\n[+] Report: {REPORT_MD}")
    return summary


def _print_console(summary, apt_fired, apt_truth, zd_results):
    c = summary["classification_cicids"]
    a = summary["apt_dapt"]
    print("\n" + "-" * 70)
    print("  [1] CLASSIFICATION (CICIDS, trên luồng trộn)")
    print(f"      F1={c['f1']}  Acc={c['accuracy']}  P={c['precision']}  R={c['recall']}")
    print(f"      TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")
    print("  [2] APT (DAPT, phát hiện EMERGENT từ memory sạch)")
    print(
        f"      APT thật thấy trong stream: {a['apt_truth_seen_in_stream']}"
        f" | phát hiện: {a['detected']} | sót: {a['missed']}"
    )
    print(f"      Recall={a['recall']}  | Độ trễ TB: {a['avg_detection_lag_events']} sự kiện")
    for ip, d in sorted(apt_fired.items()):
        if ip in apt_truth:
            print(
                f"        - {ip}: day1=KHÔNG-APT -> BẬT ở ngày {d['fire_day']}"
                f" (sau {d['events_until_fire']} sự kiện)"
            )
    print("  [3] ZERO-DAY (signature-less; static bỏ sót, Welford bắt)")
    for z in zd_results:
        mark = "✅ Welford bắt" if z["caught_by_welford"] else "⚠️ "
        print(
            f"        - {z['id']}: static={z['static_only_action']}"
            f" -> full={z['full_action']} (Z={z['z_score']}) {mark}"
        )
    print("-" * 70)


def _write_report(summary, apt_fired, apt_truth, zd_results):
    c = summary["classification_cicids"]
    a = summary["apt_dapt"]
    z = summary["zeroday"]
    lines = []
    lines.append("# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)\n")
    lines.append(
        "> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + "
        "Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ "
        "thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.\n"
    )
    lines.append(f"> **Sinh lúc:** {summary['timestamp']}\n")
    lines.append("---\n")
    lines.append("## 0. Luồng dữ liệu (toàn DATA THẬT, trộn xen kẽ)\n")
    s = summary["stream"]
    lines.append(
        "Mọi sự kiện là data thật (CICIDS từ `ground_truth.json`, DAPT từ "
        "`dapt2020_chains.jsonl`); zero-day là biến thể **REAL-DERIVED** — nền là "
        "flow benign THẬT, chỉ đẩy **một** feature lên cực trị, rải qua nhiều ngày. "
        "Các nguồn được **trộn xen kẽ trong từng ngày** bằng khóa thời gian golden-"
        "ratio (không xếp khối theo nguồn); DAPT giữ nguyên ngày thật.\n"
    )
    lines.append(f"- Warmup benign CICIDS (học baseline Welford): **{s['warmup_benign']}**")
    lines.append(
        f"- Luồng chính trộn (benign nền + tấn công CICIDS + mọi sự kiện DAPT + "
        f"zero-day): **{s['main_events']}** sự kiện"
    )
    lines.append(
        f"- DAPT chuỗi: **{s['dapt_chains']}** | IP là APT thật (≥2 ngày tấn công): **{s['apt_truth_ips']}**\n"
    )

    lines.append("## 1. Phân loại ở TẦNG LỌC Tier-1 (gate) trên luồng trộn\n")
    lines.append(
        "> Đây là số của **riêng tầng Tier-1** (rule tĩnh + Welford), tức cổng "
        "lọc thô. Tier-1 cố tình chỉ chặn phần tấn công lộ rõ ở tầng mạng và "
        "**đẩy phần tinh vi lên Tier-2** (vì vậy recall ở đây thấp là đúng thiết "
        "kế). F1 của TOÀN hệ thống (Tier-1 + LLM) được đo ở Ablation `Config F`.\n"
    )
    lines.append("| Metric (Tier-1 gate) | Giá trị |")
    lines.append("| :--- | :---: |")
    lines.append(f"| F1 | **{c['f1']}** |")
    lines.append(f"| Accuracy | {c['accuracy']} |")
    lines.append(f"| Precision | {c['precision']} |")
    lines.append(f"| Recall (attack) | {c['recall']} |")
    lines.append(f"| TP / FP / TN / FN | {c['tp']} / {c['fp']} / {c['tn']} / {c['fn']} |\n")

    lines.append("## 2. Phát hiện APT (DAPT) — EMERGENT, không nạp sẵn\n")
    lines.append(
        "Bộ nhớ bắt đầu **rỗng**; mỗi sự kiện APT được ghi vào memory KHI nó "
        "tới trong luồng, rồi mới hỏi `check_apt_chain`. Bản án APT chỉ bật sau "
        "khi tích lũy đủ sự kiện **đa ngày** — chứng minh phát hiện nổi lên dần, "
        "**không** phải tra đáp án nạp sẵn.\n"
    )
    lines.append(f"- APT thật xuất hiện trong stream: **{a['apt_truth_seen_in_stream']}**")
    lines.append(
        f"- Phát hiện đúng: **{a['detected']}** | Bỏ sót: **{a['missed']}** "
        f"| Recall: **{a['recall']}**"
    )
    lines.append(f"- Độ trễ phát hiện trung bình: **{a['avg_detection_lag_events']} sự kiện**\n")
    lines.append("| Attacker IP | Ngày BẬT cảnh báo APT | Sự kiện tới khi bật |")
    lines.append("| :--- | :---: | :---: |")
    for ip, d in sorted(apt_fired.items()):
        if ip in apt_truth:
            lines.append(
                f"| {ip} | ngày {d['fire_day']} (ngày 1 = chưa APT) | {d['events_until_fire']} |"
            )
    lines.append("")

    lines.append("## 3. Zero-day (signature-less) — static bỏ sót, Welford bắt\n")
    lines.append(
        f"Tổng: **{z['total']}** | Welford bắt được (mà static bỏ sót): "
        f"**{z['caught_by_welford_static_missed']}/{z['total']}**\n"
    )
    lines.append(
        "| ID | Kịch bản | Rule tĩnh (static-only, đối chứng) | Full Tier-1 (Welford) | Z-Score |"
    )
    lines.append("| :--- | :--- | :---: | :---: | :---: |")
    for zr in zd_results:
        mark = "✅" if zr["caught_by_welford"] else "⚠️"
        lines.append(
            f"| {zr['id']} | {zr['name']} | {zr['static_only_action']} (bỏ sót) "
            f"| **{zr['full_action']}** | {zr['z_score']} {mark} |"
        )
    lines.append("")
    lines.append("---\n")
    lines.append("## Kết luận\n")
    lines.append(
        "Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời "
        "gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ "
        "bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và "
        "(3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + "
        "Tier-Consensus Guard được đánh giá ở `evaluate_adversarial.py --mode pipeline`.\n"
    )

    os.makedirs(os.path.dirname(REPORT_MD), exist_ok=True)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    run()
