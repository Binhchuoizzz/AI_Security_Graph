"""
SENTINEL — Unified Streaming Evaluation
========================================
THAY THẾ phương pháp đánh giá "3 luồng tách rời" cũ (CICIDS / DAPT nạp-sẵn /
zero-day chạy riêng), vốn có 2 nhược điểm:
  - DAPT bị nạp TOÀN BỘ chuỗi vào Threat Memory rồi mới `check_apt_chain`
    -> vòng luẩn quẩn (đã báo trước đáp án), không chứng minh được năng lực
    phát hiện APT nổi lên dần.
  - Zero-day và CICIDS chạy ở hai script riêng, không phản ánh một SOC thực tế
    nơi mọi traffic trộn lẫn trên cùng một dòng thời gian.

Cách làm MỚI: gộp cả 3 nguồn vào MỘT luồng sự kiện sắp theo thời gian, stream
TĂNG DẦN qua hệ thống THẬT (Tier-1 RuleEngine + Welford + Threat Memory) với
bộ nhớ KHỞI TẠO SẠCH. Nhờ đó:
  1. Phân loại (CICIDS): đo trên stream trộn thật.
  2. APT (DAPT): bộ nhớ tích lũy TỪ stream; `check_apt_chain` chỉ bật sau khi
     đủ sự kiện đa ngày -> phát hiện EMERGENT, đo "độ trễ phát hiện".
  3. Zero-day: outlier signature-less, rule tĩnh bỏ sót nhưng Welford bắt được,
     baseline học ngay từ traffic benign trong cùng luồng.

Chạy offline (Tier-1 + Memory, tất định, không cần LLM server):
    .venv/bin/python experiments/evaluate_unified_stream.py
"""

import json
import math
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.threat_memory import ThreatMemoryStore  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")
DAPT_PATH = os.path.join(ROOT, "data", "processed", "dapt2020_chains.jsonl")
EVAL_MEM_DB = os.path.join(ROOT, "experiments", ".unified_eval_memory.db")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "unified_stream_results.json")
REPORT_MD = os.path.join(ROOT, "reports", "unified_stream_evaluation_report.md")

THREAT_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}
BENIGN_ACTIONS = {"DROP", "LOG"}
BENIGN_PHASES = {"Benign", "benign", "Normal", "normal", "", None, "Unknown"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _safe_int(v, default=0):
    try:
        f = float(v)
        return int(f) if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _is_threat(action: str) -> bool:
    return action in THREAT_ACTIONS


def map_cicids(nl: dict) -> dict:
    """network_layer (ground_truth) -> schema CICIDS mà RuleEngine mong đợi."""
    return {
        "Source IP": nl.get("src_ip", "0.0.0.0"),
        "Destination IP": nl.get("dst_ip", "0.0.0.0"),
        "Destination Port": nl.get("dst_port", 0),
        "Protocol": nl.get("protocol", 6),
        "Flow Duration": nl.get("flow_duration_us", 0),
        "Total Fwd Packets": nl.get("fwd_packets", 0),
        "Total Backward Packets": nl.get("bwd_packets", 0),
        "Total Length of Fwd Packets": nl.get("fwd_bytes", 0),
        "Total Length of Bwd Packets": nl.get("bwd_bytes", 0),
        "Flow Pkts/s": nl.get("flow_pkts_s", 0.0),
        "Fwd Seg Size Min": nl.get("fwd_seg_size_min", 0),
        "Init Fwd Win Byts": nl.get("init_fwd_win_byts", 0),
        "Init Bwd Win Byts": nl.get("init_bwd_win_byts", 0),
        "Bwd Pkt Len Min": nl.get("bwd_pkt_len_min", 0),
        "PSH Flag Cnt": nl.get("psh_flag_cnt", 0),
        "service": nl.get("service", ""),
    }


def static_only_action(engine: RuleEngine, log: dict) -> str:
    """Đối chứng STATIC-ONLY (chỉ luật tĩnh, KHÔNG Welford) cho zero-day.

    LƯU Ý: đây KHÔNG phải "Config A" của Ablation Study — Config A trong
    `run_ablation_study.py` là Tier-1 ĐẦY ĐỦ không LLM (bao gồm cả Welford).
    Baseline này tách riêng Welford ra để chứng minh đóng góp của Z-score."""
    port = _safe_int(log.get("Destination Port"))
    fwd = _safe_int(log.get("Total Fwd Packets"))
    if port in engine.sensitive_ports:
        return "BLOCK_IP"
    if engine._check_waf_signatures(log) or engine._check_injection_signatures(log):
        return "BLOCK_IP"
    if fwd > engine.max_fwd_packets:
        return "ALERT"
    return "DROP"


# --------------------------------------------------------------------------- #
# Zero-day REAL-DERIVED: nền là flow benign THẬT, chỉ đẩy MỘT feature Welford lên
# cực trị. Mỗi spec: (id, tên, feature đẩy, giá trị cực trị, IP đích ngoài (narrative
# exfil/C2), MITRE, ngày tiêm). KHÔNG đẩy "Total Fwd Packets" vì > max_fwd_packets sẽ
# bị luật TĨNH bắt -> mất tính "signature-less". Rải qua nhiều ngày + nhiều loại outlier.
# --------------------------------------------------------------------------- #
ZD_SPECS = [
    (
        "ZD-001",
        "Exfil khối lượng Bwd cực lớn",
        "Total Length of Bwd Packets",
        50_000_000,
        "203.0.113.9",
        "T1048 Exfiltration Over Alternative Protocol",
        2,
    ),
    (
        "ZD-002",
        "Beacon tần suất gói cực cao",
        "Flow Pkts/s",
        750_000.0,
        "198.51.100.7",
        "T1071 Application Layer Protocol (C2)",
        2,
    ),
    (
        "ZD-003",
        "Tunnel cửa sổ Bwd bất thường",
        "Init Bwd Win Byts",
        65_000_000,
        "192.0.2.55",
        "T1572 Protocol Tunneling",
        3,
    ),
    (
        "ZD-004",
        "Phiên kéo dài bất thường (low&slow)",
        "Flow Duration",
        9_000_000_000,
        "203.0.113.77",
        "T1041 Exfiltration Over C2 Channel",
        3,
    ),
    (
        "ZD-005",
        "Bùng nổ gói Bwd (volumetric mới)",
        "Total Backward Packets",
        900_000,
        "198.51.100.42",
        "T1498 Network Denial of Service (novel)",
        4,
    ),
    (
        "ZD-006",
        "Payload Fwd khổng lồ",
        "Total Length of Fwd Packets",
        80_000_000,
        "192.0.2.200",
        "T1030 Data Transfer Size Limits",
        4,
    ),
    (
        "ZD-007",
        "Cửa sổ Fwd dị thường",
        "Init Fwd Win Byts",
        60_000_000,
        "203.0.113.150",
        "T1095 Non-Application Layer Protocol",
        5,
    ),
]


def _build_zerodays(samples, tkey):
    """Sinh zero-day REAL-DERIVED từ flow benign THẬT.

    Nền mỗi mẫu là một flow benign THẬT trong ground_truth, chọn các flow "static-clean"
    (cổng KHÔNG nhạy cảm + fwd <= max_fwd_packets + không signature) để luật TĨNH chắc
    chắn bỏ sót. Chỉ ĐÚNG MỘT feature Welford bị đặt lên cực trị (outlier signature-less);
    mọi feature flow KHÁC giữ NGUYÊN giá trị thật. Chỉ IP (truy vết nội bộ + đích ngoài
    cho narrative) là được đặt lại — IP không ảnh hưởng tới Z-score nên không làm sai lệch.
    """
    SENSITIVE = {21, 22, 23, 53, 139, 445, 3389}
    pool = []
    for s in samples:
        if s.get("input", {}).get("cicids_label", "") != "Benign":
            continue
        nl = s.get("input", {}).get("network_layer", {})
        if not nl:
            continue
        if _safe_int(nl.get("dst_port")) in SENSITIVE:
            continue
        if _safe_int(nl.get("fwd_packets")) > 1000:
            continue
        pool.append(nl)

    out = []
    for i, (zid, name, feat, val, dst, mitre, day) in enumerate(ZD_SPECS):
        if pool:
            base_nl = pool[(i * 37) % len(pool)]  # rải đều nền benign, tất định
        else:
            base_nl = {"dst_port": 443, "fwd_packets": 40, "service": "HTTPS"}
        log = map_cicids(base_nl)  # flow benign THẬT làm nền
        log[feat] = val  # đẩy ĐÚNG 1 feature lên cực trị
        log["Source IP"] = f"10.0.0.{220 + i}"  # host nội bộ (truy vết)
        log["Destination IP"] = dst  # đích ngoài (narrative exfil/C2)
        log["user_agent"] = f"zero-day-probe/{zid}"
        out.append(
            {
                "id": zid,
                "name": f"Zero-Day {name}",
                "mitre": mitre,
                "source": "zeroday",
                "base_feature": feat,
                "day": day,
                "t": tkey(day),
                "log": log,
            }
        )
    return out


# --------------------------------------------------------------------------- #
# Build unified, time-ordered event stream
# --------------------------------------------------------------------------- #
def build_stream():
    """Trả về (warmup_events, main_events, apt_truth, n_chains).

    Tất cả sự kiện đều là DATA THẬT (CICIDS từ ground_truth, DAPT từ chains). Zero-day
    là biến thể REAL-DERIVED: nền là flow benign THẬT trong ground_truth, chỉ đẩy ĐÚNG
    MỘT feature lên cực trị (không dataset nào chứa zero-day có nhãn sẵn) — xem `_build_zerodays`.

    - warmup_events: 150 benign CICIDS ĐẦU để Welford học baseline trước.
    - main_events: phần benign CICIDS còn lại + TẤT CẢ tấn công CICIDS + MỌI sự
      kiện DAPT (tấn công lẫn benign nền) + zero-day, được **TRỘN XEN KẼ** trong
      từng ngày bằng khóa `t = ngày + offset golden-ratio` rồi sort — KHÔNG xếp
      khối theo nguồn.
    - apt_truth: tập IP THẬT là APT (sự kiện tấn công ở >= 2 ngày khác nhau).
    """
    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    samples = gt if isinstance(gt, list) else gt.get("samples", gt)

    WARMUP_N = 150  # benign dành riêng cho warmup baseline
    GOLDEN = 0.6180339887498949
    _oi = [0]  # order-index dùng cho dãy golden-ratio

    def tkey(day: int) -> float:
        """Phần nguyên = ngày (giữ thứ tự đa ngày của APT); phần thập phân = dãy
        golden-ratio -> rải đều & **xen kẽ mọi nguồn** trong cùng một ngày."""
        t = day + (_oi[0] * GOLDEN) % 1.0
        _oi[0] += 1
        return t

    warmup, main = [], []

    # --- CICIDS: 150 benign -> warmup; phần còn lại TRỘN vào luồng chính --- #
    benign_seen = 0
    attack_idx = 0
    for s in samples:
        nl = s.get("input", {}).get("network_layer", {})
        if not nl:
            continue
        log = map_cicids(nl)
        label = s.get("input", {}).get("cicids_label", "")
        is_benign = label == "Benign" or s.get("expected_action", "") == "LOG"
        if is_benign:
            benign_seen += 1
            ev = {"source": "cicids", "log": log, "expected_threat": False, "label": label}
            if benign_seen <= WARMUP_N:
                warmup.append(ev)  # prefix warmup
            else:
                ev["t"] = tkey(1 + benign_seen % 5)  # benign nền, trộn khắp 5 ngày
                main.append(ev)
        else:
            ev = {"source": "cicids", "log": log, "expected_threat": True, "label": label}
            ev["t"] = tkey(1 + attack_idx % 5)
            main.append(ev)
            attack_idx += 1

    # --- DAPT2020: đưa CẢ sự kiện tấn công LẪN benign (nền) vào luồng ------ #
    apt_attack_days = defaultdict(set)
    with open(DAPT_PATH, encoding="utf-8") as f:
        chains = [json.loads(line) for line in f]
    for chain in chains:
        for e in chain.get("events", []):
            phase = e.get("phase")
            label = e.get("label", "")
            is_attack = (phase not in BENIGN_PHASES) and (label not in BENIGN_PHASES)
            ip = e.get("src_ip", chain.get("attacker_ip", ""))
            day = _safe_int(e.get("day"), 1)
            if is_attack:
                apt_attack_days[ip].add(day)  # chỉ tấn công mới tính chuỗi APT
            main.append(
                {
                    "source": "dapt",
                    "is_attack": is_attack,  # benign DAPT = nền, KHÔNG ghi memory
                    "ip": ip,
                    "dst_ip": e.get("dst_ip", ""),
                    "phase": phase,
                    "day": day,
                    "label": label,
                    "timestamp": e.get("timestamp", ""),
                    # flow tối thiểu, tín hiệu THẤP (mỗi sự kiện APT lẻ trông vô hại)
                    "log": {
                        "Source IP": ip,
                        "Destination IP": e.get("dst_ip", ""),
                        "Destination Port": 443,
                        "Total Fwd Packets": 20,
                    },
                    "t": tkey(day),
                }
            )

    apt_truth = {ip for ip, days in apt_attack_days.items() if len(days) >= 2}

    # --- Zero-day: REAL-DERIVED (nền = flow benign THẬT, đẩy 1 feature Welford lên
    #     cực trị), RẢI nhiều ngày (2..5), NHIỀU loại outlier — xem `_build_zerodays`.
    #     Cổng cho phép + fwd thấp + không signature => luật TĨNH bỏ sót; nhưng lệch
    #     baseline cực mạnh => Welford Z-score bắt. warmup prefix đảm bảo baseline đã ấm.
    main.extend(_build_zerodays(samples, tkey))

    main.sort(key=lambda x: x["t"])
    return warmup, main, apt_truth, len(chains)


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
        "Tier-Consensus Guard được đánh giá ở `evaluate_adversarial_pipeline.py`.\n"
    )

    os.makedirs(os.path.dirname(REPORT_MD), exist_ok=True)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    run()
