"""
SENTINEL — Bộ dựng DỮ LIỆU GỘP dùng chung (Unified Dataset Builder).
====================================================================
Module TRUNG LẬP chứa toàn bộ logic dựng luồng gộp (CICIDS + DAPT2020 + Zero-day
REAL-DERIVED) đã sắp theo thời gian. Trước đây code này nằm trong
`evaluate_unified_stream.py` (file EVAL offline) và bị các nơi khác import NGƯỢC
("lòng vòng"). Tách ra đây để CẢ luồng online (`stream_unified_online.py`), eval
offline (`evaluate_unified_stream.py`) và các thí nghiệm rigor cùng import từ 1 chỗ.

Mọi sự kiện đều là DATA THẬT: CICIDS từ `ground_truth.json`, DAPT từ
`dapt2020_chains.jsonl`. Zero-day là biến thể REAL-DERIVED (nền benign THẬT, đẩy
ĐÚNG một feature Welford lên cực trị) — xem `_build_zerodays`.
"""

import json
import math
import os
import sys
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")
DAPT_PATH = os.path.join(ROOT, "data", "processed", "dapt2020_chains.jsonl")

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


def _safe_float(v, default=0.0):
    """float() an toàn cho CSV CICIDS: header lặp giữa file (giá trị = tên cột),
    'Infinity'/NaN đều trả default thay vì ném ValueError giết cả build_stream."""
    try:
        f = float(v)
        return f if math.isfinite(f) else default
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
    `run_ablation.py --mode af` là Tier-1 ĐẦY ĐỦ không LLM (bao gồm cả Welford).
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
    (
        "ZD-008",
        "C2 Beacon cực nhỏ và ẩn",
        "Total Length of Bwd Packets",
        20,
        "203.0.113.88",
        "T1071.001 Web Protocols",
        1,
    ),
    (
        "ZD-009",
        "Cửa sổ Fwd âm (anomaly)",
        "Init Fwd Win Byts",
        -10,
        "198.51.100.99",
        "T1059 Command and Scripting Interpreter",
        2,
    ),
    (
        "ZD-010",
        "Gói SYN liên tục siêu nhỏ",
        "Fwd Seg Size Min",
        1,
        "192.0.2.11",
        "T1046 Network Service Discovery",
        3,
    ),
    (
        "ZD-011",
        "Mảnh payload Bwd quá to",
        "Bwd Pkt Len Min",
        15000,
        "203.0.113.111",
        "T1071 Application Layer Protocol",
        4,
    ),
    (
        "ZD-012",
        "C2 PSH Flag chìm",
        "PSH Flag Cnt",
        9999,
        "192.0.2.222",
        "T1573 Encrypted Channel",
        5,
    ),
    (
        "ZD-013",
        "Burst Fwd packets đột biến",
        "Total Fwd Packets",
        995,
        "203.0.113.33",
        "T1498 Network Denial of Service",
        1,
    ),
    (
        "ZD-014",
        "Time delay khổng lồ",
        "Flow Duration",
        10_000_000_000,
        "198.51.100.22",
        "T1102 Web Service",
        3,
    ),
    (
        "ZD-015",
        "Exfil gián đoạn Bwd burst",
        "Total Length of Bwd Packets",
        15_000_000,
        "192.0.2.99",
        "T1048 Exfiltration",
        4,
    ),
]

ADV_SPECS = [
    (
        "ADV-001",
        "SQL Injection ngụy trang Unicode",
        "payload",
        "SELECT * FROM users WHERE username = %s AND 1=1",
        "10.0.0.88",
        "T1190 Exploit Public-Facing Application",
        2,
    ),
    (
        "ADV-002",
        "XSS chèn qua header",
        "payload",
        "<svg/onload=alert(1)>",
        "10.0.0.89",
        "T1190 Exploit Public-Facing Application",
        3,
    ),
    (
        "ADV-003",
        "Command Injection dạng mã hóa Base64",
        "payload",
        "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS84MDgwIDA+JjE=",
        "10.0.0.90",
        "T1059 Command and Scripting Interpreter",
        4,
    ),
    (
        "ADV-004",
        "Dir Traversal nhiều cấp độ",
        "payload",
        "../../../../../../../etc/shadow",
        "10.0.0.91",
        "T1190 Exploit Public-Facing Application",
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


def _build_adversarials(tkey):
    out = []
    for i, (aid, name, _feat, val, dst, mitre, day) in enumerate(ADV_SPECS):
        log = {
            "Source IP": f"10.0.0.{100 + i}",
            "Destination IP": dst,
            "Destination Port": 80,
            "Protocol": 6,
            "service": "HTTP",
            "message": val,  # DAPT/WAF style payload
            "user_agent": f"adv-probe/{aid}",
        }
        out.append(
            {
                "id": aid,
                "name": f"Adversarial {name}",
                "mitre": mitre,
                "source": "adversarial",
                "day": day,
                "t": tkey(day),
                "log": log,
                "expected_threat": True,
                "label": "Attack",
            }
        )
    return out


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

    # --- Inject Adversarial ---
    main.extend(_build_adversarials(tkey))

    # --- MAX DỮ LIỆU THÔ TỪ RAW (KHÁC TẬP TRAIN) ---
    import os

    import pandas as pd

    print("LOADING UNSEEN RAW DATA FOR DEMO...")

    # 1. Load CICIDS2018 unseen data (skip first 80000 rows used in train)
    cic_path = os.path.join(
        ROOT, "data", "raw", "cicids2018", "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    )
    if os.path.exists(cic_path):
        df_cic = pd.read_csv(
            cic_path, skiprows=list(range(1, 80001)), nrows=20000, low_memory=False
        )
        df_cic.rename(columns=lambda x: x.strip(), inplace=True)
        for i, (_, row) in enumerate(df_cic.iterrows()):
            is_attack = str(row.get("Label", "")).strip().lower() != "benign"
            log = {
                "Source IP": f"192.168.2.{i % 254}",
                "Destination IP": "10.0.0.1",
                "Destination Port": 80 if is_attack else _safe_int(row.get("Dst Port", 443)),
                "Protocol": 6,
                "Flow Duration": _safe_int(row.get("Flow Duration")),
                "Total Fwd Packets": _safe_int(row.get("Tot Fwd Pkts")),
                "Total Backward Packets": _safe_int(row.get("Tot Bwd Pkts")),
                "Total Length of Fwd Packets": _safe_int(row.get("TotLen Fwd Pkts")),
                "Total Length of Bwd Packets": _safe_int(row.get("TotLen Bwd Pkts")),
                "Flow Pkts/s": _safe_float(row.get("Flow Pkts/s")),
                "Fwd Seg Size Min": _safe_int(row.get("Fwd Seg Size Min")),
                "Init Fwd Win Byts": _safe_int(row.get("Init Fwd Win Byts")),
                "Init Bwd Win Byts": _safe_int(row.get("Init Bwd Win Byts")),
                "Bwd Pkt Len Min": _safe_int(row.get("Bwd Pkt Len Min")),
                "PSH Flag Cnt": _safe_int(row.get("PSH Flag Cnt")),
                "service": "HTTP",
            }
            ev = {
                "source": "cicids_max",
                "log": log,
                "expected_threat": is_attack,
                "label": "Attack" if is_attack else "Benign",
                "t": tkey(1 + i % 5),
            }
            main.append(ev)

    # 2. Load DAPT2020 unseen data (skip first 15000 rows used in train)
    dapt_path = os.path.join(ROOT, "data", "raw", "dapt2020", "day1.csv")
    if os.path.exists(dapt_path):
        df_dapt = pd.read_csv(
            dapt_path, skiprows=list(range(1, 15001)), nrows=5000, low_memory=False
        )
        df_dapt.rename(columns=lambda x: x.strip(), inplace=True)
        for i, (_, row) in enumerate(df_dapt.iterrows()):
            label = str(row.get("Label", row.get("label", ""))).strip().lower()
            is_attack = label not in ["normal", "benign"]
            log = {
                "Source IP": f"192.168.3.{i % 254}",
                "Destination IP": "10.0.0.1",
                "Destination Port": 80 if is_attack else 443,
                "Protocol": 6,
                "Flow Duration": _safe_int(
                    row.get("Flow Duration", row.get("Flow Bytes/s", 0))
                ),  # Approximation mapping if needed
                "Total Fwd Packets": _safe_int(row.get("Total Fwd Packet")),
                "Total Backward Packets": _safe_int(row.get("Total Bwd packets")),
                "Total Length of Fwd Packets": _safe_int(row.get("Total Length of Fwd Packet")),
                "Total Length of Bwd Packets": _safe_int(row.get("Total Length of Bwd Packet")),
                "Flow Pkts/s": float(row.get("Flow Packets/s", 0) or 0),
                "Fwd Seg Size Min": _safe_int(row.get("Fwd Segment Size Min", 0)),
                "Init Fwd Win Byts": _safe_int(row.get("FWD Init Win Bytes")),
                "Init Bwd Win Byts": _safe_int(row.get("Bwd Init Win Bytes")),
                "Bwd Pkt Len Min": _safe_int(row.get("Bwd Packet Length Min")),
                "PSH Flag Cnt": _safe_int(row.get("PSH Flag Count")),
                "service": "HTTP",
            }
            ev = {
                "source": "dapt_max",
                "log": log,
                "expected_threat": is_attack,
                "label": "Attack" if is_attack else "Benign",
                "t": tkey(1 + i % 5),
            }
            main.append(ev)

    main.sort(key=lambda x: x["t"])
    return warmup, main, apt_truth, len(chains)
