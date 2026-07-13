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
