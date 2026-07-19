"""
SENTINEL — Bộ dựng DỮ LIỆU GỘP dùng chung (Unified Dataset Builder).
====================================================================
Module TRUNG LẬP chứa toàn bộ logic dựng luồng gộp (CICIDS + DAPT2020 + Zero-day
REAL-DERIVED) đã sắp theo thời gian. Trước đây code này nằm trong
`evaluate_unified_stream.py` (file EVAL offline) và bị các nơi khác import NGƯỢC
("lòng vòng"). Tách ra đây để CẢ đường online (`scripts/build_demo.py`,
`scripts/build_datatest.py` → `scripts/demo.py`/`push_datatest.py`), eval offline
(`evaluate_unified_stream.py`) và các thí nghiệm rigor cùng import từ 1 chỗ.

Ngoài `build_stream()`, module này cũng là NGUỒN DUY NHẤT của `enrich()`,
`determine_queue()` và `build_sequence()` (kế thừa từ `stream_unified_online.py`
đã gỡ bỏ) — mọi script push/demo và test đều import từ đây, KHÔNG copy tay.

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


# Số dòng tối đa quét MỖI file CICIDS raw khi lấy mẫu đa-ngày (giữ RAM bị chặn; đủ để
# bắt các cụm tấn công + benign của ngày đó). Xử lý từng ngày một -> đỉnh RAM ~1 ngày.
RAW_DAY_SCAN_ROWS = 250_000

# Cổng well-known -> tên dịch vụ THẬT (tín hiệu luồng trung thực, thay cho gán cứng "HTTP").
_PORT_SERVICE = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP",
}


def _infer_service_from_port(port) -> str:
    """Suy dịch vụ TỪ CỔNG THẬT (honest flow signal). Cổng lạ -> PORT_<n> (để Tier-2 thấy
    đúng là cổng phi chuẩn, không nguỵ trang thành HTTP)."""
    p = _safe_int(port)
    return _PORT_SERVICE.get(p, f"PORT_{p}")


def map_cicids(nl: dict) -> dict:
    """network_layer (ground_truth) -> schema CICIDS mà RuleEngine mong đợi."""
    # Trả về toàn bộ các key trong nl, đảm bảo tính đồng bộ với ML pipeline
    res = nl.copy()

    # Chuẩn hoá các key cũ nếu có (dành cho ground_truth.json cũ)
    mapping = {
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "dst_port": "Destination Port",
        "protocol": "Protocol",
        "flow_duration_us": "Flow Duration",
        "fwd_packets": "Total Fwd Packets",
        "bwd_packets": "Total Backward Packets",
        "fwd_bytes": "Total Length of Fwd Packets",
        "bwd_bytes": "Total Length of Bwd Packets",
        "flow_pkts_s": "Flow Pkts/s",
        "fwd_seg_size_min": "Fwd Seg Size Min",
        "init_fwd_win_byts": "Init Fwd Win Byts",
        "init_bwd_win_byts": "Init Bwd Win Byts",
        "bwd_pkt_len_min": "Bwd Pkt Len Min",
        "psh_flag_cnt": "PSH Flag Cnt",
    }

    for old_k, new_k in mapping.items():
        if old_k in res and new_k not in res:
            res[new_k] = res.pop(old_k)

    return res


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


def _build_zerodays(samples, tkey, repeat: int = 1):
    """Sinh zero-day REAL-DERIVED từ flow benign THẬT.

    Nền mỗi mẫu là một flow benign THẬT trong ground_truth, chọn các flow "static-clean"
    (cổng KHÔNG nhạy cảm + fwd <= max_fwd_packets + không signature) để luật TĨNH chắc
    chắn bỏ sót. Chỉ ĐÚNG MỘT feature Welford bị đặt lên cực trị (outlier signature-less);
    mọi feature flow KHÁC giữ NGUYÊN giá trị thật. Chỉ IP (truy vết nội bộ + đích ngoài
    cho narrative) là được đặt lại — IP không ảnh hưởng tới Z-score nên không làm sai lệch.

    repeat: mỗi spec áp lên NHIỀU nền benign THẬT khác nhau (cycle qua pool) + IP nguồn
    RIÊNG -> nhân số lượng probe cho demo tải lớn. KHÔNG bịa flow: nền 100% thật, chỉ đẩy
    1 feature outlier tài liệu hoá + đổi IP (replay signature-less từ nhiều nguồn).
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
    n = 0
    for r in range(max(1, repeat)):
        for i, (zid, name, feat, val, dst, mitre, day) in enumerate(ZD_SPECS):
            if pool:
                base_nl = pool[(n * 37 + r * 13) % len(pool)]  # rải đều nền benign, tất định
            else:
                base_nl = {"dst_port": 443, "fwd_packets": 40, "service": "HTTPS"}
            log = map_cicids(base_nl)  # flow benign THẬT làm nền
            log[feat] = val  # đẩy ĐÚNG 1 feature lên cực trị
            uid = zid if repeat == 1 else f"{zid}-{r:03d}"
            log["Source IP"] = f"10.{r % 250}.{(i * 7) % 250}.{(220 + i) % 254}"  # nguồn riêng
            log["Destination IP"] = dst  # đích ngoài (narrative exfil/C2)
            log["user_agent"] = f"zero-day-probe/{uid}"
            out.append(
                {
                    "id": uid,
                    "name": f"Zero-Day {name}",
                    "mitre": mitre,
                    "source": "zeroday",
                    "base_feature": feat,
                    "day": day,
                    "t": tkey(day),
                    "log": log,
                }
            )
            n += 1
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


def build_stream(
    cicids_max_rows: int = 20000,
    cicids_max_days: tuple[str, ...] = ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",),
    dapt_max_rows: int = 5000,
    zeroday_repeat: int = 1,
):
    """Trả về (warmup_events, main_events, apt_truth, n_chains).

    Tham số (MẶC ĐỊNH = hành vi cũ → datatest/eval KHÔNG đổi trừ khi caller override):
      cicids_max_rows: tổng dòng CICIDS raw nạp (chia đều cho các ngày) — nguồn KHỐI LƯỢNG.
      cicids_max_days: danh sách file ngày CICIDS THẬT để trích tấn công đa dạng + benign.
      dapt_max_rows:   số dòng DAPT day1 raw.
      zeroday_repeat:  nhân số zero-day real-derived (xem `_build_zerodays`).

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
                    "mitre_ttp": e.get("mitre_ttp", ""),  # TTP THẬT của DAPT2020 (đừng vứt đi)
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

    # --- MAX DỮ LIỆU THÔ TỪ RAW: ĐA-NGÀY CICIDS (nguồn KHỐI LƯỢNG + đa dạng tấn công) ---
    import os

    import pandas as pd

    print(f"LOADING RAW CICIDS ({len(cicids_max_days)} ngày, ~{cicids_max_rows} dòng)...")

    cic_dir = os.path.join(ROOT, "data", "raw", "cicids2018")
    n_days = max(1, len(cicids_max_days))
    per_day = max(1, cicids_max_rows // n_days)
    per_atk = max(1, int(per_day * 0.25))  # ~25% tấn công / 75% benign (nhiều benign để drop)
    per_ben = max(1, per_day - per_atk)
    _POP = ("Label", "Timestamp", "Flow ID", "Src IP", "Dst IP", "Src Port")

    for d_idx, day_file in enumerate(cicids_max_days):
        cic_path = os.path.join(cic_dir, day_file)
        if not os.path.exists(cic_path):
            continue
        try:
            df_cic = pd.read_csv(
                cic_path, nrows=RAW_DAY_SCAN_ROWS, low_memory=False, on_bad_lines="skip"
            )
        except Exception as _e:  # 1 file lỗi KHÔNG được giết cả build
            print(f"  [!] Bỏ qua {day_file}: {_e}")
            continue
        df_cic.rename(columns=lambda x: x.strip(), inplace=True)
        if "Label" not in df_cic.columns:
            continue
        df_cic = df_cic[df_cic["Label"].astype(str).str.strip() != "Label"]  # bỏ header lặp
        _lab = df_cic["Label"].astype(str).str.strip().str.lower()  # pyright: ignore[reportAttributeAccessIssue]
        atk_df = df_cic.loc[_lab != "benign"]
        ben_df = df_cic.loc[_lab == "benign"]
        if len(atk_df) > per_atk:
            atk_df = atk_df.sample(per_atk, random_state=42)  # pyright: ignore[reportAttributeAccessIssue]
        if len(ben_df) > per_ben:
            ben_df = ben_df.sample(per_ben, random_state=42)  # pyright: ignore[reportAttributeAccessIssue]
        rows = (
            pd.concat([atk_df, ben_df])  # pyright: ignore[reportCallIssue,reportArgumentType]
            if (len(atk_df) or len(ben_df))
            else df_cic.head(0)
        )
        for i, (_, row) in enumerate(rows.iterrows()):
            is_attack = str(row.get("Label", "")).strip().lower() != "benign"
            log = row.to_dict()
            for k, v in log.items():
                if pd.isna(v):
                    log[k] = 0
            port = _safe_int(row.get("Dst Port", 0))
            log.update(
                {
                    "Source IP": f"192.168.{10 + (d_idx % 40)}.{i % 254}",
                    "Destination IP": "10.0.0.1",
                    "Destination Port": port if port else (80 if is_attack else 443),
                    "Protocol": _safe_int(row.get("Protocol", 6)) or 6,
                    "service": _infer_service_from_port(port),  # TÍN HIỆU LUỒNG THẬT (từ cổng)
                }
            )
            for _k in _POP:
                log.pop(_k, None)
            ev = {
                "source": "cicids_max",
                "log": log,
                "expected_threat": is_attack,
                "label": "Attack" if is_attack else "Benign",
                "t": tkey(1 + i % 5),
            }
            # Bù warmup bằng benign THẬT (Welford cần baseline ấm trước khi bật Z-score).
            if not is_attack and len(warmup) < WARMUP_N:
                ev.pop("t", None)
                warmup.append(ev)
            else:
                main.append(ev)

    # --- DAPT2020 raw: day2..day5 (CÓ tấn công THẬT: Network/Web scan, Dir/Account
    #     Bruteforce, SQLi, Command Injection, Data Exfiltration). day1 toàn "Normal" -> BỎ. ---
    DAPT_DAYS = ("day2.csv", "day3.csv", "day4.csv", "day5.csv")
    dapt_dir = os.path.join(ROOT, "data", "raw", "dapt2020")
    dapt_per_day = max(1, dapt_max_rows // len(DAPT_DAYS))
    for dd_idx, dfile in enumerate(DAPT_DAYS):
        dpath = os.path.join(dapt_dir, dfile)
        if not os.path.exists(dpath):
            continue
        try:
            df_dapt = pd.read_csv(dpath, low_memory=False, on_bad_lines="skip")
        except Exception as _e:
            print(f"  [!] Bỏ qua DAPT {dfile}: {_e}")
            continue
        df_dapt.rename(columns=lambda x: x.strip(), inplace=True)
        if len(df_dapt) > dapt_per_day:
            df_dapt = df_dapt.sample(dapt_per_day, random_state=42)
        for i, (_, row) in enumerate(df_dapt.iterrows()):
            label = str(row.get("Label", row.get("label", ""))).strip().lower()
            is_attack = label not in ["normal", "benign"]
            log = {
                "Source IP": f"192.168.{40 + dd_idx}.{i % 254}",
                "Destination IP": "10.0.0.1",
                "Destination Port": 80 if is_attack else 443,
                "Protocol": 6,
                "Flow Duration": _safe_int(row.get("Flow Duration", row.get("Flow Bytes/s", 0))),
                "Total Fwd Packets": _safe_int(row.get("Total Fwd Packet")),
                "Total Backward Packets": _safe_int(row.get("Total Bwd packets")),
                "Total Length of Fwd Packets": _safe_int(row.get("Total Length of Fwd Packet")),
                "Total Length of Bwd Packets": _safe_int(row.get("Total Length of Bwd Packet")),
                "Flow Pkts/s": _safe_float(row.get("Flow Packets/s")),
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

    # --- Zero-day: REAL-DERIVED (nền benign THẬT + 1 feature outlier), nhân theo
    #     zeroday_repeat (IP riêng) cho tải demo. Cổng cho phép + fwd thấp + không signature
    #     => luật TĨNH bỏ sót; lệch baseline mạnh => Welford Z-score bắt. Xem `_build_zerodays`.
    main.extend(_build_zerodays(samples, tkey, repeat=zeroday_repeat))

    # --- Inject Adversarial (4 payload OWASP THẬT) ---
    main.extend(_build_adversarials(tkey))

    main.sort(key=lambda x: x["t"])
    return warmup, main, apt_truth, len(chains)


# --------------------------------------------------------------------------- #
# Giao ước ONLINE dùng chung (kế thừa stream_unified_online.py đã gỡ bỏ):
# enrich + determine_queue + build_sequence — scripts/demo.py, push_datatest.py,
# build_demo.py, build_datatest.py và tests đều import từ ĐÂY (1 nguồn chân lý).
# --------------------------------------------------------------------------- #
FIREWALL_PORTS = {21, 22, 23, 53, 139, 445, 3389}
WAF_PORTS = {80, 443, 8080}


def determine_queue(log: dict) -> str:
    """Port-based → payload/UA → default firewall."""
    try:
        port = int(log.get("Destination Port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if port in FIREWALL_PORTS:
        return "queue_firewall"
    if port in WAF_PORTS:
        return "queue_waf"
    if log.get("payload") or log.get("user_agent"):
        return "queue_waf"
    return "queue_firewall"


def enrich(ev: dict, demo_signals: bool = False) -> dict:
    """Gắn metadata theo nguồn vào log để subscriber/agent/dashboard dùng được.

    Toàn bộ đi trong MỘT blob JSON dưới field 'log' (đúng giao ước publisher).

    demo_signals: CHỈ bật cho luồng TRÌNH DIỄN (build_demo.py). Khi bật, DAPT tấn công
    được đính ngữ cảnh threat-intel THẬT (giai đoạn + MITRE TTP có sẵn trong dataset
    DAPT2020) vào field `message` để Tier-2 ánh xạ ĐÚNG kỹ thuật ĐA DẠNG (T1046/T1087/
    T1083/T1190/T1068...) thay vì đoán T1571 từ mỗi số cổng. TẮT cho benchmark
    (build_datatest.py) -> KHÔNG rò nhãn vào số thực nghiệm (datatest.json giữ nguyên).
    """
    log = dict(ev["log"])
    log["dataset_source"] = "unified_stream"
    log["unified_source"] = ev["source"]

    if ev["source"] == "dapt":
        # Metadata để subscriber ghi chuỗi APT (emergent) vào Threat Memory.
        log["apt_phase"] = ev.get("phase")
        log["apt_day"] = ev.get("day")
        log["apt_label"] = ev.get("label", "")
        log["apt_is_attack"] = bool(ev.get("is_attack"))
        log["apt_timestamp"] = ev.get("timestamp", "")
        log["apt_mitre_ttp"] = ev.get("mitre_ttp", "")  # TTP THẬT (hiển thị tab Threat Intel)
        # DEMO ONLY: threat-intel THẬT của DAPT2020 làm ngữ cảnh phát hiện. `message` sống
        # sót qua rule_engine (engine chỉ ghi đè tier1_reasons) và được node_rag_context đọc
        # vào truy vấn RAG -> LLM ánh xạ đúng TTP. Nội dung 100% từ dataset (không tự chế).
        if demo_signals and bool(ev.get("is_attack")) and ev.get("mitre_ttp"):
            log["message"] = (
                f"[Threat-Intel DAPT2020] Giai đoạn tấn công: {ev.get('phase', '')}; "
                f"kỹ thuật MITRE ATT&CK ghi nhận: {ev.get('mitre_ttp', '')}."
            )
    elif ev["source"] == "zeroday":
        log["zd_id"] = ev.get("id")
        log["zd_mitre"] = ev.get("mitre")
        log["zd_name"] = ev.get("name")
    elif ev["source"] == "adversarial":
        # payload OWASP LLM Top-10 để thử Guardrails/Tier-2 khi escalate
        log["adv_id"] = ev["log"].get("gt_id", "")
        log["adv_source"] = "owasp_llm_top10"
    else:  # cicids / cicids_max / dapt_max: flow có nhãn ground-truth phẳng
        log["gt_label"] = ev.get("label", "")
        log["expected_threat"] = bool(ev.get("expected_threat"))
    return log


def build_sequence():
    """Luồng phát online: warmup benign TRƯỚC (làm ấm Welford) rồi luồng chính trộn.

    Adversarial (OWASP LLM) đã được build_stream() trộn sẵn trong main — không cần
    cờ --include-adversarial như bản cũ. Trả về (seq, warmup, main, apt_truth, n_chains).
    """
    warmup, main, apt_truth, n_chains = build_stream()
    seq = list(warmup) + list(main)  # warmup giữ prefix; main đã sort theo thời gian
    return seq, warmup, main, apt_truth, n_chains
