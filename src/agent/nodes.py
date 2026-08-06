"""
LangGraph Nodes for SENTINEL Agent
"""

import hashlib
import logging
import os
import re
import time
import urllib.parse
from typing import Any

import mlflow  # type: ignore

from src.agent import trace
from src.agent.attack_mapper import (
    AttackMapperInput,
    build_mitre_url,
    map_attack,
    verify_technique_label,
)
from src.agent.llm_client import DECISION_JSON_SCHEMA, llm_client
from src.agent.prompts import build_triage_prompt
from src.agent.response_cache import response_cache
from src.agent.state import SentinelState
from src.agent.threat_memory import threat_memory
from src.guardrails import (
    DecisionValidator,
    DelimitedDataEncapsulator,
    GuardrailsPipeline,
    audit_logger,
    context_overflow_guard,
    decision_policy,
    loop_detector,
    output_sanitizer,
)
from src.guardrails.constants import TIER_LLM, normalize_log_keys
from src.rag.retriever import DualRetriever
from src.response.executor import block_ip, raise_alert
from src.tier1_filter.feedback_listener import FeedbackListener

logger = logging.getLogger(__name__)

# Khởi tạo Retriever (Singleton)
retriever = DualRetriever(use_cache=True)

# Số ký tự payload thô tối đa đưa vào truy vấn NGỮ CẢNH (truy vấn KỸ THUẬT không nhận
# payload — xem `node_rag_context`). LLM vẫn luôn nhận log đầy đủ, đây chỉ là truy vấn RAG.
PAYLOAD_QUERY_CHARS = 120

# ==============================================================================
# ÁNH XẠ NHÃN PHÁT HIỆN (tiếng Việt) -> CỤM TỪ VỰNG MITRE (tiếng Anh)
# ==============================================================================
# Nhãn của Tier-1 là TIẾNG VIỆT ("WAF: Phát hiện SQL Injection (SQLi) trong 'message'"),
# còn kho MITRE/NIST là TIẾNG ANH và embedder all-MiniLM-L6-v2 thiên tiếng Anh -> chuỗi
# Việt gần như KHÔNG đóng góp tín hiệu truy xuất. Bảng này dịch nhãn sang đúng từ vựng
# MITRE để truy vấn neo vào KỸ THUẬT.
#
# BẮT BUỘC PHỦ ĐỦ 29 HỌ của `_WAF_PATTERNS` (rule_engine.py). Trước đây bảng chỉ có 11
# needle phủ 7/29 họ; 22 họ còn lại sinh nhãn thuần Việt -> truy vấn rơi hoàn toàn về
# payload thô -> truy xuất trượt sang nhóm kỹ thuật sai. Test
# `test_attack_terms_cover_all_waf_families` KHOÁ bất biến này: thêm họ chữ ký mà quên
# ánh xạ thì CI đỏ.
#
# Khoá tra là chuỗi con VIẾT THƯỜNG của tên họ trong `_WAF_PATTERNS`, nên khớp trực tiếp
# với chuỗi lý do mà `_check_waf_signatures` sinh ra.
_ATTACK_TERMS: tuple[tuple[str, str], ...] = (
    # ── Tiêm nhiễm web kinh điển ──
    ("sql injection", "SQL injection exploit public-facing application web vulnerability"),
    ("sqli", "SQL injection exploit public-facing application web vulnerability"),
    ("nosql injection", "NoSQL injection exploit public-facing application database query"),
    ("cross-site scripting", "cross-site scripting XSS drive-by compromise web client exploit"),
    ("xss", "cross-site scripting XSS drive-by compromise web client exploit"),
    (
        "dò tệp sao lưu/mã nguồn",
        "active scanning wordlist scanning content discovery probing for backup and source "
        "files restricted file extension reconnaissance",
    ),
    ("path traversal", "File and Directory Discovery path traversal directory traversal T1083"),
    ("duyệt thư mục", "File and Directory Discovery path traversal directory traversal T1083"),
    (
        "infilteration",
        "Application Layer Protocol Web Protocols infiltration Command and Control T1071.001",
    ),
    (
        "infiltration",
        "Application Layer Protocol Web Protocols infiltration Command and Control T1071.001",
    ),
    ("lfi", "path traversal local file inclusion exploit public-facing application"),
    ("command injection", "command and scripting interpreter command injection exploit"),
    ("ldap injection", "LDAP injection exploit public-facing application directory query"),
    ("xxe injection", "XML external entity XXE exploit public-facing application file read"),
    ("ssti", "server-side template injection exploit public-facing application code execution"),
    ("ssrf", "server-side request forgery cloud instance metadata API internal service access"),
    ("crlf", "HTTP response splitting header injection exploit public-facing application"),
    (
        "prototype pollution",
        "prototype pollution exploit public-facing application object injection",
    ),
    ("graphql", "GraphQL introspection abuse exploit public-facing application data discovery"),
    ("jwt", "forge web credentials JSON web token authentication bypass"),
    # ── Thực thi mã / web shell / RCE ──
    ("log4shell", "exploit public-facing application JNDI lookup remote code execution Log4j"),
    ("jndi injection", "exploit public-facing application JNDI lookup remote code execution"),
    ("web shell", "server software component web shell persistence remote command execution"),
    ("web shell qua tệp tải lên", "server software component web shell upload persistence"),
    (
        "insecure deserialization",
        "exploit public-facing application deserialization code execution",
    ),
    ("reverse shell", "command and scripting interpreter reverse shell remote access"),
    ("encoded powershell", "command and scripting interpreter PowerShell obfuscated execution"),
    ("living-off-the-land", "signed binary proxy execution system binary abuse LOLBin"),
    ("lolbin", "signed binary proxy execution system binary abuse LOLBin"),
    # ── Trinh sát / công cụ tấn công ──
    ("scanner", "active scanning vulnerability scanning reconnaissance attack tooling"),
    ("attack tooling", "active scanning vulnerability scanning reconnaissance attack tooling"),
    ("quét cổng", "network service discovery port scanning reconnaissance"),
    ("port scan", "network service discovery port scanning reconnaissance"),
    ("cổng nhạy cảm", "remote services SSH RDP SMB valid accounts lateral movement"),
    ("brute", "brute force password guessing valid accounts remote services"),
    # ── Truy cập thông tin xác thực / tệp nhạy cảm ──
    ("đánh cắp thông tin xác thực", "OS credential dumping LSASS memory DCSync Kerberoasting"),
    ("sensitive file access", "unsecured credentials credentials in files configuration discovery"),
    # ── Né tránh ──
    ("mã hoá né tránh", "obfuscated files or information encoding evasion defense evasion"),
    ("encoding evasion", "obfuscated files or information encoding evasion defense evasion"),
    # ── Tác động / hậu khai thác ──
    ("ransomware", "data encrypted for impact inhibit system recovery shadow copy deletion"),
    ("phá huỷ", "data destruction inhibit system recovery disk wipe impact"),
    ("đào tiền mã hoá", "resource hijacking cryptocurrency mining compute abuse"),
    (
        "rò rỉ ra dịch vụ ngoài",
        "exfiltration over web service to cloud storage alternative protocol",
    ),
    # ── Phát hiện KHÔNG-CHỮ-KÝ của Tier-1 (NetFlow thuần) ──────────────────────────
    # Bảng trên phủ 29 họ chữ ký WAF, tức chỉ sự kiện CÓ payload. Ba mục dưới đây bổ sung
    # các lý do NGƯỠNG/NHỊP ĐỘ mà Tier-1 sinh ra cho NetFlow thuần — nhóm chiếm đa số lưu
    # lượng leo thang. (Quét cổng · cổng nhạy cảm · brute đã có ở phần trên, đừng thêm lại:
    # `_canonical_attack_terms` khử trùng theo GIÁ TRỊ, nên hai cụm gần-giống-nhau đều được
    # nối vào và chỉ làm truy vấn loãng đi.)
    # CHỈ MÔ TẢ HIỆN TƯỢNG ĐO ĐƯỢC — KHÔNG tự khai một họ kỹ thuật nào.
    #
    # Bản trước nhét thẳng "network denial of service ..." vào cả ba cụm ngưỡng. Đó đúng là
    # hành vi mà ghi chú của `_ANOMALY_FEATURE_TERMS` ngay bên dưới đã cấm ("đoán kỹ thuật từ
    # một con số"), chỉ khác là nó nằm ở bảng ngưỡng nên không ai để ý. Hậu quả đo được trên
    # luồng sống: 82% truy vấn RAG trả top-1 = T1498, và LLM — vốn được dặn chọn kỹ thuật TỪ
    # ngữ cảnh RAG — đọc lại chính lời tự khai đó như thể là bằng chứng. Vòng lặp tự khẳng
    # định: truy vấn nói "DoS" -> RAG trả DoS -> LLM kết luận DoS.
    #
    # Một ngưỡng bị vượt CHỈ chứng minh "khối lượng/nhịp độ bất thường". DoS, C2 beaconing và
    # rò rỉ dữ liệu đều khớp như nhau; chọn giúp một cái là bịa bằng chứng. Để bộ truy xuất
    # tự quyết kỹ thuật nào gần nhất, và khi không đủ căn cứ thì AWAIT_HITL mới là đáp án đúng.
    ("vượt ngưỡng", "connection count above learned baseline repeated requests from single source"),
    ("tốc độ yêu cầu cao", "elevated request rate single source repeated connection attempts"),
    ("tần suất", "high event frequency short interval repeated network connections"),
)

# Các KHOÁ ngưỡng/nhịp-độ: cụm của chúng là "chung chung" và phải bị loại khi lô đã có chữ
# ký cụ thể. Giữ DANH SÁCH KHOÁ ở đây rồi SUY RA cụm từ `_ATTACK_TERMS`, thay vì chép lại
# chuỗi — bản trước chép tay vào `_GENERIC_TERMS`, nên khi sửa lời trong bảng thì tập khử
# vẫn trỏ vào chuỗi cũ và cơ chế khử tắt IM LẶNG, không có gì đỏ lên để báo.
_THRESHOLD_KEYS = frozenset({"vượt ngưỡng", "tốc độ yêu cầu cao", "tần suất"})


# Đặc trưng Welford -> mô tả tiếng Anh của HIỆN TƯỢNG QUAN SÁT ĐƯỢC.
#
# CỐ Ý KHÔNG GÁN MÃ ATT&CK. Bản nháp trước ánh xạ mọi dị biệt thống kê thành
# "beaconing command and control" và hậu quả đo được rất rõ: một flow brute-force web
# (nhãn thật T1110) chỉ lệch ở `Total Fwd Packets` lại truy xuất ra T1071.001/T1041/T1571 —
# tức chính lỗi "đoán kỹ thuật từ một con số" mà dự án đã cấm ở chỗ khác. Welford biết
# DUY NHẤT một điều: đặc trưng nào lệch bao nhiêu độ lệch chuẩn. Vậy thì truy vấn chỉ được
# nói đúng chừng đó, và để bộ truy xuất tự quyết kỹ thuật nào gần nhất.
_ANOMALY_FEATURE_TERMS: dict[str, str] = {
    "total fwd packets": "high outbound packet count repeated connection attempts",
    "total backward packets": "high inbound packet count response flooding",
    "total length of fwd packets": "large outbound data transfer volume",
    "total length of bwd packets": "large inbound data transfer size limits",
    "flow duration": "unusually long lived network session",
    "flow pkts/s": "high packet rate network flooding",
    "flow byts/s": "high byte rate network flooding",
    "init fwd win byts": "abnormal tcp window size non standard protocol behaviour",
    "init bwd win byts": "abnormal tcp window size non standard protocol behaviour",
    "bwd pkt len min": "abnormal small packet length protocol anomaly",
    "fwd seg size min": "abnormal segment size protocol anomaly",
    "psh flag cnt": "abnormal tcp flag pattern protocol anomaly",
}

_ANOMALY_FEATURE_RE = re.compile(r"dị biệt thống kê[^\[]*\[([^\]]+)\]", re.IGNORECASE)


# Cụm từ vựng CHUNG CHUNG — mô tả "có gì đó bất thường về khối lượng/nhịp độ", KHÔNG chỉ ra
# một kỹ thuật cụ thể nào. Chúng hữu ích khi đó là TẤT CẢ những gì ta biết (NetFlow thuần),
# nhưng phải BỊ LOẠI khi đã có chữ ký cụ thể — xem `_canonical_attack_terms`.
_GENERIC_TERMS = frozenset(
    {en for vi, en in _ATTACK_TERMS if vi in _THRESHOLD_KEYS} | set(_ANOMALY_FEATURE_TERMS.values())
)


def _canonical_attack_terms(reasons: list) -> list[str]:
    """Suy cụm từ MITRE tiếng Anh từ các lý do phát hiện (tiếng Việt) của Tier-1.

    ƯU TIÊN CHỮ KÝ CỤ THỂ HƠN TỪ VỰNG CHUNG. Một log có thể vừa khớp chữ ký WAF ("SQL
    Injection") vừa vượt ngưỡng khối lượng. Nếu nối cả hai vào một truy vấn, phần "network
    denial of service traffic flooding…" sẽ kéo vector về phía họ DoS và ĐẨY TỤT kỹ thuật
    đúng: đo được trên bộ web-attack, T1190 tụt từ hạng 1 xuống hạng 3 sau T1499.002/T1498
    cho payload SQLi, khiến ánh xạ chọn sai. Một chữ ký cụ thể luôn giàu thông tin hơn
    "có gì đó vượt ngưỡng", nên khi đã có chữ ký thì bỏ hẳn phần chung.
    """
    joined = " ".join(str(r) for r in reasons)
    low = joined.lower()
    out: list[str] = []
    for needle, terms in _ATTACK_TERMS:
        if needle in low and terms not in out:
            out.append(terms)
    # Dị biệt Welford: mô tả ĐẶC TRƯNG đã lệch, không gán kỹ thuật (xem chú thích ở trên).
    for feat in _ANOMALY_FEATURE_RE.findall(joined):
        terms = _ANOMALY_FEATURE_TERMS.get(feat.strip().lower())
        if terms and terms not in out:
            out.append(terms)

    specific = [t for t in out if t not in _GENERIC_TERMS]
    return specific or out


def evidence_layer_of(logs) -> str:
    """Lô này mang bằng chứng tầng ỨNG DỤNG hay chỉ có FLOW?

    Quyết định mức chi tiết mà Tier-2 được phép quy kết. ATT&CK định nghĩa phần lớn kỹ thuật
    trên hành vi endpoint/ứng dụng; NetFlow thuần chỉ có số đếm gói/byte/cổng, mà từ đó thì
    DoS · C2 beaconing · rò rỉ dữ liệu khớp NHƯ NHAU. Ép mô hình trả một mã kỹ thuật cho lô
    không có payload là ép nó đoán — nên ở đây ta phân luồng để prompt hỏi đúng câu:
    có payload -> hỏi KỸ THUẬT; chỉ có flow -> hỏi TACTIC + bước ứng phó.

    Cùng bộ trường mà `build_rag_queries` coi là "nội dung ứng dụng", giữ một định nghĩa duy
    nhất để hai nơi không trôi khỏi nhau.
    """
    if isinstance(logs, dict):
        logs = [logs]
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        for k in ("message", "payload", "uri", "URI", "user_agent"):
            if str(lg.get(k) or "").strip():
                return "application"
    return "flow"


def build_rag_queries(first_log: dict | list) -> tuple[str, str]:
    """Dựng HAI truy vấn RAG tách biệt: (truy vấn KỸ THUẬT, truy vấn NGỮ CẢNH).

    VÌ SAO PHẢI TÁCH — đây là nguyên nhân gốc của Context Precision thấp.
    Bản trước nối cụm chuẩn tiếng Anh RỒI payload thô vào CÙNG một chuỗi, với lập luận
    "đặt nhãn phát hiện lên trước thì nó thắng". Lập luận đó SAI: embedding câu là túi
    ngữ nghĩa, KHÔNG có trọng số theo vị trí — thêm payload vào là dời cả vector.

    Đo thật trên chính bộ truy xuất này với payload SQLi `' UNION SELECT password FROM users--`:
        chỉ cụm EN            -> T1190 hạng 1                     ✅
        cụm EN + payload      -> T1212, T1110.004, T1539 …        ❌ T1190 rớt khỏi top-5
        chỉ payload           -> T1555, T1110.001 …               ❌
    Chữ `password` trong payload kéo vector sang nhóm ĐÁNH CẮP THÔNG TIN XÁC THỰC. Vì
    prompt dặn LLM đặt `N/A` + `AWAIT_HITL` khi không khớp technique nào, RAG trượt kéo
    theo LLM không bao giờ chặn được.

    GIẢI PHÁP: hai truy vấn, hai mục đích.
      1. KỸ THUẬT — thuần tiếng Anh (cụm chuẩn + metadata flow), TUYỆT ĐỐI không payload.
         Đây là khối LLM dùng để chọn technique.
      2. NGỮ CẢNH — có payload, dùng để bồi thêm ngữ cảnh vận hành ở ưu tiên THẤP HƠN.
         Giữ lại tín hiệu từ vựng của cuộc tấn công mà không để nó lái phần ánh xạ.

    Trả `("", "")` khi log rỗng. Truy vấn ngữ cảnh trả "" khi log không có payload —
    đại đa số lưu lượng là NetFlow thuần nên nhánh đó thường không tốn lượt truy xuất nào.
    """
    # Nhận MỘT log (tương thích ngược) hoặc CẢ LÔ.
    #
    # LỖI ĐÃ SỬA — đo được trên luồng demo thật: hàm này từng chỉ đọc `current_batch_logs[0]`,
    # trong khi một lô Tier-2 gộp tới 10 log của cùng một IP. Với chuỗi DAPT, chín log đầu là
    # NetFlow trần và chỉ log thứ 9-10 mang `message="…Hoạt động ghi nhận: Account Discovery…"`.
    # Hệ quả quan sát được: truy vấn kỹ thuật rơi về từ vựng NGƯỠNG/KHỐI-LƯỢNG, RAG trả về
    # T1498/T1499/T1571 (toàn DoS), và LLM — vốn được prompt dặn "chọn technique TỪ ngữ cảnh
    # RAG" — trả lời T1498 cho một sự kiện Account Discovery (thật là T1087). Không phải LLM
    # suy luận kém: nó không bao giờ được thấy dòng chữ quyết định.
    logs = [first_log] if isinstance(first_log, dict) else list(first_log or [])
    logs = [x for x in logs if isinstance(x, dict)]
    if not logs:
        return "", ""

    # ── Phần THUẦN ANH: nhãn phát hiện đã chuẩn hoá + metadata flow thật ──
    # Gom lý do của TOÀN LÔ (khử trùng, giữ thứ tự) — một lô là một chuỗi hành vi của cùng
    # một IP, nên tín hiệu ở log thứ 10 cũng thuộc về nó như log thứ nhất.
    reasons: list = []
    for lg in logs:
        for rs in lg.get("tier1_reasons") or []:
            if rs not in reasons:
                reasons.append(rs)
    parts: list[str] = list(_canonical_attack_terms(reasons[:8]))

    # BỔ SUNG TRÍCH XUẤT TÍN HIỆU HEURISTIC TỪ PAYLOAD/URI KHI REASONS THIẾU
    # Trích xuất từ vựng kỹ thuật MITRE từ URI/payload giải mã (double URL decode)
    p_terms: list[str] = []
    text_blobs: list[str] = []
    for lg in logs:
        msg = str(lg.get("message", "")) + " " + str(lg.get("payload", ""))
        uri_str = str(lg.get("uri") or lg.get("URI") or "")
        raw_str = msg + " " + uri_str
        if raw_str.strip():
            dec = urllib.parse.unquote(urllib.parse.unquote(raw_str))
            text_blobs.append(dec.lower())
    full_text = " ".join(text_blobs)

    if full_text:
        # Tự động trích xuất khái niệm an ninh mạng chuẩn (RAG Query Expansion Layer)
        # KHÔNG hardcode mã kỹ thuật MITRE hay tên file cụ thể của tập dữ liệu
        if re.search(
            r"\.(inc|bak|old|tmp|swp|zip|tar|gz|config|env)\b|/\.(bak|old|inc)|dirb|gobuster|wordlist",
            full_text,
            re.IGNORECASE,
        ):
            p_terms.append(
                "web file extension enumeration directory content scanning wordlist probing"
            )
        if re.search(
            r"waitfor\s*\+?\s*delay|union\s+select|select\s+.*from|exec\s*\(|drop\s+table",
            full_text,
            re.IGNORECASE,
        ):
            p_terms.append("sql injection database query delay public application exploitation")
        if re.search(
            r"<script|script>|alert\(|set-cookie|javascript:|%\w{2}set-cookie",
            full_text,
            re.IGNORECASE,
        ):
            p_terms.append("cross site scripting inline javascript execution command interpreter")
        if re.search(
            r"etc/passwd|win\.ini|web-inf|web\.xml|cmd=|exec\b|cat\s+/|/bin/sh|/bin/bash|\.\./",
            full_text,
            re.IGNORECASE,
        ):
            p_terms.append("path traversal sensitive configuration file directory discovery")
        if re.search(r"login=|pwd=|password=", full_text, re.IGNORECASE):
            p_terms.append("authentication request credential submission login attempt brute force")

    for pt in p_terms:
        if pt not in parts:
            parts.append(pt)

    # KHÔNG đưa chuỗi lý do THÔ (tiếng Việt) vào: KB và embedder đều thiên tiếng Anh nên
    # nó gần như 0 tín hiệu truy xuất mà vẫn làm nhiễu vector.
    head = logs[0]
    svc = head.get("service") or head.get("Service")
    if svc:
        parts.append(f"service {svc}")
    port = head.get("Destination Port") or head.get("dst_port")
    if port not in (None, "", 0):
        parts.append(f"destination port {port}")
    technique_q = " ".join(parts).strip()[:300]

    # ── Truy vấn NGỮ CẢNH: payload + URI. URI thuộc về đây chứ không phải truy vấn kỹ
    # thuật, vì nó mang từ vựng do KẺ TẤN CÔNG kiểm soát (đúng bản chất như payload). ──
    # Chọn log GIÀU NỘI DUNG NHẤT trong lô, không phải log đầu: log đầu thường là NetFlow trần.
    def _payload_of(lg: dict) -> str:
        return (str(lg.get("message", "")) + " " + str(lg.get("payload", ""))).strip()

    best = max(
        logs, key=lambda lg: len(_payload_of(lg)) + len(str(lg.get("uri") or lg.get("URI") or ""))
    )
    ctx_parts: list[str] = []
    uri = best.get("uri") or best.get("URI")
    if uri:
        ctx_parts.append(f"uri {uri}")
    msg = _payload_of(best)
    if msg:
        ctx_parts.append(msg[:PAYLOAD_QUERY_CHARS])
    context_q = " ".join(ctx_parts).strip()[:300]

    return technique_q, context_q


# ==============================================================================
# Hàm phụ cho TRACER (chỉ được gọi bên trong `if trace.enabled():`)
# ==============================================================================
def _trace_rag_hits(results: list | None, top: int = 5) -> list[dict]:
    """Rút gọn kết quả truy xuất: chỉ id/tên/điểm RRF. BỎ `text` — độ dài đã đo riêng bằng
    `*_context_chars`, còn nội dung thì đã nằm nguyên trong `llm.prompt`."""
    return [
        {
            "id": r.get("id", ""),
            "name": r.get("name", ""),
            "rrf": round(float(r.get("rrf_score", 0.0) or 0.0), 5),
        }
        for r in (results or [])[:top]
    ]


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Mã kỹ thuật ATT&CK trong khối ngữ cảnh RAG — dùng để kiểm tra câu trả lời của LLM có
# THỰC SỰ neo vào tài liệu vừa truy xuất hay không (xem lá chắn neo bằng chứng ở
# `node_attack_mapper`).
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _annotate_reused_verdict(reasoning: str, decision: dict, target: str) -> str:
    """Ghi rõ khi phần lập luận được TÁI SỬ DỤNG từ một luồng có IP khác.

    LỖI THẬT quan sát được trên luật động sinh ra ở lượt chạy 2026-07-28: luật chặn
    `172.20.0.122` mang phần lý do nói về `10.200.4.164`; luật chặn `192.168.41.100` và
    `192.168.41.5` đều mang lý do viết cho `192.168.42.174`. Nguồn gốc là cache lớp-2 (gộp
    theo ĐẶC TRƯNG, cố ý bỏ IP/timestamp khỏi khoá): `target` THỰC THI đã được bảo vệ đúng
    (xem chú thích ở `node_llm_triage`), nhưng chuỗi `reasoning` do LLM viết cho IP GỐC thì
    đi thẳng vào nhật ký kiểm toán, lý do của luật động và giao diện analyst.

    Ta KHÔNG viết lại câu chữ của LLM để nó nhắc tên IP mới: làm vậy là bịa ra một lời giải
    thích mà model chưa từng đưa ra cho IP này — với một hệ thống lấy tính GIẢI THÍCH ĐƯỢC
    làm đóng góp chính thì đó là cái giá quá đắt. Thay vào đó ta nói thẳng xuất xứ, giữ
    nguyên văn phần lập luận gốc.
    """
    if not reasoning or not target or target == "UNKNOWN_TARGET":
        return reasoning
    origin = ""
    for ioc in decision.get("extracted_iocs") or []:
        if isinstance(ioc, dict) and ioc.get("ioc_type") == "ip" and ioc.get("value"):
            origin = str(ioc["value"])
            break
    if not origin:
        found = _IPV4_RE.findall(reasoning)
        origin = found[0] if found else ""
    if not origin or origin == target:
        return reasoning
    return (
        f"[PHÁN QUYẾT TÁI SỬ DỤNG — luồng này có cùng dấu vân hành vi với một luồng đã phân "
        f"tích trước đó (khác IP/thời điểm), nên hệ thống dùng lại kết luận thay vì gọi LLM "
        f"lần nữa. Phần lập luận dưới đây được LLM viết cho {origin}, áp dụng cho {target}.]\n"
        f"{reasoning}"
    )


def _trace_verdict(d: dict | None) -> dict:
    """Ảnh chụp gọn một verdict, để so TRƯỚC/SAU mỗi lớp kiểm duyệt."""
    d = d or {}
    return {
        "action": d.get("action", ""),
        "confidence": d.get("confidence"),
        "target": d.get("target", ""),
        "mitre_technique": d.get("mitre_technique", ""),
        "error": d.get("error", ""),
    }


# Khởi tạo Guardrails / DecisionValidator (Singleton)
guardrails_pipeline = GuardrailsPipeline()
decision_validator = DecisionValidator()


def node_guardrails(state: SentinelState) -> dict[str, Any]:
    """
    Guardrails Node: Nén log và làm sạch trước khi đưa vào RAG/LLM.
    """
    logger.info("--- NODE: GUARDRAILS (MINING & FILTERING) ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_guardrails")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if not state.current_batch_logs:
        return {"current_batch_encapsulated": ""}

    # 2. Xử lý và nén log qua pipeline
    #
    # `gt_id` BỊ LOẠI KHỎI PROMPT, nhưng vẫn ở lại `state.current_batch_logs` cho tracer.
    # Nó là khoá nối hậu kiểm (xem `scripts/stamp_demo_ids.py`): tracer cần nó để chấm kết
    # quả với đáp án, còn LLM thì không được lợi gì từ một định danh mờ — đưa vào chỉ tổ
    # thêm nhiễu và cho người phản biện một cái cớ hỏi "sao dữ liệu chấm điểm lại nằm trong
    # prompt?". Tách ở đây là chỗ hẹp nhất: mọi thứ vào prompt đều đi qua `process_batch`.
    _prompt_logs = [
        {k: v for k, v in lg.items() if k != "gt_id"} if isinstance(lg, dict) else lg
        for lg in state.current_batch_logs
    ]
    processed_data = guardrails_pipeline.process_batch(_prompt_logs)
    batch_enc = processed_data["batch_encapsulated"]

    if trace.enabled():
        trace.add("nodes", guardrails=round(time.time(), 6))
        # `individual_results` bị VỨT ngay sau dòng này ở bản gốc — cùng với mọi cờ
        # injection/jailbreak theo từng log. Đó là lý do cột `guardrail_injected` trong
        # logs/guardrails_audit.db LUÔN bằng 0 trên toàn bộ 3.261 dòng đã lưu.
        _res = processed_data.get("individual_results", []) or []
        _levels = {r.get("isolation_level", "NORMAL") for r in _res if isinstance(r, dict)}
        trace.add(
            "guardrails",
            total_logs=processed_data.get("total_logs", 0),
            injection_count=processed_data.get("injection_count", 0),
            jailbreak_count=sum(
                1 for r in _res if isinstance(r, dict) and r.get("jailbreak_detected")
            ),
            # `process_batch` KHÔNG trả isolation_level ở mức trên -> phải suy ra từ từng log.
            isolation_level=(
                "CRITICAL" if "CRITICAL" in _levels else ("HIGH" if "HIGH" in _levels else "NORMAL")
            ),
            injection_fields=sorted(
                {f for r in _res if isinstance(r, dict) for f in (r.get("injection_fields") or [])}
            ),
            injection_patterns=sorted(
                {
                    str(p)
                    for r in _res
                    if isinstance(r, dict)
                    for p in (r.get("injection_patterns") or [])
                }
            )[:20],
            encapsulated_chars=len(batch_enc),
            system_instruction_chars=len(processed_data.get("system_instruction", "")),
        )

    # 3. Giám sát tràn Context Window (Context Overflow Guard)
    # Ước lượng token: 2000 tokens cơ bản của prompt + kích thước của log đóng gói
    prompt_tokens_est = 2000
    log_tokens_est = len(batch_enc) // 4
    overflow_res = context_overflow_guard.check(prompt_tokens_est, log_tokens_est)

    if overflow_res["is_overflow"]:
        logger.warning(
            f"[GUARDRAILS] Log volume overflow detected by ContextOverflowGuard! "
            f"Est tokens: {overflow_res['total_tokens']}/{overflow_res['max_allowed']}. Truncating logs..."
        )
        # Giới hạn cứng logs đóng gói ở mức an toàn
        batch_enc = batch_enc[:4000] + "\n... [TRUNCATED DUE TO CONTEXT OVERFLOW]"

    if trace.enabled():
        trace.add(
            "guardrails",
            overflow=dict(overflow_res),
            truncated=bool(overflow_res.get("is_overflow")),
            encapsulated_chars_final=len(batch_enc),
        )

    # ── CỜ TẤN CÔNG NHẮM VÀO LLM — THEO TỪNG LOG, KHÔNG THEO CẢ LÔ ──
    #
    # HAI LỖI ĐÃ VÁ Ở ĐÂY.
    #
    # (1) SAI HỌ CHỮ KÝ. Bản trước đọc `injection_detected`, mà cờ đó gộp cả chữ ký tấn
    #     công WEB (`UNION SELECT`, `<script>`, `; exec`). Một câu SQLi dạng chữ vì thế bị
    #     coi là tấn công vào LLM và bị ép quy kết sang AML.T0051 thay vì T1190. Nay đọc
    #     `llm_attack_detected` — cờ chỉ bật với chữ ký nhắm vào LLM.
    #
    # (2) SAI PHẠM VI. Bản trước dùng `any(...)` trên CẢ LÔ 10 log, nên một payload tiêm
    #     nhiễm làm 9 log còn lại cùng mất ngữ cảnh và cùng bị ép nhãn. Nay giữ cờ theo
    #     từng log; cờ mức lô chỉ còn để ghi vết, KHÔNG dùng để định tuyến quy kết.
    _res = processed_data.get("individual_results", []) or []
    adv_flags = [
        bool(r.get("llm_attack_detected") or r.get("jailbreak_detected"))
        if isinstance(r, dict)
        else False
        for r in _res
    ]
    if trace.enabled():
        trace.add("guardrails", llm_attack_flags=adv_flags, n_llm_attack=sum(adv_flags))

    return {
        "current_batch_encapsulated": batch_enc,
        "_llm_attack_flags": adv_flags,
        "_guardrails_system_instruction": processed_data["system_instruction"],
        # Giữ khoá cũ cho tương thích, nhưng nay nó CHỈ mang nghĩa "lô có ít nhất một log
        # bị tấn công nhắm vào LLM" và chỉ dùng để ghi vết / hiển thị. Mọi quyết định quy
        # kết phải đọc `_llm_attack_flags` theo đúng chỉ số log.
        "_is_adversarial": any(adv_flags),
    }


def node_rag_context(state: SentinelState) -> dict[str, Any]:
    """
    RAG Context Node: Trích xuất thông tin từ batch log để query RAG.
    """
    logger.info("--- NODE: RAG CONTEXT ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_rag_context")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    # Truyền CẢ LÔ (không phải mỗi log đầu) — xem chú thích lỗi trong build_rag_queries.
    technique_q, context_q = build_rag_queries(state.current_batch_logs or [])

    if not technique_q:
        technique_q = state.narrative_summary or "suspicious network activity"

    if trace.enabled():
        # HAI truy vấn này trước đây KHÔNG được log ở bất kỳ mức nào — không có chúng thì
        # không thể phân biệt "bộ truy xuất tồi" với "truy vấn đưa vào đã rỗng nghĩa".
        trace.add("nodes", rag_context=round(time.time(), 6))
        trace.add("rag", technique_query=technique_q, context_query=context_q)

    # ── LÔ BỊ TẤN CÔNG NHẮM VÀO LLM: BỎ TRUY VẤN 2, KHÔNG BỎ CẢ RAG ──
    #
    # LỖI ĐÃ VÁ. Bản trước `return {"rag_mitre_context": "", ...}` cho cả lô. Ý định đúng
    # (đừng để payload tiêm nhiễm lái kết quả truy xuất) nhưng cách làm phá một bất biến
    # lớn hơn: `node_attack_mapper` suy ra tập mã được phép từ CHÍNH chuỗi này —
    #
    #     _rag_ids_pre = set(_TECHNIQUE_ID_RE.findall(state.rag_mitre_context or ""))
    #     _grounded(x) = not _rag_ids_pre or x in _rag_ids_pre
    #
    # Ngữ cảnh rỗng ⇒ `_rag_ids_pre` rỗng ⇒ `_grounded()` trả True cho MỌI mã. Tức mỗi lô
    # đối kháng là một lô lá chắn neo bằng chứng bị TẮT — đúng những lô cần nó nhất.
    #
    # Chỗ nhiễm độc thật sự chỉ nằm ở TRUY VẤN 2 (mang payload). Truy vấn 1 đã thuần tiếng
    # Anh và tuyệt đối không payload — xem `build_rag_queries`. Nên chỉ cần bỏ truy vấn 2.
    _adv_flags = getattr(state, "_llm_attack_flags", None) or []
    _skip_payload_query = any(_adv_flags)
    if _skip_payload_query:
        logger.info(
            "[RAG CONTEXT] Lô có tấn công nhắm vào LLM -> bỏ truy vấn theo payload, "
            "GIỮ truy vấn kỹ thuật (lá chắn neo bằng chứng vẫn hiệu lực)."
        )
        if trace.enabled():
            trace.add("rag", payload_query_skipped_for_llm_attack=True)

    # ── TRUY VẤN 1 (KỸ THUẬT): thuần tiếng Anh, KHÔNG payload -> ánh xạ MITRE ──
    results = retriever.retrieve(technique_q)
    mitre_context = results.get("mitre_context", "")
    nist_context = results.get("nist_context", "")

    if trace.enabled():
        trace.add(
            "rag",
            technique_cache_hit=bool(results.get("cache_hit")),
            technique_mitre=_trace_rag_hits(results.get("mitre_results")),
            technique_nist=_trace_rag_hits(results.get("nist_results")),
            mitre_context_chars=len(mitre_context),
            nist_context_chars=len(nist_context),
        )

    # ── TRUY VẤN 2 (NGỮ CẢNH): có payload -> bồi thêm ngữ cảnh vận hành ──
    # Chỉ chạy khi log THỰC SỰ có payload và nội dung khác truy vấn kỹ thuật, để không
    # tốn một lượt truy xuất vô ích trên NetFlow thuần (đại đa số lưu lượng).
    if context_q and context_q != technique_q and not _skip_payload_query:
        ctx = retriever.retrieve(context_q)
        if trace.enabled():
            trace.add(
                "rag",
                context_query_ran=True,
                context_cache_hit=bool(ctx.get("cache_hit")),
                context_mitre=_trace_rag_hits(ctx.get("mitre_results")),
            )
        # NỐI THÊM, không thay thế: khối kỹ thuật giữ nguyên thứ hạng của truy vấn thuần
        # EN (đó là khối LLM dùng để chọn technique), khối payload chỉ là phụ lục tham chiếu.
        extra = ctx.get("mitre_context", "")
        if extra and extra not in mitre_context:
            mitre_context = (
                f"{mitre_context}\n\n"
                f"[Ngữ cảnh bổ sung — truy xuất theo NỘI DUNG payload, ưu tiên THẤP HƠN "
                f"phần ánh xạ kỹ thuật ở trên]\n{extra}"
            )

    if trace.enabled():
        trace.add("rag", mitre_context_chars_final=len(mitre_context))

    return {"rag_mitre_context": mitre_context, "rag_nist_context": nist_context}


def _degraded_reason(decision: dict) -> str:
    """Câu giải thích cho analyst khi quyết định KHÔNG có phần lập luận của LLM.

    Chỉ xảy ra ở đường suy biến an toàn (LLM trả JSON hỏng / rỗng). Nói rõ nguyên nhân
    thay vì "No reasoning provided." — analyst cần biết đây là LỖI ĐỊNH DẠNG của model,
    không phải hệ thống đánh giá sự cố là vô hại, và vì sao độ tin cậy = 0.
    """
    err = str(decision.get("error", "") or "")
    if err == "llm_unavailable":
        # Nguyên nhân HẠ TẦNG — tách hẳn khỏi "model trả JSON hỏng". Gộp hai thứ này vào một
        # câu là đẩy analyst đi truy sai hướng (đã xảy ra: thông điệp đổ lỗi max_tokens trong
        # khi máy chủ LLM đơn giản là không chạy).
        return (
            "Máy chủ LLM KHÔNG phản hồi nên Tier-2 chưa từng chạy — đây là sự cố hạ tầng, "
            "không phải model trả lời sai. Hệ thống suy biến an toàn: chuyển người xử lý. "
            "Độ tin cậy 0 phản ánh việc KHÔNG có phán quyết, KHÔNG có nghĩa sự cố vô hại. "
            "Kiểm tra dịch vụ LLM rồi cho chạy lại; Tier-1 vẫn bảo vệ độc lập."
        )
    if err == "parse_failed":
        return (
            "Tác tử AI đã phân tích nhưng model trả về JSON KHÔNG hợp lệ — không trích được "
            "phần lập luận. Hệ thống suy biến an toàn: chuyển sự cố cho người xử lý thay vì "
            "tự quyết. Độ tin cậy 0 phản ánh việc KHÔNG có phán quyết hợp lệ, KHÔNG có nghĩa "
            "là sự cố vô hại. Xem LOG THÔ bên dưới để phân tích thủ công."
        )
    if err:
        return (
            f"Không có lập luận của tác tử AI (lỗi: {err}). Hệ thống suy biến an toàn: chuyển "
            f"người xử lý. Xem LOG THÔ bên dưới."
        )
    return (
        "Model không trả về phần lập luận cho quyết định này. Chuyển người xử lý để đảm bảo "
        "an toàn. Xem LOG THÔ bên dưới."
    )


def node_llm_triage(state: SentinelState) -> dict[str, Any]:
    """
    LLM Triage Node: Phân tích toàn bộ cụm log (Incident-Level) và đưa ra 1 quyết định duy nhất.
    """
    logger.info("--- NODE: LLM TRIAGE ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_llm_triage")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if trace.enabled():
        trace.add("nodes", llm_triage=round(time.time(), 6))

    # Query Long-Term Threat Memory cho source IPs trong batch
    threat_context_parts = []
    seen_ips = set()
    for log in state.current_batch_logs:
        src_ip = log.get("Source IP") or log.get("src_ip", "")
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            entity = threat_memory.is_known_entity(src_ip)
            if entity:
                threat_context_parts.append(
                    f"⚠️ IP {src_ip} is a KNOWN INTERNAL ENTITY "
                    f"({entity['entity_type']}: {entity['description']}). "
                    f"Consider as LEGITIMATE traffic unless proven otherwise."
                )
            ip_context = threat_memory.get_context_for_prompt(src_ip)
            if ip_context:
                threat_context_parts.append(ip_context)

    threat_memory_context = "\n".join(threat_context_parts)

    if trace.enabled():
        # LỖI ĐÃ SỬA (2026-07-28): chuỗi này từng được TÍNH ở đây, cất vào state — rồi thôi.
        # `build_triage_prompt()` chỉ nhận (log_data, rag_context), còn
        # `SentinelState.get_memory_for_prompt()` thì KHÔNG có nơi nào gọi. Nghĩa là Bộ nhớ
        # Đe doạ dài hạn chưa bao giờ tới được LLM, dù đó là đóng góp chính của RQ3. Nay đã
        # truyền xuống prompt, nên cờ dưới đây phản ánh SỰ THẬT thay vì hằng số False.
        trace.add(
            "threat_memory",
            ips_queried=sorted(seen_ips)[:50],
            hits=len(threat_context_parts),
            context_chars=len(threat_memory_context),
            injected_into_prompt=bool(threat_memory_context.strip()),
        )

    # Đóng gói Raw Logs (kết hợp với Guardrails Encapsulation)
    raw_logs_str = state.current_batch_encapsulated
    if not raw_logs_str:
        emergency_enc = DelimitedDataEncapsulator()
        raw_content = "\n".join([str(log) for log in state.current_batch_logs])
        raw_logs_str = emergency_enc.encapsulate(raw_content)

    # Xây dựng Prompt (inject Guardrails system_instruction vào LLM)
    rag_combined = (
        f"MITRE ATT&CK:\n{state.rag_mitre_context}\n\nNIST SP 800-61r2:\n{state.rag_nist_context}"
    )
    # Ghi ra tracer để bộ chấm hậu kiểm dùng CHÍNH định nghĩa mà hệ thống đã dùng lúc chạy,
    # thay vì suy lại từ tên nguồn dataset (hai cách suy sẽ trôi khỏi nhau lúc nào không hay).
    _layer = evidence_layer_of(state.current_batch_logs)
    if trace.enabled():
        trace.add("batch", evidence_layer=_layer)
    messages = build_triage_prompt(
        log_data=raw_logs_str,
        rag_context=rag_combined,
        threat_memory_context=threat_memory_context,
        evidence_layer=_layer,
    )

    guardrails_instruction = getattr(state, "_guardrails_system_instruction", "")
    logger.info(f"Guardrails instruction length: {len(guardrails_instruction)}")
    if guardrails_instruction:
        messages[0]["content"] = guardrails_instruction + "\n\n" + messages[0]["content"]

    if state.narrative_summary:
        messages[0]["content"] += f"\n\n=== PREVIOUS CONTEXT ===\n{state.narrative_summary}"

    if trace.enabled():
        # PROMPT ĐẦY ĐỦ. Đây là thứ DUY NHẤT cho phép kiểm chứng hậu kiểm rằng không mẩu
        # nhãn dataset nào (mã T####, 'zero-day-probe', 'grayzone'...) lọt vào đầu vào LLM.
        # sha256 tính trên bản CHƯA cắt nên vẫn đối chiếu được kể cả khi tracer cắt bớt.
        _joined = "\n\n".join(str(m.get("content", "")) for m in messages)
        trace.add(
            "llm",
            prompt=[{"role": m.get("role", ""), "content": m.get("content", "")} for m in messages],
            prompt_chars=len(_joined),
            prompt_sha256=hashlib.sha256(_joined.encode("utf-8", "replace")).hexdigest(),
        )

    decision_json = {}
    _feature_log = state.current_batch_logs[0] if state.current_batch_logs else {}
    _cache_layer = "exact"
    # Prompt nay CÓ chứa tiền sử IP, nên rổ cache lớp-2 phải tách theo "đã có tiền sử hay
    # chưa" — nếu không, verdict của một IP sạch sẽ được tái dùng cho kẻ tái phạm và tính
    # năng vừa bật coi như vô hiệu. Xem `ExactMatchResponseCache._history_token`.
    _has_history = bool(threat_memory_context.strip())
    cached_decision = response_cache.get(raw_logs_str)
    if not cached_decision:
        # Lớp 2 — gộp theo ĐẶC TRƯNG: các flow cùng bản chất (khác mỗi IP/timestamp, vd
        # hàng trăm DAPT nền benign) dùng chung 1 verdict -> KHÔNG tốn 1 call LLM mỗi cái.
        cached_decision = response_cache.get_by_features(_feature_log, has_history=_has_history)
        _cache_layer = "feature"
    if cached_decision:
        validated_decision = cached_decision
        decision_json = cached_decision
        raw_response = '{"status": "from_cache"}'
        latency_sec = 0.001
        logger.info("[NODE LLM] Trả về quyết định từ Response Cache (Bypass LLM)")
        if trace.enabled():
            # Trước đây chỉ suy được cache-hit qua `latency_sec == 0.001`, và KHÔNG biết
            # trúng lớp nào. Phân biệt exact/feature mới trả lời được "cache gộp theo đặc
            # trưng có thực sự đóng góp không, hay chỉ là trùng khớp nguyên văn".
            trace.add("llm", cache_hit=True, cache_layer=_cache_layer, latency_sec=latency_sec)
    else:
        start_time = time.time()
        # Suy biến có kiểm soát (graceful degradation): nếu LLM cục bộ chết/không kết nối
        # được (connection refused, timeout sau retry), KHÔNG để vỡ đồ thị — chuyển AWAIT_HITL
        # an toàn. Tier-1 (xác định) vẫn bảo vệ độc lập.
        llm_unavailable_err = ""
        try:
            # response_format=json_schema -> server ép JSON hợp lệ (hết "parse lỗi"/prose) và
            # reasoning bám tiếng Việt; max_tokens rộng để JSON reasoning dài KHÔNG bị cắt cụt.
            raw_response = llm_client.invoke(
                messages=messages,
                temperature=0.1,
                response_format=DECISION_JSON_SCHEMA,
                max_tokens=1536,
            )
        except Exception as e:
            logger.error(
                f"[LLM UNAVAILABLE] Tier-2 (LLM) call thất bại ({e}). Suy biến an toàn -> AWAIT_HITL; "
                f"Tier-1 vẫn bảo vệ độc lập."
            )
            raw_response = ""
            llm_unavailable_err = str(e) or e.__class__.__name__
        end_time = time.time()
        latency_sec = end_time - start_time

        if llm_unavailable_err:
            # KHÔNG parse chuỗi rỗng. LỖI ĐÃ SỬA: trước đây nhánh này rơi thẳng vào
            # `parse_llm_response("")`, chạy hết cascade salvage rồi trả thông điệp mặc định
            # đổ lỗi cho "output bị cắt cụt theo max_tokens hoặc sai định dạng". Thực tế máy
            # chủ LLM không phản hồi — không có output nào để mà cắt cụt. Đo được ngày
            # 2026-08-03: container restart, 10 lần `APIConnectionError`, 3 bản ghi
            # AWAIT_HITL mang lý do sai khiến analyst đi truy một vấn đề không tồn tại.
            decision_json = {
                "action": "AWAIT_HITL",
                "confidence": 0.0,
                "reasoning": (
                    f"⚠️ Máy chủ LLM không phản hồi ({llm_unavailable_err}). Đây là sự cố "
                    "HẠ TẦNG, không phải mô hình trả lời sai. Tự động chuyển AWAIT_HITL để "
                    "người xác minh; Tier-1 (xác định) vẫn bảo vệ độc lập."
                ),
                "error": "llm_unavailable",
            }
        else:
            # Parse JSON an toàn
            decision_json = llm_client.parse_llm_response(raw_response)

        if trace.enabled():
            trace.add(
                "llm",
                cache_hit=False,
                cache_layer="",
                latency_sec=round(latency_sec, 4),
                raw_response=raw_response,
                raw_response_chars=len(raw_response),
                parsed=decision_json if isinstance(decision_json, dict) else str(decision_json),
            )

        if trace.enabled():
            trace.add("validator", pre=_trace_verdict(decision_json))

        # 2. CHẠY QUYẾT ĐỊNH QUA LLM DECISION VALIDATOR (Enforce Enum, Shield critical, Sanitize reasoning)
        validated_decision = decision_validator.validate_decision(decision_json)

        if trace.enabled():
            trace.add("validator", post_validate=_trace_verdict(validated_decision))

        # 2b. LÁ CHẮN BẤT ĐỒNG TIER-1/TIER-2 (chống social-engineering ngữ nghĩa):
        # Nếu Tier-1 (xác định) coi luồng là tấn công nhưng LLM hạ cấp xuống bỏ qua,
        # buộc AWAIT_HITL — Tier-1 không thể bị "nói chuyện" hạ cấp như LLM.
        tier1_flagged_attack = any(
            log.get("tier1_action") in ("BLOCK_IP", "ESCALATE", "AWAIT_HITL", "ALERT")
            or float(log.get("tier1_score", 0) or 0) >= 30
            for log in state.current_batch_logs
        )
        validated_decision = decision_validator.enforce_tier_consensus(
            validated_decision, tier1_flagged_attack
        )

        if trace.enabled():
            trace.add(
                "validator",
                tier1_flagged_attack=tier1_flagged_attack,
                post_consensus=_trace_verdict(validated_decision),
            )

        # LỖI ĐÃ SỬA — cache CẢ `AWAIT_HITL`.
        #
        # Bản trước cố ý BỎ QUA AWAIT_HITL với lý do "mỗi ca cần người xem luôn tươi". Lập
        # luận đó sai về hệ quả: phiếu HITL cho IP đó ĐÃ được tạo ngay ở node bên dưới, nên
        # gọi lại LLM không cho analyst dữ liệu tươi hơn — nó tạo THÊM MỘT PHIẾU TRÙNG cho
        # đúng cùng một sự việc. Đó chính là "mệt mỏi cảnh báo" mà luận văn mở đầu bằng.
        #
        # Đo được trên ba lượt chạy luồng demo (2026-07-28): ở lượt KHÔNG reset, 163/338 lô
        # Tier-2 (48%) là IP ĐÃ phán quyết ở lượt trước, và 151/163 (93%) trong số đó đã
        # nhận AWAIT_HITL. Mỗi lô như vậy tốn thêm một lượt suy luận ~22 s để ra đúng kết
        # luận cũ. Cache lại là cách duy nhất cắt vòng lặp đó mà không mất phiếu HITL nào.
        response_cache.set(raw_logs_str, validated_decision)
        response_cache.set_by_features(_feature_log, validated_decision, has_history=_has_history)

    action = validated_decision.get("action", "AWAIT_HITL")
    confidence = validated_decision.get("confidence", 0.0)

    # ── CHÍNH SÁCH ĐỘ-TIN-CẬY THỐNG NHẤT (chung Cổng ML + LLM) ────────────────────
    # Confidence LÁI action thay vì để LLM tự chọn (sửa lỗi "0.75 + T1571 chung chung -> BLOCK").
    #   LLM cho là ĐE DOẠ (BLOCK_IP/ALERT) -> map theo ngưỡng: >=0.85 BLOCK · 0.65–0.85 ALERT ·
    #     <0.65 AWAIT_HITL (không chắc -> người).  DROP/LOG (sạch) và AWAIT_HITL (LLM tự thấy
    #   không chắc) GIỮ NGUYÊN. Chạy SAU validate + enforce_tier_consensus + shield (vẫn ưu tiên).
    # QUAN TRỌNG: nếu shield critical-asset đã hạ BLOCK->ALERT thì KHÔNG remap (tránh đẩy ngược
    # ALERT->BLOCK, phá bảo vệ hạ tầng).
    if action in ("BLOCK_IP", "ALERT") and not validated_decision.get("_critical_shield"):
        # Bước banding này trước đây KHÔNG có một dòng log nào, nên chuyển đổi
        # "LLM nói BLOCK -> chính sách hạ xuống ALERT" là hoàn toàn vô hình sau khi chạy.
        if trace.enabled():
            trace.add("policy", action_before=action, confidence=float(confidence or 0.0))
        action = decision_policy.classify_llm(is_threat=True, confidence=float(confidence or 0.0))
        validated_decision["action"] = action
        if action == "AWAIT_HITL":
            validated_decision["hitl_reason"] = "low_confidence"
        if trace.enabled():
            trace.add("policy", action_after=action, remapped=True)
    elif trace.enabled():
        trace.add(
            "policy",
            action_before=action,
            action_after=action,
            confidence=float(confidence or 0.0),
            remapped=False,
            skipped_critical_shield=bool(validated_decision.get("_critical_shield")),
        )

    # MỌI đường dẫn tới AWAIT_HITL phải mang MỘT mã lý do máy đọc được (xem
    # `decision_policy.HITL_REASONS`). Không có mã thì hàng đợi HITL chỉ là một đống việc
    # không phân loại được, và không thống kê được "hệ chuyển người vì lý do gì".
    # Đặt ở ĐÂY, sau khi action đã chốt, để bắt cả hai đường còn lại: mô hình TỰ chọn
    # AWAIT_HITL, và suy biến an toàn khi không đọc được phản hồi.
    if action == "AWAIT_HITL" and not validated_decision.get("hitl_reason"):
        _err = str(validated_decision.get("error") or "")
        if _err == "llm_unavailable":
            # Máy chủ không phản hồi — sự cố VẬN HÀNH. Tách khỏi "model trả JSON hỏng" vì
            # hai thứ này cần hai cách sửa khác hẳn nhau (bật lại dịch vụ vs. sửa prompt).
            validated_decision["hitl_reason"] = "llm_unavailable"
        elif _err in ("parse_failed", "parse_salvaged"):
            validated_decision["hitl_reason"] = "llm_output_unreadable"
        else:
            validated_decision["hitl_reason"] = "llm_abstained"
    if trace.enabled():
        if validated_decision.get("hitl_reason"):
            trace.add("policy", hitl_reason=validated_decision["hitl_reason"])

    # Khi LLM trả JSON hỏng, parse_llm_response suy biến an toàn về AWAIT_HITL và KHÔNG có
    # khoá 'reasoning'. Mặc định cũ ("No reasoning provided.") khiến Dashboard trông như
    # agent im lặng/hỏng, trong khi thực tế là: agent ĐÃ chạy, LLM ĐÃ trả lời, nhưng câu
    # trả lời sai định dạng -> chuyển người xử lý. Nói thẳng điều đó cho analyst.
    reasoning = validated_decision.get("reasoning") or _degraded_reason(validated_decision)
    new_iocs = validated_decision.get("extracted_iocs", [])

    # Ghi nhận vào MLflow (Tracking)
    try:
        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
        mlflow.set_experiment("Sentinel_Reasoning_Latency")
        with mlflow.start_run(run_name=f"Triage_Cycle_{state.cycle_count}", nested=True):
            mlflow.log_metric("reasoning_latency_sec", latency_sec)
            mlflow.log_metric("confidence_score", confidence)
            mlflow.log_param("action_taken", action)
            mlflow.log_param("batch_size", len(state.current_batch_logs))
    except Exception as e:
        logger.warning(f"MLflow tracking failed: {e}")

    # Target để THỰC THI (block/alert) LUÔN lấy từ Source IP của batch HIỆN TẠI, KHÔNG
    # lấy từ extracted_iocs của quyết định: khi Response Cache HIT trên một IP KHÁC có
    # cùng vân log (cùng payload/flow), IOC trong cache là IP CŨ -> nếu dùng làm target
    # sẽ CHẶN NHẦM IP cũ. IOC chỉ là metadata làm giàu, không phải mục tiêu thực thi.
    target = "UNKNOWN_TARGET"
    if state.current_batch_logs:
        log_entry = state.current_batch_logs[0]
        target = log_entry.get("Source IP") or log_entry.get("src_ip") or "UNKNOWN_TARGET"

    # Chỉ log lớp-ứng-dụng THUẦN payload (không có Source IP flow) mới rơi về IOC trích xuất.
    if target == "UNKNOWN_TARGET" and new_iocs and isinstance(new_iocs, list) and len(new_iocs) > 0:
        target = new_iocs[0].get("value", "UNKNOWN_TARGET")

    # Nếu verdict đến TỪ CACHE và lô hiện tại là một IP khác, nói rõ xuất xứ trong phần lập
    # luận — nếu không, nhật ký kiểm toán sẽ khẳng định một điều về IP mà LLM chưa từng nói.
    if cached_decision:
        reasoning = _annotate_reused_verdict(reasoning, validated_decision, target)
        if trace.enabled():
            trace.add("llm", reasoning_reused_from_other_ip="[PHÁN QUYẾT TÁI SỬ DỤNG" in reasoning)

    decision_entry = {
        "action": action,
        "confidence": confidence,
        "reasoning": reasoning,
        "target": target,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "cycle_count": state.cycle_count + 1,
        # Cờ tình trạng parse LLM (parse_failed/parse_salvaged) — để attack_mapper KHÔNG
        # dập một technique "tự tin" lên một triage rỗng/hỏng (tránh MITRE gây hiểu lầm).
        "error": validated_decision.get("error", ""),
        # Mã lý do chuyển người xử lý (rỗng nếu action không phải AWAIT_HITL).
        # `node_attack_mapper` có thể ghi đè khi lá chắn của nó khai hoả sau bước này.
        "hitl_reason": validated_decision.get("hitl_reason", ""),
    }

    new_narrative = f"Last Incident: {action} based on RAG - {validated_decision.get('mitre_technique', 'None')}. Reasoning: {reasoning}"
    # Đã sanitize trong decision_validator, nhưng vẫn bảo vệ kép cho narrative summary
    new_narrative = output_sanitizer.sanitize(new_narrative)

    # 3. GHI LOG KIỂM TOÁN (Audit Trail)
    # Lấy thông số từ Tier-1 log để đối chiếu trong ablation study
    t1_score = 0
    t1_action = "LOG"
    if state.current_batch_logs:
        first_log = state.current_batch_logs[0]
        t1_score = first_log.get("tier1_score", 0)
        t1_action = first_log.get("tier1_action", "LOG")

    audit_event = {
        "event_type": "LLM_TRIAGE_DECISION",
        "source_ip": target,
        "tier1_score": t1_score,
        "tier1_action": t1_action,
        "guardrail_injected": validated_decision.get("_injection_detected", False)
        or decision_json.get("_injection_detected", False),
        "agent_decision": action,
        "agent_reasoning": reasoning,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "hitl_approved": False if action == "AWAIT_HITL" else None,
        "hitl_reason": validated_decision.get("hitl_reason", ""),
        "latency_ms": latency_sec * 1000,
        "metadata": {
            "total_logs_in_batch": len(state.current_batch_logs),
            "cycle_count": state.cycle_count,
            "raw_decision": decision_json,
        },
    }
    audit_logger.log_event(audit_event)

    # Record incident logic moved to node_action_executor & node_human_in_the_loop

    return {
        "decisions": [decision_entry],
        "extracted_iocs": new_iocs,
        "narrative_summary": new_narrative,
        "threat_memory_context": threat_memory_context,
        "cycle_count": state.cycle_count + 1,
    }


def node_attack_mapper(state: SentinelState) -> dict[str, Any]:
    """
    ATT&CK Mapper Node: chạy SAU node_llm_triage cho các quyết định tin cậy cao.

    Biến `mitre_technique` free-text của triage thành bản đồ MITRE ATT&CK CÓ CẤU
    TRÚC (tactic/technique/sub-technique/URL/mapping_confidence/recommended_response),
    bồi đắp vào quyết định mới nhất để node HITL / Action Executor dùng được.

    TÁI DÙNG hạ tầng sẵn có: `retriever` (DualRetriever) + `llm_client`. KHÔNG gọi
    LLM thêm trong đường XÁC ĐỊNH (web attack phổ biến) -> giữ độ trễ thấp.
    """
    logger.info("--- NODE: ATT&CK MAPPER ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_attack_mapper")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if trace.enabled():
        trace.add("nodes", attack_mapper=round(time.time(), 6))

    if not state.decisions:
        if trace.enabled():
            trace.add("attack_mapper", ran=False, skipped="no_decisions")
        return {}

    decision = dict(state.decisions[-1])  # copy để bồi đắp, giữ action/target/confidence

    # GATE: nếu triage KHÔNG đọc được (parse_failed) thì KHÔNG dập một MITRE "tự tin" lên một
    # triage rỗng — sẽ gây hiểu lầm (vd T1548.003 "Sudo Caching" trên một flow mạng). Để
    # technique NEUTRAL, giữ reasoning trung thực; con người xác minh (đã AWAIT_HITL).
    # `llm_unavailable` phải nằm CÙNG cổng này: triage khi máy chủ LLM chết cũng rỗng y hệt
    # lúc JSON hỏng, nên dập một mã MITRE lên nó cũng gây hiểu lầm y hệt.
    _triage_err = str(decision.get("error") or "")
    if _triage_err in ("parse_failed", "llm_unavailable"):
        logger.warning(
            f"[ATT&CK MAPPER] Bỏ qua ánh xạ vì triage {_triage_err} — tránh MITRE gây hiểu lầm."
        )
        if trace.enabled():
            trace.add(
                "attack_mapper",
                ran=False,
                skipped=_triage_err,
                mapping_status=f"unmapped_{_triage_err}",
            )
        decision.update(
            {
                "mitre_technique": "N/A — chưa phân loại (LLM parse lỗi)",
                "mitre_technique_id": "",
                "mitre_tactic": "",
                "mitre_tactic_id": "",
                "mitre_subtechnique": "",
                "mitre_subtechnique_id": "",
                "mitre_url": "",
                "mapping_confidence": 0.0,
                "mapping_status": "unmapped_parse_failed",
                "recommended_response": "Chờ người xác minh (AWAIT_HITL).",
            }
        )
        return {"decisions": [decision]}

    # Kỹ thuật LLM tự suy (GIỮ LẠI trước khi mapper chuẩn hoá). Nếu triage đã nêu 1
    # technique CỤ THỂ (Txxxx / AML.Txxxx) thì ƯU TIÊN giữ nó cho badge — để badge KHỚP
    # với phần reasoning người xem đọc, và tránh mọi alert bị gom hết về AML.T0051 chỉ vì
    # tín hiệu injection lọt trong tier1_reasons. Chỉ dùng kết quả mapper khi LLM để N/A.
    import re as _re

    _llm_tech_raw = str(decision.get("mitre_technique", "")).strip()
    _llm_tech_m = _re.search(r"\b(AML\.T\d{4}|T\d{4}(?:\.\d{3})?)\b", _llm_tech_raw, re.IGNORECASE)

    # Dựng đầu vào mapper từ triage + batch log thật.
    first_log = state.current_batch_logs[0] if state.current_batch_logs else {}
    payload = (str(first_log.get("message", "")) + " " + str(first_log.get("payload", ""))).strip()
    # Tín hiệu loại tấn công: free-text mitre_technique + reasoning + tier1_reasons.
    type_hint = " ".join(
        [
            str(decision.get("mitre_technique", "")),
            str(decision.get("reasoning", "")),
            " ".join(str(r) for r in (first_log.get("tier1_reasons") or [])[:3]),
        ]
    ).strip()

    # Ép `type_hint` về prompt_injection CHỈ khi chính log đang xét bị tấn công nhắm vào
    # LLM. Bản trước dùng cờ mức LÔ (`any()` trên 10 log), nên một payload tiêm nhiễm lẫn
    # trong lô đủ để mọi log còn lại bị gán nhãn ATLAS — kể cả một SQLi thật đáng ra phải
    # là T1190. `first_log` là log mapper đang xét, nên lấy cờ ở đúng chỉ số 0.
    _adv_flags_m = getattr(state, "_llm_attack_flags", None) or []
    if _adv_flags_m and _adv_flags_m[0]:
        type_hint = "prompt_injection"

    mapper_input = AttackMapperInput(
        attack_type=type_hint,
        confidence=float(decision.get("confidence", 0.0) or 0.0),
        payload=payload,
        features=first_log if isinstance(first_log, dict) else {},
    )

    try:
        mapping = map_attack(mapper_input, retriever=retriever, llm=llm_client)
    except Exception as e:
        # Suy biến an toàn: mapping hỏng KHÔNG được phá đồ thị — giữ quyết định gốc.
        logger.error(f"[ATT&CK MAPPER] Lỗi ánh xạ ({e}). Giữ nguyên quyết định triage.")
        return {}

    # _ATTRIBUTION_MUST_BE_DETERMINISTIC_AND_GROUNDED
    #
    # LỖI ĐÃ VÁ (đo được, không phải suy đoán). Bản trước cho kỹ thuật LLM TỰ KHAI thắng bộ
    # ánh xạ RRF bất cứ khi nào nó nêu một mã hợp lệ, vì mục đích hiển thị: "badge phải khớp
    # reasoning". Nhưng `mitre_technique_id` không chỉ để hiển thị — nó là ĐẦU RA QUY KẾT của
    # hệ, thứ được chấm điểm và ghi vào vết kiểm toán. Hậu quả trên 300 mẫu CSIC:
    #
    #     rrf (llm=None, chỉ RRF)       exact 67,33%   tactic 67,33%
    #     e2e (toàn tuyến, LLM thắng)   exact  2,33%   tactic 24,33%
    #
    # `tactic` chỉ tụt một nửa vì nó vẫn lấy từ `mapping` — đúng theo cách mã cũ quy định.
    # Nói cách khác: RAG lấy ĐÚNG tài liệu (trần độ phủ KB = 100%), RRF chọn ĐÚNG kỹ thuật,
    # rồi free-text của LLM ghi đè lên ở bước cuối.
    #
    # Nặng hơn: lá chắn neo bằng chứng phía dưới CHỈ nằm ở nhánh "LLM trả N/A". Khi LLM CÓ
    # nêu mã, mã đó đi thẳng ra quyết định mà không hề đối chiếu với tài liệu RAG của lô —
    # chỉ TÊN được kiểm. Một mã bịa hoàn toàn vẫn lọt. Lá chắn canh đúng cái cửa mà kẻ gian
    # không đi qua.
    #
    # NGUYÊN TẮC MỚI: quy kết là việc của bộ ánh xạ tất định; mọi mã — dù của mapper hay của
    # LLM — đều phải CÓ NEO trong `rag_mitre_context` của chính lô này. Free-text của LLM vẫn
    # được giữ nguyên ở `llm_claimed_technique` để trang hiển thị đối chiếu được hai nguồn,
    # tức vẫn đạt mục đích ban đầu mà không đánh đổi tính đúng đắn.
    #
    # Neo rỗng (lô không có ngữ cảnh RAG) thì không kiểm được -> tin bộ ánh xạ, như bản cũ.
    _rag_ids_pre = set(_TECHNIQUE_ID_RE.findall(state.rag_mitre_context or ""))
    _mapper_id = mapping.mitre_technique_id or ""
    _llm_id = _llm_tech_m.group(1).upper() if _llm_tech_m and _llm_tech_raw.upper() != "N/A" else ""

    def _grounded(tech_id: str, from_curated: bool = False) -> bool:
        """Không có ngữ cảnh RAG thì không có gì để đối chiếu — không kết tội được.

        NGOẠI LỆ ATLAS, VÀ VÌ SAO NÓ PHẢI HẸP. Kho tri thức hiện có **0 mục `AML.*`**
        (toàn bộ 433 mục là ATT&CK Enterprise), và `_TECHNIQUE_ID_RE` cũng chỉ khớp
        `T\\d{4}`. Nên một mã ATLAS hợp lệ như `AML.T0051` (Prompt Injection) KHÔNG BAO GIỜ
        neo được vào RAG — không phải vì nó sai, mà vì KB không chứa khung đó.

        Bản trước xử lý bằng cách cho MỌI mã bắt đầu `AML.` đi qua. Quá rộng: regex bóc mã
        của LLM là `(AML\\.T\\d{4}|T\\d{4}...)`, nên model tự khai `AML.T9999` cũng lọt
        thẳng ra quyết định — đúng thứ lá chắn sinh ra để chặn.

        Nay ngoại lệ chỉ áp cho mã đến từ **bảng ánh xạ thủ công tất định**
        (`WEB_ATTACK_MAP`), là nguồn do con người soạn và kiểm được. Free-text của LLM
        KHÔNG được hưởng ngoại lệ này. Đường `_from_triage_anchor` và đường RRF đều không
        thể sinh mã `AML.*` (một bên regex chỉ bắt `T\\d{4}`, một bên tra KB không có ATLAS),
        nên `from_curated` là điều kiện đủ chặt.
        """
        if not tech_id:
            return False
        if from_curated and tech_id.upper().startswith("AML."):
            return True
        return not _rag_ids_pre or tech_id in _rag_ids_pre

    _name_verified = True
    _rejected_id = ""
    # Ứng viên đã bị loại vì KHÔNG neo được. Lá chắn phía dưới cần biết để còn ghi đúng
    # `mapping_status` + lý do vào vết kiểm toán — nếu chỉ lặng lẽ trả "" thì kết quả đúng
    # nhưng nhật ký mất dấu VÌ SAO nó thành N/A.
    _ungrounded_candidate = ""
    if _grounded(_mapper_id, from_curated=True):
        # Đường chính: bộ ánh xạ tất định thắng. Đây là cấu hình đo được 67,33%.
        _final_tech = f"{_mapper_id} - {mapping.mitre_technique}".strip(" -")
        _final_tech_id = _mapper_id
        if _llm_id and _llm_id != _mapper_id:
            _rejected_id = _llm_id
    elif _grounded(_llm_id):
        # Mapper không neo được nhưng LLM nêu một mã CÓ trong tài liệu RAG của lô -> nhận,
        # vì nó vẫn truy nguyên được về bằng chứng. TÊN phải khớp nguồn sự thật cục bộ:
        # trước đây nhãn free-text đi thẳng ra dashboard nên lọt ca "đúng id, sai tên"
        # (T1087 gắn nhãn "Network Service Discovery" — thực ra là T1046).
        _final_tech, _name_verified = verify_technique_label(_llm_id, _llm_tech_raw)
        _final_tech_id = _llm_id
        _rejected_id = _mapper_id
    else:
        # Không nguồn nào neo được -> giữ "không biết", để lá chắn tự-chém phía dưới ép
        # AWAIT_HITL với đúng lý do `technique_unmappable`.
        #
        # Đo trên lượt chạy sống 281 lô: lá chắn khai hoả 96 lần, 93 lần do MAPPER đoán từ
        # TỪ KHOÁ (T1590.005, T1527, T1595, T1056.003...) khi LLM đã đúng đắn trả N/A. Nếu
        # lấy tỉ lệ "không neo" làm chỉ số ảo giác của LLM thì SAI ĐỊA CHỈ hoàn toàn.
        _final_tech, _final_tech_id = "N/A", ""
        _rejected_id = _mapper_id or _llm_id
        _ungrounded_candidate = _rejected_id

    if _rejected_id:
        logger.info(
            f"[ATT&CK MAPPER] Kỹ thuật '{_rejected_id}' bị loại (không neo trong tài liệu RAG "
            f"của lô, hoặc thua bộ ánh xạ tất định). Chốt: '{_final_tech_id or 'N/A'}'."
        )
        if trace.enabled():
            trace.add(
                "attack_mapper",
                mapper_guess_suppressed=not _final_tech_id,
                mapper_guess_rejected=_rejected_id,
                llm_technique_rejected=_llm_id if _llm_id and _llm_id != _final_tech_id else "",
                rag_grounded_ids=sorted(_rag_ids_pre)[:12],
            )

    # URL phải trỏ ĐÚNG technique đang hiển thị: khi badge lấy id của LLM (khác id mapper),
    # dùng lại mitre_url của mapper sẽ link sang một kỹ thuật KHÁC.
    _final_url = (
        mapping.mitre_url
        if _final_tech_id == mapping.mitre_technique_id
        else build_mitre_url(_final_tech_id)
    )

    # Bồi đắp các trường có cấu trúc vào quyết định (free-text được thay bằng chuẩn hoá).
    decision.update(
        {
            "mitre_technique": _final_tech,
            "mitre_technique_name_verified": _name_verified,
            # Kỹ thuật do MODEL tự khai, giữ NGUYÊN VĂN và TÁCH RIÊNG khỏi đầu ra quy kết.
            # Trang hiển thị đối chiếu được hai nguồn (bộ ánh xạ vs model) mà không để lời
            # tự khai lọt vào trường được chấm điểm và ghi vết kiểm toán.
            "llm_claimed_technique": _llm_tech_raw,
            "mitre_tactic": mapping.mitre_tactic,
            "mitre_tactic_id": mapping.mitre_tactic_id,
            "mitre_technique_id": _final_tech_id,
            "mitre_subtechnique": mapping.mitre_subtechnique or "",
            "mitre_subtechnique_id": mapping.mitre_subtechnique_id or "",
            "mitre_url": _final_url,
            "mapping_confidence": mapping.mapping_confidence,
            "mapping_status": mapping.mapping_status,
            "recommended_response": mapping.recommended_response,
        }
    )

    logger.info(
        f"[ATT&CK MAPPER] {mapping.mitre_technique_id} ({mapping.mitre_tactic}) "
        f"status={mapping.mapping_status} conf={mapping.mapping_confidence:.2f}"
    )

    if trace.enabled():
        # Node này chạy SAU khi dòng `audit_log` đã được ghi ở node_llm_triage, nên toàn bộ
        # kết quả ánh xạ (kể cả việc nó ÉP action về AWAIT_HITL) không bao giờ tới
        # logs/guardrails_audit.db. Đây là nơi DUY NHẤT ghi lại nó.
        trace.add(
            "attack_mapper",
            ran=True,
            llm_technique_raw=_llm_tech_raw,
            final_technique_id=_final_tech_id,
            name_verified=_name_verified,
            mapper_technique_id=mapping.mitre_technique_id,
            mapper_tactic=mapping.mitre_tactic,
            mapper_tactic_id=mapping.mitre_tactic_id,
            mapping_status=mapping.mapping_status,
            mapping_confidence=round(mapping.mapping_confidence or 0.0, 4),
            action_before=decision.get("action", ""),
        )

    # ── LÁ CHẮN NEO BẰNG CHỨNG: không CHẶN TỰ ĐỘNG bằng kỹ thuật KHÔNG có trong RAG ──
    #
    # Lá chắn cũ (ngay dưới) chỉ hỏi "kỹ thuật này có tồn tại trong kho không?". Nó KHÔNG
    # hỏi "kỹ thuật này có nằm trong những tài liệu vừa truy xuất cho lô này không?". Một
    # mã có thật trong KB nhưng chưa bao giờ được truy xuất vẫn đi lọt với trạng thái
    # `resolved`, dù prompt đã dặn rõ "chọn technique TỪ ngữ cảnh RAG".
    #
    # ĐO ĐƯỢC trên lượt chạy nguội (274 lô): 25 câu trả lời nằm NGOÀI ngữ cảnh RAG, và độ
    # chính xác của chúng là 0/4 trên các lô có nhãn — so với 8/25 khi câu trả lời có neo
    # trong RAG. Đáng lo nhất: 3 trong số đó thành BLOCK_IP TỰ ĐỘNG với confidence
    # 0.93/0.93/0.95. Tức là hệ thống chặn vĩnh viễn một IP dựa trên một kỹ thuật mà bộ
    # truy xuất chưa từng đưa ra — đúng định nghĩa "ảo giác tự tin".
    #
    # THI HÀNH ĐÚNG HỢP ĐỒNG CỦA CHÍNH PROMPT. Prompt đã dặn: "nếu KHÔNG khớp technique nào
    # trong ngữ cảnh RAG thì PHẢI đặt action='AWAIT_HITL' và mitre_technique='N/A'". Đo thật:
    # model chỉ trả 'N/A' 2/136 lần (1,5%) — còn lại nó chọn một kỹ thuật "nghe hợp lý" từ
    # trí nhớ tham số. Lời dặn trong prompt là điều kiện MỀM; ta thi hành nó bằng MÃ.
    #
    # Hạ `mitre_technique` về 'N/A' thay vì để một mã sai nằm lại: nhật ký kiểm toán và giao
    # diện analyst KHÔNG được khẳng định một kỹ thuật mà bằng chứng không đỡ. "Không biết"
    # là câu trả lời đúng và hữu ích hơn một phán đoán sai nghe có vẻ chắc chắn.
    _rag_ids = set(_TECHNIQUE_ID_RE.findall(state.rag_mitre_context or ""))
    # Hai đường vào lá chắn:
    #   (a) một mã đã lọt tới đây nhưng không có trong tài liệu RAG của lô;
    #   (b) khâu quy kết phía trên ĐÃ loại hết ứng viên vì không neo được (_ungrounded_candidate).
    # Thiếu (b) thì kết quả vẫn là N/A nhưng `mapping_status` ở lại "resolved" — vết kiểm toán
    # mất dấu VÌ SAO, và đó đúng là thứ hội đồng sẽ hỏi.
    _is_aml = bool(_final_tech_id) and _final_tech_id.upper().startswith("AML.")
    _ungrounded = (
        bool(_final_tech_id) and not _is_aml and bool(_rag_ids) and _final_tech_id not in _rag_ids
    ) or bool(_ungrounded_candidate)
    _shield_target = _final_tech_id or _ungrounded_candidate
    if trace.enabled():
        trace.add("attack_mapper", technique_grounded_in_rag=not _ungrounded)
    if _ungrounded:
        _was_block = decision.get("action") == "BLOCK_IP"
        logger.warning(
            f"[NEO BẰNG CHỨNG] {_shield_target} KHÔNG có trong ngữ cảnh RAG của lô này — "
            f"đặt kỹ thuật về N/A và chuyển người xử lý (đúng hợp đồng prompt)."
        )
        decision["action"] = "AWAIT_HITL"
        decision["hitl_reason"] = "technique_not_in_rag"
        decision["mitre_technique"] = "N/A"
        decision["mitre_technique_id"] = ""
        decision["mitre_technique_name_verified"] = False
        decision["mapping_status"] = "ungrounded_in_rag"
        decision["mitre_url"] = ""
        # Nói ĐÚNG ai đề xuất: đo được 93/96 ca là do bộ ánh xạ tự suy sau khi LLM đã trả
        # N/A, chỉ 3 ca là do LLM. Ghi "do model đề xuất" cho cả hai là quy sai trách nhiệm
        # trong nhật ký kiểm toán — và nếu ai đó lấy tỉ lệ này làm chỉ số ảo giác của LLM thì
        # con số sẽ sai gấp nhiều lần.
        _who = "model" if (_llm_tech_m and _llm_tech_raw.upper() != "N/A") else "bộ ánh xạ"
        decision["reasoning"] = (
            f"[NEO BẰNG CHỨNG: kỹ thuật {_shield_target} do {_who} đề xuất KHÔNG nằm trong "
            f"tài liệu đã truy xuất cho lô này — hệ thống KHÔNG khẳng định kỹ thuật, chuyển "
            f"người xử lý] {decision.get('reasoning', '')}"
        )
        if trace.enabled():
            trace.add(
                "attack_mapper",
                grounding_shield_fired=True,
                grounding_shield_downgraded_block=_was_block,
                grounding_shield_rejected_technique=_shield_target,
            )

    # LÁ CHẮN BẢO VỆ CHỐNG HALLUCINATION (TỰ CHÉM):
    # Nếu LLM phân tích nhưng mapper không thể khớp với bất kỳ kỹ thuật MITRE nào,
    # hoặc độ tin cậy của việc khớp rất thấp, ép hành động về AWAIT_HITL để con người duyệt.
    if (
        mapping.mapping_status in ("unresolved", "low_confidence", "unmapped_parse_failed")
        or not _final_tech_id
    ):
        logger.warning(
            f"[ATT&CK MAPPER] Dấu hiệu tự chém/không match kỹ thuật rõ ràng "
            f"(status={mapping.mapping_status}). Ép action về AWAIT_HITL."
        )
        if trace.enabled():
            trace.add("attack_mapper", hallucination_shield=True)
        decision["action"] = "AWAIT_HITL"
        decision.setdefault("hitl_reason", "technique_unmappable")
        if "[WARNING]" not in str(decision.get("reasoning", "")):
            decision["reasoning"] = (
                f"[WARNING: Unable to confidently map technique, potential hallucination risk] {decision.get('reasoning', '')}"
            )

    if trace.enabled():
        trace.add("attack_mapper", action_after=decision.get("action", ""))

    return {"decisions": [decision]}


# ── Học "kỹ thuật" (behavioral signature) — không chỉ nhớ IP ─────────────────
# Điểm cho luật hành vi: đủ vượt risk_threshold để Tier-1 CỜ (flag/ESCALATE) IP
# mới cùng ngón đòn, nhưng KHÔNG cao như luật IP (100) để tránh hard-block mù trên
# một heuristic hành vi (an toàn: vẫn PENDING + HITL duyệt trước khi ACTIVE).
BEHAVIORAL_RULE_SCORE = 50

# Chữ ký công cụ tấn công RÕ RÀNG trên User-Agent (an toàn, khái quát hoá tốt —
# bất kỳ IP nào dùng công cụ này đều đáng ngờ). CỐ Ý loại "curl"/"python-requests"
# vì quá phổ biến trong automation hợp lệ → tránh dương-tính-giả.
_TOOL_SIGNATURES = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "hydra",
    "gobuster",
    "dirbuster",
    "dirb",
    "wpscan",
    "nuclei",
    "zgrab",
    "acunetix",
    "havij",
    "metasploit",
    "fuzz",
)

# Token tấn công đặc trưng trên URI (đủ hẹp để không FP diện rộng ở score 50).
_URI_ATTACK_TOKENS = (
    "union select",
    "../../",
    "..\\..\\",
    "/etc/passwd",
    "<script",
    "cmd.exe",
    "/bin/bash",
    "%00",
    "' or '1'='1",
    "exec(",
    "; ls",
    "wget http",
)


def _check_apt_signal(target: str, mitre_technique: str, confidence: float):
    """Kiểm tra tín hiệu APT (persistent-IP / multi-day chain) và ghi indicator.
    KHÔNG record_incident ở đây — nơi gọi đã ghi (raise_alert / _handle_threat_memory_incident)
    nên tránh đếm TRÙNG total_alerts (điều kiện repeat-offender phụ thuộc số này)."""
    if target == "UNKNOWN_TARGET":
        return
    apt_check = threat_memory.check_apt_pattern(target)
    apt_chain = threat_memory.check_apt_chain(target)

    if apt_check and apt_check["is_apt_candidate"]:
        logger.warning(
            f"[APT DETECTION] IP {target} flagged as APT candidate: "
            f"{apt_check['total_incidents']} incidents over {apt_check['days_active']} days"
        )
        threat_memory.record_apt_indicator(
            indicator_type="persistent_ip",
            indicator_value=target,
            confidence=confidence,
            related_ips=target,
            mitre_chain=mitre_technique,
        )
    elif apt_chain.get("is_apt"):
        logger.warning(
            f"[APT DETECTION] IP {target} part of multi-day APT chain: "
            f"{apt_chain['chain_length']} days, phases={apt_chain.get('phases_seen', '')}"
        )
        threat_memory.record_apt_indicator(
            indicator_type="multi_day_chain",
            indicator_value=target,
            confidence=confidence,
            related_ips=target,
            mitre_chain=str(apt_chain.get("phases_seen", ""))[:120],
        )


def _handle_threat_memory_incident(
    target: str, action: str, mitre_technique: str, confidence: float
):
    """Ghi incident (tăng reputation/total_*) rồi kiểm tra APT. Dùng cho BLOCK_IP/AWAIT_HITL.
    Lưu ý: nhánh ALERT KHÔNG dùng hàm này nữa — raise_alert là choke-point ghi ALERT +
    tự leo thang repeat-offender (tránh đếm trùng total_alerts)."""
    if target == "UNKNOWN_TARGET" or action not in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
        return
    threat_memory.record_incident(ip=target, action=action, mitre_technique=mitre_technique)
    _check_apt_signal(target, mitre_technique, confidence)


def _derive_behavioral_rule(log_entry: dict) -> tuple[str, str, int] | None:
    """
    Trích một CHỮ KÝ HÀNH VI an toàn từ log gây ra BLOCK để Tier-1 có thể bắt
    nhanh một IP KHÁC dùng CÙNG kỹ thuật (không chỉ nhớ đúng IP cũ).

    Ưu tiên chữ ký công cụ trên User-Agent (khái quát nhất); fallback token tấn
    công trên URI. Trả `None` nếu không có chữ ký an toàn → chỉ ghi luật IP
    (suy biến nhẹ nhàng). Field trả về LUÔN là nơi token thực sự nằm, để luật
    khớp đúng field của log tương lai. Mọi field/score đều qua FeedbackValidator.
    """
    norm = normalize_log_keys(log_entry)
    ua = str(norm.get("User-Agent", "")).strip()
    uri = str(norm.get("URI", "")).strip()
    ua_l, uri_l = ua.lower(), uri.lower()

    for tool in _TOOL_SIGNATURES:
        if tool in ua_l:
            return ("User-Agent", tool, BEHAVIORAL_RULE_SCORE)
    for tok in _URI_ATTACK_TOKENS:
        if tok in uri_l:
            return ("URI", tok, BEHAVIORAL_RULE_SCORE)
    return None


def _serialize_repr_log(batch_logs: list, target_ip: str) -> str:
    """Chọn LOG THÔ đại diện cho một quyết định (khớp Source IP == target, fallback log
    đầu batch) và tuần tự hoá JSON để đính kèm audit -> Dashboard hiển thị đầu vào thô.
    Suy biến an toàn: batch rỗng / lỗi serialize -> '{}'."""
    import json as _json

    repr_log = next(
        (
            lg
            for lg in (batch_logs or [])
            if str(normalize_log_keys(lg).get("Source IP", "")) == target_ip
        ),
        ((batch_logs or [{}])[0] if batch_logs else {}),
    )
    try:
        return _json.dumps(repr_log, ensure_ascii=False, default=str)
    except Exception:
        return "{}"


def node_action_executor(state: SentinelState) -> dict[str, Any]:
    """
    Action Executor Node: Xử lý các action BLOCK_IP hoặc ALERT.
    """
    logger.info("--- NODE: ACTION EXECUTOR ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_action_executor")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if trace.enabled():
        trace.add("nodes", action_executor=round(time.time(), 6))

    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "UNKNOWN")

    mitre = latest_decision.get("mitre_technique", "N/A")
    conf = latest_decision.get("confidence", 0.0)
    raw_reasoning = latest_decision.get("reasoning") or _degraded_reason(latest_decision)
    safe_reasoning = output_sanitizer.sanitize(raw_reasoning)
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2%}] {safe_reasoning}"

    # LOG THÔ đại diện (khớp target, fallback log đầu batch) -> đính kèm audit để Dashboard
    # hiển thị "cái gì đã vào Tier-1/LLM". Đây là đặc trưng luồng ĐÃ LOẠI nhãn (label leak).
    raw_log_json = _serialize_repr_log(
        state.current_batch_logs, str(latest_decision.get("target", ""))
    )

    target = latest_decision.get("target", "UNKNOWN_TARGET")
    mitre_tech = latest_decision.get("mitre_technique", "")
    confidence = latest_decision.get("confidence", 0.0)

    # Cờ: block ĐÃ thực thi bên trong raise_alert (repeat-offender) -> KHÔNG chặn lại ở dưới.
    _alert_escalated_block = False

    # ALERT: raise_alert là CHOKE-POINT THỐNG NHẤT (chung với Cổng ML) — ghi ALERT, và nếu IP
    # TÁI PHẠM (đã cảnh báo trước) / known-bad thì TỰ leo thang -> BLOCK ngay bên trong.
    if action == "ALERT":
        # ALERT của LLM theo classify_llm LUÔN nằm dải [0.65, 0.85) nên vẫn được tính vào
        # bộ đếm tái phạm; truyền tường minh để chính sách nằm ở MỘT chỗ (decision_policy)
        # thay vì phụ thuộc ngầm vào việc dải nào gọi hàm này.
        result_action = raise_alert(
            target,
            formatted_reasoning,
            raw_log=raw_log_json,
            confidence=float(confidence or 0.0),
            tier=TIER_LLM,
        )
        # Tín hiệu APT (persistent-IP / multi-day) — đọc incident vừa ghi, KHÔNG record trùng.
        _check_apt_signal(target, mitre_tech, confidence)
        if result_action == "BLOCK_IP":
            logger.warning(f"[*] Escalate ALERT -> BLOCK_IP for {target} (tái phạm cảnh báo)")
            action = "BLOCK_IP"
            latest_decision["action"] = "BLOCK_IP"
            formatted_reasoning += " [HỆ THỐNG LEO THANG: IP tái phạm cảnh báo -> tự động CHẶN]"
            _alert_escalated_block = True

    if trace.enabled():
        # `raise_alert` có thể TỰ leo thang ALERT -> BLOCK_IP khi IP tái phạm. Chuyển đổi đó
        # chỉ để lại một logger.warning; nếu không ghi ở đây thì hậu kiểm sẽ thấy một lệnh
        # BLOCK "từ trên trời rơi xuống" mà LLM không hề yêu cầu.
        trace.add(
            "execution",
            action_in=str(latest_decision.get("action", "")),
            escalated_alert_to_block=_alert_escalated_block,
            target=target,
        )

    if action == "BLOCK_IP":
        # Ghi incident cho BLOCK_IP TRỰC TIẾP từ LLM. Nếu do leo thang ALERT thì raise_alert đã
        # xử lý reputation/incident -> KHÔNG ghi lại (tránh đếm trùng).
        if not _alert_escalated_block:
            _handle_threat_memory_incident(target, action, mitre_tech, confidence)
            block_ip(
                target,
                formatted_reasoning,
                raw_log=raw_log_json,
                tier=TIER_LLM,
            )

        rule_pattern = target
        rule_source = "ml_triage" if getattr(state, "_ml_bypass", False) else "langgraph_agent"

        # (1) Luật theo IP — "nhớ mặt" kẻ tấn công (chạy qua FeedbackValidator ngầm định)
        FeedbackListener().receive_new_rule(
            "Source IP",
            rule_pattern,
            score=100,
            reason=raw_reasoning,
            source=rule_source,
            status="ACTIVE",
        )

        # (2) Luật theo CHỮ KÝ HÀNH VI — "nhớ ngón đòn": trích chữ ký công cụ/URI từ
        # log gây ra block để Tier-1 CỜ nhanh một IP KHÁC dùng CÙNG kỹ thuật. Suy biến
        # nhẹ nhàng: không có log hoặc không có chữ ký an toàn → bỏ qua, chỉ giữ luật IP.
        offending = next(
            (
                lg
                for lg in state.current_batch_logs
                if str(normalize_log_keys(lg).get("Source IP", "")) == str(rule_pattern)
            ),
            None,
        )
        if offending:
            beh = _derive_behavioral_rule(offending)
            if beh:
                b_field, b_pattern, b_score = beh
                FeedbackListener().receive_new_rule(
                    b_field,
                    b_pattern,
                    score=b_score,
                    source=f"{rule_source}_behavioral",
                    reason=f"Behavioral signature learned from {rule_pattern}: {raw_reasoning}",
                    status="ACTIVE",
                )
                logger.info(
                    f"--- LEARNED TECHNIQUE: {b_field}~'{b_pattern}' (score {b_score}) "
                    f"from {rule_pattern} ---"
                )

    return {}


def node_human_in_the_loop(state: SentinelState) -> dict[str, Any]:
    """
    HITL Node: Treo lại các cảnh báo phức tạp hoặc Parse Failures.
    """
    logger.info("--- NODE: HUMAN IN THE LOOP (AWAIT_HITL) ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_human_in_the_loop")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if trace.enabled():
        trace.add("nodes", human_in_the_loop=round(time.time(), 6))

    latest_decision = state.decisions[-1] if state.decisions else {}

    mitre = latest_decision.get("mitre_technique", "N/A")
    conf = latest_decision.get("confidence", 0.0)
    raw_reasoning = latest_decision.get("reasoning") or _degraded_reason(latest_decision)
    # LÝ DO chuyển người, ngay ở đầu chuỗi: analyst nhìn hàng đợi phải phân loại được ngay
    # việc nào là "kho thiếu kỹ thuật" (việc của kỹ sư tri thức), việc nào là "bằng chứng
    # yếu" (cần thêm telemetry), việc nào là "LLM hỏng" (việc của kỹ sư vận hành).
    _reason_code = str(latest_decision.get("hitl_reason") or "")
    _reason_txt = (
        f"[REASON: {decision_policy.hitl_reason_text(_reason_code)}] " if _reason_code else ""
    )
    formatted_reasoning = f"{_reason_txt}[MITRE: {mitre}] [Confidence: {conf:.2%}] {raw_reasoning}"

    logger.warning(f" [HÀNG ĐỢI SOC ANALYST] Cần con người kiểm duyệt: {formatted_reasoning}")

    target = latest_decision.get("target", "UNKNOWN_TARGET")

    # LEO THANG KHI TÁI PHẠM (đề xuất vận hành, khớp cơ chế repeat-offender đã có ở
    # `raise_alert`): một IP ĐÃ được chuyển cho người xử lý mà QUAY LẠI vẫn đáng ngờ thì
    # không nên tiếp tục đẻ thêm phiếu HITL trùng nhau — nó phải LEO THANG.
    #
    # Vì sao cần: `AWAIT_HITL` chỉ cộng +5 điểm uy tín, trong khi ngưỡng ép ESCALATE là 50
    # và ngưỡng tự chặn là 70 — tức phải lặp 10-14 lần mới hội tụ. Đo thật cho thấy IP cứ
    # quay lại Tier-2 mãi mà điểm không bao giờ tới ngưỡng. Nâng lần TÁI PHẠM lên ALERT
    # (+10) đưa nó vào đúng đường repeat-offender sẵn có: ALERT lần 2 -> `raise_alert` tự
    # chuyển BLOCK_IP. Lần ĐẦU vẫn là AWAIT_HITL — không cướp quyền quyết định của người.
    _repeat_hitl = False
    if target and target != "UNKNOWN_TARGET":
        try:
            _rep = threat_memory.get_ip_reputation(target) or {}
            _repeat_hitl = int(_rep.get("total_incidents", 0) or 0) >= 1
        except Exception:  # noqa: BLE001 — không có trí nhớ thì cứ xử lý như lần đầu
            _repeat_hitl = False

    if _repeat_hitl:
        logger.warning(
            f"[HITL TÁI PHẠM] {target} đã từng được chuyển người xử lý mà vẫn quay lại — "
            f"leo thang AWAIT_HITL -> ALERT (đường repeat-offender sẽ tự chặn nếu tiếp diễn)."
        )
        latest_decision["action"] = "ALERT"
        formatted_reasoning = f"[LEO THANG: tái phạm sau HITL] {formatted_reasoning}"
        _handle_threat_memory_incident(target, "ALERT", mitre, conf)
    else:
        _handle_threat_memory_incident(target, "AWAIT_HITL", mitre, conf)

    if trace.enabled():
        trace.add("hitl", repeat=_repeat_hitl, action=latest_decision.get("action", ""))

    from src.response.executor import _log_to_db

    raw_log_json = _serialize_repr_log(
        state.current_batch_logs, str(latest_decision.get("target", ""))
    )
    _log_to_db(
        "AWAIT_HITL",
        latest_decision.get("target", "UNKNOWN_TARGET"),
        formatted_reasoning,
        raw_log=raw_log_json,
    )

    # Đưa vào hàng đợi duyệt luật (Tab Phê duyệt Luật HITL) để human có thể xem xét
    target_ip = latest_decision.get("target", "UNKNOWN_TARGET")
    if target_ip != "UNKNOWN_TARGET":
        from src.tier1_filter.feedback_listener import FeedbackListener

        FeedbackListener().receive_new_rule(
            "Source IP",
            target_ip,
            score=50,  # 50 cho AWAIT_HITL vì chưa chắc chắn
            source="langgraph_agent_hitl",
            reason=formatted_reasoning,
        )

    return {}


# ==============================================================================
# CONDITIONAL EDGES (ROUTING)
# ==============================================================================


def route_triage_decision(state: SentinelState) -> str:
    """
    Quyết định nhánh đi tiếp theo dựa trên Action từ LLM.
    """
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "LOG")

    if action in ["BLOCK_IP", "ALERT"]:
        return "execute_action"
    elif action == "AWAIT_HITL":
        return "await_hitl"
    else:
        return "end_cycle"


# Action cần làm giàu MITRE (bỏ qua LOG/benign — ánh xạ ATT&CK cho benign vô nghĩa).
_MAPPABLE_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL"}


def route_after_triage(state: SentinelState) -> str:
    """
    Cổng điều kiện SAU triage — gate theo ACTION:
      - Nếu là verdict đáng-hành-động (BLOCK_IP/ALERT/AWAIT_HITL) -> attack_mapper ("map").
      - Ngược lại (LOG/benign) -> giữ nguyên định tuyến theo action.

    GHI CHÚ THIẾT KẾ: trước đây cổng còn đòi confidence > 0.7, nhưng đo thực tế
    cho thấy triage gán ALERT với confidence ~0.6-0.7 cho bất thường flow, nên
    ngưỡng strict đó lọc mất gần như mọi verdict thật. ALERT vẫn là threat verdict
    đáng làm giàu ATT&CK cho analyst -> gate theo ACTION (không theo confidence).
    Sau attack_mapper, route_triage_decision định tuyến tiếp theo action.
    """
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "LOG")

    if action in _MAPPABLE_ACTIONS:
        return "map"
    return route_triage_decision(state)
