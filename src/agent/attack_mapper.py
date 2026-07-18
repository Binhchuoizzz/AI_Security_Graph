"""
SENTINEL Tier-2 — MITRE ATT&CK Mapping Layer (structured enrichment)

MỤC ĐÍCH:
  node_llm_triage đã xuất `mitre_technique` dạng FREE-TEXT (vd "T1190 - ...").
  Lớp này biến nó thành bản đồ ATT&CK CÓ CẤU TRÚC, kiểm chứng được:
  tactic / tactic_id / technique / technique_id / sub-technique / URL /
  mapping_confidence / recommended_response.

THIẾT KẾ (đã chốt với chủ nhiệm đề tài):
  - TÁI DÙNG hạ tầng có sẵn: knowledge_base/mitre_attack.json (299 kỹ thuật) +
    DualRetriever (FAISS+BM25, RRF k=60) + llm_client (llama.cpp Q6_K @ :5000).
    KHÔNG tải lại STIX, KHÔNG tạo KB/endpoint song song.
  - Đường XÁC ĐỊNH (deterministic) cho các tấn công web phổ biến: tra
    WEB_ATTACK_MAP (do người soạn, mọi technique/tactic đều là ATT&CK THẬT).
    => test tái lập được, KHÔNG cần LLM/CI server.
  - Đường suy luận: nếu attack_type lạ -> RRF lấy top-3 ứng viên từ KB ->
    LLM chọn cái khớp nhất (graceful fallback về top-RRF nếu LLM chết).
  - Fallback "C + cờ trạng thái": LUÔN ghi structured fields từ ứng viên tốt
    nhất + mapping_confidence THẬT + mapping_status ∈ {resolved, low_confidence};
    KHÔNG bịa độ tin cậy, KHÔNG vứt thông tin.
  - recommended_response: rule-based theo tactic (xác định, đúng cho web). KB
    response_actions chỉ override khi đặc thù (250/299 kỹ thuật là generic).

LƯU Ý TRUNG THỰC (no-fabrication):
  - Prompt Injection KHÔNG thuộc ATT&CK Enterprise -> ánh xạ sang MITRE ATLAS
    AML.T0051. tactic_id của ATLAS CỐ TÌNH để trống vì chưa verify được số TA
    chính xác (không bịa). Có thể điền sau khi tra atlas.mitre.org.
  - IDOR không có kỹ thuật ATT&CK riêng -> ánh xạ T1190 với confidence thấp hơn
    và ghi chú rõ giới hạn.
"""

import functools
import json
import logging
import os
import re
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# === Đường dẫn KB tái dùng (không tạo store mới) ===
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KB_PATH = os.path.join(_BASE_DIR, "knowledge_base", "mitre_attack.json")

# Dưới ngưỡng này => mapping_status = "low_confidence".
# (Cổng KÍCH HOẠT mapper nằm ở nodes.route_after_triage và gate theo ACTION threat,
#  không theo confidence — xem ghi chú thiết kế ở đó.)
LOW_CONFIDENCE_THRESHOLD = 0.5

FRAMEWORK_ATTACK = "MITRE ATT&CK Enterprise"
FRAMEWORK_ATLAS = "MITRE ATLAS"


@functools.lru_cache(maxsize=1)
def _llm_select_enabled() -> bool:
    """Có gọi LLM lần 2 (chọn MITRE trong ứng viên RRF) cho ca MƠ HỒ không.

    Mặc định TẮT (tối ưu tốc độ): ca không phải web-attack curated và triage KHÔNG nêu
    technique-id -> KHÔNG tốn thêm 1 inference LLM để đoán. Đính top-RRF làm GỢI Ý nhưng để
    low_confidence -> lá chắn node_attack_mapper ép AWAIT_HITL (log không khớp rõ -> người
    duyệt). Bật lại bằng config `tier2.attack_mapper.llm_select: true` (phục vụ ablation)."""
    try:
        import yaml  # type: ignore

        p = os.path.join(_BASE_DIR, "config", "system_settings.yaml")
        with open(p) as f:
            cfg = yaml.safe_load(f) or {}
        return bool(cfg.get("tier2", {}).get("attack_mapper", {}).get("llm_select", False))
    except Exception:
        return False


# ==============================================================================
# PYDANTIC MODELS (schema luôn hợp lệ — pydantic validate khi khởi tạo)
# ==============================================================================
class AttackMapperInput(BaseModel):
    """Đầu vào: kết quả phân loại của node_llm_triage."""

    attack_type: str = ""
    confidence: float = 0.0
    payload: str = ""
    features: dict[str, Any] = Field(default_factory=dict)


class MitreMapping(BaseModel):
    """Đầu ra có cấu trúc của lớp mapping."""

    attack_type: str
    confidence: float  # độ tin cậy PHÁT HIỆN (từ triage), giữ nguyên
    framework: str = FRAMEWORK_ATTACK
    mitre_tactic: str
    mitre_tactic_id: str
    mitre_technique: str
    mitre_technique_id: str
    mitre_subtechnique: str | None = None
    mitre_subtechnique_id: str | None = None
    mitre_url: str
    mapping_confidence: float  # độ tin cậy của riêng phép ÁNH XẠ (heuristic, [0,1])
    mapping_status: str  # "resolved" | "low_confidence"
    recommended_response: str


# ==============================================================================
# BẢNG TACTIC CHÍNH THỨC (sự thật công khai, ổn định của ATT&CK Enterprise)
# ==============================================================================
TACTIC_IDS: dict[str, str] = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
    "Command and Control": "TA0011",
    "Impact": "TA0040",
    "Resource Development": "TA0042",
    "Reconnaissance": "TA0043",
}

# KB dùng vài nhãn tactic phi chuẩn -> chuẩn hoá về tên ATT&CK chính thức.
TACTIC_ALIASES: dict[str, str] = {
    "stealth": "Defense Evasion",
    "defense impairment": "Defense Evasion",
    "command and control": "Command and Control",
    "command & control": "Command and Control",
}

# Phản hồi đề xuất theo TACTIC (rule-based, xác định). Viết tiếng Việt để khớp
# quy ước trường reasoning hiển thị trên dashboard SOC.
TACTIC_RESPONSE: dict[str, str] = {
    "Initial Access": "Chặn IP nguồn tại WAF/firewall, vá/cô lập endpoint bị khai thác, leo thang HITL để xác minh phạm vi.",
    "Execution": "Chặn IP nguồn, cô lập hoặc kết thúc tiến trình đáng ngờ, thu thập artefact, leo thang HITL.",
    "Persistence": "Cô lập host, gỡ cơ chế bám trụ (scheduled task/service/DLL), kiểm tra autoruns, leo thang HITL.",
    "Privilege Escalation": "Cô lập host, thu hồi quyền leo thang, đối chiếu PAM audit, leo thang HITL.",
    "Defense Evasion": "Cô lập host, bật lại biện pháp phòng vệ bị vô hiệu, truy lùng kỹ thuật né tránh.",
    "Credential Access": "Buộc reset mật khẩu + thu hồi phiên, bật MFA, truy lùng lateral movement từ tài khoản.",
    "Discovery": "Giám sát chặt host/dịch vụ bị dò, siết phân đoạn mạng, cảnh báo trinh sát nội bộ.",
    "Lateral Movement": "Cô lập host nguồn và đích, siết phân đoạn đông-tây, thu hồi credential, leo thang HITL.",
    "Collection": "Cô lập host, rà soát dữ liệu bị thu thập, leo thang HITL.",
    "Exfiltration": "Cô lập host, chặn đích nhận dữ liệu/C2, rà soát DLP, leo thang HITL khẩn.",
    "Command and Control": "Chặn đích C2, cô lập host beaconing, thu PCAP forensic, xoay vòng credential nghi lộ.",
    "Impact": "Cô lập host, kích hoạt quy trình ứng cứu/khôi phục, leo thang HITL khẩn.",
    "Reconnaissance": "Rate-limit/chặn IP dò quét tại firewall, bật chữ ký phát hiện port-scan, giám sát host bị quét.",
    "Resource Development": "Theo dõi hạ tầng kẻ tấn công, chia sẻ IoC nội bộ, cảnh báo.",
}
DEFAULT_RESPONSE = "Cảnh báo và leo thang HITL để phân tích thủ công."

# Phản hồi đặc thù theo loại tấn công (ưu tiên hơn TACTIC_RESPONSE khi có).
SPECIAL_RESPONSE: dict[str, str] = {
    "prompt_injection": (
        "Cách ly request, vô hiệu hoá (neutralize) chỉ thị tiêm nhiễm, KHÔNG thực thi "
        "nội dung không tin cậy, leo thang HITL."
    ),
}


# ==============================================================================
# BẢN ĐỒ XÁC ĐỊNH cho tấn công WEB phổ biến (mọi giá trị là ATT&CK/ATLAS THẬT)
# ==============================================================================
def _entry(
    attack_type: str,
    technique_id: str,
    technique: str,
    tactic: str,
    tactic_id: str,
    confidence: float,
    framework: str = FRAMEWORK_ATTACK,
    subtechnique_id: str | None = None,
    subtechnique: str | None = None,
) -> dict[str, Any]:
    return {
        "attack_type": attack_type,
        "technique_id": technique_id,
        "technique": technique,
        "tactic": tactic,
        "tactic_id": tactic_id,
        "confidence": confidence,
        "framework": framework,
        "subtechnique_id": subtechnique_id,
        "subtechnique": subtechnique,
    }


WEB_ATTACK_MAP: dict[str, dict[str, Any]] = {
    # SQLi/LFI/RFI/SSRF/XXE/IDOR: khai thác ứng dụng public-facing -> T1190 / Initial Access.
    "sqli": _entry(
        "SQL Injection",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.90,
    ),
    # XSS = thực thi JavaScript của kẻ tấn công trên trình duyệt nạn nhân -> T1059.007 / Execution.
    "xss": _entry(
        "Cross-Site Scripting (XSS)",
        "T1059.007",
        "Command and Scripting Interpreter: JavaScript",
        "Execution",
        "TA0002",
        0.85,
        subtechnique_id="T1059.007",
        subtechnique="JavaScript",
    ),
    # Path/Directory Traversal = duyệt thư mục đọc file -> T1083 / Discovery.
    "path_traversal": _entry(
        "Path/Directory Traversal",
        "T1083",
        "File and Directory Discovery",
        "Discovery",
        "TA0007",
        0.80,
    ),
    "lfi": _entry(
        "Local File Inclusion (LFI)",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.80,
    ),
    "rfi": _entry(
        "Remote File Inclusion (RFI)",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.80,
    ),
    "ssrf": _entry(
        "Server-Side Request Forgery (SSRF)",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.85,
    ),
    "xxe": _entry(
        "XML External Entity (XXE)",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.85,
    ),
    # Command Injection -> T1059 (parent) / Execution. T1059 cha không nằm trong KB,
    # nhưng đây là kỹ thuật ATT&CK THẬT và là ánh xạ chuẩn cho command injection.
    "command_injection": _entry(
        "Command Injection",
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "TA0002",
        0.90,
    ),
    # IDOR: ATT&CK KHÔNG có kỹ thuật riêng -> gần nhất là T1190; hạ confidence + ghi chú.
    "idor": _entry(
        "Insecure Direct Object Reference (IDOR)",
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "TA0001",
        0.60,
    ),
    # Prompt Injection: KHÔNG thuộc ATT&CK Enterprise -> MITRE ATLAS AML.T0051.
    # tactic_id CỐ TÌNH để trống (chưa verify số AML.TA — không bịa).
    "prompt_injection": _entry(
        "LLM Prompt Injection",
        "AML.T0051",
        "LLM Prompt Injection",
        "Initial Access",
        "",
        0.85,
        framework=FRAMEWORK_ATLAS,
    ),
}

# Từ khoá -> khoá chuẩn (quét trên attack_type + payload + features). Thứ tự ưu
# tiên xử lý trường hợp chồng lấn (vd "../" rất chung).
_ATTACK_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    (
        "prompt_injection",
        (
            "prompt injection",
            "jailbreak",
            "ignore previous instructions",
            "ignore all previous",
            "system prompt",
        ),
    ),
    (
        "sqli",
        (
            "sqli",
            "sql injection",
            "sql-injection",
            "union select",
            "or 1=1",
            "' or '1'='1",
            "sqlmap",
        ),
    ),
    (
        "xss",
        (
            "xss",
            "cross-site scripting",
            "cross site scripting",
            "<script",
            "onerror=",
            "javascript:",
        ),
    ),
    (
        "command_injection",
        (
            "command injection",
            "os command",
            "rce",
            "remote code execution",
            "; cat ",
            "&& whoami",
            "$(",
            "`id`",
            "|nc ",
        ),
    ),
    (
        "ssrf",
        (
            "ssrf",
            "server-side request forgery",
            "server side request forgery",
            "169.254.169.254",
            "gopher://",
        ),
    ),
    ("xxe", ("xxe", "xml external entity", "<!entity", "<!doctype")),
    ("rfi", ("rfi", "remote file inclusion")),
    ("lfi", ("lfi", "local file inclusion", "php://filter")),
    ("path_traversal", ("path traversal", "directory traversal", "../", "..%2f", "%2e%2e")),
    ("idor", ("idor", "insecure direct object", "broken object level", "bola")),
]


# ==============================================================================
# HÀM HỖ TRỢ
# ==============================================================================
def _kw_hit(kw: str, haystack: str) -> bool:
    """Khớp keyword. Keyword 'từ' (chỉ chữ/số/space) phải khớp NGUYÊN TỪ (word
    boundary) để tránh dương-tính-giả như 'rce' lọt trong 'fo[rce]' (brute force).
    Keyword chứa ký tự đặc biệt (../, <script, $(, javascript:) thì khớp substring."""
    if all(c.isalnum() or c.isspace() for c in kw):
        return re.search(r"\b" + re.escape(kw) + r"\b", haystack) is not None
    return kw in haystack


def normalize_attack_type(*texts: str) -> str:
    """Quét nhiều chuỗi (attack_type, payload, reasoning...) -> khoá chuẩn hoặc ""."""
    haystack = " ".join(t for t in texts if t).lower()
    if not haystack:
        return ""
    for key, kws in _ATTACK_KEYWORDS:
        if any(_kw_hit(kw, haystack) for kw in kws):
            return key
    return ""


def normalize_tactic(raw: str) -> tuple[str, str]:
    """Chuẩn hoá nhãn tactic (kể cả nhãn phi chuẩn của KB) -> (tên chính thức, TA id)."""
    if not raw:
        return ("Unknown", "")
    low = raw.strip().lower()
    if low in TACTIC_ALIASES:
        canon = TACTIC_ALIASES[low]
    else:
        canon = next((c for c in TACTIC_IDS if c.lower() == low), raw.strip())
    return (canon, TACTIC_IDS.get(canon, ""))


def build_mitre_url(technique_id: str, framework: str = FRAMEWORK_ATTACK) -> str:
    """Dựng URL chính thức cho technique/sub-technique."""
    if not technique_id:
        return ""
    if "ATLAS" in framework or technique_id.startswith("AML"):
        return f"https://atlas.mitre.org/techniques/{technique_id}"
    if "." in technique_id:
        parent, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def _response_for(key: str, tactic: str) -> str:
    """recommended_response: ưu tiên đặc thù theo loại tấn công, rồi tới tactic."""
    if key in SPECIAL_RESPONSE:
        return SPECIAL_RESPONSE[key]
    return TACTIC_RESPONSE.get(tactic, DEFAULT_RESPONSE)


_KB_INDEX: dict[str, dict] | None = None


def _load_kb_index() -> dict[str, dict]:
    """Nạp (lười) knowledge_base/mitre_attack.json -> dict theo technique id."""
    global _KB_INDEX
    if _KB_INDEX is None:
        try:
            with open(KB_PATH, encoding="utf-8") as f:
                data = json.load(f)
            _KB_INDEX = {t["id"]: t for t in data if isinstance(t, dict) and t.get("id")}
        except Exception as e:  # KB thiếu -> đường RRF tự suy biến an toàn
            logger.warning(f"[attack_mapper] Không nạp được KB ({e}); đường RRF sẽ suy biến.")
            _KB_INDEX = {}
    return _KB_INDEX


def _from_curated(key: str, inp: AttackMapperInput) -> MitreMapping:
    """Dựng MitreMapping từ bản đồ xác định (resolved, độ tin cậy cao)."""
    e = WEB_ATTACK_MAP[key]
    conf = float(e["confidence"])
    return MitreMapping(
        attack_type=e["attack_type"],
        confidence=inp.confidence,
        framework=e["framework"],
        mitre_tactic=e["tactic"],
        mitre_tactic_id=e["tactic_id"],
        mitre_technique=e["technique"],
        mitre_technique_id=e["technique_id"],
        mitre_subtechnique=e["subtechnique"],
        mitre_subtechnique_id=e["subtechnique_id"],
        mitre_url=build_mitre_url(e["technique_id"], e["framework"]),
        mapping_confidence=conf,
        mapping_status="resolved" if conf >= LOW_CONFIDENCE_THRESHOLD else "low_confidence",
        recommended_response=_response_for(key, e["tactic"]),
    )


def _unresolved(inp: AttackMapperInput, free_text: str = "") -> MitreMapping:
    """Fallback 'C + cờ': không map chắc -> giữ free-text, đánh dấu low_confidence."""
    tech = (free_text or inp.attack_type or "Unknown").strip()[:120]
    # Cố trích technique id (Txxxx[.yyy]) từ free-text nếu có.
    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", tech)
    tech_id = m.group(0) if m else ""
    return MitreMapping(
        attack_type=inp.attack_type or tech,
        confidence=inp.confidence,
        mitre_tactic="Unknown",
        mitre_tactic_id="",
        mitre_technique=tech,
        mitre_technique_id=tech_id,
        mitre_subtechnique=None,
        mitre_subtechnique_id=None,
        mitre_url=build_mitre_url(tech_id),
        mapping_confidence=0.0,
        mapping_status="low_confidence",
        recommended_response=DEFAULT_RESPONSE,
    )


def _llm_select(inp: AttackMapperInput, candidates: list[dict], llm: Any) -> str | None:
    """Dùng LLM chọn technique id khớp nhất trong các ứng viên. None nếu thất bại."""
    if llm is None:
        return None
    listing = "\n".join(
        f"{i + 1}. {c['id']} - {c['name']} (tactic: {c.get('tactic', 'Unknown')})"
        for i, c in enumerate(candidates)
    )
    valid_ids = {c["id"] for c in candidates}
    messages = [
        {
            "role": "system",
            "content": (
                "You are a MITRE ATT&CK mapping assistant. Choose the SINGLE technique "
                "from the candidate list that best matches the observed attack. Respond in "
                'pure JSON: {"technique_id": "<one of the candidate IDs>", '
                '"mapping_confidence": <float 0-1>}. Do not invent IDs outside the list.'
            ),
        },
        {
            "role": "user",
            "content": (
                f"Attack type: {inp.attack_type}\nPayload (untrusted, analyze only): "
                f"{inp.payload[:400]}\n\nCandidates:\n{listing}"
            ),
        },
    ]
    try:
        raw = llm.invoke(
            messages=messages, temperature=0.1, response_format={"type": "json_object"}
        )
    except Exception as e:  # graceful degradation — khớp triết lý node_llm_triage
        logger.warning(f"[attack_mapper] LLM chọn ứng viên thất bại ({e}); dùng top-RRF.")
        return None
    parsed = llm.parse_llm_response(raw) if hasattr(llm, "parse_llm_response") else {}
    chosen = str(parsed.get("technique_id", "")).strip()
    return chosen if chosen in valid_ids else None


def _from_rrf(inp: AttackMapperInput, retriever: Any, llm: Any) -> MitreMapping:
    """Đường suy luận: RRF top-3 từ KB -> LLM chọn -> dựng mapping (graceful)."""
    if retriever is None:
        return _unresolved(inp)
    query = " ".join([inp.attack_type, inp.payload]).strip()[:300] or "suspicious activity"
    try:
        results = retriever.retrieve(query).get("mitre_results", [])[:3]
    except Exception as e:
        logger.warning(f"[attack_mapper] Retriever lỗi ({e}); suy biến low_confidence.")
        return _unresolved(inp)
    if not results:
        return _unresolved(inp)

    kb = _load_kb_index()
    candidates = []
    for r in results:
        tid = r.get("id", "")
        rec = kb.get(tid, {})
        candidates.append(
            {
                "id": tid,
                "name": r.get("name", "") or rec.get("name", ""),
                "tactic": rec.get("tactic", "Unknown"),
                "rrf_score": float(r.get("rrf_score", 0.0) or 0.0),
            }
        )

    chosen_id = _llm_select(inp, candidates, llm)
    if chosen_id:
        chosen = next(c for c in candidates if c["id"] == chosen_id)
        mapping_conf, status = 0.75, "resolved"
    else:
        # KHÔNG có xác nhận LLM -> đính top-RRF làm GỢI Ý cho analyst nhưng để low_confidence:
        # lá chắn node_attack_mapper ép AWAIT_HITL (log không khớp CHẮC -> người duyệt), thay vì
        # auto-act trên một match RRF mờ (khớp yêu cầu "không match rõ -> HITL").
        chosen = candidates[0]
        mapping_conf, status = 0.40, "low_confidence"

    tactic, tactic_id = normalize_tactic(chosen["tactic"])
    tid = chosen["id"]
    sub_id = tid if "." in tid else None
    return MitreMapping(
        attack_type=inp.attack_type or chosen["name"],
        confidence=inp.confidence,
        mitre_tactic=tactic,
        mitre_tactic_id=tactic_id,
        mitre_technique=chosen["name"],
        mitre_technique_id=tid,
        mitre_subtechnique=chosen["name"] if sub_id else None,
        mitre_subtechnique_id=sub_id,
        mitre_url=build_mitre_url(tid),
        mapping_confidence=mapping_conf,
        mapping_status=status if mapping_conf >= LOW_CONFIDENCE_THRESHOLD else "low_confidence",
        recommended_response=_response_for("", tactic),
    )


def _from_triage_anchor(inp: AttackMapperInput) -> MitreMapping | None:
    """
    NEO vào technique-id mà TRIAGE đã gán (nếu attack_type chứa Txxxx hợp lệ).

    Triết lý A (đã chốt): mapper KHÔNG ghi đè verdict của triage — triage đã
    grounded trên RAG MITRE; mapper chỉ CẤU TRÚC HOÁ (thêm tactic/url/response).
    Trả None nếu không tìm thấy id -> đi tiếp đường RRF (fallback khi triage mơ hồ).
    """
    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", inp.attack_type or "")
    if not m:
        return None
    tid = m.group(0)
    kb = _load_kb_index()
    rec = kb.get(tid) or kb.get(tid.split(".")[0])
    if rec:
        name = rec.get("name", "") or tid
        tactic, tactic_id = normalize_tactic(rec.get("tactic", ""))
        conf = 0.80  # triage grounded + KB xác nhận id
    else:
        # id hợp lệ nhưng KB không phủ -> vẫn NEO (đúng hơn là để RRF chệch sang
        # kỹ thuật cổng/giao thức), nhưng tactic để TRỐNG (honest) + hạ confidence.
        name = tid
        tactic, tactic_id = ("Unknown", "")
        conf = 0.60
    sub_id = tid if "." in tid else None
    return MitreMapping(
        attack_type=inp.attack_type.strip()[:120] or tid,
        confidence=inp.confidence,
        mitre_tactic=tactic,
        mitre_tactic_id=tactic_id,
        mitre_technique=name,
        mitre_technique_id=tid,
        mitre_subtechnique=name if (sub_id and rec) else None,
        mitre_subtechnique_id=sub_id,
        mitre_url=build_mitre_url(tid),
        mapping_confidence=conf,
        mapping_status="resolved" if conf >= LOW_CONFIDENCE_THRESHOLD else "low_confidence",
        recommended_response=_response_for("", tactic),
    )


# ==============================================================================
# API CHÍNH
# ==============================================================================
def map_attack(
    inp: AttackMapperInput,
    retriever: Any = None,
    llm: Any = None,
    use_llm_select: bool | None = None,
) -> MitreMapping:
    """
    Ánh xạ một kết quả phân loại sang MITRE ATT&CK có cấu trúc.

    Args:
        inp: AttackMapperInput (attack_type/confidence/payload/features).
        retriever: DualRetriever (tái dùng singleton). None -> bỏ đường RRF.
        llm: llm_client. None -> bỏ bước LLM chọn (vẫn dùng top-RRF/curated).
        use_llm_select: có gọi LLM lần 2 chọn MITRE cho ca mơ hồ không. None -> đọc
            config `tier2.attack_mapper.llm_select` (mặc định TẮT); True/False -> ép rõ
            (test/ablation).

    Returns:
        MitreMapping — schema LUÔN hợp lệ (pydantic validate khi khởi tạo).
    """
    # 1) Đường XÁC ĐỊNH: dò loại tấn công web phổ biến trên mọi tín hiệu sẵn có.
    key = normalize_attack_type(inp.attack_type, inp.payload, str(inp.features))
    if key in WEB_ATTACK_MAP:
        return _from_curated(key, inp)
    # 2) NEO vào verdict của triage nếu attack_type chứa technique-id hợp lệ (triết lý A).
    anchored = _from_triage_anchor(inp)
    if anchored is not None:
        return anchored
    # 3) Đường suy luận RRF. Mặc định KHÔNG gọi LLM lần 2 (tốc độ): ca mơ hồ đằng nào cũng
    #    ra AWAIT_HITL nên không cần thêm 1 inference để đoán technique.
    if use_llm_select is None:
        use_llm_select = _llm_select_enabled()
    return _from_rrf(inp, retriever, llm if use_llm_select else None)
