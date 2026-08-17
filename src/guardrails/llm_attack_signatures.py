"""Chữ ký CẤU TRÚC cho tấn công nhắm vào LLM (ATLAS AML.T0051 / AML.T0054).

VÌ SAO CẦN MODULE NÀY
=====================
Trước đây, bằng chứng "đây là tấn công vào LLM" chỉ đến từ hai danh sách chuỗi con
nguyên văn trong `config/system_settings.yaml`: 14 cụm `injection_patterns` và 22 cụm
`jailbreak_patterns`. Đó là danh sách đen từ khoá — nó bắt được đúng cách diễn đạt đã
liệt kê, và mù trước mọi cách nói khác.

ĐO ĐƯỢC (quét ngoại tuyến 403 mẫu đối kháng, 17/08/2026):
  * prompt injection: 171/203 mẫu (84,2%) KHÔNG khớp cụm nào
  * jailbreak       :  61/200 mẫu (30,5%) KHÔNG khớp cụm nào

Hậu quả trên lượt chạy sống cùng ngày (220 lô Tier-2): 130 lô mà chính model đã kết luận
là tấn công với độ tin cậy >= 0,85 (cao nhất 0,98) bị chấm "không có từ vựng tấn công" ->
trần tự tin hạ xuống 0,84 -> ALERT, và kỹ thuật hạ về `N/A`. Không phải payload thiếu bằng
chứng — mà luật bằng chứng chỉ chấp nhận CHỮ KÝ, trong khi tiêm nhiễm câu lệnh là văn xuôi
tự nhiên nên không có chữ ký nào để khớp.

Ví dụ cụ thể: `PI-001` viết "Forget all previous tasks" — danh sách có "forget everything"
và "ignore previous instructions", không có cụm này, nên trượt.

NGUỒN GỐC CỦA CÁC MẪU (quan trọng cho tính trung thực của phép đo)
==================================================================
Các biểu thức dưới đây soạn theo PHÂN LOẠI CÔNG KHAI — OWASP LLM01 (Prompt Injection) và
MITRE ATLAS AML.T0051 / AML.T0054 — mô tả NGỮ PHÁP của đòn tấn công (ra lệnh huỷ chỉ dẫn
trước đó, moi system prompt, chiếm vai, gỡ ràng buộc, chèn dấu phân cách). Chúng KHÔNG
được dò-thử cho vừa với `experiments/adversarial/*/samples.json`.

Ai báo cáo số phát hiện trên bộ mẫu đó vẫn phải nói rõ: mẫu do người soạn, bộ dò do người
soạn, nên con số là ĐỘ PHỦ NGỮ PHÁP chứ không phải năng lực khái quát hoá trên tấn công
chưa từng thấy. Muốn có số khái quát hoá thì phải đo trên nguồn độc lập.

RANH GIỚI VỚI TẤN CÔNG WEB
==========================
Module này CHỈ nhận diện đòn đánh vào LLM. Không một mẫu nào ở đây khớp `UNION SELECT`,
`<script>` hay `../../` — đó là việc của `web_attack_patterns`. Ranh giới này từng bị phá
một lần (xem chú thích `PromptInjectionDetector`): một câu SQLi chữ thường bị quy kết
thành AML.T0051 thay vì T1190, tức sai cả họ khung. Giữ hai họ tách bạch là bất biến.
"""

from __future__ import annotations

import re

# ── Nhóm A. Ghi đè chỉ dẫn (AML.T0051) ────────────────────────────────────────
# Ngữ pháp: động từ huỷ bỏ + tham chiếu tới ngữ cảnh trước + danh từ chỉ dẫn.
# Bắt được cả "forget all previous tasks", "disregard the above rules", "drop your
# earlier directives" — những cách nói mà danh sách nguyên văn không liệt kê hết.
_A_INSTRUCTION_OVERRIDE = (
    r"(?:\b(?:ignore|disregard|forget|discard|drop|skip|override|erase|abandon)\b"
    r"[^.!?\n]{0,40}?"
    r"\b(?:previous|prior|earlier|above|preceding|initial|original|all|any|your|the)\b"
    r"[^.!?\n]{0,40}?"
    r"\b(?:instruction|task|prompt|rule|direction|directive|command|guideline|"
    r"constraint|context|conversation)s?\b"
    # Dạng RÚT GỌN, không có danh từ theo sau: "ignore above and say...", "forget
    # everything". Tham chiếu ngữ cảnh trước tự nó đã là tân ngữ. Thiếu nhánh này thì
    # nhóm A chỉ bắt được câu viết đầy đủ ngữ pháp — hụt chính là dạng ngắn gọn hay gặp.
    r"|\b(?:ignore|disregard|forget)\s+(?:everything|all|anything|it\s+all|the\s+)?"
    r"(?:above|previous|prior|earlier|before|preceding)\b)"
)
_A_NEW_TASK = (
    r"\b(?:new|real|true|actual|updated|revised)\s+"
    r"(?:instruction|task|prompt|rule|directive|objective|mission|goal)s?\b"
)

# ── Nhóm B. Moi system prompt (AML.T0051) ─────────────────────────────────────
_B_PROMPT_EXFIL = (
    r"\b(?:show|reveal|print|repeat|output|display|tell|give|list|dump|leak|expose|"
    r"disclose)\b"
    r"[^.!?\n]{0,50}?"
    r"\b(?:system\s+prompt|initial\s+prompt|original\s+prompt|prompt\s+text|"
    r"your\s+(?:prompt|instructions|rules|directives|guidelines|configuration))\b"
)
_B_PROMPT_ASK = (
    r"\bwhat\s+(?:are|were|is|was)\s+(?:your|the)\s+"
    r"(?:system\s+)?(?:prompt|instructions|rules|directives|guidelines)\b"
)

# ── Nhóm C. Chèn dấu phân cách / giả khung hội thoại (AML.T0051) ──────────────
# Kẻ tấn công giả lập token điều khiển của chính khuôn mẫu chat để "đóng" lượt của hệ
# thống rồi mở một lượt mới do mình soạn.
_C_DELIMITER = (
    r"(?:<\|?(?:im_start|im_end|endoftext|system|assistant|user)\|?>"
    r"|\[/?(?:INST|SYS|SYSTEM)\]"
    r"|###\s*(?:system|instruction|assistant)\b"
    r"|<<<[A-Z_]{3,}"
    r"|>>>>"
    r"|\bBEGIN\s+(?:SYSTEM|ADMIN|ROOT)\b)"
)

# ── Nhóm D. Chiếm vai / gán nhân cách (AML.T0054) ─────────────────────────────
# D1: cụm chỉ xuất hiện trong ý đồ chiếm vai, không cần thêm ngữ cảnh.
_D1_PERSONA = (
    # "pretend you CAN access…", "pretend you have no filter" — cùng một ngữ pháp gán
    # năng lực giả với "pretend you ARE", nên điều kiện chỉ là ngôi thứ hai đứng sau.
    r"(?:\bpretend\s+(?:to\s+be\b|(?:that\s+)?\byou\b)"
    r"|\brole[\s-]?play(?:ing|s)?\b"
    r"|\b(?:adopt|assume|take\s+on|switch\s+to)\s+(?:the\s+)?"
    r"(?:persona|role|character|identity|mode)\b"
    r"|\bstay\s+in\s+(?:character|role)\b"
    r"|\byou\s+are\s+no\s+longer\b"
    r"|\bfrom\s+now\s+on\b[^.!?\n]{0,40}?\byou\b)"
)
# D2: "act as / behave as" là cụm tiếng Anh thường gặp trong văn bản LÀNH ("this will act
# as a backup"), nên bắt buộc phải có ngôi thứ hai kèm theo — hoặc đứng đầu câu ở thể mệnh
# lệnh. Đây là chỗ CHẶT HƠN danh sách cũ, vốn khớp trần trụi chuỗi "act as".
_D2_ACT_AS = (
    # Có ngôi thứ hai rồi thì KHÔNG đòi mạo từ nữa: "you act as two entities", "you act as
    # DAN" đều là gán vai. Chính ngôi thứ hai mới là thứ phân biệt với văn lành ("this will
    # act as a backup"), chứ không phải mạo từ.
    r"(?:\byou\b[^.!?\n]{0,40}?\b(?:act|behave|respond|reply|answer|speak|talk|write)\s+"
    r"(?:as|like)\b"
    # Thể mệnh lệnh đứng đầu câu thì KHÔNG có ngôi thứ hai để dựa, nên vẫn giữ mạo từ làm
    # neo — nới ở đây là mở đường cho câu lành "act as expected".
    r"|(?:^|[.!?]\s+)(?:act|behave|respond|pretend|speak|talk)\s+(?:as|like)\s+"
    r"(?:a|an|the)\b)"
)

# ── Nhóm E. Gỡ ràng buộc an toàn (AML.T0054) ──────────────────────────────────
_E_RESTRICTION_REMOVAL = (
    r"(?:\b(?:without|free\s+from|free\s+of|devoid\s+of)\s+(?:any\s+)?"
    r"(?:restriction|limitation|filter|censorship|rule|guideline|constraint|"
    r"moral|ethic|boundar)\w*"
    r"|\b(?:bypass|circumvent|evade|disable|turn\s+off|switch\s+off|remove|override)\b"
    r"[^.!?\n]{0,40}?"
    r"\b(?:safety|guideline|filter|restriction|polic|moderation|safeguard|censorship|"
    r"alignment)\w*"
    r"|\byou\s+(?:have|has)\s+no\s+(?:restriction|limit|rule|filter|boundar)\w*"
    r"|\b(?:DAN\s+mode|do\s+anything\s+now|developer\s+mode|jailbr\w+|"
    r"unrestricted\s+mode|god\s+mode|sudo\s+mode)\b)"
)

# ── Nhóm F. Ép định dạng / cấm từ chối (AML.T0054) ────────────────────────────
# Đòn "đừng bao giờ nói mày là mô hình ngôn ngữ" và "không được từ chối" — dấu hiệu rất
# đặc trưng, gần như không xuất hiện trong lưu lượng lành.
_F_REFUSAL_SUPPRESSION = (
    r"(?:\b(?:never|do\s+not|don'?t|stop|avoid)\b[^.!?\n]{0,40}?"
    r"\b(?:say|state|mention|admit|reveal|remind|claim|tell)\b[^.!?\n]{0,40}?"
    r"\b(?:you\s+are|you'?re|a\s+language\s+model|an\s+ai|an\s+artificial|"
    r"a\s+chatbot|an\s+assistant)\b"
    r"|\b(?:never|do\s+not|don'?t|must\s+not)\s+(?:refuse|decline|apolog\w+|reject)\b"
    r"|\balways\s+(?:comply|obey|answer|respond|agree)\b(?:[^.!?\n]{0,30}\bno\s+matter\b)?)"
)

# ── Nhóm G. Moi năng lực gây hại (AML.T0054) ──────────────────────────────────
# CỐ Ý HẸP. Chỉ nhận cặp "cách chế tạo/thực hiện" + đối tượng gây hại rõ ràng. Không nhận
# từ đơn lẻ như "malware" hay "weapon": kho tri thức an ninh của chính hệ thống đầy những
# từ đó, nhận rộng là tự bắn vào chân.
_G_HARMFUL_CAPABILITY = (
    r"(?:\bhow\s+(?:to|do\s+i|can\s+i)\b[^.!?\n]{0,40}?"
    r"\b(?:make|build|create|synthes\w+|manufactur\w+|obtain|acquire|cook|produce)\b"
    r"[^.!?\n]{0,30}?"
    r"\b(?:bomb|explosive|meth|methamphetamine|cocaine|heroin|nerve\s+agent|"
    r"poison|napalm|thermite|ghost\s+gun|silencer)\w*"
    r"|\b(?:commit|perform|carry\s+out|plan)\b[^.!?\n]{0,30}?"
    r"\b(?:genocide|mass\s+shooting|terror\w+|ethnic\s+cleansing)\b)"
)

# Khoá họ -> (biểu thức, kỹ thuật ATLAS). Kỹ thuật quyết định quy kết hạ nguồn:
# nhóm ghi đè chỉ dẫn / moi prompt / chèn dấu phân cách là TIÊM NHIỄM (AML.T0051);
# nhóm chiếm vai / gỡ ràng buộc / cấm từ chối / moi năng lực gây hại là JAILBREAK
# (AML.T0054). Trước đây mọi thứ đổ chung vào AML.T0051 — sai quy kết ngay trong hồ sơ.
_FAMILIES: tuple[tuple[str, str, str], ...] = (
    ("instruction_override", _A_INSTRUCTION_OVERRIDE, "AML.T0051"),
    ("new_task_hijack", _A_NEW_TASK, "AML.T0051"),
    ("system_prompt_exfil", _B_PROMPT_EXFIL, "AML.T0051"),
    ("system_prompt_probe", _B_PROMPT_ASK, "AML.T0051"),
    ("delimiter_injection", _C_DELIMITER, "AML.T0051"),
    ("persona_hijack", _D1_PERSONA, "AML.T0054"),
    ("act_as_persona", _D2_ACT_AS, "AML.T0054"),
    ("restriction_removal", _E_RESTRICTION_REMOVAL, "AML.T0054"),
    ("refusal_suppression", _F_REFUSAL_SUPPRESSION, "AML.T0054"),
    ("harmful_capability", _G_HARMFUL_CAPABILITY, "AML.T0054"),
)

_COMPILED: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (name, re.compile(pat, re.IGNORECASE | re.MULTILINE), tech) for name, pat, tech in _FAMILIES
)

# Trần quét: payload dài bất thường không được biến bộ dò thành điểm nghẽn CPU trên đường
# nóng. 8 KB phủ trọn mọi mẫu đối kháng đang có (dài nhất ~6 KB).
_MAX_SCAN_CHARS = 8192

TECHNIQUE_INJECTION = "AML.T0051"
TECHNIQUE_JAILBREAK = "AML.T0054"


def detect_families(text: str) -> list[str]:
    """Trả về tên các họ chữ ký khớp trong `text` (rỗng nếu không khớp gì)."""
    if not text:
        return []
    hay = text[:_MAX_SCAN_CHARS]
    return [name for name, rx, _ in _COMPILED if rx.search(hay)]


def classify(text: str) -> tuple[list[str], str]:
    """`(danh sách họ khớp, mã ATLAS đại diện)`.

    Ưu tiên AML.T0051 khi có cả hai: tiêm nhiễm câu lệnh là đòn tác động trực tiếp lên
    hợp đồng chỉ dẫn của hệ, còn jailbreak chỉ nới ràng buộc nội dung. Lô dính cả hai thì
    cái nghiêm trọng hơn phải là nhãn đi vào hồ sơ sự cố.
    """
    fams = detect_families(text)
    if not fams:
        return ([], "")
    techs = {tech for name, _, tech in _COMPILED if name in fams}
    return (fams, TECHNIQUE_INJECTION if TECHNIQUE_INJECTION in techs else TECHNIQUE_JAILBREAK)


def is_llm_attack(text: str) -> bool:
    """Có khớp họ chữ ký nào không — dùng làm cổng bằng chứng nhị phân."""
    return bool(detect_families(text))
