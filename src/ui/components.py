"""
Các component giao diện dùng lại cho Streamlit Dashboard.
NÂNG CẤP PREMIUM: Thiết kế chuẩn SOC/SIEM Glassmorphism hiện đại.
"""

import html as html_lib
import json
import os
import re
from datetime import datetime

import pandas as pd  # type: ignore
import streamlit as st  # type: ignore

from src.guardrails.constants import TIER_LLM, TIER_MANUAL, TIER_ML, TIER_RULE

# Marker chuỗi để nhận diện phán quyết đến từ CỔNG ML Tier-1 (dùng CHUNG cho components.py
# và app.py để phân loại nguồn NHẤT QUÁN — 1 nguồn chân lý, tránh drift giữa các nơi).
# "Cổng ML" đã bao "Cổng ML Tier-1 (LightGBM)" (substring) nên không cần liệt kê riêng;
# "ML Tier 2" / "Decision Tree" là nhãn LỊCH SỬ cho các bản ghi CŨ còn trong DB (phòng thủ).
ML_GATE_MARKERS = ("Cổng ML", "ML Tier 2", "Decision Tree")


# Khoá nhãn trong sidecar `data/*.labels.json`, xếp theo nguồn. Sidecar là ĐÁP ÁN — nó nằm
# NGOÀI luồng, chưa bao giờ đi vào prompt; tra ở đây chỉ để analyst đối chiếu bằng mắt.
_GT_TECH_KEYS = ("wa_mitre", "zd_mitre", "adv_mitre", "apt_mitre_ttp")
_GT_LABELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


@st.cache_data(ttl=60, show_spinner=False)
def _load_ground_truth(_stamp: tuple) -> dict:
    """Gộp mọi `data/*.labels.json` thành một bảng tra gt_id -> nhãn.

    `_stamp` là (đường dẫn, mtime) của từng tệp — đổi tệp thì cache tự hỏng. Gộp mọi
    sidecar vì Dashboard không biết luồng nào đang chạy (demo.json hay demo_small.json).
    """
    merged: dict = {}
    for path, _ in _stamp:
        try:
            with open(path) as f:
                merged.update(json.load(f))
        except (OSError, ValueError):
            continue
    return merged


def get_ground_truth(gt_id: str) -> dict | None:
    """Tra đáp án của MỘT sự kiện theo `gt_id`. Trả None nếu không có sidecar/không khớp."""
    if not gt_id:
        return None
    try:
        stamp = tuple(
            sorted(
                (os.path.join(_GT_LABELS_DIR, n), os.path.getmtime(os.path.join(_GT_LABELS_DIR, n)))
                for n in os.listdir(_GT_LABELS_DIR)
                if n.endswith(".labels.json")
            )
        )
    except OSError:
        return None
    if not stamp:
        return None
    return _load_ground_truth(stamp).get(gt_id)


def render_ground_truth(raw_log_str) -> None:
    """In ĐÁP ÁN của bộ dữ liệu ngay cạnh log thô, để đối chiếu bằng mắt.

    Log thô đã bị LOẠI mọi khoá nhãn trước khi vào Tier-1 (chống lộ nhãn) — chỉ `gt_id`
    được giữ, và nó là mã băm vô nghĩa với mô hình. Đáp án nằm ở sidecar tách rời, đọc
    tại đây và CHỈ tại đây. Không có sidecar thì im lặng, không bịa.
    """
    if not raw_log_str:
        return
    try:
        rec = json.loads(raw_log_str) if isinstance(raw_log_str, str) else raw_log_str
        gt_id = str((rec or {}).get("gt_id") or "")
    except (ValueError, TypeError, AttributeError):
        return
    gt = get_ground_truth(gt_id)
    if not gt:
        return

    techs = []
    for k in _GT_TECH_KEYS:
        v = gt.get(k)
        if isinstance(v, str) and v.strip():
            techs.append(v.strip())
        elif isinstance(v, list):
            techs.extend(str(x).strip() for x in v if str(x).strip())
    seen: list[str] = []
    for t in techs:
        if t not in seen:
            seen.append(t)

    is_attack = bool(gt.get("expected_threat") or gt.get("apt_is_attack"))
    verdict = "🔴 TẤN CÔNG" if is_attack else "🟢 LÀNH TÍNH"
    color = "#FF7875" if is_attack else "#95DE64"

    dong = [f'<span style="color:{color};font-weight:800;">{verdict}</span>']
    if gt.get("gt_label"):
        dong.append(f"nhãn <b>{html_lib.escape(str(gt['gt_label']))}</b>")
    if seen:
        dong.append(
            "kỹ thuật <code>"
            + "</code> · <code>".join(html_lib.escape(t) for t in seen)
            + "</code>"
        )
    if gt.get("wa_expected_action"):
        dong.append(
            f"hành động kỳ vọng <code>{html_lib.escape(str(gt['wa_expected_action']))}</code>"
        )
    if gt.get("unified_source"):
        dong.append(f"nguồn <i>{html_lib.escape(str(gt['unified_source']))}</i>")

    st.markdown(
        '<div style="margin-top:6px;padding:8px 10px;background:rgba(250,173,20,0.07);'
        'border-left:3px solid #FAAD14;border-radius:4px;font-size:0.85rem;color:#D9D9D9;">'
        '<span style="color:#FAAD14;font-weight:800;">📗 ĐÁP ÁN BỘ DỮ LIỆU</span> — '
        + " · ".join(dong)
        + f'<div style="opacity:0.6;font-size:0.78rem;margin-top:4px;">gt_id <code>{html_lib.escape(gt_id)}</code>'
        " · đọc từ sidecar <code>data/*.labels.json</code>, KHÔNG đi qua Tier-1/LLM</div></div>",
        unsafe_allow_html=True,
    )


def is_valid_ip(ip_str: str) -> bool:
    """Kiểm tra chuỗi IP hợp lệ (IPv4 hoặc IPv6)."""
    ip_str = ip_str.strip()
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(re.match(ipv6_pattern, ip_str))


def _derive_tier1_attack_type(reasons: list[str]) -> str:
    """Suy ra nhãn 'kiểu tấn công' ngắn gọn từ danh sách lý do Tier-1 (chữ ký/thống kê).

    Dùng cho thẻ Whitelist: IP whitelist vẫn được phân tích nên phải nêu được nó ĐANG
    làm kỹ thuật gì, dù không bị chặn. Trả nhãn tổng hợp (nối bằng ' + ').
    """
    labels: list[str] = []
    joined = " ".join(reasons)
    # WAF: "WAF: Phát hiện <loại> trong '<field>'"
    for m in re.finditer(r"WAF:\s*Phát hiện\s*([^']+?)\s*trong", joined):
        lbl = m.group(1).strip()
        if lbl and lbl not in labels:
            labels.append(lbl)
    if "Prompt Injection Pattern" in joined and "Prompt Injection" not in labels:
        labels.append("Prompt Injection")
    if "Jailbreak Pattern" in joined and "Jailbreak / Bypass" not in labels:
        labels.append("Jailbreak / Bypass")
    if ("Zero-day" in joined or "dị biệt thống kê" in joined) and (
        "Bất thường thống kê (nghi Zero-day)" not in labels
    ):
        labels.append("Bất thường thống kê (nghi Zero-day)")
    if "cổng nhạy cảm" in joined and "Truy cập cổng nhạy cảm" not in labels:
        labels.append("Truy cập cổng nhạy cảm")
    if "APT chain" in joined and "Chuỗi APT đa ngày" not in labels:
        labels.append("Chuỗi APT đa ngày")
    if not labels:
        return (
            "Không có dấu hiệu tấn công (truy cập thường)"
            if not reasons
            else "Hoạt động đáng chú ý"
        )
    return " + ".join(labels)


# ── Bộ dựng badge DÙNG CHUNG ───────────────────────────────────────────────────────
# VÌ SAO PHẢI GOM MỘT CHỖ. Cùng logic này trước đây có BA bản chép tay: thẻ cảnh báo
# (`render_alert_card`), cụm HITL trong `app.py`, và thẻ chặn Tier-1. Ba bản trôi dạt khác
# nhau, và mỗi lần sửa một giá trị bịa lại phải đi tìm đủ ba nơi — thực tế đã có bốn giá trị
# bịa phải sửa hai lần ở hai tệp. Một nguồn chân lý thì không tái diễn được.
#
# NGUYÊN TẮC CHUNG cho mọi hàm dưới đây: **không có dữ liệu thì nói là không có**, tuyệt đối
# không điền giá trị mặc định trông-như-thật (điểm 100.0, đủ 5 mã, TTFT 0.3s…).

_BADGE_RED = "background:rgba(255,77,79,0.15);color:#ff7875;border:1px solid rgba(255,77,79,0.35);"
_BADGE_CYAN = (
    "background:rgba(87,227,249,0.12);color:#57e3f9;border:1px solid rgba(87,227,249,0.3);"
)
_BADGE_GREEN = (
    "background:rgba(82,196,26,0.15);color:#95de64;border:1px solid rgba(82,196,26,0.35);"
)
_BADGE_AMBER = (
    "background:rgba(250,173,20,0.15);color:#faad14;border:1px solid rgba(250,173,20,0.35);"
)
_BADGE_BLUE = (
    "background:rgba(24,144,255,0.15);color:#69c0ff;border:1px solid rgba(24,144,255,0.35);"
)
_BADGE_PURPLE = (
    "background:rgba(114,46,209,0.15);color:#d3adf7;border:1px solid rgba(114,46,209,0.35);"
)

_GUARDRAIL_BOX = (
    "color: #faad14; margin-top: 5px; font-size: 0.83rem; background: rgba(250,173,20,0.08);"
    " padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(250,173,20,0.25);"
)

# Bắt cả mã ATT&CK Enterprise (T1190, T1059.007) lẫn mã ATLAS (AML.T0051). `_TECHNIQUE_ID_RE`
# ở tầng agent CỐ Ý không bắt AML.* — ở đây thì phải bắt, vì màn hình cần hiện cả hai họ.
_TECH_CODE_RE = re.compile(r"\b(AML\.T\d{4}|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


def parse_mitre_technique(raw_reason: str) -> str:
    """Bóc mã kỹ thuật từ chuỗi reason. Trả `"N/A"` khi không có — KHÔNG đoán thay."""
    # `[MITRE: ...]` có thể chứa ngoặc vuông lồng nhau (ví dụ "[Tự suy luận]"), nên regex
    # phải cho phép một cấp lồng thay vì dùng `[^\]]*` tham lam.
    m = re.search(r"\[MITRE:\s*((?:[^\[\]]|\[[^\[\]]*\])*)\]", raw_reason, re.IGNORECASE)
    if m and m.group(1).strip():
        return m.group(1).strip()
    if t := _TECH_CODE_RE.search(raw_reason):
        return t.group(1).upper()
    return "N/A"


# Dấu hiệu LÁ CHẮN NEO ĐÃ NỔ. Chuỗi này do `src/agent/nodes.py` đóng vào `reasoning`, và nó
# CHỈ được sinh ở nhánh lá chắn TỪ CHỐI kỹ thuật (hai chỗ: log cảnh báo và tiền tố reasoning).
# Không có chỗ nào trong hệ sinh chuỗi này với nghĩa "đã neo được".
_SHIELD_MARK = "NEO BẰNG CHỨNG"


def build_grounding_badge(raw_reason: str, mitre_tech: str) -> tuple[str, bool]:
    """Thẻ neo-bằng-chứng. Trả `(html, is_grounded)` để bên gọi dùng lại cờ.

    ĐẢO DẤU ĐÃ VÁ (2026-08-17). Bản trước viết:

        is_grounded = "NEO BẰNG CHỨNG" in raw_reason or (has_tech and ...)

    tức coi sự CÓ MẶT của dấu hiệu lá chắn là bằng chứng ĐÃ NEO ĐƯỢC — trong khi dấu hiệu
    đó chỉ xuất hiện đúng lúc lá chắn **TỪ CHỐI** kỹ thuật vì nó KHÔNG có trong tài liệu đã
    truy xuất. Hậu quả nhìn thấy trên Dashboard: một thẻ vừa in `MITRE: N/A`, vừa in dòng
    "[NEO BẰNG CHỨNG: kỹ thuật T1684 … KHÔNG nằm trong tài liệu đã truy xuất]", lại vừa gắn
    badge xanh `✅ GROUNDED IN RAG`. Ba mảnh trên cùng một thẻ nói ba điều khác nhau, và
    badge là mảnh nói sai.

    Cùng họ lỗi với `evaluate_feedback_loop` từng đếm `BLOCK_IP` là *leo thang*: đọc đúng
    tín hiệu, gán ngược ý nghĩa.

    BA TRẠNG THÁI, không phải hai — vì "lá chắn đã chặn" KHÁC "không có gì để quy kết":
      * đã neo        : có kỹ thuật, lá chắn không nổ           -> xanh
      * lá chắn chặn  : model có đề xuất, lá chắn bác bỏ        -> hổ phách, đây là an toàn
                        CHẠY ĐÚNG, không phải hỏng hóc
      * không quy kết : không có kỹ thuật nào và lá chắn im     -> hổ phách nhạt
    """
    has_tech = bool(mitre_tech and mitre_tech != "N/A" and not mitre_tech.startswith("N/A"))
    shield_fired = _SHIELD_MARK in raw_reason
    is_grounded = has_tech and not shield_fired and "unmappable" not in raw_reason.lower()

    if is_grounded:
        return f'<span class="soc-badge" style="{_BADGE_GREEN}">✅ GROUNDED IN RAG</span>', True
    if shield_fired:
        return (
            f'<span class="soc-badge" style="{_BADGE_AMBER}">🛡️ LÁ CHẮN NEO ĐÃ CHẶN</span>',
            False,
        )
    return (
        f'<span class="soc-badge" style="{_BADGE_AMBER}">🛡️ DEGRADED SAFEGUARD (N/A)</span>',
        False,
    )


def build_origin_badge(raw_reason: str) -> str:
    """Nguồn phán quyết: bộ đệm ngữ nghĩa hay suy luận thật trên GPU.

    KHÔNG kèm số thời gian. Thẻ này chỉ phân biệt NGUỒN, nó không đo gì cả — bản cũ ghi
    "(TTFT 0.3s)" cho mọi lô, một con số không đến từ phép đo nào.
    """
    low = raw_reason.lower()
    if "PHÁN QUYẾT TÁI SỬ DỤNG" in raw_reason or "responsecache" in low or "tái sử dụng" in low:
        return f'<span class="soc-badge" style="{_BADGE_PURPLE}">⚡ Semantic Cache Hit</span>'
    return f'<span class="soc-badge" style="{_BADGE_BLUE}">🧠 Live GPU</span>'


def build_threat_memory_badge(raw_reason: str, reputation: dict | None = None) -> str:
    """Lịch sử uy tín IP — ƯU TIÊN bản ghi THẬT trong kho, chỉ đọc câu văn khi không có.

    `reputation`: hàng `ip_reputation` lấy từ `ThreatMemoryStore.get_ip_reputation(ip)`.

    VÌ SAO PHẢI TRUYỀN VÀO. Bản cũ CHỈ regex trên `raw_reason`, mà chuỗi "reputation score
    of X/100" chỉ có mặt khi prompt đã nhét ngữ cảnh Threat Memory vào — tức khi IP ĐÃ có
    tiền sử lúc gọi LLM. Với IP lần đầu bị chặn, câu văn không có số, nên badge in "chưa có
    dữ liệu uy tín" TRONG KHI kho đã ghi `reputation_score = 100`. Đo thật trên
    `203.0.113.159`: kho có `total_blocks=2, reputation_score=100.0`, màn hình vẫn nói chưa
    có gì. Cùng một bệnh với việc phân tab bằng cách dò chuỗi.

    CHỈ hiện phần biết chắc. Bản cũ hơn nữa còn mặc định `reputation = "100.0"` khi không
    parse được, nên IP sạch cũng hiện Risk 100/100.
    """
    if isinstance(reputation, dict) and reputation:
        blk = int(reputation.get("total_blocks") or 0)
        alr = int(reputation.get("total_alerts") or 0)
        hits = int(reputation.get("blocked_hits") or 0)
        rep_v = reputation.get("reputation_score")
        # `blocked_hits` = gói đến từ IP ĐÃ bị chặn (chặn tại chỗ). Tách hẳn khỏi số LẦN CHẶN
        # vì chính sách là "2 ALERT -> 1 BLOCK, chặn rồi thì thôi" — gộp hai thứ vào một cột
        # từng làm một IP hiện "24 lần chặn" trong khi sổ kiểm toán có 0 lệnh chặn cho nó.
        phan = []
        if blk:
            phan.append(f"{blk} lần chặn")
        if alr:
            phan.append(f"{alr} cảnh báo")
        if hits:
            phan.append(f"{hits} gói chặn tại chỗ")
        if rep_v is not None:
            phan.append(f"điểm {float(rep_v):.0f}/100")
        if phan:
            return (
                f'<span class="soc-badge" style="{_BADGE_RED}">'
                f"📜 Threat Memory: {' · '.join(phan)}</span>"
            )

    inc_m = re.search(r"(\d+)\s+incidents", raw_reason, re.IGNORECASE)
    blk_m = re.search(r"(\d+)\s+blocks", raw_reason, re.IGNORECASE)
    score_m = re.search(
        r"reputation score of ([\d.]+)/100|điểm rủi ro:?\s*(\d+)", raw_reason, re.IGNORECASE
    )
    inc = int(inc_m.group(1)) if inc_m else None
    blk = int(blk_m.group(1)) if blk_m else None
    rep = (score_m.group(1) or score_m.group(2)) if score_m else None
    risk = f" · Risk: {rep}/100" if rep else ""

    if inc is not None and blk is not None:
        rem = max(0, inc - blk)
        rem_s = f" · {rem} HITL/Audit" if rem > 0 else ""
        body = f"{inc} sự cố ({blk} Block{rem_s}){risk}"
    elif inc is not None:
        body = f"{inc} sự cố{risk}"
    elif rep:
        body = f"Risk {rep}/100"
    else:
        return (
            f'<span class="soc-badge" style="{_BADGE_CYAN}">📜 Threat Memory: chưa có điểm</span>'
        )
    return f'<span class="soc-badge" style="{_BADGE_RED}">📜 Threat Memory: {body}</span>'


def build_technique_codes_html(raw_reason: str) -> str:
    """Các mã kỹ thuật NÊU TRONG phán quyết. Không có mã nào thì trả `""` (ẩn hẳn khối).

    Bản cũ độn `["T1190","T1595.003","T1059.007","T1083","T1046"]` cho đủ 5 rồi dán nhãn
    "Top-5 Ứng viên RAG Truy xuất (FAISS + BM25)" — tức gán cho bộ truy xuất những mã nó chưa
    từng trả về. Nhãn nay nói đúng thứ đang hiện: mã đọc được từ chuỗi phán quyết.

    VÁ 2026-08-17 — KHI LÁ CHẮN NEO ĐÃ NỔ, ĐÂY LÀ MÃ BỊ BÁC BỎ, KHÔNG PHẢI PHÁT HIỆN.
    Cùng một thẻ cảnh báo từng hiện: `MITRE: N/A` ở trên, dòng "[NEO BẰNG CHỨNG: kỹ thuật
    T1684 … KHÔNG nằm trong tài liệu]" ở giữa, rồi `🔍 Mã kỹ thuật nêu trong phán quyết (2):
    T1684 · T1036.012` ở dưới — in bằng cùng màu xanh thông tin như mọi phát hiện hợp lệ.
    Analyst đọc lướt sẽ ghi T1684 vào hồ sơ sự cố, đúng cái mã mà hệ vừa từ chối khẳng định.
    """
    seen: list[str] = []
    for c in _TECH_CODE_RE.findall(raw_reason):
        cu = c.upper()
        if cu not in seen:
            seen.append(cu)
    if not seen:
        return ""
    shown = seen[:5]
    rejected = _SHIELD_MARK in raw_reason

    if rejected:
        color, bg = "#FFB454", "rgba(255,180,84,0.15)"
        nhan = f"Mã model ĐỀ XUẤT nhưng lá chắn BÁC BỎ ({len(shown)}):"
        duoi = " — không có trong tài liệu RAG của lô này, <b>đừng ghi vào hồ sơ sự cố</b>"
    else:
        color, bg = "#69c0ff", "rgba(24,144,255,0.15)"
        nhan = f"Mã kỹ thuật nêu trong phán quyết ({len(shown)}):"
        duoi = ""

    badges = " · ".join(
        f'<code style="color:{color};background:{bg};padding:1px 5px;'
        f'border-radius:3px;font-size:0.8rem;">{html_lib.escape(c)}</code>'
        for c in shown
    )
    return (
        f'<div class="soc-reasoning-section" style="color: {color}; margin-top: 6px; font-size: 0.82rem;">'
        f"  🔍 <b>{nhan}</b> {badges}{duoi}"
        "</div>"
    )


_OVERRIDE_RE = re.compile(r"\[CHÍNH SÁCH:\s*model đề nghị\s+(\w+)\s*->\s*hệ thực thi\s+(\w+)\]")


def build_policy_override_note(raw_reason: str) -> str:
    """Khối nói rõ CHÍNH SÁCH ĐÃ GHI ĐÈ model. Rỗng khi hai hành động trùng nhau.

    VÌ SAO CẦN. Phần biện giải của model hay kết bằng "Therefore, the action is BLOCK_IP",
    trong khi tiêu đề thẻ ghi `[HIGH] ALERT`. Không có khối này thì thẻ tự mâu thuẫn ngay
    trước mắt người đọc, và cách hiểu tự nhiên nhất là "màn hình hiển thị sai" — trong khi
    sự thật là hệ ĐÃ CỐ Ý hạ cấp, và đó chính là cơ chế an toàn đáng khoe nhất.

    Nhãn `[CHÍNH SÁCH: …]` do `src/agent/nodes.py::_policy_override_tag` ghi vào `reason`
    từ trường `_policy_action_before` — tức đọc DỮ LIỆU đã lưu, không suy từ câu chữ model.
    """
    m = _OVERRIDE_RE.search(raw_reason or "")
    if not m:
        return ""
    # Hai giá trị này đến từ `reason` — chuỗi mà LLM đã góp phần sinh ra, nên vẫn phải thoát
    # và đặt tên `safe_` đúng quy ước của tệp (xem `test_ma_mitre_khong_duoc_nhung_tho_vao_html`).
    safe_want = html_lib.escape(m.group(1))
    safe_got = html_lib.escape(m.group(2))
    return (
        f'<div style="{_GUARDRAIL_BOX}">  ⚖️ <b>Chính sách ghi đè model:</b> '
        f"model đề nghị <code>{safe_want}</code>, hệ thống thực thi <code>{safe_got}</code>. "
        "Đoạn biện giải bên dưới là lập luận CỦA MODEL nên vẫn nói "
        f"<code>{safe_want}</code> — hành động thật của hệ là <code>{safe_got}</code>.</div>"
    )


def build_guardrail_note(
    is_grounded: bool, mitre_tech: str, action: str, raw_reason: str = ""
) -> str:
    """Ghi chú chính sách Guardrail — chỉ hiện cho ca bị ép hạ xuống `AWAIT_HITL`.

    `raw_reason` để phân biệt "lá chắn đã bác một đề xuất cụ thể" với "không có gì để quy
    kết". Bản trước gộp hai ca đó vào cùng một câu "Không chắc kỹ thuật MITRE cụ thể", nên
    analyst không đọc ra được rằng model ĐÃ đề xuất một mã và hệ đã chủ động bác nó.
    """
    if action.upper() != "AWAIT_HITL":
        return ""
    if _SHIELD_MARK in raw_reason:
        body = (
            "Model có đề xuất một mã kỹ thuật, nhưng mã đó <b>không nằm trong tài liệu RAG "
            "đã truy xuất cho chính lô này</b> ➔ lá chắn neo bác bỏ, hạ kỹ thuật về "
            "<code>N/A</code> và chuyển <code>AWAIT_HITL</code>. Đây là lá chắn CHẠY ĐÚNG, "
            "không phải lỗi."
        )
    elif is_grounded and mitre_tech and mitre_tech != "N/A":
        body = (
            f"Nhận diện mã kỹ thuật <code>{html_lib.escape(mitre_tech)}</code>, nhưng chưa chắc "
            "bằng chứng payload (chỉ có tín hiệu tổng quát/cổng lạ) ➔ Tự động ép hạ "
            "<code>AWAIT_HITL</code>."
        )
    else:
        body = (
            "Không chắc kỹ thuật MITRE cụ thể (hạ về N/A) ➔ Tự động ép hạ "
            "<code>AWAIT_HITL</code> cho L3 Analyst duyệt."
        )
    return f'<div style="{_GUARDRAIL_BOX}">  🛡️ <b>Guardrail Policy (AGENTS.md):</b> {body}</div>'


def build_tier1_block_badge(count: int, tier1_score) -> str:
    """Thẻ cho bảng "Chặn tức thời Tier-1" — nguồn là `config/tier1_blocks.json`.

    KHÔNG dùng `build_threat_memory_badge` ở đây: hai nguồn dữ liệu khác nhau.
    - Threat Memory = kho uy tín SQLite, thang 0–100 (ngưỡng chặn 70).
    - `tier1_score` = bộ CỘNG DỒN của rule engine, KHÔNG chặn trên (+50/+40/+30/+100/+z…).

    Bản cũ in `Risk: {tier1_score}/100` nên hai luật cùng khớp là ra "Risk: 150/100" — một
    phần trăm bất khả thi; và in `{count} sự cố ({count} Block)`, tức cùng một biến hiện hai
    lần như thể hai con số độc lập xác nhận nhau.
    """
    return (
        f'<span class="soc-badge" style="{_BADGE_RED}">'
        f"⚡ Tier-1 Rule Engine: {count} lần chặn · điểm luật {tier1_score}</span>"
    )


def _build_mitre_hierarchy_html(mitre_tech: str) -> str:
    """Xây dựng Cây Phân rã MITRE ATT&CK: Tactic -> Technique -> Sub-technique."""
    tech_upper = mitre_tech.upper()

    if "AML.T0051" in tech_upper or "PROMPT INJECTION" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">Framework: MITRE ATLAS</span> ➔ '
            '<span style="color:#69c0ff;">Tactic: LLM Attack Vector</span> ➔ '
            '<span style="color:#b7eb8f;">Technique: AML.T0051 - Prompt Injection</span>'
            "</div>"
        )

    if "T1110.004" in tech_upper or "CREDENTIAL STUFFING" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">TA0006 (Credential Access)</span> ➔ '
            '<span style="color:#69c0ff;">T1110 (Brute Force)</span> ➔ '
            '<span style="color:#b7eb8f;">T1110.004 (Credential Stuffing)</span>'
            "</div>"
        )
    elif "T1110" in tech_upper or "BRUTE FORCE" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">TA0006 (Credential Access)</span> ➔ '
            '<span style="color:#69c0ff;">T1110 (Brute Force)</span>'
            "</div>"
        )

    if "T1190" in tech_upper or "EXPLOIT" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">TA0001 (Initial Access)</span> ➔ '
            '<span style="color:#69c0ff;">T1190 (Exploit Public-Facing Application)</span>'
            "</div>"
        )

    if "T1595.003" in tech_upper or "WORDLIST SCANNING" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">TA0043 (Reconnaissance)</span> ➔ '
            '<span style="color:#69c0ff;">T1595 (Active Scanning)</span> ➔ '
            '<span style="color:#b7eb8f;">T1595.003 (Wordlist Scanning)</span>'
            "</div>"
        )

    if "T1059.007" in tech_upper or "JAVASCRIPT" in tech_upper:
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            "  🎯 <b>Cây Phân rã MITRE:</b> "
            '<span style="color:#ffa940;">TA0002 (Execution)</span> ➔ '
            '<span style="color:#69c0ff;">T1059 (Command & Scripting)</span> ➔ '
            '<span style="color:#b7eb8f;">T1059.007 (JavaScript Execution)</span>'
            "</div>"
        )

    m_id = re.search(r"T(\d{4})(?:\.(\d{3}))?", tech_upper)
    if m_id:
        t_id = f"T{m_id.group(1)}"
        sub_id = f"T{m_id.group(1)}.{m_id.group(2)}" if m_id.group(2) else ""
        if sub_id:
            return (
                '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
                f'  🎯 <b>Cây Phân rã MITRE:</b> <span style="color:#ffa940;">TA0001 (Security Event)</span> ➔ '
                f'<span style="color:#69c0ff;">{t_id} (Parent Technique)</span> ➔ '
                f'<span style="color:#b7eb8f;">{sub_id} (Sub-Technique)</span>'
                "</div>"
            )
        return (
            '<div class="soc-reasoning-section" style="color: #d3adf7; margin-top: 6px; font-size: 0.83rem;">'
            f'  🎯 <b>Cây Phân rã MITRE:</b> <span style="color:#ffa940;">TA0001 (Security Event)</span> ➔ '
            f'<span style="color:#69c0ff;">{t_id} (Primary Technique)</span>'
            "</div>"
        )

    return ""


def render_alert_card(
    alert,
    is_l3_manager=False,
    on_whitelist=None,
    on_block=None,
    card_id="",
    is_whitelisted=False,
    is_blocked=False,
    is_tampered=False,
    reputation=None,
):
    """Hiển thị một cảnh báo bảo mật từ audit_trail với giao diện SOC Premium.

    `reputation`: hàng `ip_reputation` của IP đích (nếu nơi gọi tra sẵn được). Truyền vào thì
    badge Threat Memory đọc SỐ THẬT trong kho thay vì regex trên câu văn — xem
    `build_threat_memory_badge`.
    """
    timestamp = alert.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted_time = html_lib.escape(str(timestamp))

    action = str(alert.get("action", "UNKNOWN")).upper()
    target = html_lib.escape(str(alert.get("target", "N/A")))
    raw_reason = str(alert.get("reason", "N/A"))

    # ── Thẻ RIÊNG cho truy cập được WHITELIST cho qua ──────────────────────────
    # IP whitelist VẪN được Tier-1 phân tích đầy đủ (kiểu tấn công + suy luận) để
    # analyst QUAN SÁT — hiển thị bằng thẻ XANH "cho qua". Khác thẻ tấn công ở chỗ:
    # đã đặc cách nên KHÔNG bị chặn / không escalate LLM / không HITL. Nhờ vậy lần
    # chạy thứ 2 vẫn thấy được hành vi của IP whitelist thay vì bị nuốt lặng.
    if action == "WHITELIST":
        # Lấy phân tích Tier-1 từ raw_log (tier1_reasons/score) — nguồn "kiểu tấn công + suy luận".
        _wl_raw = alert.get("raw_log") if isinstance(alert, dict) else None
        _wl_reasons: list[str] = []
        _wl_score = None
        if _wl_raw:
            try:
                _wl_obj = json.loads(_wl_raw)
                _wl_reasons = [str(x) for x in (_wl_obj.get("tier1_reasons") or [])]
                _wl_score = _wl_obj.get("tier1_score")
            except Exception:
                _wl_reasons = []
        attack_type = _derive_tier1_attack_type(_wl_reasons)
        score_txt = f" · điểm Tier-1 {_wl_score}" if _wl_score is not None else ""

        reasons_html = (
            "".join(
                f'<li style="margin-bottom:3px;">{html_lib.escape(r)}</li>' for r in _wl_reasons
            )
            or '<li style="color:#95de64;">Không có dấu hiệu tấn công — truy cập thường.</li>'
        )

        wl_html = (
            '<div class="soc-card" style="border-left:4px solid #52c41a;'
            'background:rgba(82,196,26,0.06);">'
            '<div class="soc-card-header">'
            '<h4 class="soc-card-title">✅ [WHITELIST] Truy cập được CHO QUA (không chặn)</h4>'
            '<span class="soc-badge" style="background:rgba(82,196,26,0.2);color:#95de64;'
            "border:1px solid rgba(82,196,26,0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🟢 Tier-1 Filter</span>'
            f'<span class="soc-timestamp">{formatted_time}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-label">IP nguồn:</span>'
            f'<span class="soc-value-code">{target}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-label">Kiểu phát hiện (Tier-1):</span>'
            f'<span class="soc-value-code" style="color:#ffa940;">{html_lib.escape(attack_type)}</span>'
            f'<span style="color:#8c8c8c;font-size:0.8rem;">{html_lib.escape(score_txt)}</span>'
            "</div>"
            '<div class="soc-reasoning-box" style="margin-top:8px;">'
            '<div class="soc-reasoning-title">🔎 Suy luận Tier-1 (để giám sát, KHÔNG dùng LLM):</div>'
            f'<ul style="margin:6px 0 0 18px;font-size:0.85rem;color:#d9d9d9;">{reasons_html}</ul>'
            "</div>"
            '<div class="soc-detail-row" style="margin-top:8px;">'
            '<span class="soc-badge" style="background:rgba(82,196,26,0.15);'
            'color:#95de64;border:1px solid rgba(82,196,26,0.35);">'
            "✅ WHITELIST · đặc cách CHO QUA — không chặn / không escalate</span>"
            "</div>"
            "</div>"
        )
        st.markdown("".join(line.strip() for line in wl_html.split("\n")), unsafe_allow_html=True)
        with st.expander("🔍 Xem LOG THÔ (Raw Flow từ IP Whitelist)", expanded=False):
            if _wl_raw:
                render_ground_truth(_wl_raw)
                try:
                    st.json(json.loads(_wl_raw))
                except Exception:
                    st.code(str(_wl_raw))
            else:
                st.caption("Không có log thô đính kèm.")
        return

    # Bóc tách Regex từ chuỗi Reason
    mitre_tech = parse_mitre_technique(raw_reason)
    confidence = "Chưa rõ"

    conf_match = re.search(
        r"(?:Confidence|Độ\s+tin\s+cậy):\s*([01]?\.\d+|1(?:\.0)?|\d+(?:\.\d+)?%)",
        raw_reason,
        re.IGNORECASE,
    )
    if conf_match:
        try:
            val_str = conf_match.group(1)
            if val_str.endswith("%"):
                confidence = val_str
            else:
                val = float(val_str)
                # 2 chữ số thập phân, ĐỒNG NHẤT với Cổng ML và với chuỗi reason mới
                # (đã ghi sẵn dạng "40.00%"). Trước đây làm tròn về số nguyên nên bản
                # ghi cũ/định dạng float hiển thị "95%" còn bản ghi mới "95.00%".
                confidence = f"{val * 100:.2f}%"
        except ValueError:
            pass

    # Xử lý chống Stored XSS cho các biến trích xuất động
    mitre_tech = html_lib.escape(mitre_tech)
    confidence = html_lib.escape(confidence)

    # Phân cấp mức độ nghiêm trọng (Severity) dựa trên Risk Score & Action
    severity_level = "INFO"
    css_class = "severity-info"
    icon = "ℹ️"

    if action == "BLOCK_IP":
        severity_level = "CRITICAL"
        css_class = "severity-critical"
        icon = "🛑"
    elif action == "ALERT":
        severity_level = "HIGH"
        css_class = "severity-high"
        icon = "⚠️"
    elif action == "AWAIT_HITL":
        severity_level = "MEDIUM"
        css_class = "severity-medium"
        icon = "🧑‍💻"

    action_translations = {
        "BLOCK_IP": "BLOCK IP",
        "ALERT": "ALERT",
        "AWAIT_HITL": "AWAIT HITL",
        "LOG": "LOG",
        "WHITELIST": "WHITELIST",
    }
    action_display = action_translations.get(action, action)

    is_self_inferred = "Self-inferred" in raw_reason or "Tự suy luận" in raw_reason
    inference_badge = ""
    if is_self_inferred:
        inference_badge = '<span class="soc-badge" style="background:rgba(250, 173, 20, 0.15); color:#faad14; border:1px solid rgba(250, 173, 20, 0.35); margin-left:4px;">🤖 Self-Inferred</span>'

    override_note_html = build_policy_override_note(raw_reason)

    clean_reason = html_lib.escape(raw_reason)
    clean_reason = re.sub(
        r"\[MITRE:(?:[^\[\]]|\[[^\[\]]*\])*\]", "", clean_reason, flags=re.IGNORECASE
    )
    # Nhãn ghi đè đã được tách ra thành khối riêng ở trên -> gỡ khỏi đoạn văn để khỏi lặp.
    clean_reason = re.sub(r"\[CHÍNH SÁCH:[^\]]*\]", "", clean_reason).strip()
    clean_reason = re.sub(
        r"\[(?:Confidence|Độ\s+tin\s+cậy):\s*[^\]]*\]", "", clean_reason, flags=re.IGNORECASE
    ).strip()

    if clean_reason.startswith("]"):
        clean_reason = clean_reason[1:].strip()

    clean_reason = clean_reason.replace("\n", "<br>")

    reason_text = raw_reason
    # NGUỒN CHÂN LÝ là cột `tier` do chính tầng ra quyết định ghi vào audit_trail. Dò chuỗi
    # chỉ dùng cho bản ghi có TRƯỚC khi thêm cột. Huy hiệu trên thẻ là thứ analyst nhìn đầu
    # tiên; để nó suy từ văn xuôi thì một sự cố Tier-2 có cụm "Tier-1" trong lý do sẽ đeo
    # nhầm huy hiệu Tier-1 — ngay cạnh cái tab đã phân loại nó đúng.
    _tier_col = str(alert.get("tier") or "") if isinstance(alert, dict) else ""
    if _tier_col:
        is_manual = _tier_col == TIER_MANUAL
        is_llm = _tier_col == TIER_LLM
        is_ml_tier = _tier_col == TIER_ML
        is_tier1 = _tier_col == TIER_RULE
    else:
        is_manual = (
            "Manual" in reason_text
            or "MANUAL" in reason_text.upper()
            or "Chặn thủ công" in reason_text
        )
        is_llm = (
            reason_text.startswith("[REASON:")
            or reason_text.startswith("[MITRE:")
            or reason_text.startswith("[LÝ DO:")
        )
        is_ml_tier = not is_manual and not is_llm and any(k in reason_text for k in ML_GATE_MARKERS)
        is_tier1 = (
            not is_manual
            and not is_llm
            and not is_ml_tier
            and ("Tier-1" in reason_text or "whitelist" in reason_text.lower())
        )

    if is_manual:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(24,144,255,0.2);color:#1890ff;'
            "border:1px solid rgba(24,144,255,0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🔧 Manual Action</span>'
        )
        reasoning_title = "🔧 Manual Action Note:"
        mitre_section_text = "🎯 MITRE ATT&CK Mapping: <code>N/A (Manual Action)</code>"
    elif is_tier1:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(82, 196, 26, 0.2);color:#95de64;'
            "border:1px solid rgba(82, 196, 26, 0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🟢 Tier-1 Filter</span>'
        )
        reasoning_title = "⚡ Tier-1 Rule/Filter Reasoning:"
        mitre_section_text = "🎯 Mapping: Initial analysis from raw log telemetry"
    elif is_ml_tier:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(250, 173, 20, 0.2);color:#faad14;'
            "border:1px solid rgba(250, 173, 20, 0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">⚡ Tier-1 · ML Gate</span>'
        )
        reasoning_title = "⚡ Tier-1 ML Gate Reasoning (LightGBM):"
        # KHÔNG điền mã thay khi hệ trả N/A. Trước đây chỗ này in sẵn "T1190 - Exploit
        # Public-Facing Application" cho MỌI ca không quy kết được — tức màn hình công bố
        # một kỹ thuật mà hệ chưa hề kết luận. N/A là kết quả thật, phải hiện đúng N/A.
        mitre_section_text = f"🎯 MITRE ATT&CK Mapping: <code>{mitre_tech}</code>"
        if mitre_tech == "N/A":
            mitre_section_text = (
                "🎯 MITRE ATT&CK Mapping: <code>N/A</code> — chưa quy kết được kỹ thuật"
            )
    else:
        tier_badge = (
            '<span class="soc-badge" style="background:rgba(24,144,255,0.2);color:#69c0ff;'
            "border:1px solid rgba(24,144,255,0.4);font-size:0.75rem;padding:2px 8px;"
            'border-radius:4px;margin-left:8px;">🧠 Tier-2 · LLM Agent</span>'
        )
        reasoning_title = "🤖 Agentic LLM Reasoning (Foundation-Sec-8B):"
        mitre_section_text = f"🎯 MITRE ATT&CK Mapping: <code>{mitre_tech}</code>"
        if mitre_tech == "N/A":
            mitre_section_text = (
                "🎯 MITRE ATT&CK Mapping: <code>N/A</code> — chưa quy kết được kỹ thuật"
            )

    # ── KHUYẾN NGHỊ PHẢN HỒI — LÀ CHÍNH SÁCH CỦA HỆ, KHÔNG PHẢI TRÍCH DẪN ────────────
    #
    # LỖI ĐÃ SỬA 17/08/2026 — TRÍCH DẪN BỊA. Bốn dòng này từng in
    #     "NIST Incident Response Playbook (Section 3.2.1): Execute emergency containment…"
    # và sai ở ba tầng cùng lúc:
    #
    #   1. Chuỗi được chọn THUẦN theo `severity_level` — một bảng tra cứng, không có một
    #      lượt truy xuất nào. Nhưng nó nằm ngay dưới khối quy kết, in màu như tri thức
    #      lấy từ kho, nên đọc như thể đã tra tài liệu.
    #   2. Kho NIST của chính dự án (`knowledge_base/nist_800_61r2.json`) gồm 13 playbook
    #      khoá `NIST.IR.*` — KHÔNG có mục nào đánh số "3.2.x". Số mục đó không tồn tại
    #      trong nguồn mà hệ thống thật sự đọc.
    #   3. Đối chiếu bản gốc SP 800-61r2 thì số mục còn SAI: §3.2 là "Detection and
    #      Analysis" (3.2.1 Attack Vectors · 3.2.2 Signs of an Incident · 3.2.3 Sources of
    #      Precursors and Indicators). Ngăn chặn nằm ở §3.3.1 "Choosing a Containment
    #      Strategy". Thẻ ghi "Section 3.2.1: Execute emergency containment" là gán hành
    #      động ngăn chặn cho mục nói về véc-tơ tấn công.
    #
    # Cùng họ lỗi "đúng ID sai tên" mà `verify_technique_label` đã chặn cho MITRE — chỉ
    # khác là ở đây trích dẫn được BỊA hẳn. Một hội đồng thuộc SP 800-61r2 bắt được ngay.
    #
    # Nay gọi đúng tên: đây là bảng ánh xạ mức nghiêm trọng -> hành động của HỆ. Muốn trích
    # dẫn thật thì phải hiển thị playbook mà bộ truy xuất trả về cho chính lô này.
    nist_playbook_text = (
        "🛡️ Khuyến nghị phản hồi (chính sách hệ thống): ghi nhận sự kiện và tiếp tục "
        "giám sát hành vi."
    )
    if severity_level == "CRITICAL":
        nist_playbook_text = (
            "🛡️ Khuyến nghị phản hồi (chính sách hệ thống): ngăn chặn khẩn cấp — chặn IP "
            "nguồn tại tường lửa để cô lập phạm vi tấn công."
        )
    elif severity_level == "HIGH":
        nist_playbook_text = (
            "🛡️ Khuyến nghị phản hồi (chính sách hệ thống): cảnh báo ưu tiên cao tới "
            "chuyên viên L1/L3; đưa IP vào danh sách theo dõi rủi ro cao."
        )
    elif severity_level == "MEDIUM":
        nist_playbook_text = (
            "🛡️ Khuyến nghị phản hồi (chính sách hệ thống): cần chuyên viên duyệt (HITL) "
            "trước khi kích hoạt luật chặn tự động."
        )

    # ── Badge: dùng bộ dựng CHUNG (xem đầu tệp) để thẻ này, cụm HITL trong app.py và
    # thẻ chặn Tier-1 không còn trôi dạt khỏi nhau.
    grounding_badge, is_grounded = build_grounding_badge(raw_reason, mitre_tech)
    origin_badge = build_origin_badge(raw_reason)
    rep_badge = build_threat_memory_badge(raw_reason, reputation)
    mitre_hierarchy_html = _build_mitre_hierarchy_html(mitre_tech)
    rag_candidates_html = build_technique_codes_html(raw_reason)
    guardrail_note_html = build_guardrail_note(is_grounded, mitre_tech, action, raw_reason)

    # Render HTML Card
    html_content = (
        f'<div class="soc-card {css_class}">'
        f'    <div class="soc-card-header">'
        f'        <h4 class="soc-card-title">{icon} [{severity_level}] {action_display}</h4>'
        f"        {tier_badge}"
        f'        <span class="soc-timestamp">{formatted_time}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">IP Mục tiêu:</span>'
        f'        <span class="soc-value-code">{target}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row" style="flex-wrap:wrap;gap:4px;">'
        f'        <span class="soc-label">Ngữ cảnh:</span>'
        f'        <span class="soc-badge soc-mitre-badge">MITRE: {mitre_tech}</span>'
        f'        <span class="soc-badge soc-conf-badge">Độ tin cậy: {confidence}</span>'
        f"        {inference_badge}"
        f"        {grounding_badge}"
        f"        {origin_badge}"
        f"        {rep_badge}"
        f"    </div>"
        f'    <div class="soc-reasoning-box">'
        f'        <div class="soc-reasoning-title">{reasoning_title}</div>'
        # Đặt TRƯỚC đoạn biện giải: người đọc phải biết "đây là lời model, không phải hành
        # động của hệ" TRƯỚC khi đọc câu "the action is BLOCK_IP" ở cuối đoạn.
        f"        {override_note_html}"
        f'        <div style="margin-bottom: 8px;">{clean_reason}</div>'
        f'        <div class="soc-reasoning-section" style="color: #D3ADF7;">{mitre_section_text}</div>'
        f"        {mitre_hierarchy_html}"
        f"        {rag_candidates_html}"
        f"        {guardrail_note_html}"
        f'        <div style="color: #98FB98; margin-top: 4px; font-size: 0.85rem; font-weight: 500;">{nist_playbook_text}</div>'
        f"    </div>"
        f"</div>"
    )

    # Nén HTML để tránh khoảng trắng dọc của Streamlit
    clean_html = "".join([line.strip() for line in html_content.split("\n")])
    st.markdown(clean_html, unsafe_allow_html=True)

    # Nút Whitelist và Block IP dành cho mọi alert có target là IP hợp lệ
    cleaned_target = target.strip()
    if is_valid_ip(cleaned_target):
        st.write("")
        col_btn1, col_btn2 = st.columns([1, 4])
        with col_btn1:
            if on_whitelist:
                # Nếu có truyền callback, hiển thị nút Whitelist
                if is_l3_manager:
                    if is_whitelisted:
                        st.button(
                            f"✅ Đã Whitelist: {cleaned_target}",
                            key=f"wl_btn_done_{cleaned_target}_{timestamp}_{card_id}",
                            disabled=True,
                        )
                    elif st.button(
                        f"🛡️ Whitelist IP: {cleaned_target}",
                        key=f"wl_btn_{cleaned_target}_{timestamp}_{card_id}",
                    ):
                        on_whitelist(cleaned_target)
                        st.success(f"IP {cleaned_target} đã được thêm vào Whitelist thành công!")
                        st.rerun()
                else:
                    st.button(
                        f"🛡️ Whitelist IP: {cleaned_target}",
                        key=f"wl_btn_dis_{cleaned_target}_{timestamp}_{card_id}",
                        disabled=True,
                        help="💡 Yêu cầu vai trò L3 Manager để whitelist IP này.",
                    )
        with col_btn2:
            if on_block and action != "BLOCK_IP":
                if is_l3_manager:
                    if is_blocked:
                        st.button(
                            f"✅ Đã Block: {cleaned_target}",
                            key=f"blk_btn_done_{cleaned_target}_{timestamp}_{card_id}",
                            disabled=True,
                        )
                    elif st.button(
                        f"🛑 Block IP: {cleaned_target}",
                        key=f"blk_btn_{cleaned_target}_{timestamp}_{card_id}",
                    ):
                        on_block(cleaned_target)
                        st.success(f"IP {cleaned_target} đã được thêm vào Blocklist thành công!")
                        st.rerun()
                else:
                    st.button(
                        f"🛑 Block IP: {cleaned_target}",
                        key=f"blk_btn_dis_{cleaned_target}_{timestamp}_{card_id}",
                        disabled=True,
                        help="💡 Yêu cầu vai trò L3 Manager để Block IP này.",
                    )

    # LOG THÔ ĐẦU VÀO (đặc trưng luồng đã loại nhãn) — chính là dữ liệu đã đưa vào
    # Tier-1/LLM, KHÔNG phải bản ghi quyết định. Minh bạch "cái gì đã vào hệ thống".

    # Tạo tiêu đề động cho Expander chứa Log thô
    mitre_display_title = mitre_tech if mitre_tech != "N/A" else "Không xác định"
    expander_title = f"🔍 Xem LOG THÔ ĐẦY ĐỦ (Minh chứng cho {mitre_display_title})"

    with st.expander(expander_title, expanded=False):
        # Mô tả cũ ("log đặc trưng tiêu biểu … chỉ lưu log đại diện để tiết kiệm DB") là SAI:
        # audit_trail lưu TRỌN bản ghi đã đưa vào Tier-1 (đo thật: 106 trường, gồm đủ đặc
        # trưng luồng CICIDS + tier1_reasons + tier1_score). Nói đúng để còn audit tận gốc.
        st.caption(
            f"ℹ️ **Toàn bộ log thô** đã được đưa vào Tier-1 cho IP {cleaned_target} — đúng thứ "
            "hệ thống nhìn thấy khi ra quyết định, không cắt bớt trường nào. Chỉ LOẠI nhãn/đáp "
            "án của bộ dữ liệu để chống lộ nhãn (Label Leakage)."
        )
        raw_log_str = alert.get("raw_log") if isinstance(alert, dict) else None
        if raw_log_str:
            render_ground_truth(raw_log_str)
            try:
                st.json(json.loads(raw_log_str))
            except (ValueError, TypeError):
                st.code(str(raw_log_str), language="json")
        else:
            st.caption(
                "⚠️ Bản ghi này chưa đính kèm log thô (được tạo trước khi bật tính năng, "
                "hoặc là hành động thủ công). Hiển thị bản ghi quyết định thay thế:"
            )
            st.json(alert)


def render_ioc_table(iocs):
    """Hiển thị danh sách IOC trích xuất được."""
    if not iocs:
        st.info("Không có IOC nào được ghi nhận.")
        return

    df = pd.DataFrame(iocs)
    st.dataframe(df, width="stretch")


def render_metrics_header(
    all_alerts,
    pending_rules,
    active_rules,
    total_raw_logs=0,
    live_fpr=None,
    t1_blocks=None,
    offload_counts=None,
    blocks_by_tier=None,
):
    """Hiển thị Header KPI chuẩn SOC SIEM bằng HTML Glassmorphism.

    CHỈ MỘT chỉ số phần trăm: xả tải LLM = 1 − (`escalated_to_llm` / log thô).

    Tham số `noise_reduction` cũ đã BỎ. Nó là đại lượng khác — (log thô − cảnh báo gửi
    analyst) / log thô — và luôn cao hơn ~11 điểm vì một lô nhiều log gộp thành 1 cảnh báo.
    Hai phần trăm đứng cạnh nhau chỉ khiến người đọc trích nhầm số nào cũng thấy "đúng".

    offload_counts: dict `offload_counts` nguyên văn từ `config/pipeline_stats.json`.
    """
    # ---- Phễu: MỘT nguồn duy nhất, KHÔNG trần -------------------------------------------
    # LỖI ĐÃ SỬA (đo trên lượt chạy 10k): phễu cũ ghép ba nguồn có cửa sổ lưu trữ khác nhau
    # rồi đặt cạnh nhau như thể cộng được:
    #     t1_count  = len(t1_blocks)   <- ring buffer `tier1_blocks.json`, UI cắt còn 12
    #     ml_count / llm_count         <- audit_trail qua all_alerts, trần 2000
    # Ba con số cho CÙNG khái niệm "chặn" khi ấy là 50 / 140 / 4.083. Phễu vì thế vẽ Tier-1
    # ≈ 12 bên cạnh Cổng ML hàng trăm — ĐẢO NGƯỢC câu chuyện xả tải, làm tầng gánh nặng
    # nhất trông như tầng yếu nhất.
    #
    # `pipeline_stats.json` đếm TOÀN luồng, không trần -> là nguồn đúng cho phễu.
    _oc = offload_counts if isinstance(offload_counts, dict) else {}

    def _oc_int(key: str) -> int:
        try:
            return int(_oc.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    escalated_to_llm = _oc_int("escalated_to_llm")
    # Hai thẻ giữa phễu in SỐ LỆNH CHẶN, đọc từ chính bảng `audit_trail` mà các tab nhật ký
    # đọc — nên hai màn hình không thể lệch nhau.
    #
    # BẢN CŨ in `ml_gate_resolved` (1.881) và `escalated_to_llm` (1.403), là số SỰ KIỆN ĐI
    # QUA chứ không phải lệnh chặn. Đối chiếu với nhật ký (210 và 77 dòng) lệch cả chục lần,
    # vì Cổng ML giải quyết phần lớn bằng nhánh DROP vốn không ghi sổ, còn phần đẩy sang
    # Tier-2 thì bị nén spam và xếp hàng chờ.
    _bt = blocks_by_tier if isinstance(blocks_by_tier, dict) else {}
    ml_count = int(_bt.get(TIER_ML, 0) or 0)
    llm_count = int(_bt.get(TIER_LLM, 0) or 0)
    # Luật Tier-1 tự xử = tổng luồng trừ phần nó đẩy tiếp cho Cổng ML.
    #
    # NHÃN PHẢI NÓI ĐÚNG NÓ ĐẾM GÌ. Trước đây thẻ ghi "Tier-1 xử lý", mà con số lại là phần
    # LUẬT tĩnh giải quyết TRƯỚC khi Cổng ML vào cuộc. Với `tier1.ml_gate_all_events` bật —
    # mọi sự kiện đi qua Cổng ML — con số đó tụt còn ~38% luồng, đứng ngay cạnh tiêu đề
    # "Xả tải LLM 98,3%". Hai số đúng, đặt cạnh nhau thì trông như một số sai.
    t1_count = max(0, int(total_raw_logs or 0) - _oc_int("action:ESCALATE"))

    # Xả tải LLM = phần KHÔNG tốn một token nào. Khác hẳn `noise_reduction` ở trên.
    #
    # `escalated_to_llm` đếm sự kiện RỜI Cổng ML về phía Tier-2 — KHÔNG phải sự kiện thật sự
    # tốn token. Hai chốt chặn nằm SAU bộ đếm đó và cắt phần lớn:
    #   `tier2_skipped_flow_only` — lô chỉ có đặc trưng luồng, dừng ở ALERT (xem subscriber);
    #   `tier2_suppressed`        — IP đang có lô chạy dở (`pending_ai`, TTL 60 giây).
    # Bỏ qua hai khoản này thì màn hình BÁO THIẾU chính chỉ số nó dùng làm tiêu đề. Đo tại mốc
    # 128.369 sự kiện: 1.907 rời Cổng ML nhưng 1.718 bị chặn lại, chỉ ~189 tới LLM — màn hình
    # in 98,5% trong khi con số thật là 99,85%.
    llm_offload = None
    reached_llm = max(
        0, escalated_to_llm - _oc_int("tier2_skipped_flow_only") - _oc_int("tier2_suppressed")
    )
    # CỐ Ý KHÔNG in phần "Cổng ML gánh" (= `action:ESCALATE` − `reached_llm`) lên thẻ này:
    # đó là bộ đếm SỰ KIỆN ĐI QUA, không so được với nhật ký chặn, và từng khiến 1.881 đứng
    # cạnh một nhật ký 210 dòng. `tests/unit/test_ui_badges.py` canh đúng điều đó.
    if total_raw_logs > 0 and _oc:
        llm_offload = (1 - reached_llm / total_raw_logs) * 100

    if not (TIER_ML in _bt or TIER_LLM in _bt):
        # Sổ kiểm toán chưa có bản ghi nào mang cột `tier` (dữ liệu tạo TRƯỚC lần thêm cột)
        # -> rơi về cách suy từ câu lý do. Kém chính xác nhưng KHÔNG bịa: chỉ đếm dòng thật.
        ml_count = llm_count = 0
        if isinstance(all_alerts, list):
            for alert in all_alerts:
                r = alert.get("reason", "")
                if alert.get("action") != "BLOCK_IP":
                    continue
                is_manual = "Chặn thủ công" in r or "MANUAL" in r.upper()
                is_llm = r.startswith("[MITRE:")
                if not is_manual and not is_llm and any(k in r for k in ML_GATE_MARKERS):
                    ml_count += 1
                elif is_llm:
                    llm_count += 1

    if not _oc:
        # Chưa có pipeline_stats (vd. mở Dashboard trước khi đẩy luồng) -> KHÔNG bịa số cho
        # Tier-1, và để `llm_offload` là None (hiện "—").
        t1_count = len(t1_blocks) if isinstance(t1_blocks, list) else 0

    # Tỉ lệ analyst BÁC BỎ luật do hệ đề xuất — KHÔNG phải False Positive Rate (xem chú thích
    # tại chỗ tính trong app.py). None = chưa ai duyệt luật nào -> hiện "—", không hiện 0.0%.
    reject_str = f"{live_fpr:.1f}%" if live_fpr is not None else "—"
    fpr_color = "#52c41a"  # xanh
    if live_fpr is None:
        fpr_color = "#94A3B8"  # xám: chưa đo được
    elif live_fpr > 25.0:
        fpr_color = "#ff4d4f"  # đỏ
    elif live_fpr > 10.0:
        fpr_color = "#faad14"  # vàng

    # CHỈ MỘT chỉ số phần trăm trên phễu: xả tải LLM = 1 − (sự kiện TỚI LLM / log thô).
    # "Giảm nhiễu" từng đứng cạnh đây nhưng là đại lượng KHÁC (log thô − cảnh báo tới
    # analyst) và luôn cao hơn ~11 điểm, nên đặt cạnh nhau chỉ khiến người đọc trích nhầm.
    offload_str = f"{llm_offload:.1f}%" if llm_offload is not None else "—"

    html_kpi = (
        f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">'
        f'  <div style="font-size: 0.95rem; font-weight: 800; color: #CBD5E1; letter-spacing: 0.5px;">'
        f"    📊 Real-Time Cyber Security Operational Metrics"
        f"  </div>"
        f'  <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.35); padding: 4px 14px; border-radius: 20px; font-size: 0.78rem; color: #34D399; font-weight: 700; letter-spacing: 0.5px;">'
        f'    <span class="blink" style="display: inline-block; width: 8px; height: 8px; background-color: #10B981; border-radius: 50%; box-shadow: 0 0 8px #10B981;"></span>'
        f"    REALTIME STREAMING ACTIVE · SYNC 4S"
        f"  </div>"
        f"</div>"
        f'<div class="kpi-container">'
        f'  <div class="kpi-card" style="border-top: 4px solid #64748B;">'
        f'    <div class="kpi-val" style="color: #F8FAFC;">{int(total_raw_logs or 0):,}</div>'
        f'    <div class="kpi-label">Raw Input Logs</div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid #FF5252;">'
        f'    <div class="kpi-val" style="color: #FF5252;">{offload_str}</div>'
        f'    <div class="kpi-label">Xả tải LLM 🛡️<br/><span style="font-size: 0.85em; font-weight: 600; opacity: 0.85; color: #94A3B8;">Luật Tier-1 tự xử {t1_count:,}</span></div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid #3B82F6;">'
        f'    <div class="kpi-val" style="color: #60A5FA;">{ml_count:,}</div>'
        f'    <div class="kpi-label">Cổng ML chặn ⚡</div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid #8B5CF6;">'
        f'    <div class="kpi-val" style="color: #A78BFA;">{llm_count:,}</div>'
        f'    <div class="kpi-label">Tier-2 LLM chặn 🧠</div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid #F59E0B;">'
        f'    <div class="kpi-val" style="color: #FBBF24;">{int(pending_rules or 0):,}</div>'
        f'    <div class="kpi-label">HITL Approvals 🧑‍💻</div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid #10B981;">'
        f'    <div class="kpi-val" style="color: #34D399;">{int(active_rules or 0):,}</div>'
        f'    <div class="kpi-label">Active Block Rules 🔒</div>'
        f"  </div>"
        f'  <div class="kpi-card" style="border-top: 4px solid {fpr_color};">'
        f'    <div class="kpi-val" style="color: {fpr_color};">{reject_str}</div>'
        f'    <div class="kpi-label">Analyst bác bỏ luật 🎯</div>'
        f"  </div>"
        f"</div>"
    )
    st.markdown(html_kpi, unsafe_allow_html=True)


def render_threat_intel_tables(high_risk_ips):
    """Hiển thị bảng Threat Intelligence với màu sắc neon trực quan. Hỗ trợ chọn hàng để điều tra."""
    selected_ip = None

    st.subheader("🔴 Địa chỉ IP nguy cơ cao (Threat Actor)")
    if not high_risk_ips:
        st.info("Chưa ghi nhận Threat Actor nào.")
    else:
        df_high_risk = pd.DataFrame(
            high_risk_ips,
            columns=["Địa chỉ IP", "Điểm danh tiếng (Reputation)"],  # type: ignore
        )

        def color_score(val):
            color = "#ff4d4f" if val >= 70 else "#faad14" if val >= 40 else "#52c41a"
            return f"color: {color}; font-weight: bold; font-family: monospace;"

        from typing import Any, cast

        selection = st.dataframe(
            cast(
                Any,
                df_high_risk.style.map(color_score, subset=["Điểm danh tiếng (Reputation)"]).format(
                    {"Điểm danh tiếng (Reputation)": "{:.1f}"}
                ),
            ),
            on_select="rerun",
            selection_mode="single-row",
            key="threat_actor_table_select",
            use_container_width=True,
        )

        select_data = selection.get("selection", {}) if selection else {}
        rows = select_data.get("rows", [])
        if rows:
            row_idx = rows[0]
            selected_ip = df_high_risk.iloc[row_idx]["Địa chỉ IP"]

    return selected_ip


def render_apt_events_table(events):
    """Hiển thị bảng chuỗi tấn công APT từ DAPT2020. Hỗ trợ chọn hàng để điều tra."""
    st.subheader("🎯 Nhật ký chuỗi tấn công APT (DAPT2020 Tracker)")
    if not events:
        st.info("Chưa ghi nhận sự kiện chuỗi APT nào.")
        return None

    df = pd.DataFrame(events)
    df = df.rename(
        columns={
            "id": "ID",
            "src_ip": "IP Nguồn",
            "dst_ip": "IP Đích",
            "apt_phase": "Giai đoạn APT",
            "apt_day": "Ngày tấn công",
            "label": "Nhãn",
            "timestamp": "Thời gian xảy ra",
        }
    )

    from typing import Any, cast

    selection = st.dataframe(
        cast(Any, df), on_select="rerun", selection_mode="single-row", key="apt_events_table_select"
    )

    selected_ip = None
    select_data = selection.get("selection", {}) if selection else {}
    rows = select_data.get("rows", [])
    if rows:
        row_idx = rows[0]
        selected_ip = df.iloc[row_idx]["IP Nguồn"]
    return selected_ip


def render_theme_styles(theme="dark"):
    """Enforces pure Cyber Dark Mode across the dashboard."""
    pass
