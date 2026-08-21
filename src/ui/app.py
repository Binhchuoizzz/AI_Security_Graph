"""
SENTINEL - Main SOC Dashboard (v2.5 Premium Audit UI)
Khởi chạy bằng lệnh: streamlit run src/ui/app.py

CHUỖI NÀY PHẢI ĐỨNG ĐẦU TỆP. Trước đây `import typing` nằm trên nó, nên nó KHÔNG còn là
docstring mà là một biểu thức trần cấp module — và "magic" của Streamlit in mọi biểu thức
trần ra trang. Kết quả: dòng "SENTINEL - Main SOC Dashboard (v2.5 Premium Audit UI) Khởi
chạy bằng lệnh: streamlit run src/ui/app.py" hiện ngay đầu dashboard, trên cả màn đăng nhập.
Đừng chèn bất cứ câu lệnh nào lên trên khối này.
"""

import math
import os
import re
import sys
import time

import pandas as pd  # type: ignore

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import html
import json
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

import streamlit as st  # type: ignore
from streamlit_autorefresh import st_autorefresh  # type: ignore

from src.agent.threat_memory import threat_memory
from src.guardrails.constants import (
    TIER_LLM,
    TIER_MANUAL,
    TIER_ML,
    TIER_RULE,
    vn_num,
    vn_pct,
)
from src.response.executor import (
    count_audit_alerts,
    count_blocks_by_tier,
    get_audit_trail,
    get_audit_trail_for_ip,
    verify_audit_trail_integrity,
)


# ---------------------------------------------------------------------------
# Caching DB / I/O để tối ưu hiệu năng (Anti-Lag)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=2)
def cached_get_audit_trail(limit=50, tier=None):
    return get_audit_trail(limit, tier)


@st.cache_data(ttl=2)
def cached_count_audit_alerts():
    """Tổng số cảnh báo THẬT (COUNT(*), không bị trần limit) — dùng cho tỷ lệ giảm tải."""
    return count_audit_alerts()


# Nhãn hiển thị của từng tầng — MỘT nơi duy nhất, để bảng "đã chặn", phần chia tab và mọi
# chỗ khác không thể gọi cùng một tầng bằng hai cái tên.
_TIER_LABELS = {
    TIER_RULE: "Luật Tier-1 🟢",
    TIER_ML: "Cổng ML ⚡",
    TIER_LLM: "LLM 🧠",
    TIER_MANUAL: "Analyst 🧑‍💻",
}


def _nhan_tang(alert: dict) -> str:
    """Tầng nào ra quyết định này — đọc cột `tier`, chỉ đoán khi bản ghi có trước migration."""
    nhan = _TIER_LABELS.get(str(alert.get("tier") or ""))
    if nhan:
        return nhan
    r = str(alert.get("reason", ""))
    if any(k in r for k in ML_GATE_MARKERS):
        return "Cổng ML ⚡"
    return "LLM 🧠" if r.startswith("[MITRE:") else "Luật Tier-1 🟢"


@st.cache_data(ttl=2)
def cached_count_blocks_by_tier():
    """Số lệnh chặn theo tầng — đọc CÙNG bảng mà các tab nhật ký đọc, nên không thể lệch."""
    return count_blocks_by_tier()


@st.cache_data(ttl=2)
def cached_get_audit_trail_for_ip(ip, limit=50):
    return get_audit_trail_for_ip(ip, limit)


@st.cache_data(ttl=2)
def cached_get_tier1_blocks(show=12):
    return _get_tier1_blocks(show)


# HAI PHÉP KIỂM TOÀN VẸN DUYỆT TRỌN CHUỖI HMAC — phải cache, TTL dài.
#
# Cả hai băm lại từng dòng của `audit_trail` để dò đứt chuỗi, nên chi phí tăng TUYẾN TÍNH theo
# độ dài sổ. Đo trên 35.856 dòng: `verify_audit_trail_integrity` 197,1 ms và
# `get_tampered_audit_ids` 201,0 ms — gần **0,4 giây cho MỖI lượt vẽ lại**, mà Streamlit vẽ lại
# toàn bộ trang mỗi 2 giây. Đó là phần lớn cảm giác giật, và ở luồng 500k nó thành hàng giây.
#
# TTL 30 giây là đúng bản chất việc: đây là kiểm tra pháp y trên sổ ĐÃ ghi, không phải chỉ số
# thời gian thực. Giả mạo bị phát hiện chậm nhất nửa phút — vẫn là phát hiện.
@st.cache_data(ttl=30)
def cached_verify_audit_integrity():
    return verify_audit_trail_integrity()


@st.cache_data(ttl=30)
def cached_get_tampered_audit_ids():
    from src.response.executor import get_tampered_audit_ids

    return get_tampered_audit_ids()


@st.cache_data(ttl=5)
def cached_get_ip_reputation(ip: str):
    """Hàng `ip_reputation` của một IP — nguồn THẬT cho badge Threat Memory.

    Trước đây badge chỉ regex trên câu lý do, nên IP lần đầu bị chặn hiện "chưa có dữ liệu
    uy tín" dù kho đã ghi `reputation_score = 100`. Cache 5s vì mỗi thẻ cảnh báo gọi một lần
    và `st.tabs` render mọi tab mỗi lượt refresh.
    """
    if not ip:
        return None
    try:
        return threat_memory.get_ip_reputation(ip)
    except Exception:
        return None


@st.cache_data(ttl=5)
def cached_get_all_threat_events():
    return threat_memory.get_all_threat_events()


@st.cache_data(ttl=5)
def cached_get_high_risk_ips(min_score=1.0):
    return threat_memory.get_high_risk_ips(min_score=min_score)


# ---------------------------------------------------------------------------
# Kết quả thực nghiệm: ĐỌC TỪ FILE, không viết cứng
# ---------------------------------------------------------------------------
# Sáu ô "Kết quả Thực nghiệm" từng là CHUỖI CỨNG, kèm caption khẳng định "mọi số truy được
# về experiments/results/*.json". Đối chiếu tay ngày 2026-07-28 cho thấy 5/6 khớp nhưng ô
# "Cổng ML giảm tải LLM" thì KHÔNG: giao diện ghi 83.8% / F1 0.9739 (761/908 ca) trong khi
# ablation_mlgate_results.json ghi 80.59% / 0.969 (602/747). Số cũ có từ trước lần dựng lại
# ground_truth và không ai cập nhật lại giao diện — đúng kiểu trôi số mà chỉ cần chạy lại
# benchmark một lần nữa là tái diễn. Đọc thẳng từ file thì không thể trôi được nữa.
@st.cache_data(ttl=30)
def cached_mitre_options() -> list[str]:
    """Danh sách kỹ thuật MITRE dựng TỪ CHÍNH sổ kiểm toán, không viết cứng.

    Bản cũ ghim sẵn ["T1059.004", "T1190", "T1595", "T1071"]. Bốn mã đó là phỏng đoán từ
    một lượt chạy cũ, nên bộ lọc vừa liệt kê kỹ thuật hệ thống KHÔNG hề quy kết, vừa
    KHÔNG có mã mà nó quy kết nhiều nhất (T1595.003) — chọn mục nào cũng ra bảng rỗng và
    người xem tưởng hệ thống không phát hiện gì. Đọc thẳng dữ liệu thì không thể lệch.
    """
    techs: set[str] = set()
    try:
        for a in get_audit_trail(1000, None):
            t = _extract_mitre_technique(a.get("reason", ""))
            if not t:
                continue
            # Chuỗi thật có dạng "T1190 - Exploit Public-Facing Application" -> lấy mã.
            code = t.split("-")[0].split()[0].strip() if t.split() else ""
            if code.upper().startswith("T"):
                techs.add(code)
    except Exception:
        return []
    return sorted(techs)


# Thư mục kết quả thực nghiệm — MỘT nơi khai báo, để panel kết quả và mọi chỗ khác
# không thể trỏ về hai đường dẫn khác nhau.
_RES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "experiments", "results")


from src.tier1_filter.feedback_listener import FeedbackListener
from src.ui import components as ui_components
from src.ui.auth import logout, require_auth
from src.ui.components import (
    ML_GATE_MARKERS,
    build_tier1_block_badge,
    is_valid_ip,
    render_alert_card,
    render_apt_events_table,
    render_metrics_header,
    render_theme_styles,
    render_threat_intel_tables,
)


def _model_display_name() -> str:
    """Tên model ĐANG chạy, đọc động — KHÔNG viết cứng.

    Bản trước dán thẳng chuỗi tên model cũ vào chú giải và sơ đồ luồng. Khi hệ đổi sang
    Foundation-Sec, giao diện vẫn khai tên cũ: người xem demo (kể cả hội đồng) đọc được một
    tên model không hề chạy ở đâu. Viết cứng tên model là thứ chắc chắn sẽ rữa.
    """
    raw = os.getenv("LLM_MODEL_FILE") or ""
    if not raw:
        try:
            from src.agent.llm_client import DEFAULT_MODEL

            raw = DEFAULT_MODEL
        except Exception:
            return "LLM cục bộ"
    # "Foundation-Sec-8B-Instruct-Q4_K_M.gguf" -> "Foundation-Sec-8B"
    stem = raw.rsplit("/", 1)[-1].removesuffix(".gguf")
    m = re.match(r"([A-Za-z0-9.\-]*?\d+[Bb])(?:[-_]|$)", stem)
    return m.group(1) if m else stem


# Cấu hình trang
st.set_page_config(
    page_title="SENTINEL AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Nạp CSS tuỳ chỉnh
css_path = os.path.join(os.path.dirname(__file__), "style.css")
if os.path.exists(css_path):
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# 1. Bắt buộc đăng nhập
require_auth()

feedback_mgr = FeedbackListener()


def _extract_mitre_technique(reason: str) -> str:
    """Rút mã kỹ thuật MITRE từ chuỗi reason dạng '[MITRE: T1110 - Brute Force] ...'."""
    m = re.search(r"\[MITRE:\s*([^\]]+)\]", reason or "")
    return m.group(1).strip() if m else ""


def _fmt_local_ts(raw) -> str:
    """Đổi timestamp ISO (thường UTC +00:00 do record_incident lưu) sang GIỜ ĐỊA
    PHƯƠNG, để tab APT/Investigation đồng bộ với audit/HITL (đã sửa về giờ local).
    Chuỗi không parse được -> trả nguyên trạng (an toàn)."""
    if not raw or str(raw) == "N/A":
        return "N/A"
    try:
        dt = datetime.fromisoformat(str(raw))
        if dt.tzinfo is not None:
            dt = dt.astimezone()  # -> TZ tiến trình (container: Asia/Ho_Chi_Minh)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(raw)


def _rule_severity(score) -> tuple[str, str]:
    """Ánh xạ điểm luật -> (icon, nhãn mức độ nghiêm trọng) cho HITL."""
    s = score or 0
    if s >= 100:
        return ("🔴", "CAO")
    if s >= 50:
        return ("🟠", "TRUNG BÌNH")
    return ("🟡", "THẤP")


def handle_whitelist_approval(ip: str):
    """Callback thêm IP vào Whitelist — TÔN TRỌNG kết quả validator (không báo giả)."""
    ok = feedback_mgr.add_to_whitelist(ip)
    st.session_state[f"whitelisted_{ip}"] = ok
    if ok:
        from src.response.executor import _log_to_db, unblock_ip

        unblock_ip(ip)
        _log_to_db("LOG", ip, "Whitelist thủ công qua nút bấm SIEM (Tier-1 Rule)")
        st.cache_data.clear()
        st.toast(f"✅ Đã whitelist {ip}", icon="✅")
    else:
        st.toast(
            f"⚠️ Không whitelist được {ip} — chỉ CHẶN dải quá rộng (wildcard 0.0.0.0/0, "
            "*, any, hoặc CIDR < /16). IP host cụ thể đều được phép.",
            icon="⚠️",
        )
    st.rerun()


def handle_block_approval(ip: str):
    """Callback chặn thủ công IP từ tab Nhật ký SIEM."""
    feedback_mgr.receive_new_rule(
        "Source IP",
        ip,
        score=100,
        source=f"manual_{st.session_state.get('username')}",
        reason=f"Chặn thủ công từ tab Nhật ký SIEM bởi {st.session_state.get('username')}",
    )
    # Duyệt luôn
    feedback_mgr.approve_rule(ip, "Source IP")

    # Ghi audit log
    from src.response.executor import _add_to_blacklist, _log_to_db

    _add_to_blacklist(ip)
    _log_to_db("LOG", ip, "Chặn thủ công qua nút bấm SIEM (Tier-1 Rule)")

    st.cache_data.clear()
    st.toast(f"🛑 Đã block {ip} thành công", icon="🛑")
    st.rerun()


def _get_tier1_blocks(show: int = 12) -> list[dict]:
    """Đọc config/tier1_blocks.json (do subscriber ghi) -> block Tier-1 gần nhất kèm LÝ DO.

    Dùng FILE qua volume config/ — KHÔNG dùng Redis, vì Redis chỉ reach được từ host,
    container Dashboard không reach được (cùng lý do pipeline_stats.json đọc từ file).
    Khử trùng theo IP (mới nhất trước). An toàn khi thiếu file -> trả rỗng.
    """
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "config",
        "tier1_blocks.json",
    )
    try:
        with open(path) as f:
            blocks = json.load(f)
    except Exception:
        return []
    if not isinstance(blocks, list):
        return []
    # Đếm TỔNG số lần mỗi IP bị Tier-1 chặn (trên toàn bộ lịch sử file, gồm nhiều lần chạy)
    counts: dict[str, int] = {}
    for b in blocks:
        if isinstance(b, dict):
            ip = b.get("ip")
            if isinstance(ip, str) and ip:
                counts[ip] = counts.get(ip, 0) + 1

    # Khử trùng để hiển thị (mới nhất trước) nhưng ĐÍNH KÈM số lần + timestamp lần cuối.
    seen: dict[str, dict] = {}
    for b in reversed(blocks):  # mới nhất trước
        if not isinstance(b, dict):
            continue
        ip = b.get("ip")
        if not isinstance(ip, str) or not ip or ip in seen:  # ip phải là str hashable, không rỗng
            continue
        _r = b.get("reasons")
        reasons = [str(x) for x in _r] if isinstance(_r, list) else []
        seen[ip] = {
            "ip": ip,
            "score": b.get("score", 0),
            "reasons": reasons,
            "count": counts.get(ip, 1),  # số lần bị chặn (không bị dedup che mất)
            "ts": str(b.get("ts", "")),  # timestamp lần chặn gần nhất
        }
        if len(seen) >= show:
            break
    return list(seen.values())


def render_demo_overview(
    all_alerts,
    active_rules,
    pending_rules,
    raw_logs_count,
    pending_llm=0,
    offload_counts=None,
    pending_llm_stale=False,
    blocks_by_tier=None,
):
    """Tab Tổng quan Trình diễn — gom mọi thứ cần show vào MỘT màn hình."""
    st.markdown("## 🎬 SENTINEL — Bảng trình diễn tổng quan")
    st.markdown(
        "*Kiến trúc nhận thức hai tầng: **Tier-1** lọc ở tốc độ đường truyền bằng thuật toán "
        "Welford $O(1)$ + **Cổng ML** (cùng Tier-1) → **Tier-2** tác tử LangGraph (Foundation-Sec-8B-Instruct Q4\\_K\\_M qua llama.cpp) + "
        "**Dual-RAG** (MITRE ATT&CK / NIST SP 800-61r2) phía sau rào chắn mật mã, có **HITL** giám sát.*"
    )

    # ---------- Thu thập dữ liệu (an toàn) ----------
    try:
        # Qua cache (ttl=5): st.tabs render MỌI tab mỗi lượt refresh 4s nên các query này
        # nổ bất kể tab đang xem — cache gộp lại 1 lần đọc DB thay vì nhiều lần/refresh.
        apt_events = cached_get_all_threat_events() or []
    except Exception:
        apt_events = []
    apt_ips = sorted({s for e in apt_events if (s := e.get("src_ip"))})
    try:
        integ_valid, _integ_msg = cached_verify_audit_integrity()
    except Exception:
        integ_valid = True

    _oc = offload_counts if isinstance(offload_counts, dict) else {}

    def _n(key: str) -> int:
        try:
            return int(_oc.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    # Hàng metric in SỐ LỆNH CHẶN theo tầng, đọc từ chính `audit_trail` mà các tab nhật ký
    # đọc — hai màn hình vì thế không thể lệch. Các bộ đếm SỰ KIỆN ĐI QUA (escalated_to_llm,
    # ml_gate_resolved) không lên màn hình nữa: chúng đếm thứ khác hẳn với "đã chặn" và từng
    # khiến 1.881 đứng cạnh một nhật ký 210 dòng.
    _bt = blocks_by_tier if isinstance(blocks_by_tier, dict) else {}
    _ml_blk = int(_bt.get(TIER_ML, 0) or 0)
    _llm_blk = int(_bt.get(TIER_LLM, 0) or 0)
    # LỖ HỔNG ĐÃ BIẾT: nhánh `BLOCK_IP` của Tier-1 (subscriber.py) đẩy IP vào blacklist Redis,
    # ghi Threat Memory và ring buffer, nhưng KHÔNG gọi `_log_to_db`. Hàng nghìn lệnh chặn
    # Tier-1 vì thế KHÔNG có dòng nào trong sổ kiểm toán HMAC — đếm theo `tier` sẽ ra 0 và
    # trông như Tier-1 chẳng chặn gì. Lấy số từ bộ đếm luồng và NÓI RÕ nguồn khác nhau, thay
    # vì lặng lẽ trộn hai nguồn vào một hàng như thể chúng cùng gốc.
    _t1_blk_audit = int(_bt.get(TIER_RULE, 0) or 0)
    _t1_blk = _t1_blk_audit or _n("action:BLOCK_IP")
    _t1_tu_so_dem = _t1_blk_audit == 0 and _t1_blk > 0
    # Tổng lấy bằng COUNT(*) chứ KHÔNG đếm trên `all_alerts`: danh sách đó bị trần 2000 dòng
    # nên khi luồng vượt ngưỡng, "tổng lệnh chặn" âm thầm bão hoà và nhỏ hơn tổng ba tầng.
    escalated = sum(int(v or 0) for v in _bt.values())

    # ---------- Operational Metrics Row ----------
    st.markdown("### 📊 Chỉ số vận hành thời gian thực")
    c1, c2, c3, c4, c5, c6, c7, c8 = st.columns(8)
    c1.metric("Log thô vào", vn_num(raw_logs_count))
    c2.metric(
        "Chặn ghi sổ kiểm toán",
        vn_num(escalated),
        help="Phán quyết BLOCK_IP CÓ dòng trong audit trail HMAC (Cổng ML + Tier-2 + thủ "
        "công). CHƯA gồm lệnh chặn của luật Tier-1 — nhánh đó hiện không ghi sổ.",
    )
    c3.metric(
        "Tier-1 luật chặn" + (" ⚠️" if _t1_tu_so_dem else ""),
        vn_num(_t1_blk),
        help=(
            "⚠️ Số này đọc từ BỘ ĐẾM LUỒNG (pipeline_stats), KHÔNG từ sổ kiểm toán: nhánh "
            "BLOCK_IP của luật Tier-1 đẩy IP vào blacklist Redis + Threat Memory nhưng không "
            "ghi dòng audit nào. Vì vậy nó KHÔNG nằm trong chuỗi HMAC và không tra ngược "
            "được từng lệnh."
            if _t1_tu_so_dem
            else "Lệnh chặn do bộ máy luật Tier-1 ra, đếm trên audit trail."
        ),
    )
    c4.metric("Cổng ML chặn", vn_num(_ml_blk), help="Lệnh chặn do Cổng ML (LightGBM) ra.")
    c5.metric(
        "Tier-2 LLM chặn",
        vn_num(_llm_blk),
        help="Lệnh chặn do tác tử LangGraph ra — khớp đúng số thẻ ở tab Tier-2.",
    )
    c6.metric(
        "Hàng đợi LLM (lô) ⏳",
        f"{pending_llm}" + (" ⏸" if pending_llm_stale and pending_llm else ""),
        help=(
            "Số LÔ còn chờ Tier-2 (mỗi lô gom nhiều log cùng một IP), ảnh chụp tức thời. "
            + (
                "⏸ = luồng ĐÃ DỪNG (hơn 60s không ai ghi pipeline_stats.json)."
                if pending_llm_stale and pending_llm
                else ""
            )
        ),
    )
    c7.metric("Chờ duyệt (HITL)", f"{len(pending_rules)}")
    c8.metric("Chuỗi HMAC", "✅ Nguyên vẹn" if integ_valid else "⚠️ Bị sửa")

    st.markdown("---")
    col_left, col_right = st.columns([3, 2])

    # ---------- Left Column: Live Feed + APT ----------
    with col_left:
        st.markdown("### 🚨 Dòng cảnh báo trực tiếp")
        if all_alerts:
            feed = [
                {
                    "Timestamp": str(a.get("timestamp", ""))[5:19],
                    "Action": a.get("action", ""),
                    "Target IP": a.get("target", ""),
                    "MITRE ATT&CK": _extract_mitre_technique(a.get("reason", "")) or "—",
                }
                for a in all_alerts[:10]
            ]
            st.dataframe(pd.DataFrame(feed), width="stretch", height=300, hide_index=True)
        else:
            st.info(
                "Chưa có cảnh báo nào. Đẩy luồng bằng `scripts/run_demo.sh` "
                "(hoặc `scripts/demo.py`) để hệ thống bắt đầu chấm sự kiện."
            )

        st.markdown("### 🎯 Chiến dịch APT nhiều ngày")
        if apt_events:
            apt_tbl = [
                {
                    "Source IP": e.get("src_ip", ""),
                    "Day": e.get("apt_day", ""),
                    "Killchain Phase": e.get("apt_phase", ""),
                    "Threat Label": e.get("label", ""),
                }
                for e in apt_events[:12]
            ]
            st.dataframe(pd.DataFrame(apt_tbl), width="stretch", height=240, hide_index=True)
            st.caption(
                f"🔗 Detected **{len(apt_ips)} APT IPs** via multi-day threat correlation in Threat Memory (SQLite)."
            )
        else:
            st.info(
                "Chưa ghi nhận sự kiện APT nào. Nạp DAPT2020 (`scripts/build_dapt_chains.py`) "
                "để có tương quan nhiều ngày."
            )

    # ---------- Right Column: Benchmark Results + System Status ----------
    with col_right:
        # ── BỐN CON SỐ CỦA SLIDE KẾT QUẢ ────────────────────────────────────────
        # Màn hình này và slide Kết quả PHẢI nói cùng một bộ số. Bản cũ in sáu chỉ số
        # khác hẳn (0,509 ms · −69,24% · 68,2% · APT recall 1,00 · 99,58%) lấy từ những
        # lượt đo khác, nên hội đồng nhìn slide rồi nhìn Dashboard sẽ thấy hai bộ số
        # không con nào trùng con nào — mà cả hai đều đúng, chỉ khác phép đo. Nay đọc
        # thẳng đúng bốn tệp mà slide trích, không viết cứng con số nào.
        st.markdown("### 🏆 Bốn con số của luận văn")

        def _J(name: str) -> dict:
            try:
                with open(os.path.join(_RES_DIR, f"{name}.json")) as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                return {}

        _off = _J("offload_vs_baserate_demo")
        _lat = _J("latency_benchmark")
        _tri = (_J("tier2_decision_results").get("summary") or {}).get("triage") or {}
        _adv = _J("adversarial_pipeline_results")
        _tam = _J("audit_tamper_results")
        _mode = _tam.get("by_mode") or {}

        # Dùng CHUNG bộ định dạng với hàng chỉ số phía trên (src/guardrails/constants.py).
        # Bản trước tự viết lại ở đây, nên cùng một con số hiện hai kiểu trên một màn hình.
        _pct, _num = vn_pct, vn_num

        _core = sum(
            int((_mode.get(k) or {}).get("detected", 0)) for k in _tam.get("core_modes") or []
        )
        _core_n = sum(
            int((_mode.get(k) or {}).get("trials", 0)) for k in _tam.get("core_modes") or []
        )

        _cards = [
            (
                "#22D3EE",
                "Tỷ lệ xả tải",
                _pct(_off.get("offload_tong")),
                f"{_num(_off.get('n_events'), 0)} sự kiện · nền tấn công "
                f"{_pct(_off.get('attack_rate_do_duoc'), 2)} · chỉ "
                f"{_pct(_off.get('ti_le_toi_llm'), 2)} chạm tới LLM",
            ),
            (
                "#FBBF24",
                "Độ trễ trung vị",
                f"{_num(_lat.get('two_tier_median_ms'), 2)} ms",
                f"so với {_num(_lat.get('baseline_median_ms'), 1)} ms của LLM đơn tầng · "
                f"n={_num(_lat.get('n_events'), 0)}",
            ),
            (
                "#A78BFA",
                "Cắt giảm tải chuyên viên",
                _pct(_tri.get("workload_reduction"), 2),
                f"trên {_num(_tri.get('n_alerts_in'), 0)} cảnh báo leo thang · hàng đợi hoãn "
                f"({_pct(_tri.get('defer_rate'), 2)} khối lượng) giữ "
                f"{_pct(_tri.get('threat_recall_in_deferred'), 1)} đe doạ thật",
            ),
            (
                "#34D399",
                "Tiêm nhiễm và toàn vẹn sổ",
                _pct((_adv.get("resistance_rate_pct") or 0) / 100),
                f"{_adv.get('resisted', '?')}/{_adv.get('n_tested', '?')} mẫu tiêm nhiễm bị chặn · "
                f"chuỗi HMAC bắt {_core}/{_core_n} lần sửa, chèn, xoá giữa sổ",
            ),
        ]
        st.markdown(
            '<div class="res-grid">'
            + "".join(
                f'<div class="res-card" style="--accent:{c}">'
                f'<div class="res-eyebrow">{lbl}</div>'
                f'<div class="res-val" style="color:{c}">{val}</div>'
                f'<div class="res-den">{den}</div>'
                "</div>"
                for c, lbl, val, den in _cards
            )
            + "</div>",
            unsafe_allow_html=True,
        )

        # GIỚI HẠN NẰM CẠNH CON SỐ, không lùi xuống chú thích cuối trang. Ba câu dưới đây
        # là ba chỗ số liệu KHÔNG đẹp, và đều đọc từ chính các tệp ở trên.
        _tail = _mode.get("xoá_dòng_cuối") or {}
        st.markdown(
            '<div class="res-limits">'
            "<b>Giới hạn phải nói kèm.</b> "
            f"Trung vị giảm mạnh nhưng <b>p95 xấu đi</b> — {_num(_lat.get('two_tier_p95_ms'), 1)} ms "
            f"so với {_num(_lat.get('baseline_p95_ms'), 1)} ms, vì ca leo thang trả phí cả hai tầng. "
            "Tỉ lệ xả tải là hàm của hỗn hợp lưu lượng, <b>không phải hằng số</b>. "
            f"Chuỗi HMAC <b>không phát hiện được cắt đuôi sổ</b> ({_tail.get('detected', 0)}/"
            f"{_tail.get('trials', 0)})."
            "</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="res-src">Đọc trực tiếp từ <code>experiments/results/</code> mỗi lần tải '
            "trang: <code>offload_vs_baserate_demo</code> · <code>latency_benchmark</code> · "
            "<code>tier2_decision_results</code> · <code>adversarial_pipeline_results</code> · "
            "<code>audit_tamper_results</code>. Đây đúng năm tệp mà slide Kết quả trích.</div>",
            unsafe_allow_html=True,
        )

        st.markdown("### 🔐 Trạng thái Hệ thống")
        st.success("🟢 LLM cục bộ: Foundation-Sec-8B-Instruct Q4\\_K\\_M (llama.cpp · air-gapped)")
        st.success(
            "🟢 Audit HMAC-SHA256: " + ("Toàn vẹn" if integ_valid else "CẢNH BÁO: bị sửa đổi")
        )
        st.success(f"🟢 Luật đang chặn (active): {len(active_rules)} · Whitelist nội bộ đã seed")

        # Ngân sách ngữ cảnh LLM (observability) — biết prompt cách trần n_ctx bao xa.
        from src.agent.token_monitor import get_stats as _get_token_stats

        _tok = _get_token_stats()
        if _tok and _tok.get("calls", 0) > 0:
            _util = _tok.get("utilization_pct_max", 0.0)
            _c = "🟢" if _util < 75 else "🟡" if _util < 90 else "🔴"
            st.markdown(
                f"{_c} **Ngân sách ngữ cảnh:** p95 **{_tok.get('utilization_pct_p95', 0)}%** · "
                f"max **{_util}%** của {_tok.get('n_ctx', 16384)} token · "
                f"prompt TB {_tok.get('prompt_tokens_mean', 0)} / max {_tok.get('prompt_tokens_max', 0)} · "
                f"⚠️ {_tok.get('overflow_warnings', 0)} cảnh báo sát trần ({_tok.get('calls', 0)} call)"
            )
        else:
            st.caption(
                "ℹ️ Ngân sách ngữ cảnh: chưa có dữ liệu token — chạy pipeline/eval để thu thập."
            )

    # ---------- Vòng phản hồi Hai tầng: Tier-1 chặn ↔ Tier-2 dạy ----------
    st.markdown("---")
    st.markdown("### 🔁 Vòng phản hồi hai tầng — Tier-1 chặn, ML/LLM dạy ngược")
    fb_left, fb_right = st.columns(2)

    with fb_left:
        st.markdown("#### 🛡️ Tier-1 đã chặn (tốc độ đường truyền · KHÔNG cần LLM)")
        t1_blocks = cached_get_tier1_blocks()
        if t1_blocks:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "IP nguồn": b["ip"],
                            "Điểm": b["score"],
                            "Số lần": b.get("count", 1),
                            "Lần cuối": (b.get("ts") or "")[-8:] or "—",
                            "Lý do Tier-1": " · ".join(b["reasons"][:2]) or "—",
                        }
                        for b in t1_blocks
                    ]
                ),
                width="stretch",
                height=248,
                hide_index=True,
            )

            # AUDIT TẬN GỐC: cho phép soi LOG THÔ ĐẦY ĐỦ của đúng IP đã bị Tier-1 chặn.
            # Trước đây bảng chỉ có ip/score/reasons -> không truy được bản ghi nào gây ra
            # lệnh chặn. Sidecar tier1_blocks.json nay kèm raw_log (xem subscriber.py).
            _with_raw = [b for b in t1_blocks if b.get("raw_log")]
            if _with_raw:
                _opts = {
                    f"{b['ip']}  (điểm {b.get('score', 0)} · {(b.get('ts') or '')[-8:]})": b
                    for b in _with_raw
                }
                _pick = st.selectbox(
                    "🔍 Soi LOG THÔ ĐẦY ĐỦ của IP bị Tier-1 chặn",
                    list(_opts.keys()),
                    key="t1_block_raw_pick",
                )
                _b = _opts[_pick]
                with st.expander(f"🔍 LOG THÔ ĐẦY ĐỦ — {_b['ip']}", expanded=False):
                    st.caption(
                        "Toàn bộ bản ghi đã đưa vào Tier-1 (không cắt trường), kèm `tier1_score` "
                        "và `tier1_reasons` — đúng thứ luật đã nhìn thấy khi quyết định CHẶN. "
                        "Chỉ loại nhãn/đáp án của bộ dữ liệu (chống lộ nhãn)."
                    )
                    st.markdown(f"**Lý do chặn:** {' · '.join(_b.get('reasons') or []) or '—'}")
                    ui_components.render_ground_truth(_b["raw_log"])
                    st.json(_b["raw_log"])
            else:
                st.caption(
                    "ℹ️ Các bản ghi chặn hiện có được tạo TRƯỚC khi bật đính kèm log thô — "
                    "chạy lại demo để có dữ liệu soi tận gốc."
                )

            st.caption(
                "Tấn công RÕ RÀNG (chữ ký WAF/injection, cổng nhạy cảm, quét cổng) bị chặn "
                "TỨC THỜI bằng luật xác định — không tốn LLM. **Số lần** = tổng số lần IP đó bị "
                "Tier-1 chặn (gộp mọi lần chạy); **Lần cuối** = thời điểm chặn gần nhất. Chặn này "
                "là **tạm thời** (Redis blacklist, TTL 1 giờ, tự hết hạn)."
            )
        else:
            st.info(
                "Chưa có block Tier-1 gần đây (queue_decisions rỗng hoặc chưa chạy luồng). "
                "Đẩy adversarial/CICIDS để minh hoạ."
            )

    with fb_right:
        st.markdown("#### 🔄 ML (Tier-1) & LLM (Tier-2) đã dạy Tier-1 (luật học được · lâu dài)")
        # ACTIVE (luật đã duyệt, đang chặn) hiển thị TRƯỚC để không bị ẩn khi nhiều PENDING
        loop_rules = list(active_rules or []) + list(pending_rules or [])
        if loop_rules:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Trạng thái": (
                                "✅ Đang chặn" if rule.get("status") == "ACTIVE" else "⏳ Chờ duyệt"
                            ),
                            "Pattern": rule.get("pattern", ""),
                            "Điểm": rule.get("score", ""),
                            "Lý do": (str(rule.get("reason", "")) or "—")[:90],
                        }
                        for rule in loop_rules[:12]
                    ]
                ),
                width="stretch",
                height=248,
                hide_index=True,
            )
            st.caption(
                f"Mỗi phán quyết BLOCK/HITL từ Cổng ML (Tier-1), LLM (Tier-2) và luật Tier-1 sinh **1 luật** "
                f"({len(pending_rules or [])} chờ duyệt · {len(active_rules or [])} đang chặn). "
                "Analyst DUYỆT (HITL) → luật **ACTIVE** → Tier-1 tự động CHẶN ngay lần sau. "
                "Khác với block Redis (TTL 1h), luật đã duyệt **KHÔNG hết hạn** — đây là lý do số "
                "'luật chờ duyệt' có thể nhiều hơn số 'đang chặn tức thời'."
            )
        else:
            st.info(
                "Chưa có luật nào ML/LLM dạy cho Tier-1. Chạy luồng có escalate để hệ thống sinh luật."
            )

    # ---------- Cổng ML (Tier-1) + LLM (Tier-2) đã CHẶN — phán quyết ghi vào Audit Trail ----------
    st.markdown("### 🧠 Cổng ML và LLM đã chặn — có ghi sổ kiểm toán")
    _t2_blocks = [a for a in all_alerts if str(a.get("action", "")).upper() in ("BLOCK_IP",)]
    if _t2_blocks:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Thời gian": str(a.get("timestamp", ""))[5:19],
                        "Hành động": a.get("action", ""),
                        "IP / Host": a.get("target", ""),
                        # Đọc cột `tier` do CHÍNH tầng ra quyết định ghi. Bản cũ dò chuỗi
                        # trong câu lý do, cùng lỗi đã vá ở phần chia tab: câu lý do của
                        # Tier-2 có thể chứa cụm "Tier-1" và bị gán nhầm nguồn.
                        "Quyết định bởi": _nhan_tang(a),
                        "MITRE": _extract_mitre_technique(a.get("reason", "")) or "—",
                        "Lý do": (str(a.get("reason", "")) or "—")[:110],
                    }
                    for a in _t2_blocks[:15]
                ]
            ),
            width="stretch",
            height=280,
            hide_index=True,
        )
        st.caption(
            f"**{len(_t2_blocks)}** quyết định CHẶN do Cổng ML (Tier-1), LLM (Tier-2) (và thao tác thủ công của "
            "Analyst) ghi vào Audit Trail HMAC-SHA256. Khác với *Tier-1 đã chặn* (chữ ký tốc độ "
            "cao, TTL 1h ở Redis): đây là phán quyết **có suy luận MITRE/NIST** của LLM sau khi "
            "leo thang. IP đã whitelist KHÔNG bao giờ xuất hiện ở đây (đã miễn trừ)."
        )
    else:
        st.info(
            "Chưa có quyết định CHẶN nào từ Cổng ML (Tier-1) hoặc LLM (Tier-2). Chạy luồng có escalate (adversarial/APT) để "
            "LLM phán quyết và ghi vào Audit Trail."
        )

    st.markdown("---")
    st.caption(
        "💡 Tab này gom toàn bộ thành phần để trình bày tổng quan. Các tab kế tiếp cung cấp "
        "chi tiết: Nhật ký SIEM & Audit, Phê duyệt Luật (HITL), Giám sát APT, Blocklist/Whitelist, và Tri thức Graph."
    )


def main_dashboard():
    # Force pure Cyber Dark Mode theme
    render_theme_styles("dark")

    # Auto-refresh UI mỗi 4000ms (4s) - mượt mà, phản hồi nhanh, tiết kiệm CPU.
    #
    # `limit=None` = KHÔNG giới hạn (đúng giá trị canh mà thư viện ghi trong tài liệu; `0` là
    # suy đoán, không dùng). Bản trước đặt `limit=10000`, tức 10.000 × 4s ≈ **11,1 giờ**
    # rồi tự-làm-mới DỪNG HẲN — không có thông báo nào. Từ giây phút đó Dashboard hiện số
    # ĐÔNG CỨNG trông y hệt số sống: một buổi demo dài hoặc một màn hình treo tường qua đêm
    # sẽ báo cáo trạng thái của nhiều giờ trước mà không ai biết. Đó là chế độ hỏng tệ nhất
    # với một bảng điều khiển an ninh — sai mà trông như đúng.
    count = st_autorefresh(interval=4000, limit=None, key="siem_dashboard_refresh")

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👤 Tài khoản: `{st.session_state.get('username')}`")
        st.markdown(f"### 🔑 Vai trò: `{st.session_state.get('role')}`")
        if st.button("🚪 Đăng xuất"):
            logout()

        st.markdown("---")
        st.markdown("### 🔍 Bộ lọc sự cố")

        # Lọc theo hành động
        # Chỉ liệt kê các hành động THỰC SỰ có trong nhật ký sự cố (bỏ "LOG" vì đó là
        # ghi chú benign/quản trị, không phải sự cố cần phân loại → tránh bộ lọc rỗng).
        action_filter = st.selectbox(
            "Phân loại Hành động",
            options=["Tất cả", "BLOCK_IP", "ALERT", "WHITELIST"],
            index=0,
            key="action_filter_sb",
        )

        _mitre_opts = cached_mitre_options()
        mitre_filter = st.selectbox(
            "Kỹ thuật MITRE",
            options=["Tất cả", *_mitre_opts, "N/A"],
            index=0,
            key="mitre_filter_sb",
            help=(
                f"{len(_mitre_opts)} kỹ thuật đọc từ sổ kiểm toán (1.000 bản ghi gần nhất). "
                "Danh sách trống nghĩa là chưa có bản ghi nào được quy kết."
                if _mitre_opts
                else "Chưa có bản ghi nào được quy kết MITRE — đẩy luồng để hệ thống sinh dữ liệu."
            ),
        )

        st.markdown("---")
        show_tampered_only = st.checkbox(
            "🚨 Chỉ hiện thẻ bị GIẢ MẠO (Lỗi HMAC)",
            value=False,
            help="Chỉ hiển thị các dòng log đã bị thao túng nội dung hoặc đứt gãy chuỗi băm.",
        )

        # Tìm kiếm theo IP Mục tiêu
        search_ip = st.text_input("Tìm kiếm IP mục tiêu", placeholder="Nhập IP để lọc...").strip()

        # Số dòng trên một trang
        page_size = st.slider(
            "Số lượng hiển thị / trang", min_value=5, max_value=50, value=5, step=5
        )

        st.markdown("---")
        st.markdown("### ⚙️ Quản lý dữ liệu")

        # Nút Reset — gated L3_Manager + tích xác nhận để tránh xoá nhầm dữ liệu demo
        _is_mgr = st.session_state.get("role") == "L3_Manager"
        _confirm_reset = st.checkbox(
            "Xác nhận: xoá TẤT CẢ dữ liệu demo (audit · danh tiếng IP · APT · luật · Tier-1 blocks) — KHÔNG hoàn tác",
            key="confirm_reset_db",
            disabled=not _is_mgr,
        )
        if not _is_mgr:
            st.caption("🔒 Chỉ tài khoản L3_Manager mới được Reset hệ thống.")
        if st.button(
            "🗑️ Reset Hệ thống & Demo từ đầu",
            disabled=not (_is_mgr and _confirm_reset),
            help="Xóa sạch audit, danh tiếng IP, sự kiện APT, luật động và Tier-1 blocks để chạy lại demo. "
            "Lưu ý: blacklist Redis tự hết hạn theo TTL (dashboard không truy cập Redis được).",
        ):
            import sqlite3

            from src.agent.threat_memory import MEMORY_DB_PATH as THREAT_DB
            from src.response.executor import DB_PATH as AUDIT_DB

            try:
                # 1. Xóa audit_trail
                with sqlite3.connect(AUDIT_DB) as conn:
                    conn.execute("DELETE FROM audit_trail")
                    conn.commit()

                # 2. Xóa threat memory (bao gồm cả known_entities để seed lại)
                with sqlite3.connect(THREAT_DB) as conn:
                    conn.execute("DELETE FROM ip_reputation")
                    conn.execute("DELETE FROM threat_events")
                    conn.execute("DELETE FROM apt_indicators")
                    conn.execute("DELETE FROM known_entities")
                    conn.commit()

                # 3. Seed lại default known entities
                threat_memory._init_db()

                # 4-5. Clear dynamic rules + reset whitelist qua API HỆ THỐNG (đồng bộ với
                # reset_all; FeedbackListener bền cross-UID 0666+lock, tránh tự sửa YAML).
                feedback_mgr.clear_all_dynamic_rules()
                feedback_mgr.reset_whitelist_to_defaults()

                # 6. Reset counter log thô THẬT (file pipeline_stats.json)
                try:
                    _stats_f = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                        "config",
                        "pipeline_stats.json",
                    )
                    if os.path.exists(_stats_f):
                        os.remove(_stats_f)
                except Exception:
                    pass

                # 7. Xoá file Tier-1 blocks (panel "Tier-1 đã chặn" đọc từ đây)
                try:
                    _t1b = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                        "config",
                        "tier1_blocks.json",
                    )
                    if os.path.exists(_t1b):
                        os.remove(_t1b)
                except Exception:
                    pass

                # 8. Xoá Redis blacklist (do UI chạy cùng node nên có thể reach được)
                try:
                    import redis

                    from src.response.executor import _redis_url

                    r = redis.Redis.from_url(_redis_url(), socket_connect_timeout=1.0)
                    for key in r.scan_iter("blacklist:*"):
                        r.delete(key)
                except Exception:
                    pass

                st.cache_data.clear()
                st.success("Đã reset toàn bộ dữ liệu hệ thống về trạng thái ban đầu!")
                st.rerun()
            except Exception as e:
                st.error(f"Lỗi khi reset: {e}")

        st.markdown("---")
        st.markdown("### 🛡️ Toàn vẹn nhật ký")
        if st.button(
            "🛡️ Kiểm tra tính toàn vẹn Logs (HMAC Audit)",
            help="Xác minh chuỗi băm HMAC Ledger để phát hiện giả mạo dữ liệu",
        ):
            is_valid, msg = cached_verify_audit_integrity()
            if is_valid:
                st.success(msg)
            else:
                st.error(msg)

        st.markdown("---")
        st.markdown("### 📟 Bảng điều khiển trực tiếp")

        # Lấy 10 log mới nhất từ Audit (Cổng ML, LLM, Manual) và kết hợp với Tier-1 Blocks
        console_logs = cached_get_audit_trail(limit=10)
        combined_logs = list(console_logs)

        try:
            _t1_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "tier1_blocks.json",
            )
            with open(_t1_path) as f:
                raw_t1 = json.load(f)
            for b in raw_t1[-10:]:  # Lấy 10 cái cuối (mới nhất)
                if isinstance(b, dict):
                    combined_logs.append(
                        {
                            "timestamp": b.get("timestamp", ""),
                            "action": "BLOCK_TIER1",
                            "target": b.get("ip", "N/A"),
                        }
                    )
        except Exception:
            pass

        # Sắp xếp theo timestamp giảm dần và lấy 10 cái mới nhất
        combined_logs = sorted(
            combined_logs, key=lambda x: str(x.get("timestamp", "")), reverse=True
        )[:10]

        if not combined_logs:
            console_html = '<div class="console-box"><div class="console-line blink">> Waiting for system events...</div></div>'
        else:
            console_lines = []
            for log in reversed(combined_logs):
                t_str = log.get("timestamp", "").split(" ")[-1]  # Lấy phần HH:MM:SS
                act = log.get("action", "LOG")
                tgt = log.get("target", "N/A")
                tgt_safe = html.escape(str(tgt))
                console_lines.append(
                    f'<div class="console-line">> [{t_str}] {act} -> {tgt_safe}</div>'
                )
            # Thêm dòng blink ở cuối cùng
            console_lines.append('<div class="console-line blink">> _</div>')
            console_html = f'<div class="console-box">{"".join(console_lines)}</div>'

        st.markdown(console_html, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### 📖 Thuật ngữ")
        glossary_html = (
            '<div class="glossary-box">'
            '  <div class="glossary-item">'
            '    <span class="glossary-title">Tier 1 (Lọc nhiễu):</span>'
            # SỐ ĐO KHÔNG ĐƯỢC VIẾT CỨNG TRONG BẢNG THUẬT NGỮ. Dòng này từng ghi "lọc bỏ
            # >95% logs sạch" — một con số không có nguồn, không có mẫu số, và gán cho
            # riêng "Session Baselining" cái thành tích của CẢ tầng 1 (chữ ký WAF + z-score
            # + danh tiếng). Đo trên lượt chạy 17/08/2026 thì Tier-1 DROP 41,0%
            # (69.932/170.450) — cách xa 95%. Tỉ lệ xả tải thật đã hiển thị ở các ô số liệu
            # phía trên, đọc từ `pipeline_stats.json`; bảng thuật ngữ chỉ định nghĩa cơ chế.
            '    <div class="glossary-desc">Luật chữ ký WAF + ngưỡng lệch chuẩn Welford '
            "O(1) chấm điểm rủi ro từng sự kiện, loại nhiễu ngay tại đầu vào để chuyên viên "
            "không bị ngập cảnh báo (tỉ lệ thật xem ô số liệu phía trên).</div>"
            "  </div>"
            '  <div class="glossary-item">'
            '    <span class="glossary-title">Tier-2 · LLM Agent:</span>'
            f'    <div class="glossary-desc">LangGraph Agent truy xuất tri thức Dual-RAG (MITRE & NIST) giúp {html.escape(_model_display_name())} ra quyết định ngăn chặn.</div>'
            "  </div>"
            '  <div class="glossary-item">'
            '    <span class="glossary-title">Feedback Loop:</span>'
            '    <div class="glossary-desc">Agent tự động sinh Signature động và hot-reload trực tiếp xuống Tier 1 để chặn nguồn tấn công thời gian thực.</div>'
            "  </div>"
            '  <div class="glossary-item">'
            '    <span class="glossary-title">HITL (Human-in-the-Loop):</span>'
            '    <div class="glossary-desc">Đưa L3 Manager phê duyệt các đề xuất cách ly của AI nhằm kiểm soát rủi ro cho hệ thống.</div>'
            "  </div>"
            "</div>"
        )
        st.markdown(glossary_html, unsafe_allow_html=True)
        st.caption(f"Lượt làm mới: {count}")

    st.title("🛡️ Trung tâm Điều hành An ninh Mạng SENTINEL AI SOC")

    # Fetch tampered IDs early for filtering and rendering
    try:
        tampered_ids = cached_get_tampered_audit_ids()
    except Exception:
        tampered_ids = set()

    # Render KPI
    # Trần áp RIÊNG cho TỪNG TẦNG, không áp một lần cho cả sổ.
    #
    # Ba tab bên dưới chia theo tầng ra quyết định. Lấy chung 2.000 dòng mới nhất rồi mới tách
    # thì tầng ghi nhiều nuốt sạch hạn mức: đo ở lượt 11/08/2026, toàn bộ 2.000 dòng mới nhất
    # là ALERT của Tier-1, nên tab Tier-2 hiện "Không có sự cố nào" trong khi thẻ chỉ số ngay
    # trên đầu vẫn ghi 67 lệnh chặn của LLM. Hai con số mâu thuẫn nhau trên cùng màn hình.
    _ALERT_CAP = 2000
    _seen_ids: set = set()
    all_alerts = []
    for _t in (TIER_RULE, TIER_ML, TIER_LLM, TIER_MANUAL, ""):
        for a in cached_get_audit_trail(limit=_ALERT_CAP, tier=_t):
            if a.get("action") == "AWAIT_HITL" or a.get("id") in _seen_ids:
                continue
            _seen_ids.add(a.get("id"))
            all_alerts.append(a)
    all_alerts.sort(key=lambda a: a.get("id") or 0, reverse=True)
    # Các tab nhật ký đọc danh sách BỊ TRẦN này, còn hàng chỉ số đọc COUNT(*) không trần. Khi
    # sổ vượt trần, hai bên lệch nhau MÀ KHÔNG BÁO GÌ — người xem chỉ thấy tab ít hơn chỉ số
    # và tưởng có số bịa. Phát cảnh báo tại đúng thời điểm đó.
    _alerts_capped = cached_count_audit_alerts() > _ALERT_CAP
    active_rules = feedback_mgr.get_active_dynamic_rules()
    pending_rules = feedback_mgr.get_pending_rules()
    whitelisted_ips = feedback_mgr.get_whitelisted_ips()
    blocked_ips = {r.get("pattern") for r in active_rules if r.get("pattern")}

    # Tính toán bộ lọc sự cố
    filtered_alerts = all_alerts
    if action_filter != "Tất cả":
        filtered_alerts = [a for a in filtered_alerts if a.get("action") == action_filter]
    search_ip_tab1 = st.session_state.get("search_ip_tab1", "").strip()
    active_search_ip = search_ip or search_ip_tab1

    if active_search_ip:
        filtered_alerts = [a for a in filtered_alerts if active_search_ip in a.get("target", "")]

    if mitre_filter != "Tất cả":
        filtered_alerts = [
            a
            for a in filtered_alerts
            if mitre_filter in str(a.get("mitre_technique", ""))
            or mitre_filter in str(a.get("reason", ""))
        ]

    if show_tampered_only:
        filtered_alerts = [a for a in filtered_alerts if a.get("id") in tampered_ids]

    # Tính toán Live FPR dựa trên các rule được Duyệt (ACTIVE) vs Bác bỏ (REJECTED) bởi con người
    all_rules = feedback_mgr.get_all_dynamic_rules()
    approved_rules_count = sum(1 for r in all_rules if r.get("status") == "ACTIVE")
    rejected_rules_count = sum(1 for r in all_rules if r.get("status") == "REJECTED")
    total_reviewed = approved_rules_count + rejected_rules_count
    # ĐÂY KHÔNG PHẢI FPR. Nhãn cũ trên KPI là "Live False Positive Rate", nhưng công thức là
    # (luật bị analyst BÁC BỎ) / (luật đã được analyst xem xét) — mẫu số là số LUẬT ĐỀ XUẤT,
    # không phải số sự kiện lành tính. FPR thật là FP/(FP+TN) trên toàn luồng và phải đo bằng
    # benchmark có đáp án, không suy được từ thao tác duyệt. Trong buổi bảo vệ, in một con số
    # dán nhãn FPR mà không phải FPR là chỗ chết người.
    #
    # Chưa ai duyệt luật nào -> `None` để hiện "—". Bản cũ trả 0.0 nên Dashboard mở lên là
    # khoe "0.0% False Positive" dù chưa có một mẩu bằng chứng nào.
    live_fpr = (rejected_rules_count / total_reviewed) * 100 if total_reviewed > 0 else None

    # Số liệu THẬT (không ước lượng): đọc counter do subscriber ghi ra
    # config/pipeline_stats.json khi xử lý log thô qua Tier-1.
    # raw_logs_total = tổng log đã phân tích; pending_llm_queue = backlog Tier-2.
    raw_logs_count = 0
    try:
        import json as _json

        _stats_p = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config",
            "pipeline_stats.json",
        )
        with open(_stats_p) as _sf:
            _ps = _json.load(_sf)
        raw_logs_count = int(_ps.get("raw_logs_total", 0))
        pending_llm_count = int(_ps.get("pending_llm_queue", 0))
        # `pending_llm_queue` là ẢNH CHỤP hàng đợi TRONG TIẾN TRÌNH subscriber tại lần ghi
        # cuối. Subscriber dừng (hết luồng / bị kill) thì con số ĐÓNG BĂNG ở đó chứ không về
        # 0 — đo thật: file còn 623 trong khi Redis đã `lag 0`. Nếu cứ in trần con số, người
        # đọc tưởng Tier-2 đang chạy. Lấy tuổi tệp làm mốc: quá 60s không ai ghi = luồng đã
        # dừng, và 623 kia là số sự kiện ĐÃ ack khỏi Redis nhưng CHƯA kịp phân tích.
        pending_llm_stale = (time.time() - os.path.getmtime(_stats_p)) > 60
        # `offload_counts` chứa bộ đếm TOÀN luồng, không trần — nguồn đúng cho phễu và cho
        # tỉ lệ xả tải. Trước đây UI KHÔNG đọc khoá này một lần nào, nên phễu phải chắp vá
        # từ ring buffer 12 dòng + audit_trail trần 2000 (xem `render_metrics_header`).
        _offload_counts = _ps.get("offload_counts") or {}
    except Exception:
        pending_llm_count = 0
        pending_llm_stale = False
        _offload_counts = {}

    # "Giảm nhiễu" ĐÃ BỎ khỏi Dashboard: nó là (log thô − cảnh báo tới analyst) / log thô,
    # đại lượng KHÁC với xả tải LLM và luôn cao hơn ~11 điểm. Để cả hai phần trăm cạnh nhau
    # thì người đọc trích số nào cũng thấy "đúng". Nay chỉ giữ MỘT chỉ số: xả tải LLM.
    t1_blocks_list = cached_get_tier1_blocks()

    render_metrics_header(
        all_alerts,
        len(pending_rules),
        len(active_rules),
        raw_logs_count,
        live_fpr,
        t1_blocks=t1_blocks_list,
        offload_counts=_offload_counts,
        blocks_by_tier=cached_count_blocks_by_tier(),
    )

    tab0, tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "🎬 Tổng quan",
            "📊 Nhật ký & Sổ kiểm toán",
            "🧑‍💻 Phê duyệt (HITL)",
            "🎯 Tình báo & Chuỗi APT",
            "🔒 Chặn & Miễn trừ",
            "🔍 Lỗ hổng & Tri thức",
        ]
    )

    with tab0:
        render_demo_overview(
            all_alerts,
            active_rules,
            pending_rules,
            raw_logs_count,
            offload_counts=_offload_counts,
            pending_llm=pending_llm_count,
            pending_llm_stale=pending_llm_stale,
            blocks_by_tier=cached_count_blocks_by_tier(),
        )

    with tab1:
        # Biểu đồ Live SOC Analytics dạng collapsible
        with st.expander("📊 Biểu đồ phân tích SIEM", expanded=True):
            if not all_alerts:
                st.info("Chưa có đủ dữ liệu sự cố để vẽ biểu đồ phân tích.")
            else:
                try:
                    df_alerts = pd.DataFrame(all_alerts)
                    df_alerts["hour"] = df_alerts["timestamp"].apply(lambda x: str(x)[5:16])

                    col_chart1, col_chart2 = st.columns(2)
                    with col_chart1:
                        st.markdown("##### 📈 Xu hướng sự cố theo thời gian")

                        # Cùng nguồn chân lý với bảng "đã chặn" và phần chia tab: cột `tier`.
                        # Biểu đồ này từng dò chuỗi riêng, nên một sự cố có thể được xếp vào
                        # tầng A trên biểu đồ và tầng B ở tab ngay bên cạnh.
                        df_alerts["Nguồn"] = [_nhan_tang(a) for a in all_alerts]
                        trend_df = (
                            df_alerts.groupby(["hour", "Nguồn"]).size().reset_index(name="Số lượng")  # type: ignore[call-overload]
                        )
                        trend_df = trend_df.sort_values("hour")

                        st.bar_chart(
                            trend_df,
                            x="hour",
                            y="Số lượng",
                            color="Nguồn",
                            height=200,
                            width="stretch",
                        )
                    with col_chart2:
                        st.markdown("##### 📊 Phân bổ cảnh báo theo hành động")
                        action_df = (
                            df_alerts.groupby("action")
                            .size()
                            .to_frame(name="Số lượng")
                            .reset_index()
                        )
                        st.bar_chart(
                            action_df.set_index("action"), y="Số lượng", height=200, width="stretch"
                        )
                except Exception as e:
                    st.write("Không thể vẽ biểu đồ phân tích SIEM:", e)

        st.subheader("Phân tích ngữ cảnh và cảnh báo")
        st.caption(
            "🔵 **Tier-2 · LLM Agent**: Quyết định do LLM/Agent suy luận sau khi Tier-1 leo thang (ESCALATE).  ·  "
            "🟢 **Tier-1 Filter**: Whitelist cho qua hoặc chặn tự động (không cần LLM).  ·  "
            'Tier-1 BLOCK riêng được hiển thị tại bảng *"Vòng phản hồi Hai tầng"* ở tab Tổng quan.'
        )

        # Thêm ô tìm kiếm IP trực tiếp trong Tab 1
        st.text_input(
            "🔍 Tìm kiếm nhanh theo IP mục tiêu:",
            placeholder="Nhập địa chỉ IP để lọc lịch sử bên dưới...",
            key="search_ip_tab1",
        )

        # Xuất dữ liệu CSV để lưu trữ lịch sử
        if filtered_alerts:
            df_download = pd.DataFrame(filtered_alerts)
            df_download = df_download.rename(
                columns={
                    "timestamp": "Thời gian",
                    "action": "Hành động",
                    "target": "Đối tượng (Target)",
                    "reason": "Lý do & Lập luận",
                }
            )
            csv_data = df_download.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Tải xuống lịch sử lọc (CSV)",
                data=csv_data,
                file_name="sentinel_scan_history.csv",
                mime="text/csv",
            )

        if not filtered_alerts:
            _af = st.session_state.get("action_filter_sb", "Tất cả")
            st.markdown(
                f"""<div class="soc-empty">
                    <div class="soc-empty-title">🔎 Không có sự cố nào khớp bộ lọc hiện tại</div>
                    <div class="soc-empty-sub">Bộ lọc hành động: <b>{_af}</b>. Hãy đổi sang
                    <b>“Tất cả”</b> hoặc một phân loại khác, hoặc seed thêm dữ liệu demo.</div>
                </div>""",
                unsafe_allow_html=True,
            )
        else:
            # Chia theo 3 CHẶNG QUYẾT ĐỊNH của kiến trúc HAI tầng (không phải "3 tier"):
            # Tier-1 luật · Tier-1 Cổng ML · Tier-2 LLM. Cổng ML nằm TRONG Tier-1.
            alerts_t1_rule = []
            alerts_t1_mlgate = []
            alerts_t2_llm = []
            for alert in filtered_alerts:
                # NGUỒN CHÂN LÝ: cột `tier` do chính tầng ra quyết định ghi vào audit_trail.
                #
                # LỖI ĐÃ SỬA: trước đây chỉ có heuristic DÒ CHUỖI trong câu lý do bên dưới.
                # Câu lý do khi LLM hỏng chứa cụm "Tier-1 (xác định) vẫn bảo vệ độc lập", nên
                # một sự cố của Tier-2 rơi nhầm sang tab Tier-1 ngay khi action không phải
                # AWAIT_HITL. Phân loại bằng cách đọc văn xuôi là mời lỗi vào nhà.
                _tier = str(alert.get("tier") or "")
                if _tier == TIER_ML:
                    alerts_t1_mlgate.append(alert)
                    continue
                if _tier in (TIER_RULE, TIER_MANUAL):
                    alerts_t1_rule.append(alert)
                    continue
                if _tier == TIER_LLM:
                    alerts_t2_llm.append(alert)
                    continue

                # Bản ghi TRƯỚC migration (`tier` rỗng) -> rơi về heuristic cũ. Giữ nguyên
                # thứ tự cũ để lịch sử hiển thị y như trước, không đổi hồi tố.
                r = alert.get("reason", "")
                if any(k in r for k in ML_GATE_MARKERS):
                    alerts_t1_mlgate.append(alert)
                elif "Tier 1" in r or "Tier-1" in r or "whitelist" in r.lower():
                    alerts_t1_rule.append(alert)
                else:
                    alerts_t2_llm.append(alert)

            if _alerts_capped:
                st.warning(
                    f"⚠️ Sổ kiểm toán đã vượt {vn_num(_ALERT_CAP)} dòng — mỗi tab dưới đây hiển thị "
                    f"{vn_num(_ALERT_CAP)} sự cố MỚI NHẤT **của riêng tầng đó**. Số ở hàng chỉ số phía "
                    "trên là COUNT(*) trên toàn sổ nên sẽ LỚN HƠN tổng ba tab. Đây là giới hạn "
                    "hiển thị, không phải số liệu lệch."
                )

            t1_tab, ml_gate_tab, t2_llm_tab = st.tabs(
                [
                    "🟢 Tier-1 · Rules (Welford & Signatures)",
                    "⚡ Tier-1 · ML Gate (LightGBM)",
                    "🧠 Tier-2 · Agentic LLM (LangGraph)",
                ]
            )

            def _render_alerts_list(alert_list, tab_key):
                if not alert_list:
                    st.info("Không có sự cố nào ở Tier này.")
                    return

                total_pages = max(1, math.ceil(len(alert_list) / page_size))
                page_key = f"current_page_{tab_key}"
                if page_key not in st.session_state:
                    st.session_state[page_key] = 1
                if st.session_state[page_key] > total_pages:
                    st.session_state[page_key] = total_pages

                start_idx = (st.session_state[page_key] - 1) * page_size
                end_idx = start_idx + page_size
                page_alerts = alert_list[start_idx:end_idx]

                # Hiển thị các Alert Cards cho trang hiện tại
                for idx, alert in enumerate(page_alerts):
                    target_ip = alert.get("target", "").strip()
                    is_wl = target_ip in whitelisted_ips
                    is_bl = target_ip in blocked_ips

                    render_alert_card(
                        alert,
                        is_l3_manager=(st.session_state.get("role") == "L3_Manager"),
                        on_whitelist=handle_whitelist_approval,
                        on_block=handle_block_approval,
                        card_id=f"{tab_key}_{start_idx + idx}",
                        is_whitelisted=is_wl,
                        is_blocked=is_bl,
                        is_tampered=(alert.get("id") in tampered_ids),
                        # Số THẬT trong kho uy tín, thay cho việc regex trên câu lý do.
                        reputation=cached_get_ip_reputation(target_ip),
                    )

                # Điều hướng trang
                if total_pages > 1:
                    st.write("")
                    col_prev, col_page, col_next = st.columns([1, 2, 1])
                    with col_prev:
                        if st.button(
                            "⬅️ Trang trước",
                            disabled=(st.session_state[page_key] == 1),
                            key=f"prev_{tab_key}",
                        ):
                            st.session_state[page_key] -= 1
                            st.rerun()
                    with col_page:
                        st.markdown(
                            f"<div style='text-align:center;padding-top:5px;font-weight:bold;'>Trang {st.session_state[page_key]} / {total_pages}</div>",
                            unsafe_allow_html=True,
                        )
                    with col_next:
                        if st.button(
                            "Trang sau ➡️",
                            disabled=(st.session_state[page_key] == total_pages),
                            key=f"next_{tab_key}",
                        ):
                            st.session_state[page_key] += 1
                            st.rerun()

            with t1_tab:
                # Qua cache (ttl=2): trước đây gọi thẳng _get_tier1_blocks(1000) -> đọc + khử
                # trùng TOÀN BỘ file tier1_blocks.json mỗi lượt refresh (nặng nhất trong UI).
                tier1_blocks_data = cached_get_tier1_blocks(show=1000)

                if action_filter not in ["Tất cả", "BLOCK_IP"]:
                    tier1_blocks_data = []
                if active_search_ip:
                    tier1_blocks_data = [
                        blk for blk in tier1_blocks_data if active_search_ip in blk.get("ip", "")
                    ]
                if show_tampered_only:
                    tier1_blocks_data = []

                # Phân trang
                page_key_blocks = "current_page_t1_blocks"
                if page_key_blocks not in st.session_state:
                    st.session_state[page_key_blocks] = 1

                total_pages_blocks = max(1, math.ceil(len(tier1_blocks_data) / page_size))
                if st.session_state[page_key_blocks] > total_pages_blocks:
                    st.session_state[page_key_blocks] = total_pages_blocks

                start_idx = (st.session_state[page_key_blocks] - 1) * page_size
                end_idx = start_idx + page_size
                paged_blocks = tier1_blocks_data[start_idx:end_idx]

                # ── Phần 1: Block tức thời (Redis ring buffer) ──
                # NÓI RÕ ĐÂY LÀ "GẦN NHẤT". Nhãn cũ ("Chặn tức thời Tier-1: 12 IP") đọc như
                # một TỔNG, trong khi nguồn là ring buffer bị cắt hai lần: subscriber chỉ ghi
                # 50 bản ghi cuối, UI lại cắt còn 12. Đặt cạnh ô "Tier-1 luật chặn" hàng nghìn
                # thì trông như hai con số mâu thuẫn, thực ra là hai thứ khác nhau.
                st.markdown(
                    f"**🛡️ Chặn tức thời Tier-1 — {len(tier1_blocks_data)} IP GẦN NHẤT** "
                    "_(không phải tổng)_"
                )
                st.caption(
                    "_(ring buffer `config/tier1_blocks.json` — chỉ giữ các lệnh chặn mới nhất, "
                    "TTL 1h, không cần LLM. Tổng số lệnh chặn xem ở hàng chỉ số phía trên.)_"
                )
                if not tier1_blocks_data:
                    st.info(
                        "Chưa có IP nào bị Tier-1 chặn tức thời trong phiên này hoặc không khớp bộ lọc."
                    )
                else:
                    for blk in paged_blocks:
                        ip = html.escape(str(blk.get("ip", "N/A")))
                        score = blk.get("score", 0)
                        count = blk.get("count", 1)
                        ts = html.escape(str(blk.get("ts", "")))[:19]
                        reasons = blk.get("reasons", [])
                        reasons_html = (
                            "".join(
                                f'<li style="margin-bottom:3px;">{html.escape(str(r))}</li>'
                                for r in reasons
                            )
                            or '<li style="color:#8c8c8c;">Không có chi tiết lý do.</li>'
                        )

                        card_html = (
                            '<div class="soc-card severity-critical" style="border-left:4px solid #ff4d4f;">'
                            '  <div class="soc-card-header">'
                            '    <h4 class="soc-card-title">🛑 [BLOCK] ĐÃ CHẶN TẠI TIER-1</h4>'
                            '    <span class="soc-badge" style="background:rgba(255,77,79,0.2);color:#ff7875;'
                            "border:1px solid rgba(255,77,79,0.4);font-size:0.75rem;padding:2px 8px;"
                            'border-radius:4px;margin-left:8px;">🛡️ Tier-1 Block · Redis TTL 1h</span>'
                            f'    <span class="soc-timestamp">{ts}</span>'
                            "  </div>"
                            '  <div class="soc-detail-row" style="flex-wrap:wrap;gap:4px;">'
                            '    <span class="soc-label">IP bị chặn:</span>'
                            f'    <span class="soc-value-code" style="color:#ff7875;">{ip}</span>'
                            f"    {build_tier1_block_badge(count, score)}"
                            '    <span class="soc-badge" style="background:rgba(82,196,26,0.15);color:#95de64;border:1px solid rgba(82,196,26,0.35);">🟢 Rule Engine Match</span>'
                            "  </div>"
                            '  <div class="soc-reasoning-box" style="margin-top:8px;">'
                            '    <div class="soc-reasoning-title">⚡ Lý do Tier-1 chặn (Rule Engine):</div>'
                            f'    <ul style="margin:6px 0 0 18px;font-size:0.85rem;color:#d9d9d9;">{reasons_html}</ul>'
                            '    <div style="color: #98FB98; margin-top: 6px; font-size: 0.85rem; font-weight: 500;">🛡️ Khuyến nghị phản hồi (chính sách hệ thống): ngăn chặn khẩn cấp — chặn IP nguồn tại tường lửa để cô lập phạm vi tấn công.</div>'
                            "  </div>"
                            '  <div class="soc-detail-row" style="margin-top:8px;">'
                            '    <span class="soc-badge" style="background:rgba(255,77,79,0.15);color:#ff7875;'
                            'border:1px solid rgba(255,77,79,0.35);">🛑 CHẶN NGAY · Không cần LLM · Tự động hot-reload xuống Tier-1</span>'
                            "  </div>"
                            "</div>"
                        )
                        st.markdown(
                            "".join(line.strip() for line in card_html.split("\n")),
                            unsafe_allow_html=True,
                        )

                    # Hiển thị nút chuyển trang cho Block tức thời
                    if total_pages_blocks > 1:
                        st.write("")
                        col_prev, col_page, col_next = st.columns([1, 2, 1])
                        with col_prev:
                            if st.button(
                                "⬅️ Trang trước",
                                disabled=(st.session_state[page_key_blocks] == 1),
                                key="prev_t1_blocks",
                            ):
                                st.session_state[page_key_blocks] -= 1
                                st.rerun()
                        with col_page:
                            st.markdown(
                                f"<div style='text-align:center;padding-top:5px;font-weight:bold;'>Trang {st.session_state[page_key_blocks]} / {total_pages_blocks}</div>",
                                unsafe_allow_html=True,
                            )
                        with col_next:
                            if st.button(
                                "Trang sau ➡️",
                                disabled=(st.session_state[page_key_blocks] == total_pages_blocks),
                                key="next_t1_blocks",
                            ):
                                st.session_state[page_key_blocks] += 1
                                st.rerun()

                # ── Phần 2: Alert/Block từ Audit Trail Tier-1 ──
                st.markdown("---")
                st.markdown(
                    f"**📋 Nhật ký Tier-1 (luật) từ Audit Trail:** {len(alerts_t1_rule)} sự cố"
                )
                st.caption("_(ALERT / BLOCK được luật Tier-1 ghi vào audit trail)_")
                _render_alerts_list(alerts_t1_rule, "t1")
            with ml_gate_tab:
                st.caption(
                    f"Tổng số sự cố hiển thị: **{len(alerts_t1_mlgate)}** — phán quyết của "
                    "**Cổng ML (LightGBM, thuộc Tier-1)**, quyết ở tốc độ đường truyền, KHÔNG gọi LLM."
                )
                _render_alerts_list(alerts_t1_mlgate, "t2")
            with t2_llm_tab:
                st.caption(f"Tổng số sự cố hiển thị: **{len(alerts_t2_llm)}**")
                _render_alerts_list(alerts_t2_llm, "t3")

    with tab2:
        st.subheader("Phê duyệt Phân tích từ LLM (AWAIT_HITL)")
        if not pending_rules:
            st.info("Không có sự cố nào đang chờ phê duyệt.")
        else:

            def _render_pending_list(rules_list, page_key):
                if not rules_list:
                    st.info("Không có luật nào đang chờ phê duyệt ở Tier này.")
                    return
                # Sắp xếp: mức độ nghiêm trọng (score) giảm dần, rồi thời gian tạo mới nhất trước
                sorted_pending = sorted(
                    rules_list,
                    key=lambda r: (r.get("score") or 0, str(r.get("created_at") or "")),
                    reverse=True,
                )
                # Phân trang cho dễ nhìn
                rules_per_page = 5
                n_pages = max(1, math.ceil(len(sorted_pending) / rules_per_page))
                if st.session_state.get(page_key, 1) > n_pages:
                    st.session_state[page_key] = n_pages
                cur = st.session_state.get(page_key, 1)
                page_rules = sorted_pending[(cur - 1) * rules_per_page : cur * rules_per_page]
                st.caption(
                    f"🔽 Sắp theo mức độ nghiêm trọng rồi thời gian · {len(sorted_pending)} luật chờ duyệt"
                )

                for rule in page_rules:
                    sev_icon, sev_label = _rule_severity(rule.get("score"))
                    created = str(rule.get("created_at") or "—")[:19].replace("T", " ")

                    src = rule.get("source", "")
                    if "langgraph_agent_hitl" in src:
                        hitl_type = "🧠 AWAIT_HITL — Tier-2 LLM đề nghị chuyên viên xem xét"
                        hitl_color = "#722ed1"
                    elif "ml_triage" in src:
                        hitl_type = "⚡ AWAIT_HITL — Cổng ML đề xuất"
                        hitl_color = "#1890ff"
                    elif "tier1_rule_engine" in src:
                        hitl_type = "🛡️ AWAIT_HITL — cảnh báo từ luật Tier-1"
                        hitl_color = "#faad14"
                    elif "langgraph_agent" in src:
                        hitl_type = "🛑 BLOCK_IP — hệ thống đề nghị chặn"
                        hitl_color = "#ff4d4f"
                    else:
                        # `src` đọc từ luật động trong YAML -> thoát trước khi nhúng vào HTML.
                        hitl_type = f"🔧 MANUAL ({html.escape(str(src))})"
                        hitl_color = "#1890ff"

                    with st.expander(
                        f"{sev_icon} [{sev_label}] {rule.get('pattern')} · 🕒 {created} · score {rule.get('score')}",
                        expanded=True,
                    ):
                        st.markdown(
                            f"**Loại phê duyệt:** <span style='color: {hitl_color}; font-weight: bold;'>{hitl_type}</span>",
                            unsafe_allow_html=True,
                        )
                        st.write(
                            f"**Mức nghiêm trọng:** {sev_icon} {sev_label} (điểm {rule.get('score')})"
                        )
                        st.write(f"**Tạo lúc:** {created}")
                        st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                        st.write(f"**Lý do:** {rule.get('reason')}")

                        # ── Badge + hierarchy + mã kỹ thuật cho thẻ HITL ──────────────
                        # Dùng ĐÚNG bộ dựng mà `render_alert_card` dùng, để hai màn hình
                        # không bao giờ nói khác nhau về cùng một bản ghi. Trước đây khối
                        # này là ~70 dòng chép tay và đã trôi dạt: cùng bốn giá trị bịa phải
                        # sửa hai lần ở hai tệp.
                        raw_reason_hitl = str(rule.get("reason", ""))
                        mitre_tech_hitl = ui_components.parse_mitre_technique(raw_reason_hitl)
                        gr_badge, is_gr = ui_components.build_grounding_badge(
                            raw_reason_hitl, mitre_tech_hitl
                        )
                        # CHỐNG STORED XSS. `parse_mitre_technique` trả về NGUYÊN VĂN cụm
                        # trong `[MITRE: ...]`, mà chuỗi reason do LLM sinh ra sau khi đã ĐỌC
                        # payload của kẻ tấn công — nên nội dung đó là dữ liệu KHÔNG tin cậy.
                        # `render_alert_card` đã thoát chuỗi này (components.py), nhưng bảng
                        # HITL ở đây thì chưa: cùng một hàm, hai nơi dùng, chỉ một nơi có rào.
                        # Chỉ thoát cho phần HIỂN THỊ; các hàm dựng huy hiệu vẫn nhận bản thô
                        # vì chúng so khớp chuỗi (và tự thoát khi cần in ra).
                        safe_mitre_tech_hitl = html.escape(mitre_tech_hitl)
                        st.markdown(
                            '<div style="margin-top:8px;padding:8px;background:rgba(255,255,255,0.03);'
                            'border-radius:6px;border:1px solid rgba(255,255,255,0.08);">'
                            '<div style="margin-bottom:6px;display:flex;flex-wrap:wrap;gap:4px;">'
                            f"{gr_badge}"
                            f"{ui_components.build_origin_badge(raw_reason_hitl)}"
                            f"{ui_components.build_threat_memory_badge(raw_reason_hitl, cached_get_ip_reputation(str(rule.get('pattern') or '')))}"
                            "</div>"
                            '<div class="soc-reasoning-section" style="color:#D3ADF7;margin-top:4px;'
                            f'font-size:0.83rem;">🎯 MITRE ATT&CK Mapping: <code>{safe_mitre_tech_hitl}</code></div>'
                            f"{ui_components._build_mitre_hierarchy_html(mitre_tech_hitl)}"
                            f"{ui_components.build_technique_codes_html(raw_reason_hitl)}"
                            f"{ui_components.build_guardrail_note(is_gr, mitre_tech_hitl, 'AWAIT_HITL', raw_reason_hitl)}"
                            '<div style="color:#98FB98;margin-top:6px;font-size:0.83rem;font-weight:500;">'
                            "🛡️ Khuyến nghị phản hồi (chính sách hệ thống): cần chuyên viên "
                            "phê duyệt (HITL) trước khi luật chặn tự động có hiệu lực."
                            "</div></div>",
                            unsafe_allow_html=True,
                        )

                        # Lấy raw log để minh chứng
                        target_pattern = str(rule.get("pattern", ""))
                        ip_audits = cached_get_audit_trail_for_ip(target_pattern, limit=10)
                        # Ưu tiên lấy log có reason khớp (phòng khi 1 IP có nhiều log)
                        matched_audit = next(
                            (
                                a
                                for a in ip_audits
                                if a.get("raw_log")
                                and str(rule.get("reason", "")) in a.get("reason", "")
                            ),
                            None,
                        )
                        if not matched_audit:  # Fallback lấy cái mới nhất có raw_log
                            matched_audit = next((a for a in ip_audits if a.get("raw_log")), None)
                        if matched_audit and matched_audit.get("raw_log"):
                            with st.expander("🔍 Xem LOG THÔ ĐẦY ĐỦ (Minh chứng)"):
                                ui_components.render_ground_truth(matched_audit.get("raw_log"))
                                st.code(matched_audit.get("raw_log"), language="json")

                        if st.session_state.get("role") == "L3_Manager":
                            col1, col2 = st.columns([1, 1])
                            with col1:
                                if st.button(
                                    "✅ Duyệt", key=f"app_{rule.get('pattern')}_{page_key}"
                                ):
                                    # Phát hiện xung đột block↔whitelist TRƯỚC khi duyệt (approve_rule
                                    # sẽ tự gỡ khỏi whitelist) để thông báo cho analyst.
                                    _was_wl = (
                                        rule.get("field") == "Source IP"
                                        and rule.get("pattern")
                                        in feedback_mgr.get_whitelisted_ips()
                                    )
                                    feedback_mgr.approve_rule(
                                        rule.get("pattern"), rule.get("field")
                                    )
                                    st.cache_data.clear()
                                    st.success(f"✅ Đã DUYỆT luật chặn cho {rule.get('pattern')}")
                                    # Ghi audit khi DUYỆT luật (đồng bộ: duyệt block cũng để lại
                                    # 1 bản ghi như duyệt whitelist). Luật Source IP -> BLOCK_IP.
                                    from src.response.executor import _log_to_db

                                    _act = "BLOCK_IP" if rule.get("field") == "Source IP" else "LOG"
                                    _log_to_db(
                                        _act,
                                        str(rule.get("pattern")),
                                        f"[Tier-1 Filter] Rule APPROVED (HITL) by "
                                        f"{st.session_state.get('username')}: {rule.get('reason')}",
                                    )
                                    if _act == "BLOCK_IP":
                                        # Đưa vào kho known-bad (reputation=100) -> Tier-1 chặn
                                        # on-sight NGAY + hiện ở Threat Intel, đồng bộ với auto-block.
                                        threat_memory.mark_ip_blocked(str(rule.get("pattern")))
                                    if _was_wl:
                                        st.warning(
                                            f"⚠️ {rule.get('pattern')} đã được GỠ khỏi Whitelist "
                                            "vì luật chặn được duyệt."
                                        )
                                    st.rerun()
                            with col2:
                                if st.button(
                                    "❌ Bác bỏ", key=f"rej_{rule.get('pattern')}_{page_key}"
                                ):
                                    feedback_mgr.reject_rule(rule.get("pattern"), rule.get("field"))
                                    st.cache_data.clear()
                                    # Xóa khỏi Redis blacklist (trường hợp LLM đã block tạm thời)
                                    if rule.get("field") == "Source IP":
                                        from src.response.executor import unblock_ip

                                        unblock_ip(str(rule.get("pattern")))
                                    from src.response.executor import _log_to_db

                                    _log_to_db(
                                        "LOG",
                                        str(rule.get("pattern")),
                                        f"[Tier-1 Filter] Rule REJECTED (HITL) by {st.session_state.get('username')}: {rule.get('reason')}",
                                    )
                                    st.warning(f"Đã bác bỏ luật cho {rule.get('pattern')}")
                                    st.rerun()
                        else:
                            st.warning("Cần vai trò L3_Manager để duyệt hoặc bác bỏ.")

                # Điều hướng trang (HITL)
                if n_pages > 1:
                    cprev, cmid, cnext = st.columns([1, 2, 1])
                    with cprev:
                        if st.button(
                            "⬅️ Trang trước", disabled=(cur == 1), key=f"hitl_prev_{page_key}"
                        ):
                            st.session_state[page_key] = cur - 1
                            st.rerun()
                    with cmid:
                        st.markdown(
                            f"<div style='text-align:center;padding-top:5px;font-weight:bold;'>Trang {cur} / {n_pages}</div>",
                            unsafe_allow_html=True,
                        )
                    with cnext:
                        if st.button(
                            "Trang sau ➡️", disabled=(cur == n_pages), key=f"hitl_next_{page_key}"
                        ):
                            st.session_state[page_key] = cur + 1
                            st.rerun()

            # MỌI luật chờ duyệt đều phải hiện ở đây, không lọc theo nguồn. Bản trước chỉ
            # nhận `langgraph_agent*`, nên luật `ml_triage` / `tier1_rule_engine` /
            # `manual_*` mà rơi vào PENDING_APPROVAL sẽ KHÔNG có nút duyệt nào và mắc kẹt
            # vĩnh viễn. Bộ hiển thị ngay bên dưới VỐN ĐÃ xử lý đủ các nguồn đó (kể cả
            # nhánh MANUAL dự phòng) — chỉ riêng bộ lọc này bị bỏ quên khi mở rộng.
            llm_pending_rules = list(pending_rules)
            st.caption(f"Tổng số sự cố chờ duyệt: **{len(llm_pending_rules)}**")
            _render_pending_list(llm_pending_rules, "hitl_page_all")

        st.markdown("---")
        st.subheader("Lịch sử phê duyệt đã áp dụng")
        hitl_active_rules = [r for r in active_rules if r.get("is_hitl_approved") is True]
        if not hitl_active_rules:
            st.info("Không có luật nào đang hoạt động.")
        else:
            for rule in sorted(
                hitl_active_rules,
                key=lambda r: (r.get("score") or 0, str(r.get("created_at") or "")),
                reverse=True,
            ):
                _si, _sl = _rule_severity(rule.get("score"))
                with st.expander(
                    f"{_si} [{_sl}] {rule.get('pattern')} · score {rule.get('score')}",
                    expanded=False,
                ):
                    st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                    st.write(f"**Lý do:** {rule.get('reason')}")
                    st.write(f"**Tạo lúc:** {rule.get('created_at')}")

                    # Lấy raw log để minh chứng
                    target_pattern = str(rule.get("pattern", ""))
                    ip_audits = cached_get_audit_trail_for_ip(target_pattern, limit=10)
                    matched_audit = next(
                        (
                            a
                            for a in ip_audits
                            if a.get("raw_log")
                            and str(rule.get("reason", "")) in a.get("reason", "")
                        ),
                        None,
                    )
                    if not matched_audit:
                        matched_audit = next((a for a in ip_audits if a.get("raw_log")), None)
                    if matched_audit and matched_audit.get("raw_log"):
                        with st.expander("🔍 Xem LOG THÔ ĐẦY ĐỦ (Minh chứng)"):
                            ui_components.render_ground_truth(matched_audit.get("raw_log"))
                            st.code(matched_audit.get("raw_log"), language="json")

                    if st.session_state.get("role") == "L3_Manager":
                        if st.button("🔄 Vô hiệu hóa / Hoàn tác", key=f"rev_{rule.get('pattern')}"):
                            feedback_mgr.reject_rule(rule.get("pattern"), rule.get("field"))
                            st.cache_data.clear()
                            from src.response.executor import _log_to_db

                            _log_to_db(
                                "LOG",
                                str(rule.get("pattern")),
                                f"[Tier-1 Filter] Luật bị HOÀN TÁC (HITL) bởi {st.session_state.get('username')}: {rule.get('reason')}",
                            )
                            st.warning(f"Đã hoàn tác và vô hiệu hóa luật {rule.get('pattern')}")
                            st.rerun()

    with tab3:
        st.subheader("Giám sát chuỗi APT và danh tiếng IP")
        st.caption(
            "ℹ️ Phân biệt: **Điểm danh tiếng** = lịch sử vi phạm của MỘT IP (1 lần BLOCK = 30đ, "
            "cap 100, tự giảm theo thời gian) — KHÔNG phải 'điểm APT'. **APT thật** (bảng phía dưới) "
            "chỉ gán khi một IP xuất hiện ở **≥2 ngày KHÁC NHAU** (COUNT DISTINCT apt_day ≥ 2); "
            "chỉ dữ liệu DAPT2020 (có apt_phase) mới vào đây — log escalate lên LLM thường KHÔNG bị tính là APT."
        )

        # Lấy danh sách IP nguy hiểm từ Long-term Memory. ĐỒNG BỘ WHITELIST: IP đã whitelist
        # được MIỄN TRỪ enforcement -> KHÔNG hiển thị như "Threat Actor nguy cơ cao" (tránh
        # mâu thuẫn: vừa whitelist vừa bị liệt kê nguy hiểm). Vẫn thấy hành vi của nó ở thẻ
        # Whitelist trong Audit Trail.
        _wl_set = set(feedback_mgr.get_whitelisted_ips() or [])
        high_risk_ips = [
            r for r in cached_get_high_risk_ips(min_score=1.0) if r["ip"] not in _wl_set
        ]
        high_risk_data = [[r["ip"], r["reputation_score"]] for r in high_risk_ips]

        # Hiển thị bảng danh tiếng và whitelist, đồng thời nhận IP được click chọn (nếu có)
        selected_actor_ip = render_threat_intel_tables(high_risk_data)

        st.markdown("---")

        # Lấy và hiển thị chuỗi sự kiện APT (DAPT2020), đồng thời nhận IP được click chọn (nếu có)
        apt_events = cached_get_all_threat_events()
        selected_apt_ip = render_apt_events_table(apt_events)

        # Quản lý đồng bộ IP được chọn qua click bảng và hộp điều tra selectbox
        if "threat_investigation_ip" not in st.session_state:
            st.session_state["threat_investigation_ip"] = None

        if selected_actor_ip and selected_actor_ip != st.session_state.get(
            "last_selected_actor_ip"
        ):
            st.session_state["threat_investigation_ip"] = selected_actor_ip
            st.session_state["last_selected_actor_ip"] = selected_actor_ip
        if selected_apt_ip and selected_apt_ip != st.session_state.get("last_selected_apt_ip"):
            st.session_state["threat_investigation_ip"] = selected_apt_ip
            st.session_state["last_selected_apt_ip"] = selected_apt_ip

        # Phần điều tra sự cố IP (Drill-down Investigation)
        st.markdown("---")
        st.subheader("🔍 Trung tâm điều tra đối tượng")

        # Gom danh sách IP từ cả hai bảng để người dùng có thể điều tra bất cứ IP nào
        all_ips = set(r["ip"] for r in high_risk_ips)
        if apt_events:
            for e in apt_events:
                if e.get("src_ip"):
                    all_ips.add(e["src_ip"])
                if e.get("dst_ip"):
                    all_ips.add(e["dst_ip"])
        actor_ips = sorted(list(all_ips))

        if actor_ips:
            # Chọn index mặc định dựa trên IP trong session state
            default_ip = st.session_state.get("threat_investigation_ip")
            default_idx = 0
            if default_ip in actor_ips:
                default_idx = actor_ips.index(default_ip)
            else:
                st.session_state["threat_investigation_ip"] = actor_ips[0]
                default_idx = 0

            selected_ip = st.selectbox(
                "Chọn hoặc nhập địa chỉ IP để điều tra lịch sử tấn công (hoặc click chọn trực tiếp hàng trên 2 bảng ở trên):",
                options=actor_ips,
                index=default_idx,
                key="threat_investigation_ip_widget",
            )

            # Cập nhật ngược lại cho session state dùng chung
            st.session_state["threat_investigation_ip"] = selected_ip

            if selected_ip:
                # 1. Truy vấn thông tin danh tiếng từ threat_memory
                ip_rep = threat_memory.get_ip_reputation(selected_ip)
                # 2. Truy vấn lịch sử cảnh báo của IP này từ audit_trail
                ip_history = cached_get_audit_trail_for_ip(selected_ip, limit=50)
                # 3. Truy vấn threat events của IP này từ threat_memory
                ip_events = threat_memory.get_threat_events_for_ip(selected_ip)

                # Lấy reputation score của IP
                rep_score = 0.0
                if ip_rep:
                    rep_score = ip_rep.get("reputation_score", 0.0)

                # Hiển thị kết quả điều tra
                st.markdown(f"#### 🔍 Kết quả điều tra đối tượng cho IP: `{selected_ip}`")

                # Render hồ sơ danh tiếng & lý do bằng giao diện premium
                latest_reason = "Không có lý do chi tiết từ AI Agent."
                if ip_history:
                    # Lấy lý do từ cảnh báo mới nhất
                    latest_reason = str(ip_history[0].get("reason", "N/A"))
                    # Làm sạch reason (loại bỏ tag [MITRE...] cho giao diện đẹp)
                    latest_reason = re.sub(r"\[MITRE:\s*[^\]]*\]", "", latest_reason)
                    latest_reason = re.sub(
                        r"\[(?:Confidence|Độ\s+tin\s+cậy):\s*[^\]]*\]", "", latest_reason
                    ).strip()

                # Xử lý chống Stored XSS cho giao diện HTML tùy chỉnh
                safe_ip = html.escape(str(selected_ip))
                safe_latest_reason = html.escape(latest_reason)
                safe_first_seen = (
                    html.escape(_fmt_local_ts(ip_rep.get("first_seen", "N/A"))) if ip_rep else "N/A"
                )
                safe_last_seen = (
                    html.escape(_fmt_local_ts(ip_rep.get("last_seen", "N/A"))) if ip_rep else "N/A"
                )
                # KHÔNG độn mã thay khi kho uy tín chưa có quy kết. Bản cũ mặc định "T1190"
                # ở CẢ HAI nhánh, nên mọi IP chưa được quy kết đều hiện "Kỹ thuật MITRE cuối
                # cùng: T1190" — màn hình công bố một kết luận hệ chưa hề đưa ra. Đây đúng
                # họ lỗi đã dọn ở thẻ cảnh báo (xem tests/unit/test_ui_badges.py), chỉ còn
                # sót lại ở panel hồ sơ đối tượng. N/A là kết quả thật.
                safe_last_mitre = (
                    html.escape(str(ip_rep.get("last_mitre_technique") or "N/A"))
                    if ip_rep
                    else "N/A"
                )

                if ip_rep:
                    # Phân cấp mức độ nguy hại
                    severity_level = (
                        "CRITICAL" if rep_score >= 50 else "HIGH" if rep_score >= 20 else "MEDIUM"
                    )
                    severity_class = (
                        "severity-critical"
                        if severity_level == "CRITICAL"
                        else "severity-high"
                        if severity_level == "HIGH"
                        else "severity-medium"
                    )
                    severity_icon = (
                        "🛑"
                        if severity_level == "CRITICAL"
                        else "⚠️"
                        if severity_level == "HIGH"
                        else "🧑‍💻"
                    )

                    profile_html = (
                        f'<div class="soc-card {severity_class}">'
                        f'  <div class="soc-card-header">'
                        f'    <h4 class="soc-card-title">{severity_icon} [{severity_level}] Hồ sơ đối tượng: {safe_ip}</h4>'
                        f'    <span class="soc-timestamp">Phát hiện lần đầu: {safe_first_seen}</span>'
                        f"  </div>"
                        f'  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 12px;">'
                        f'    <div><b>Điểm nguy hại (Reputation):</b> <span class="soc-value-code" style="color: #ff4d4f; font-weight: bold;">{rep_score:.1f}/100</span></div>'
                        f'    <div><b>Tổng sự cố (Incidents):</b> <span class="soc-value-code">{ip_rep.get("total_incidents", 0)}</span></div>'
                        f'    <div><b>Số lần bị chặn (Blocks):</b> <span class="soc-value-code" style="color: #ff7875;">{ip_rep.get("total_blocks", 0)}</span></div>'
                        f'    <div><b>Số lần cảnh báo (Alerts):</b> <span class="soc-value-code" style="color: #ffd666;">{ip_rep.get("total_alerts", 0)}</span></div>'
                        f"  </div>"
                        f'  <div style="margin-bottom: 8px;"><b>Hoạt động gần nhất:</b> {safe_last_seen}</div>'
                        f'  <div style="margin-bottom: 12px;"><b>Kỹ thuật MITRE cuối cùng:</b> <code style="background: rgba(138,43,226,0.15); padding: 2px 6px; border-radius: 4px; color: #D3ADF7;">{safe_last_mitre}</code></div>'
                        f'  <div class="soc-reasoning-box">'
                        f'    <div class="soc-reasoning-title">❓ Tại sao IP này bị đưa vào danh sách đen:</div>'
                        f"    <div>{safe_latest_reason}</div>"
                        f"  </div>"
                        f"</div>"
                    )
                    st.markdown(profile_html, unsafe_allow_html=True)
                else:
                    profile_html = (
                        f'<div class="soc-card severity-medium">'
                        f'  <div class="soc-card-header">'
                        f'    <h4 class="soc-card-title">🧑‍💻 [MEDIUM] Hồ sơ đối tượng: {safe_ip}</h4>'
                        f'    <span class="soc-timestamp">Phát hiện lần đầu: N/A</span>'
                        f"  </div>"
                        f'  <div style="margin-bottom: 8px;">IP này được phát hiện tham gia chuỗi tấn công APT từ tập dữ liệu DAPT2020 nhưng chưa phát sinh cảnh báo chặn trên luồng trực tuyến.</div>'
                        f'  <div class="soc-reasoning-box">'
                        f'    <div class="soc-reasoning-title">❓ Tại sao IP này bị đưa vào danh sách đen:</div>'
                        f"    <div>Ghi nhận sự kiện tấn công tương quan trong chuỗi APT dài hạn.</div>"
                        f"  </div>"
                        f"</div>"
                    )
                    st.markdown(profile_html, unsafe_allow_html=True)

                # Hiển thị Timeline/Chi tiết lịch sử cảnh báo
                st.markdown("##### 🕒 Lịch sử hành vi và quyết định của AI Agent")
                if not ip_history:
                    st.info("Chưa có cảnh báo nào được ghi nhận trong audit_trail cho IP này.")
                else:
                    for i, record in enumerate(ip_history):
                        act = str(record.get("action") or "UNKNOWN")
                        time_str = record.get("timestamp")
                        reason = record.get("reason")

                        # Việt hóa action
                        action_badges = {
                            "BLOCK_IP": "🛑 CHẶN IP (BLOCK)",
                            "ALERT": "⚠️ CẢNH BÁO (ALERT)",
                            "LOG": "📝 GHI LOG (LOG)",
                            "WHITELIST": "✅ BỎ QUA (WHITELIST)",
                        }
                        act_disp = action_badges.get(act, act)

                        # Tạo expander cho mỗi alert
                        with st.expander(f"{time_str} - {act_disp}", expanded=(i == 0)):
                            st.write(f"**Hành động của SOC:** `{act}`")
                            st.write("**Lập luận phân tích của Agent:**")
                            st.info(reason)

                # Hiển thị APT Chain của IP này nếu có
                if ip_events:
                    st.markdown("##### 🎯 Tiến trình chuỗi tấn công APT (DAPT2020)")
                    df_ip_events = pd.DataFrame(ip_events)
                    df_ip_events = df_ip_events.rename(
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
                    st.dataframe(df_ip_events, width="stretch")
        else:
            st.info("Chưa ghi nhận IP nguy cơ cao nào trong hệ thống để thực hiện điều tra.")

    with tab4:
        st.subheader("🔒 Danh sách chặn và miễn trừ")

        # -------------------------------------------------------------
        # Phân quyền check
        # -------------------------------------------------------------
        is_l3 = st.session_state.get("role") == "L3_Manager"

        # -------------------------------------------------------------
        # 1. KPI Stats
        # -------------------------------------------------------------
        all_rules = feedback_mgr.get_all_dynamic_rules()
        ip_blocks = [r for r in all_rules if r.get("field") == "Source IP"]

        active_blocks_count = len([r for r in ip_blocks if r.get("status") == "ACTIVE"])
        pending_blocks_count = len([r for r in ip_blocks if r.get("status") == "PENDING_APPROVAL"])
        whitelisted_count = len(whitelisted_ips)
        # Chặn TỨC THỜI của Tier-1 (WAF/injection/cổng nhạy cảm) -> Redis blacklist TTL 1h.
        # Dashboard container KHÔNG reach được Redis nên đọc qua file tier1_blocks.json
        # (subscriber ghi). Trước đây tab này bỏ sót -> hiển thị nhầm "0 đang chặn".
        # TRẦN 25 — đây là "gần nhất", KHÔNG phải tổng. Cùng họ lỗi đã vá ở tab Nhật ký:
        # ring buffer `tier1_blocks.json` bị cắt hai lần (subscriber giữ 50 bản ghi cuối,
        # UI lấy 25). In trần con số cạnh ô "Tier-1 luật chặn" hàng nghìn thì đọc như hai
        # số mâu thuẫn, thực ra là hai đại lượng khác nhau.
        tier1_temp_blocks = cached_get_tier1_blocks(show=25)
        tier1_temp_count = len(tier1_temp_blocks)

        st.markdown(
            f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;">
            <div style="background: rgba(255, 77, 79, 0.1); border: 1px solid rgba(255, 77, 79, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #ff4d4f;">{tier1_temp_count}</div>
                <div style="font-size: 0.85rem; color: #ff7875; font-weight: 600; text-transform: uppercase;">🛡️ Tier-1 tạm thời (25 gần nhất)</div>
            </div>
            <div style="background: rgba(114, 46, 209, 0.1); border: 1px solid rgba(114, 46, 209, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #b37feb;">{active_blocks_count}</div>
                <div style="font-size: 0.85rem; color: #d3adf7; font-weight: 600; text-transform: uppercase;">Luật Vĩnh viễn (Active)</div>
            </div>
            <div style="background: rgba(250, 173, 20, 0.1); border: 1px solid rgba(250, 173, 20, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #faad14;">{pending_blocks_count}</div>
                <div style="font-size: 0.85rem; color: #ffc069; font-weight: 600; text-transform: uppercase;">Luật Chờ Duyệt (Pending)</div>
            </div>
            <div style="background: rgba(82, 196, 26, 0.1); border: 1px solid rgba(82, 196, 26, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #52c41a;">{whitelisted_count}</div>
                <div style="font-size: 0.85rem; color: #95de64; font-weight: 600; text-transform: uppercase;">IP Đặc Cách (Whitelist)</div>
            </div>
        </div>
        <p style="font-size: 0.8rem; color: #8E9AA8; margin-top: -12px; margin-bottom: 20px;">
            🛡️ <b>Tier-1 tạm thời</b>: IP bị chặn tức thời bởi chữ ký WAF/injection/cổng nhạy cảm (Redis blacklist, tự hết hạn TTL 1h).
            Ô này hiển thị <b>tối đa 25 lệnh chặn GẦN NHẤT</b> đọc từ ring buffer, <b>không phải tổng</b> — tổng xem hàng chỉ số đầu trang.
            <b>Luật Vĩnh viễn</b>: luật động do Tier-2 (LLM) đề xuất, đã được Analyst DUYỆT (HITL) — không hết hạn.
        </p>
        """,
            unsafe_allow_html=True,
        )

        col_left, col_right = st.columns([3, 2])

        with col_left:
            # ── Danh sách Whitelist hiện tại ──
            st.markdown("### ✅ Danh sách Whitelist hiện tại")
            if not whitelisted_ips:
                st.info("Chưa có IP nào trong danh sách Whitelist.")
            else:
                for ip in whitelisted_ips:
                    with st.expander(f"✅ Whitelisted: {ip}", expanded=False):
                        st.write(f"Mọi traffic từ `{ip}` sẽ được bỏ qua bởi Rule Engine.")
                        if is_l3:
                            if st.button("❌ Gỡ khỏi Whitelist", key=f"rmwl_t4_top_{ip}"):
                                feedback_mgr.remove_from_whitelist(ip)
                                st.cache_data.clear()

                                # Khôi phục trạng thái ACTIVE nếu có lịch sử bị chặn
                                all_rules_now = feedback_mgr.get_all_dynamic_rules()
                                for r in all_rules_now:
                                    if r.get("pattern") == ip:
                                        feedback_mgr.update_rule_status(ip, "ACTIVE", "Source IP")
                                        break

                                from src.response.executor import _log_to_db

                                _log_to_db(
                                    "LOG",
                                    ip,
                                    f"[Tier-1 Filter] Admin {st.session_state.get('username')} gỡ IP khỏi Whitelist",
                                )
                                st.warning(f"Đã gỡ IP {ip} khỏi danh sách Whitelist.")
                                st.rerun()

            st.markdown("### 🛑 Luật chặn vĩnh viễn và lịch sử")

            # Lọc bỏ các IP đang nằm trong Whitelist để không hiển thị ở 2 bảng cùng lúc
            ip_blocks = [r for r in ip_blocks if r.get("pattern") not in whitelisted_ips]

            if not ip_blocks:
                st.info("Chưa ghi nhận địa chỉ IP nào bị chặn trong cấu hình.")
            else:
                # Chuẩn bị dữ liệu bảng
                block_rows = []
                for rule in ip_blocks:
                    status_val = rule.get("status", "ACTIVE")
                    status_icon = (
                        "🛑 ACTIVE"
                        if status_val == "ACTIVE"
                        else "🧑‍💻 PENDING"
                        if status_val == "PENDING_APPROVAL"
                        else "🔓 UNBLOCKED"
                    )

                    # Phân loại HITL/Nguồn
                    src = rule.get("source", "")
                    if "langgraph_agent_hitl" in src:
                        phan_loai = "🧠 LLM Agent (Chờ duyệt)"
                    elif "ml_triage" in src:
                        phan_loai = "⚡ Cổng ML (Chờ duyệt)"
                    elif "tier1_rule_engine" in src:
                        phan_loai = "🛡️ Tier-1 (Chờ duyệt)"
                    elif "langgraph_agent" in src:
                        phan_loai = "🧠 LLM Agent (AI Block)"
                    else:
                        phan_loai = f"🔧 MANUAL ({src})"

                    block_rows.append(
                        {
                            "Địa chỉ IP": rule.get("pattern"),
                            "Trạng thái": status_icon,
                            "Phân loại": phan_loai,
                            "Điểm Risk": rule.get("score", 50),
                            "Ngày tạo": rule.get("created_at", "N/A")[:19].replace("T", " "),
                            "Lý do": rule.get("reason", "N/A"),
                        }
                    )
                df_blocks = pd.DataFrame(block_rows)

                # Interactive Table
                st.markdown(
                    "<p style='font-size: 0.85rem; color: #8E9AA8;'>💡 Click chọn hàng bất kỳ để xem chi tiết lịch sử và thực hiện Hoàn tác / Gỡ chặn:</p>",
                    unsafe_allow_html=True,
                )

                # Hàm tô màu trạng thái
                def color_status(val):
                    color = (
                        "#ff4d4f"
                        if "ACTIVE" in val
                        else "#faad14"
                        if "PENDING" in val
                        else "#8c8c8c"
                    )
                    return f"color: {color}; font-weight: bold; font-family: monospace;"

                from typing import Any, cast

                block_selection = st.dataframe(
                    cast(Any, df_blocks.style.map(color_status, subset=["Trạng thái"])),
                    on_select="rerun",
                    selection_mode="single-row",
                    key="blocklist_table_select",
                )

                selected_block_ip = None
                block_select_data = block_selection.get("selection", {}) if block_selection else {}
                block_rows = block_select_data.get("rows", [])
                if block_rows:
                    selected_row_idx = block_rows[0]
                    if selected_row_idx < len(df_blocks):
                        selected_block_ip = df_blocks.iloc[selected_row_idx]["Địa chỉ IP"]

                # Nếu người dùng đã chọn một IP
                if selected_block_ip:
                    st.markdown("---")
                    st.markdown(f"#### 🔍 Chi tiết và Hành động cho IP: `{selected_block_ip}`")

                    # Lấy luật tương ứng
                    target_rule = next(
                        (r for r in ip_blocks if r.get("pattern") == selected_block_ip), None
                    )
                    if target_rule:
                        status_val = target_rule.get("status")
                        st.write(f"**Trạng thái hiện tại:** `{status_val}`")
                        st.write(f"**Lý do block:** {target_rule.get('reason')}")
                        st.write(f"**Nguồn tạo:** `{target_rule.get('source')}`")
                        st.write(f"**Thời gian:** `{target_rule.get('created_at')}`")

                        # Điều tra lịch sử IP từ audit_trail
                        ip_audit = cached_get_audit_trail_for_ip(selected_block_ip, limit=10)
                        if ip_audit:
                            st.write("**Lịch sử hành vi trong hệ thống (SIEM Logs):**")
                            for _idx, record in enumerate(ip_audit):
                                st.caption(
                                    f"⏱️ {record.get('timestamp')} | **Action:** `{record.get('action')}` | **Lý do:** {record.get('reason')}"
                                )
                        else:
                            st.caption("Chưa ghi nhận log thô nào trong cơ sở dữ liệu cho IP này.")

                        # Nút hoàn tác
                        if is_l3:
                            col_b1, col_b2 = st.columns(2)
                            with col_b1:
                                if status_val in ["ACTIVE", "PENDING_APPROVAL"]:
                                    if st.button(
                                        "🔓 Hoàn tác / Gỡ chặn IP này",
                                        key=f"unblock_{selected_block_ip}",
                                    ):
                                        # Set status thành REJECTED
                                        feedback_mgr.reject_rule(selected_block_ip, "Source IP")
                                        st.cache_data.clear()
                                        # Xóa khỏi Redis blacklist
                                        from src.response.executor import _log_to_db, unblock_ip

                                        unblock_ip(selected_block_ip)
                                        # Log hành động unblock vào audit_trail
                                        _log_to_db(
                                            "LOG",
                                            selected_block_ip,
                                            f"[Tier-1 Filter] Admin {st.session_state.get('username')} gỡ chặn IP (Hoàn tác)",
                                        )
                                        st.success(
                                            f"Đã hoàn tác và gỡ chặn cho IP {selected_block_ip}"
                                        )
                                        st.rerun()
                                elif status_val == "REJECTED":
                                    if st.button(
                                        "🛑 Tái kích hoạt chặn IP này",
                                        key=f"reblock_{selected_block_ip}",
                                    ):
                                        # Set status thành ACTIVE (tự gỡ khỏi whitelist nếu có)
                                        _was_wl = (
                                            selected_block_ip in feedback_mgr.get_whitelisted_ips()
                                        )
                                        feedback_mgr.approve_rule(selected_block_ip, "Source IP")
                                        st.cache_data.clear()
                                        from src.response.executor import _log_to_db

                                        _log_to_db(
                                            "BLOCK_IP",
                                            selected_block_ip,
                                            f"[Tier-1 Filter] Admin {st.session_state.get('username')} tái kích hoạt chặn IP",
                                        )
                                        if _was_wl:
                                            st.warning(
                                                f"⚠️ {selected_block_ip} đã được GỠ khỏi Whitelist "
                                                "vì chuyển sang CHẶN."
                                            )
                                        st.success(
                                            f"Đã tái kích hoạt luật chặn cho IP {selected_block_ip}"
                                        )
                                        st.rerun()
                            with col_b2:
                                # Whitelist IP trực tiếp
                                if selected_block_ip not in whitelisted_ips:
                                    if st.button(
                                        "🛡️ Đưa thẳng vào Whitelist",
                                        key=f"towhitelist_{selected_block_ip}",
                                    ):
                                        # Whitelist TRƯỚC; chỉ gỡ block rule nếu whitelist THÀNH
                                        # CÔNG (tránh bug: gỡ block xong whitelist fail -> IP hết
                                        # block lẫn whitelist, lần sau lại bị chặn).
                                        ok = feedback_mgr.add_to_whitelist(selected_block_ip)
                                        if ok:
                                            feedback_mgr.reject_rule(selected_block_ip, "Source IP")
                                            st.cache_data.clear()
                                            from src.response.executor import _log_to_db, unblock_ip

                                            unblock_ip(selected_block_ip)
                                            _log_to_db(
                                                "LOG",
                                                selected_block_ip,
                                                f"[Tier-1 Filter] Admin {st.session_state.get('username')} đưa thẳng IP vào Whitelist",
                                            )
                                            st.success(
                                                f"Đã đưa IP {selected_block_ip} vào Whitelist!"
                                            )
                                        else:
                                            st.error(
                                                f"❌ Không whitelist được {selected_block_ip} — chỉ "
                                                "CHẶN dải quá rộng (wildcard 0.0.0.0/0, *, any, hoặc "
                                                "CIDR < /16). Block rule GIỮ NGUYÊN."
                                            )
                                        st.rerun()
                        else:
                            st.warning("💡 Yêu cầu vai trò L3 Manager để thay đổi trạng thái chặn.")

        with col_right:
            st.markdown("### ⚙️ Thao tác thủ công")

            # Form chặn IP thủ công (Manual Block)
            with st.expander("🛑 Chặn IP thủ công", expanded=True):
                st.write("Thêm thủ công một IP vào danh sách chặn của Tier 1.")
                manual_block_ip = st.text_input(
                    "Địa chỉ IP cần chặn",
                    placeholder="Ví dụ: 192.168.1.50",
                    key="manual_block_ip_input",
                ).strip()
                manual_block_score = st.slider(
                    "Điểm Risk Score",
                    min_value=10,
                    max_value=100,
                    value=100,
                    step=10,
                    key="manual_block_score_input",
                )
                manual_block_reason = st.text_area(
                    "Lý do chặn",
                    placeholder="Nhập lý do nghi ngờ / tấn công...",
                    key="manual_block_reason_input",
                )

                if st.button("🛑 Kích hoạt luật chặn", key="btn_trigger_manual_block"):
                    if not is_l3:
                        st.error("💡 Yêu cầu vai trò L3 Manager để thực hiện chặn IP.")
                    elif not manual_block_ip:
                        st.error("Vui lòng nhập địa chỉ IP.")
                    elif not is_valid_ip(manual_block_ip):
                        st.error("Địa chỉ IP không đúng định dạng.")
                    elif not manual_block_reason:
                        st.error("Vui lòng nhập lý do chặn.")
                    else:
                        # Ghi luật chặn mới
                        feedback_mgr.receive_new_rule(
                            "Source IP",
                            manual_block_ip,
                            score=manual_block_score,
                            source=f"manual_{st.session_state.get('username')}",
                            reason=manual_block_reason,
                        )
                        # Duyệt luôn (tự gỡ khỏi whitelist nếu IP đang được whitelist)
                        _was_wl = manual_block_ip in feedback_mgr.get_whitelisted_ips()
                        feedback_mgr.approve_rule(manual_block_ip, "Source IP")

                        # Ghi audit log
                        from src.response.executor import block_ip

                        block_ip(
                            manual_block_ip,
                            f"[Tier-1 Filter] Admin {st.session_state.get('username')} chặn thủ công: {manual_block_reason}",
                            tier=TIER_MANUAL,
                        )

                        if _was_wl:
                            st.warning(
                                f"⚠️ {manual_block_ip} đã được GỠ khỏi Whitelist vì chuyển sang CHẶN."
                            )
                        # ĐỒNG BỘ MỌI TAB: xoá cache để blocklist/threat-intel/audit/overview
                        # cùng thấy IP vừa chặn ngay (không lệch giữa các tab).
                        st.cache_data.clear()
                        st.success(f"Đã kích hoạt chặn IP {manual_block_ip} thành công!")
                        st.rerun()

            # Form Whitelist thủ công
            with st.expander("🛡️ Thêm IP vào Whitelist", expanded=True):
                st.write(
                    "Thêm thủ công một IP an toàn (Pentest, Máy chủ nội bộ) để Rule Engine bỏ qua."
                )
                manual_wl_ip = st.text_input(
                    "Địa chỉ IP an toàn",
                    placeholder="Ví dụ: 192.168.10.10",
                    key="manual_wl_ip_input",
                ).strip()

                if st.button("✅ Thêm vào Whitelist", key="btn_trigger_manual_wl"):
                    if not is_l3:
                        st.error("💡 Yêu cầu vai trò L3 Manager để whitelist IP.")
                    elif not manual_wl_ip:
                        st.error("Vui lòng nhập địa chỉ IP.")
                    elif not is_valid_ip(manual_wl_ip):
                        st.error("Địa chỉ IP không đúng định dạng.")
                    else:
                        ok = feedback_mgr.add_to_whitelist(manual_wl_ip)
                        if ok:
                            from src.response.executor import _log_to_db, unblock_ip

                            unblock_ip(manual_wl_ip)
                            _log_to_db(
                                "LOG",
                                manual_wl_ip,
                                f"[Tier-1 Filter] Admin {st.session_state.get('username')} thêm IP vào Whitelist thủ công",
                            )
                            # ĐỒNG BỘ MỌI TAB: xoá cache để whitelist/threat-intel/audit cùng cập nhật ngay.
                            st.cache_data.clear()
                            st.success(f"Đã thêm IP {manual_wl_ip} vào Whitelist thành công!")
                            st.rerun()
                        else:
                            st.error(
                                f"❌ Không whitelist được {manual_wl_ip} — chỉ CHẶN dải quá rộng "
                                "(wildcard 0.0.0.0/0, *, any, all, ::/0, hoặc CIDR < /16). "
                                "Mọi IP host cụ thể đều được phép."
                            )

    with tab5:
        st.subheader("🔍 Lỗ hổng và tri thức đồ thị")

        # 1. Nút bấm Quét Lỗ Hổng Hệ thống
        col_scan_btn, col_integrity_btn = st.columns([1, 1])
        with col_scan_btn:
            if st.button(
                "⚡ Chạy Quét Lỗ Hổng (Run Trivy Scan)",
                help="Kích hoạt quét Trivy và tự động xây dựng Knowledge Graph trong Neo4j",
            ):
                with st.spinner("Đang chạy quét lỗ hổng Trivy (có thể mất vài giây)..."):
                    try:
                        from main import build_knowledge_graph, run_vulnerability_scan

                        run_vulnerability_scan()
                        build_knowledge_graph()
                        st.success("✅ Quét lỗ hổng và cập nhật Knowledge Graph Neo4j thành công!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi khi chạy quét lỗ hổng: {e}")

        with col_integrity_btn:
            # 2. Gọi verify_document_integrity() kiểm định tài liệu RAG
            if st.button(
                "🛡️ Kiểm tra tính toàn vẹn tài liệu (RAG Integrity Check)",
                help="Xác minh SHA-256 của các tệp Knowledge Base chống RAG Poisoning",
            ):
                with st.spinner("Đang kiểm định tệp RAG..."):
                    from src.rag.security import verify_document_integrity

                    res = verify_document_integrity()
                    if res.get("verified", False):
                        st.success("✅ Toàn bộ tài liệu RAG an toàn & khớp mã băm SHA-256!")
                    else:
                        st.error(
                            "⚠️ PHÁT HIỆN LỖI TOÀN VẸN TÀI LIỆU RAG! Có thể tệp KB bị sửa đổi trái phép."
                        )
                    with st.expander("Chi tiết kiểm định tài liệu", expanded=True):
                        for detail in res.get("details", []):
                            st.write(f"- {detail}")

        # 3. Đọc dữ liệu từ data/trivy-results.json để thống kê và hiển thị
        trivy_path = "data/trivy-results.json"
        has_vulns = False
        vuln_list = []
        if os.path.exists(trivy_path):
            try:
                with open(trivy_path) as f:
                    trivy_data = json.load(f)
                results = trivy_data.get("Results", [])
                for res in results:
                    target = res.get("Target", "Unknown")
                    vulnerabilities = res.get("Vulnerabilities", [])
                    for v in vulnerabilities:
                        vuln_list.append(
                            {
                                "Target": target,
                                "CVE ID": v.get("VulnerabilityID", "N/A"),
                                "Package": v.get("PkgName", "N/A"),
                                "Installed": v.get("InstalledVersion", "N/A"),
                                "Severity": v.get("Severity", "UNKNOWN").upper(),
                                "Description": v.get("Description", "No description provided."),
                            }
                        )
                has_vulns = len(vuln_list) > 0
            except Exception as e:
                st.warning(f"Không thể đọc kết quả Trivy: {e}")

        # 4. Thống kê KPI Lỗ hổng
        if has_vulns:
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
            for v in vuln_list:
                sev = v["Severity"]
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["UNKNOWN"] += 1

            st.markdown(
                f"""
            <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 16px; margin-bottom: 24px;">
                <div style="background: rgba(255, 77, 79, 0.1); border: 1px solid rgba(255, 77, 79, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #ff4d4f;">{sev_counts["CRITICAL"]}</div>
                    <div style="font-size: 0.8rem; color: #ff7875; font-weight: 600;">CRITICAL</div>
                </div>
                <div style="background: rgba(250, 140, 22, 0.1); border: 1px solid rgba(250, 140, 22, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #fa8c16;">{sev_counts["HIGH"]}</div>
                    <div style="font-size: 0.8rem; color: #ffa940; font-weight: 600;">HIGH</div>
                </div>
                <div style="background: rgba(250, 219, 20, 0.1); border: 1px solid rgba(250, 219, 20, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #fadb14;">{sev_counts["MEDIUM"]}</div>
                    <div style="font-size: 0.8rem; color: #ffe58f; font-weight: 600;">MEDIUM</div>
                </div>
                <div style="background: rgba(24, 144, 255, 0.1); border: 1px solid rgba(24, 144, 255, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #1890ff;">{sev_counts["LOW"]}</div>
                    <div style="font-size: 0.8rem; color: #69c0ff; font-weight: 600;">LOW</div>
                </div>
                <div style="background: rgba(140, 140, 140, 0.1); border: 1px solid rgba(140, 140, 140, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #8c8c8c;">{len(vuln_list)}</div>
                    <div style="font-size: 0.8rem; color: #bfbfbf; font-weight: 600;">TOTAL VULNS</div>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

            # Bảng lỗ hổng
            df_vulns = pd.DataFrame(vuln_list)
            st.markdown("##### 📦 Chi tiết các lỗ hổng phát hiện được (Trivy Scan)")

            def color_sev(val):
                color = (
                    "#ff4d4f"
                    if val == "CRITICAL"
                    else "#fa8c16"
                    if val == "HIGH"
                    else "#fadb14"
                    if val == "MEDIUM"
                    else "#1890ff"
                )
                return f"color: {color}; font-weight: bold; font-family: monospace;"

            from typing import Any, cast

            vuln_selection = st.dataframe(
                cast(Any, df_vulns.style.map(color_sev, subset=["Severity"])),
                on_select="rerun",
                selection_mode="single-row",
                key="trivy_vulns_table_select",
                width="stretch",
            )

            # Khi chọn dòng lỗ hổng, hiện thông tin chi tiết
            selected_vuln_idx = None
            vuln_select_data = vuln_selection.get("selection", {}) if vuln_selection else {}
            vuln_rows = vuln_select_data.get("rows", [])
            if vuln_rows:
                selected_vuln_idx = vuln_rows[0]

            if selected_vuln_idx is not None:
                v = vuln_list[selected_vuln_idx]
                st.markdown("---")
                st.markdown(f"#### 🔍 Chi tiết lỗ hổng: `{v['CVE ID']}`")
                st.markdown(f"**Tập tin bị ảnh hưởng:** `{v['Target']}`")
                st.markdown(f"**Gói thư viện:** `{v['Package']}` (Đang dùng: `{v['Installed']}`)")
                st.markdown(f"**Mức độ nguy hại:** `{v['Severity']}`")
                st.info(f"**Mô tả:** {v['Description']}")

            # 5. Vẽ biểu đồ Knowledge Graph (Neo4j Visual Tree)
            st.markdown("---")
            st.markdown("##### 🧬 Biểu đồ Tri thức Lỗ hổng (Vulnerability Knowledge Graph)")

            # Xây dựng DOT code động dựa trên lỗ hổng thực tế để vẽ sơ đồ đẹp mắt
            dot_lines = [
                "digraph G {",
                '    bgcolor="transparent";',
                "    rankdir=LR;",
                '    node [color="#ffffff", fontcolor="#ffffff", style=filled, fillcolor="#112240", fontname="sans-serif", shape=box];',
                '    edge [color="#888888", fontcolor="#888888", fontname="sans-serif", fontsize=10];',
                "    ",
                "    // Nodes",
                '    SOC [label="SENTINEL_SOC\\n(Main Application)", shape=doublecircle, fillcolor="#177ddc", color="#177ddc"];',
            ]

            # Thêm tối đa 8 SubComponents và Vulnerabilities để sơ đồ không bị rối mắt
            def _dot_id(raw: str) -> str:
                """Ép chuỗi bất kỳ về một định danh DOT hợp lệ ([A-Za-z_][A-Za-z0-9_]*)."""
                out = re.sub(r"[^0-9A-Za-z_]", "_", str(raw))
                return ("n_" + out) if not out or out[0].isdigit() else out

            def _dot_label(raw: str) -> str:
                """Thoát dấu nháy kép/gạch chéo trước khi nhúng vào nhãn DOT."""
                return str(raw).replace("\\", "\\\\").replace('"', '\\"')

            subcomponents = set()
            for v in vuln_list[:8]:
                target_clean = _dot_id(v["Target"])
                if v["Target"] not in subcomponents:
                    subcomponents.add(v["Target"])
                    dot_lines.append(
                        f'    {target_clean} [label="{_dot_label(v["Target"])}", fillcolor="#14c2c2", color="#14c2c2"];'
                    )
                    dot_lines.append(f'    SOC -> {target_clean} [label="CONTAINS"];')

                cve_clean = _dot_id(v["CVE ID"])
                color = (
                    "#ff4d4f"
                    if v["Severity"] == "CRITICAL"
                    else "#fa8c16"
                    if v["Severity"] == "HIGH"
                    else "#fadb14"
                    if v["Severity"] == "MEDIUM"
                    else "#1890ff"
                )
                dot_lines.append(
                    f'    {cve_clean} [label="{_dot_label(v["CVE ID"])}\\n({v["Severity"]})", fillcolor="#1d39c4", color="{color}"];'
                )
                dot_lines.append(f'    {target_clean} -> {cve_clean} [label="HAS_VULN"];')

            dot_lines.append("}")
            dot_code = "\n".join(dot_lines)
            st.graphviz_chart(dot_code, width="stretch")
        else:
            # Trạng thái rỗng (chưa quét Trivy) — tránh tab trắng, luôn có nội dung trực quan.
            st.markdown(
                """<div class="soc-empty">
                    <div class="soc-empty-title">🧬 Chưa có dữ liệu quét lỗ hổng</div>
                    <div class="soc-empty-sub">Bấm <b>“⚡ Chạy Quét Lỗ Hổng (Trivy)”</b> ở trên để
                    quét container và dựng Knowledge Graph trong Neo4j. Bên dưới là sơ đồ kiến trúc
                    tri thức minh hoạ của hệ thống SENTINEL.</div>
                </div>""",
                unsafe_allow_html=True,
            )
            st.markdown("##### 🧬 Sơ đồ Kiến trúc Tri thức SENTINEL (minh hoạ)")
            arch_dot = (
                'digraph G { rankdir=LR; bgcolor="transparent"; '
                'node [style=filled, fontname="sans-serif", fontcolor="#ffffff", shape=box, color="#ffffff"]; '
                'edge [color="#888888", fontcolor="#888888", fontsize=10, fontname="sans-serif"]; '
                'SOC [label="SENTINEL_SOC", shape=doublecircle, fillcolor="#177ddc", color="#177ddc"]; '
                'T1 [label="Tier-1 Welford Filter", fillcolor="#14c2c2", color="#14c2c2"]; '
                'ML [label="Tier-1 ML Gate (LightGBM)", fillcolor="#52c41a", color="#52c41a"]; '
                'GR [label="Guardrails (Encapsulation)", fillcolor="#14c2c2", color="#14c2c2"]; '
                'RAG [label="Dual-RAG (MITRE+NIST)", fillcolor="#14c2c2", color="#14c2c2"]; '
                f'LLM [label="Tier-2 LLM Agent ({_model_display_name()})", fillcolor="#1d39c4", color="#1d39c4"]; '
                'MEM [label="Threat Memory (APT)", fillcolor="#1d39c4", color="#1d39c4"]; '
                'DROP [label="Tự quyết, KHÔNG gọi LLM", fillcolor="#52c41a", color="#52c41a"]; '
                'SOC -> T1 [label="ingest"]; T1 -> ML [label="escalate"]; '
                'ML -> DROP [label="bypass (tự quyết)"]; '
                'ML -> GR [label="phần còn lại"]; GR -> RAG [label="ground"]; '
                'RAG -> LLM [label="reason"]; LLM -> MEM [label="correlate"]; }'
            )
            st.graphviz_chart(arch_dot, width="stretch")


if __name__ == "__main__":
    main_dashboard()
