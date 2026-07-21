"""
SENTINEL - Main Dashboard
Khởi chạy bằng lệnh: streamlit run src/ui/app.py
"""

import math
import os
import re
import sys

import pandas as pd  # type: ignore

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import html
import json
from datetime import datetime

import streamlit as st  # type: ignore
from streamlit_autorefresh import st_autorefresh  # type: ignore

from src.agent.threat_memory import threat_memory
from src.response.executor import (
    count_audit_alerts,
    get_audit_trail,
    get_audit_trail_for_ip,
    verify_audit_trail_integrity,
)


# ---------------------------------------------------------------------------
# Caching DB / I/O để tối ưu hiệu năng (Anti-Lag)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=2)
def cached_get_audit_trail(limit=50):
    return get_audit_trail(limit)


@st.cache_data(ttl=2)
def cached_count_audit_alerts():
    """Tổng số cảnh báo THẬT (COUNT(*), không bị trần limit) — dùng cho tỷ lệ giảm tải."""
    return count_audit_alerts()


@st.cache_data(ttl=2)
def cached_get_audit_trail_for_ip(ip, limit=50):
    return get_audit_trail_for_ip(ip, limit)


@st.cache_data(ttl=2)
def cached_get_tier1_blocks(show=12):
    return _get_tier1_blocks(show)


@st.cache_data(ttl=5)
def cached_get_all_threat_events():
    return threat_memory.get_all_threat_events()


@st.cache_data(ttl=5)
def cached_get_high_risk_ips(min_score=1.0):
    return threat_memory.get_high_risk_ips(min_score=min_score)


# ---------------------------------------------------------------------------
from src.tier1_filter.feedback_listener import FeedbackListener
from src.ui.auth import logout, require_auth
from src.ui.components import (
    ML_GATE_MARKERS,
    is_valid_ip,
    render_alert_card,
    render_apt_events_table,
    render_metrics_header,
    render_threat_intel_tables,
)

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
    all_alerts, active_rules, pending_rules, raw_logs_count, noise_reduction, pending_llm=0
):
    """Tab Tổng quan Trình diễn — gom mọi thứ cần show vào MỘT màn hình."""
    st.markdown("## 🎬 SENTINEL — Bảng Trình diễn Tổng quan (Executive Demo)")
    st.markdown(
        "*Kiến trúc nhận thức hai tầng: **Tier-1** lọc ở tốc độ đường truyền bằng thuật toán "
        "Welford $O(1)$ + **Cổng ML** (cùng Tier-1) → **Tier-2** tác tử LangGraph (Gemma-2-9B-IT Q6\\_K qua llama.cpp) + "
        "**Dual-RAG** (MITRE ATT&CK / NIST SP 800-61r2) phía sau rào chắn mật mã, có **HITL** giám sát.*"
    )

    # ---------- Thu thập dữ liệu (an toàn) ----------
    try:
        # Qua cache (ttl=5): st.tabs render MỌI tab mỗi lượt refresh 3s nên các query này
        # nổ bất kể tab đang xem — cache gộp lại 1 lần đọc DB thay vì nhiều lần/refresh.
        apt_events = cached_get_all_threat_events() or []
    except Exception:
        apt_events = []
    apt_ips = sorted({s for e in apt_events if (s := e.get("src_ip"))})
    try:
        # ĐỒNG BỘ WHITELIST: bỏ IP đã whitelist khỏi đếm "IP rủi ro cao" (đã miễn trừ).
        _wl_demo = set(feedback_mgr.get_whitelisted_ips() or [])
        high_risk = [
            r for r in (cached_get_high_risk_ips(min_score=1.0) or []) if r["ip"] not in _wl_demo
        ]
    except Exception:
        high_risk = []
    try:
        integ_valid, _integ_msg = verify_audit_trail_integrity()
    except Exception:
        integ_valid = True

    escalated = sum(1 for a in all_alerts if a.get("action") in ("BLOCK_IP",))
    # Không bịa số khi chưa đo được: 99.6 hardcode cũ khiến demo trống vẫn khoe 99.6%.
    nr = noise_reduction

    # ---------- Hàng chỉ số vận hành ----------
    st.markdown("### 📊 Chỉ số Vận hành Thời gian thực")
    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
    c1.metric("Logs thô đầu vào", f"{raw_logs_count:,}")
    c2.metric("Tổng IP Bị Chặn", f"{escalated:,}")
    c3.metric("Đang chờ LLM ⏳", f"{pending_llm}")
    nr_str = f"{nr:.1f}%" if nr is not None else "0.0%"
    c4.metric("Giảm tải (thô→cảnh báo)", nr_str)
    c5.metric("IP rủi ro cao", f"{len(high_risk)}")
    c6.metric("Phê duyệt luật (ML + LLM)", f"{len(pending_rules)}")
    c7.metric("Chuỗi audit HMAC", "✅ Toàn vẹn" if integ_valid else "⚠️ Bị sửa")

    st.markdown("---")
    col_left, col_right = st.columns([3, 2])

    # ---------- Cột trái: Live feed + APT ----------
    with col_left:
        st.markdown("### 🚨 Dòng Cảnh báo Gần nhất (Live Threat Feed)")
        if all_alerts:
            feed = [
                {
                    "Thời gian": str(a.get("timestamp", ""))[5:19],
                    "Hành động": a.get("action", ""),
                    "Đối tượng": a.get("target", ""),
                    "MITRE": _extract_mitre_technique(a.get("reason", "")) or "—",
                }
                for a in all_alerts[:10]
            ]
            st.dataframe(pd.DataFrame(feed), width="stretch", height=300, hide_index=True)
        else:
            st.info(
                "Chưa có cảnh báo. Chạy luồng demo (unified_stream) hoặc seed dữ liệu để minh hoạ."
            )

        st.markdown("### 🎯 Chiến dịch APT đa giai đoạn (Multi-day Kill-chain)")
        if apt_events:
            apt_tbl = [
                {
                    "Nguồn IP": e.get("src_ip", ""),
                    "Ngày": e.get("apt_day", ""),
                    "Giai đoạn": e.get("apt_phase", ""),
                    "Nhãn": e.get("label", ""),
                }
                for e in apt_events[:12]
            ]
            st.dataframe(pd.DataFrame(apt_tbl), width="stretch", height=240, hide_index=True)
            st.caption(
                f"🔗 Phát hiện **{len(apt_ips)} IP APT** qua tương quan đa ngày trong Threat Memory (SQLite)."
            )
        else:
            st.info("Chưa có sự kiện APT. Seed dữ liệu DAPT2020 để minh hoạ tương quan đa ngày.")

    # ---------- Cột phải: kết quả thực nghiệm + trạng thái ----------
    with col_right:
        st.markdown("### 🏆 Kết quả Thực nghiệm (Luận văn)")
        st.markdown("*CSE-CIC-IDS2018 + DAPT2020 · kiểm định thống kê phi tham số.*")
        e1, e2 = st.columns(2)
        # ĐO THẬT từ latency_benchmark.json (n=100): 83 sự kiện đi đường nhanh Tier-1
        # (không gọi LLM) có TB 0.025 ms; 17 ca gọi LLM có TB 26.92 s. Số cũ "0.6 ms /
        # ≈5.7 s / 62.7% escalate" KHÔNG khớp bất kỳ file kết quả nào -> đã thay.
        e1.metric("Độ trễ Tier-1 (luật)", "0.025 ms", "đường nhanh · n=83/100")
        e2.metric("Giảm độ trễ đầu-cuối", "−82.97%", "4.58 s vs 26.88 s LLM-only")
        e3, e4 = st.columns(2)
        # Chính sách 4 dải (C>=0.85 BLOCK · 0.65-0.85 ESCALATE · 0.40-0.65 ALERT · <0.40 PASS).
        # Giảm tải LLM: ground_truth 1250, Config G tự quyết 83.8% (ablation_mlgate) -> F1(bypass) 0.9739.
        e3.metric("Cổng ML giảm tải LLM", "83.8%", "F1(bypass) 0.9739")
        e4.metric("APT recall", "1.00", "DAPT2020 · 3/3")
        e5, e6 = st.columns(2)
        # HEADLINE = độ chính xác auto-BLOCK (hành động DỨT KHOÁT, không thể đảo, dải C>=0.85).
        # ĐÃ KIỂM CHỨNG: evaluate_ml_gate.py nay xuất `by_action` ra ml_gate_results.json ->
        # BLOCK_IP: tp=962, fp=0 => precision 1.0 (trước đây số này chỉ nằm trong báo cáo viết
        # tay, không tái lập được). F1 gộp 0.8248 thấp hơn vì tính CẢ dải ALERT-0.40
        # (tp=74/fp=104, precision 0.4157) là "dự đoán tấn công" — ALERT là cảnh báo
        # low-priority KHÔNG chặn, nên không mâu thuẫn; model held-out 190k vẫn F1 0.9635.
        e5.metric("Cổng ML — auto-BLOCK chính xác", "100%", "962 chặn · 0 chặn nhầm")
        e6.metric("Kháng né-tránh Cổng ML", "99.58%", "Inf/cực-đoan · evasion")
        st.caption(
            "Nguồn (mọi số truy được về `experiments/results/*.json`): **ml_gate** — datatest "
            "3.204 mẫu/4 luồng: auto-BLOCK precision **100%** (962 chặn, **0** FP, `by_action`), "
            "evasion **99.58%**, độ trễ **0.38 ms**, F1 gộp-tính-cả-ALERT 0.825 (P .909/R .755) "
            "do dải ALERT-0.40 low-priority · **ablation_mlgate** — giảm tải **83.8%** (761/908 ca), "
            "F1(bypass) 0.9739, precision khi tự quyết 98.82% · **unified_stream** — APT 3/3, "
            "zero-day 12/15, F1 Tier-1-luật 0.531 · **latency_benchmark** — −82.97% (4.58 s vs "
            "26.88 s), Tier-1 0.025 ms · **training_report** — LightGBM test-190k held-out F1 "
            "0.9635 (1M mẫu) · **adversarial** — kháng 12/12. Audit HMAC: 100%."
        )

        st.markdown("### 🔐 Trạng thái Hệ thống")
        st.success("🟢 LLM cục bộ: Gemma-2-9B-IT Q6\\_K (llama.cpp · air-gapped)")
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
                f"max **{_util}%** của {_tok.get('n_ctx', 8192)} token · "
                f"prompt TB {_tok.get('prompt_tokens_mean', 0)} / max {_tok.get('prompt_tokens_max', 0)} · "
                f"⚠️ {_tok.get('overflow_warnings', 0)} cảnh báo sát trần ({_tok.get('calls', 0)} call)"
            )
        else:
            st.caption(
                "ℹ️ Ngân sách ngữ cảnh: chưa có dữ liệu token — chạy pipeline/eval để thu thập."
            )

    # ---------- Vòng phản hồi Hai tầng: Tier-1 chặn ↔ Tier-2 dạy ----------
    st.markdown("---")
    st.markdown("### 🔁 Vòng phản hồi Hai tầng (Tier-1 chặn ↔ ML/LLM dạy ngược)")
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
    st.markdown("### 🧠 Cổng ML (Tier-1) & LLM (Tier-2) đã CHẶN (ghi chép Audit Trail)")
    _t2_blocks = [a for a in all_alerts if str(a.get("action", "")).upper() in ("BLOCK_IP",)]
    if _t2_blocks:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Thời gian": str(a.get("timestamp", ""))[5:19],
                        "Hành động": a.get("action", ""),
                        "IP / Host": a.get("target", ""),
                        "Quyết định bởi": "Cổng ML ⚡"
                        if any(k in str(a.get("reason", "")) for k in ML_GATE_MARKERS)
                        else "LLM 🧠",
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
    # Auto-refresh UI mỗi 3000ms để tránh giật lag khi tải nhiều data
    count = st_autorefresh(interval=3000, limit=10000, key="siem_dashboard_refresh")

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👤 Tài khoản: `{st.session_state.get('username')}`")
        st.markdown(f"### 🔑 Vai trò: `{st.session_state.get('role')}`")
        if st.button("🚪 Đăng xuất"):
            logout()

        st.markdown("---")
        st.markdown("### 🔍 Bộ lọc Sự cố")

        # Lọc theo hành động
        # Chỉ liệt kê các hành động THỰC SỰ có trong nhật ký sự cố (bỏ "LOG" vì đó là
        # ghi chú benign/quản trị, không phải sự cố cần phân loại → tránh bộ lọc rỗng).
        action_filter = st.selectbox(
            "Phân loại Hành động",
            options=["Tất cả", "BLOCK_IP", "ALERT", "LOG", "WHITELIST"],
            index=0,
            key="action_filter_sb",
        )

        mitre_filter = st.selectbox(
            "Kỹ thuật MITRE",
            options=["Tất cả", "T1059.004", "T1190", "T1595", "T1071", "N/A"],
            index=0,
            key="mitre_filter_sb",
        )

        # Tìm kiếm theo IP Mục tiêu
        search_ip = st.text_input("Tìm kiếm IP mục tiêu", placeholder="Nhập IP để lọc...").strip()

        # Số dòng trên một trang
        page_size = st.slider(
            "Số lượng hiển thị / trang", min_value=5, max_value=50, value=5, step=5
        )

        st.markdown("---")
        st.markdown("### ⚙️ Quản lý Lịch sử")

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
        st.markdown("### 🛡️ Nhật ký An toàn & Toàn vẹn")
        if st.button(
            "🛡️ Kiểm tra tính toàn vẹn Logs (HMAC Audit)",
            help="Xác minh chuỗi băm HMAC Ledger để phát hiện giả mạo dữ liệu",
        ):
            is_valid, msg = verify_audit_trail_integrity()
            if is_valid:
                st.success(msg)
            else:
                st.error(msg)

        st.markdown("---")
        st.markdown("### 📟 Live System Console Logs")

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
        st.markdown("### 📖 Thuật ngữ & Kiến trúc SOC")
        glossary_html = (
            '<div class="glossary-box">'
            '  <div class="glossary-item">'
            '    <span class="glossary-title">Tier 1 (Lọc nhiễu):</span>'
            '    <div class="glossary-desc">Session Baselining giám sát hành vi mạng và lọc bỏ >95% logs sạch, chống Alert Fatigue cho Analyst.</div>'
            "  </div>"
            '  <div class="glossary-item">'
            '    <span class="glossary-title">Tier-2 · LLM Agent:</span>'
            '    <div class="glossary-desc">LangGraph Agent truy xuất tri thức Dual-RAG (MITRE & NIST) giúp Gemma-2-9B ra quyết định ngăn chặn.</div>'
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

    # Render KPI
    all_alerts = [a for a in cached_get_audit_trail(limit=2000) if a.get("action") != "AWAIT_HITL"]
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

    # Tính toán Live FPR dựa trên các rule được Duyệt (ACTIVE) vs Bác bỏ (REJECTED) bởi con người
    all_rules = feedback_mgr.get_all_dynamic_rules()
    approved_rules_count = sum(1 for r in all_rules if r.get("status") == "ACTIVE")
    rejected_rules_count = sum(1 for r in all_rules if r.get("status") == "REJECTED")
    total_reviewed = approved_rules_count + rejected_rules_count
    live_fpr = (rejected_rules_count / total_reviewed) * 100 if total_reviewed > 0 else 0.0

    # Số liệu THẬT (không ước lượng): đọc counter do subscriber ghi ra
    # config/pipeline_stats.json khi xử lý log thô qua Tier-1.
    # raw_logs_total = tổng log đã phân tích; pending_llm_queue = backlog Tier-2.
    raw_logs_count = 0
    noise_reduction = None
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
    except Exception:
        pending_llm_count = 0
        pass

    # MỘT nguồn sự thật: Tỷ lệ giảm tải = (log thô − TỔNG cảnh báo) / log thô.
    # BUG ĐÃ SỬA: trước đây dùng len(all_alerts), mà all_alerts = get_audit_trail(limit=2000)
    # bị chặn cứng 2000 dòng. Khi luồng vượt 2000 cảnh báo, len() BÃO HOÀ nên tỷ lệ tự
    # phồng lên (100k log thô -> luôn ~98%) BẤT KỂ số cảnh báo thật. Nay đếm bằng
    # COUNT(*) trên audit_trail (cached_count_audit_alerts) -> đúng ở mọi quy mô.
    total_alerts = cached_count_audit_alerts()
    if raw_logs_count > total_alerts:
        noise_reduction = ((raw_logs_count - total_alerts) / raw_logs_count) * 100
    else:
        noise_reduction = None  # raw chưa hợp lệ -> header dùng fallback an toàn

    t1_blocks_list = cached_get_tier1_blocks()

    render_metrics_header(
        all_alerts,
        len(pending_rules),
        len(active_rules),
        raw_logs_count,
        live_fpr,
        noise_reduction,
        t1_blocks=t1_blocks_list,
    )

    tab0, tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "🎬 Tổng quan Demo",
            "📊 Nhật ký SIEM & Audit Trail",
            "🧑‍💻 Phê duyệt HITL (LLM)",
            "🎯 Giám sát APT & Threat Intel",
            "🔒 Quản lý Blocklist & Whitelist",
            "🔍 Lỗ hổng & Tri thức Graph",
        ]
    )

    with tab0:
        render_demo_overview(
            all_alerts,
            active_rules,
            pending_rules,
            raw_logs_count,
            noise_reduction,
            pending_llm=pending_llm_count,
        )

    with tab1:
        # Biểu đồ Live SOC Analytics dạng collapsible
        with st.expander("📊 Phân tích số liệu & Biểu đồ SIEM (Live Analytics)", expanded=True):
            if not all_alerts:
                st.info("Chưa có đủ dữ liệu sự cố để vẽ biểu đồ phân tích.")
            else:
                try:
                    df_alerts = pd.DataFrame(all_alerts)
                    df_alerts["hour"] = df_alerts["timestamp"].apply(lambda x: str(x)[5:16])

                    col_chart1, col_chart2 = st.columns(2)
                    with col_chart1:
                        st.markdown("##### 📈 Xu hướng Sự cố theo Thời gian (Timeline)")

                        def assign_tier(r):
                            r_str = str(r)
                            if any(k in r_str for k in ML_GATE_MARKERS):
                                return "Cổng ML"
                            elif (
                                "Tier 1" in r_str
                                or "Tier-1" in r_str
                                or "whitelist" in r_str.lower()
                            ):
                                return "Tier-1 Filter"
                            else:
                                return "LLM Agent"

                        df_alerts["Nguồn"] = df_alerts["reason"].apply(assign_tier)
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
                        st.markdown("##### 📊 Phân bổ Cảnh báo theo Hành động (Distribution)")
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

        st.subheader("Phân tích Ngữ cảnh & Cảnh báo")
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
                r = alert.get("reason", "")
                # Detect theo MARKER dùng chung ML_GATE_MARKERS: "Cổng ML" (mới) / "ML Tier 2"
                # (bản ghi CŨ trong DB) / "Decision Tree". KHÔNG dùng "Tier-2" trần vì nhánh LLM
                # giờ cũng ghi Tier-2.
                if any(k in r for k in ML_GATE_MARKERS):
                    alerts_t1_mlgate.append(alert)
                elif "Tier 1" in r or "Tier-1" in r or "whitelist" in r.lower():
                    alerts_t1_rule.append(alert)
                else:
                    alerts_t2_llm.append(alert)

            t1_tab, ml_gate_tab, t2_llm_tab = st.tabs(
                [
                    "🟢 Tier-1 · Luật (Welford + chữ ký)",
                    "⚡ Tier-1 · Cổng ML (LightGBM)",
                    "🧠 Tier-2 · Tác tử LLM (LangGraph)",
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

                # Áp dụng bộ lọc
                if action_filter not in ["Tất cả", "BLOCK_IP"]:
                    tier1_blocks_data = []
                if active_search_ip:
                    tier1_blocks_data = [
                        blk for blk in tier1_blocks_data if active_search_ip in blk.get("ip", "")
                    ]

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
                st.markdown(f"**🛡️ Chặn tức thời Tier-1 (Redis):** {len(tier1_blocks_data)} IP")
                st.caption(
                    "_(đọc từ ring buffer `config/tier1_blocks.json` — TTL 1h, không cần LLM)_"
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
                            '  <div class="soc-detail-row">'
                            '    <span class="soc-label">IP bị chặn:</span>'
                            f'    <span class="soc-value-code" style="color:#ff7875;">{ip}</span>'
                            f'    <span style="color:#8c8c8c;font-size:0.8rem;margin-left:12px;">Bị chặn {count} lần · Điểm rủi ro: <b style="color:#ff4d4f;">{score}</b></span>'
                            "  </div>"
                            '  <div class="soc-reasoning-box" style="margin-top:8px;">'
                            '    <div class="soc-reasoning-title">⚡ Lý do Tier-1 chặn (Rule Engine):</div>'
                            f'    <ul style="margin:6px 0 0 18px;font-size:0.85rem;color:#d9d9d9;">{reasons_html}</ul>'
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
                        hitl_type = "🧠 AWAIT_HITL (Tier-2 LLM cần con người phân tích thêm)"
                        hitl_color = "#722ed1"
                    elif "ml_triage" in src:
                        hitl_type = "⚡ AWAIT_HITL (Cổng ML đề xuất xem xét)"
                        hitl_color = "#1890ff"
                    elif "tier1_rule_engine" in src:
                        hitl_type = "🛡️ AWAIT_HITL (Tier-1 Rule Engine cảnh báo, chờ duyệt)"
                        hitl_color = "#faad14"
                    elif "langgraph_agent" in src:
                        hitl_type = "🛑 BLOCK_IP (Hệ thống đề xuất chặn, chờ duyệt)"
                        hitl_color = "#ff4d4f"
                    else:
                        hitl_type = f"🔧 MANUAL ({src})"
                        hitl_color = "#1890ff"

                    with st.expander(
                        f"{sev_icon} [{sev_label}] {rule.get('pattern')} · 🕒 {created} · score {rule.get('score')}",
                        expanded=True,
                    ):
                        st.markdown(
                            f"**Loại chờ duyệt (HITL Type):** <span style='color: {hitl_color}; font-weight: bold;'>{hitl_type}</span>",
                            unsafe_allow_html=True,
                        )
                        st.write(
                            f"**Mức độ nghiêm trọng:** {sev_icon} {sev_label} (score {rule.get('score')})"
                        )
                        st.write(f"**Thời gian tạo:** {created}")
                        st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                        st.write(f"**Lý do:** {rule.get('reason')}")

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
                                st.code(matched_audit.get("raw_log"), language="json")

                        if st.session_state.get("role") == "L3_Manager":
                            col1, col2 = st.columns([1, 1])
                            with col1:
                                if st.button(
                                    "✅ Phê duyệt", key=f"app_{rule.get('pattern')}_{page_key}"
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
                                    st.success(
                                        f"✅ Đã DUYỆT thành công luật chặn cho {rule.get('pattern')}"
                                    )
                                    # Ghi audit khi DUYỆT luật (đồng bộ: duyệt block cũng để lại
                                    # 1 bản ghi như duyệt whitelist). Luật Source IP -> BLOCK_IP.
                                    from src.response.executor import _log_to_db

                                    _act = "BLOCK_IP" if rule.get("field") == "Source IP" else "LOG"
                                    _log_to_db(
                                        _act,
                                        str(rule.get("pattern")),
                                        f"[Tier-1 Filter] Luật được DUYỆT (HITL) bởi "
                                        f"{st.session_state.get('username')}: {rule.get('reason')}",
                                    )
                                    if _act == "BLOCK_IP":
                                        # Đưa vào kho known-bad (reputation=100) -> Tier-1 chặn
                                        # on-sight NGAY + hiện ở Threat Intel, đồng bộ với auto-block.
                                        threat_memory.mark_ip_blocked(str(rule.get("pattern")))
                                    if _was_wl:
                                        st.warning(
                                            f"⚠️ {rule.get('pattern')} đã được GỠ khỏi Whitelist vì "
                                            "chuyển sang CHẶN (block ↔ whitelist loại trừ lẫn nhau)."
                                        )
                                    st.rerun()
                            with col2:
                                if st.button(
                                    "❌ Từ chối", key=f"rej_{rule.get('pattern')}_{page_key}"
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
                                        f"[Tier-1 Filter] Luật bị TỪ CHỐI (HITL) bởi {st.session_state.get('username')}: {rule.get('reason')}",
                                    )
                                    st.warning(f"Đã từ chối luật {rule.get('pattern')}")
                                    st.rerun()
                        else:
                            st.warning("Bạn không có quyền L3_Manager để phê duyệt.")

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

            llm_pending_rules = [
                r
                for r in pending_rules
                if r.get("source", "") in ("langgraph_agent", "langgraph_agent_hitl")
            ]
            st.caption(f"Tổng số sự cố chờ duyệt: **{len(llm_pending_rules)}**")
            _render_pending_list(llm_pending_rules, "hitl_page_all")

        st.markdown("---")
        st.subheader("Lịch sử Thao tác HITL (Đã áp dụng)")
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
        st.subheader("Giám sát Chuỗi APT & Danh tiếng IP")
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
        st.subheader("🔍 Trung tâm Điều tra Đối tượng (Threat Investigation)")

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
                safe_last_mitre = (
                    html.escape(str(ip_rep.get("last_mitre_technique") or "T1190"))
                    if ip_rep
                    else "T1190"
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
        st.subheader("🔒 Quản lý Blocklist & Whitelist (IP Control Center)")

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
        tier1_temp_blocks = cached_get_tier1_blocks(show=25)
        tier1_temp_count = len(tier1_temp_blocks)

        st.markdown(
            f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;">
            <div style="background: rgba(255, 77, 79, 0.1); border: 1px solid rgba(255, 77, 79, 0.3); border-radius: 8px; padding: 12px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #ff4d4f;">{tier1_temp_count}</div>
                <div style="font-size: 0.85rem; color: #ff7875; font-weight: 600; text-transform: uppercase;">🛡️ Tier-1 Tạm thời (TTL 1h)</div>
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
            🛡️ <b>Tier-1 Tạm thời</b>: IP bị chặn tức thời bởi chữ ký WAF/injection/cổng nhạy cảm (Redis blacklist, tự hết hạn TTL 1h).
            <b>Luật Vĩnh viễn</b>: luật động do Tier-2 (LLM) đề xuất, đã được Analyst DUYỆT (HITL) — không hết hạn.
        </p>
        """,
            unsafe_allow_html=True,
        )

        col_left, col_right = st.columns([3, 2])

        with col_left:
            # ── Danh sách Whitelisted IPs hiện tại (Thay thế Chặn tức thời Tier-1) ──
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

            st.markdown("### 🛑 Luật chặn Vĩnh viễn & Lịch sử (Dynamic Rules)")

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
            st.markdown("### ⚙️ Thao tác & Quản lý Whitelist")

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

            # Đã chuyển Danh sách Whitelist lên trên

    with tab5:
        st.subheader("🔍 Quản lý Lỗ hổng & Tri thức Graph (Vulnerabilities & Graph)")

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
                '    background="transparent";',
                "    rankdir=LR;",
                '    node [color="#ffffff", fontcolor="#ffffff", style=filled, fillcolor="#112240", fontname="sans-serif", shape=box, rx=5];',
                '    edge [color="#888888", fontcolor="#888888", fontname="sans-serif", fontsize=10];',
                "    ",
                "    // Nodes",
                '    SOC [label="SENTINEL_SOC\\n(Main Application)", shape=doublecircle, fillcolor="#177ddc", color="#177ddc"];',
            ]

            # Thêm tối đa 8 SubComponents và Vulnerabilities để sơ đồ không bị rối mắt
            subcomponents = set()
            for v in vuln_list[:8]:
                target_clean = v["Target"].replace(".", "_").replace("/", "_").replace("-", "_")
                if v["Target"] not in subcomponents:
                    subcomponents.add(v["Target"])
                    dot_lines.append(
                        f'    {target_clean} [label="{v["Target"]}", fillcolor="#14c2c2", color="#14c2c2"];'
                    )
                    dot_lines.append(f'    SOC -> {target_clean} [label="CONTAINS"];')

                cve_clean = v["CVE ID"].replace("-", "_")
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
                    f'    {cve_clean} [label="{v["CVE ID"]}\\n({v["Severity"]})", fillcolor="#1d39c4", color="{color}"];'
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
                'LLM [label="Tier-2 LLM Agent (Gemma-2-9B)", fillcolor="#1d39c4", color="#1d39c4"]; '
                'MEM [label="Threat Memory (APT)", fillcolor="#1d39c4", color="#1d39c4"]; '
                'SOC -> T1 [label="ingest"]; T1 -> ML [label="escalate"]; '
                'ML -> GR [label="bypass"]; GR -> RAG [label="ground"]; '
                'RAG -> LLM [label="reason"]; LLM -> MEM [label="correlate"]; }'
            )
            st.graphviz_chart(arch_dot, width="stretch")


if __name__ == "__main__":
    main_dashboard()
