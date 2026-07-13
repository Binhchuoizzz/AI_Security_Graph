"""
Các component giao diện dùng lại cho Streamlit Dashboard.
NÂNG CẤP PREMIUM: Thiết kế chuẩn SOC/SIEM Glassmorphism hiện đại.
"""

import html as html_lib
import json
import re
from datetime import datetime

import pandas as pd  # type: ignore
import streamlit as st  # type: ignore


def is_valid_ip(ip_str: str) -> bool:
    """Kiểm tra chuỗi IP hợp lệ (IPv4 hoặc IPv6)."""
    ip_str = ip_str.strip()
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$"
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(re.match(ipv6_pattern, ip_str))


def render_alert_card(alert, is_l3_manager=False, on_whitelist=None, card_id=""):
    """Hiển thị một cảnh báo bảo mật từ audit_trail với giao diện SOC Premium."""
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
    # IP whitelist vẫn được ghi nhận + hiển thị, NHƯNG bằng thẻ xanh "cho qua",
    # KHÔNG phải thẻ tấn công (không MITRE/độ tin cậy/suy luận LLM) — nó không phải
    # tấn công, chỉ là truy cập hợp lệ đã được đặc cách.
    if action == "WHITELIST":
        wl_html = (
            '<div class="soc-card" style="border-left:4px solid #52c41a;'
            'background:rgba(82,196,26,0.06);">'
            '<div class="soc-card-header">'
            '<h4 class="soc-card-title">✅ [WHITELIST] Truy cập được cho qua</h4>'
            f'<span class="soc-timestamp">{formatted_time}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-label">IP nguồn:</span>'
            f'<span class="soc-value-code">{target}</span>'
            "</div>"
            '<div class="soc-detail-row">'
            '<span class="soc-badge" style="background:rgba(82,196,26,0.15);'
            'color:#95de64;border:1px solid rgba(82,196,26,0.35);">'
            "✅ WHITELIST · KHÔNG phân tích tấn công</span>"
            "</div>"
            f'<div style="color:#95de64;font-size:0.85rem;margin-top:6px;">'
            f"{html_lib.escape(raw_reason)}</div>"
            "</div>"
        )
        st.markdown("".join(line.strip() for line in wl_html.split("\n")), unsafe_allow_html=True)
        with st.expander("🔍 Xem LOG THÔ (Raw Flow từ IP Whitelist)", expanded=False):
            _wl_raw = alert.get("raw_log") if isinstance(alert, dict) else None
            if _wl_raw:
                try:
                    st.json(json.loads(_wl_raw))
                except Exception:
                    st.code(str(_wl_raw))
            else:
                st.caption("Không có log thô đính kèm.")
        return

    # Bóc tách Regex từ chuỗi Reason
    mitre_tech = "N/A"
    confidence = "Chưa rõ"

    mitre_match = re.search(r"MITRE:\s*([^\s\]]+)", raw_reason, re.IGNORECASE)
    if mitre_match:
        mitre_tech = mitre_match.group(1).strip()
    elif t_match := re.search(r"(T\d{4}(?:\.\d{3})?)", raw_reason):
        mitre_tech = t_match.group(1)

    conf_match = re.search(
        r"(?:Confidence|Độ\s+tin\s+cậy):\s*([01]?\.\d+|1(?:\.0)?|\d+%)", raw_reason, re.IGNORECASE
    )
    if conf_match:
        try:
            val_str = conf_match.group(1)
            if val_str.endswith("%"):
                confidence = val_str
            else:
                val = float(val_str)
                confidence = f"{val * 100:.0f}%"
        except ValueError:
            pass

    # Xử lý chống Stored XSS cho các biến trích xuất động
    mitre_tech = html_lib.escape(mitre_tech)
    confidence = html_lib.escape(confidence)

    # Phân cấp mức độ nghiêm trọng (Severity) dựa trên Risk Score & Action
    severity_level = "INFO"
    css_class = "severity-info"
    icon = "ℹ️"

    if action == "BLOCK_IP" or action == "QUARANTINE":
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

    # Việt hóa hành động
    action_translations = {
        "BLOCK_IP": "CHẶN IP (BLOCK)",
        "QUARANTINE": "CÁCH LY (QUARANTINE)",
        "ALERT": "CẢNH BÁO (ALERT)",
        "AWAIT_HITL": "CHỜ PHÊ DUYỆT (HITL)",
        "LOG": "GHI LOG (LOG)",
    }
    action_display = action_translations.get(action, action)

    # Làm sạch chuỗi lý do phân tích (loại bỏ các thẻ tag [MITRE...] để hiển thị text sạch)
    clean_reason = html_lib.escape(raw_reason)
    clean_reason = re.sub(r"\[MITRE:\s*[^\]]*\]", "", clean_reason)
    clean_reason = re.sub(r"\[(?:Confidence|Độ\s+tin\s+cậy):\s*[^\]]*\]", "", clean_reason).strip()

    # Tạo tiêu đề MITRE kỹ thuật
    mitre_section_text = f"🎯 Phân loại MITRE ATT&CK: <code>{mitre_tech}</code>"
    if mitre_tech == "N/A":
        mitre_section_text = "🎯 Phân loại MITRE ATT&CK: <code>T1190 - Exploit Public-Facing Application</code> (Suy luận)"

    # Thiết lập playbook ứng phó NIST
    nist_playbook_text = (
        "🛡️ NIST Incident Response Playbook: Thực hiện ghi log và giám sát hành vi liên tục."
    )
    if severity_level == "CRITICAL":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.1): Thực hiện ngăn chặn khẩn cấp (Containment) - Chặn IP nguồn tại Firewall để cô lập vùng tấn công."
    elif severity_level == "HIGH":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.2): Cảnh báo khẩn cấp tới L1/L3 SOC Analyst, đưa IP vào danh sách theo dõi đặc biệt."
    elif severity_level == "MEDIUM":
        nist_playbook_text = "🛡️ NIST Incident Response Playbook (Section 3.2.3): Yêu cầu phê duyệt từ L3 Manager (Human-in-the-Loop) để kích hoạt luật chặn tự động."

    # Render HTML Card
    html_content = (
        f'<div class="soc-card {css_class}">'
        f'    <div class="soc-card-header">'
        f'        <h4 class="soc-card-title">{icon} [{severity_level}] {action_display}</h4>'
        f'        <span class="soc-timestamp">{formatted_time}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">IP Mục tiêu:</span>'
        f'        <span class="soc-value-code">{target}</span>'
        f"    </div>"
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">Ngữ cảnh:</span>'
        f'        <span class="soc-badge soc-mitre-badge">MITRE: {mitre_tech}</span>'
        f'        <span class="soc-badge soc-conf-badge">Độ tin cậy AI: {confidence}</span>'
        f"    </div>"
        f'    <div class="soc-reasoning-box">'
        f'        <div class="soc-reasoning-title">🤖 Lập luận của Tác tử AI (Agentic Reasoning):</div>'
        f'        <div style="margin-bottom: 8px;">{clean_reason}</div>'
        f'        <div class="soc-reasoning-section" style="color: #D3ADF7;">{mitre_section_text}</div>'
        f'        <div style="color: #98FB98; margin-top: 4px; font-size: 0.85rem; font-weight: 500;">{nist_playbook_text}</div>'
        f"    </div>"
        f"</div>"
    )

    # Nén HTML để tránh khoảng trắng dọc của Streamlit
    clean_html = "".join([line.strip() for line in html_content.split("\n")])
    st.markdown(clean_html, unsafe_allow_html=True)

    # Nút Whitelist IP dành cho mọi alert có target là IP hợp lệ
    cleaned_target = target.strip()
    if is_valid_ip(cleaned_target):
        st.write("")
        if on_whitelist:
            # IP chưa được Whitelist
            if is_l3_manager:
                if st.button(
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
        else:
            # IP đã được Whitelist rồi
            st.button(
                f"✅ Đã Whitelist IP: {cleaned_target}",
                key=f"wl_btn_done_{cleaned_target}_{timestamp}_{card_id}",
                disabled=True,
                help="💡 IP này đã nằm trong danh sách đặc cách (Whitelist).",
            )

    # LOG THÔ ĐẦU VÀO (đặc trưng luồng đã loại nhãn) — chính là dữ liệu đã đưa vào
    # Tier-1/LLM, KHÔNG phải bản ghi quyết định. Minh bạch "cái gì đã vào hệ thống".
    with st.expander("🔍 Xem LOG THÔ đầu vào (Raw Flow đã đưa vào Tier-1/LLM)", expanded=False):
        st.caption(
            "ℹ️ Đây là **log thô đầu vào** — **đặc trưng luồng mạng** (IP, cổng, số gói/byte, "
            "thời lượng luồng, payload…) đã đưa vào Tier-1/LLM. Đã **LOẠI nhãn/đáp án** (chống lộ "
            "nhãn — xem `tests/unit/test_subscriber.py`). `action`/`MITRE` là **kết quả** tác tử "
            "suy ra từ chính log này (bản ghi quyết định đã ký HMAC nằm ở Audit Trail)."
        )
        raw_log_str = alert.get("raw_log") if isinstance(alert, dict) else None
        if raw_log_str:
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
    total_alerts, pending_rules, active_rules, total_raw_logs=0, live_fpr=0.0, noise_reduction=None
):
    """Hiển thị Header KPI chuẩn SOC SIEM bằng HTML Glassmorphism.

    noise_reduction: nếu được truyền (đo THẬT từ counter Tier-1) thì dùng trực tiếp;
    None -> fallback ước lượng (raw-alerts)/raw cho tương thích ngược.
    """
    if noise_reduction is None:
        noise_reduction = 0.0
        if total_raw_logs > 0:
            noise_reduction = ((total_raw_logs - total_alerts) / total_raw_logs) * 100

    # Xác định màu sắc cho live_fpr (dưới 10% xanh lá, dưới 25% vàng, ngược lại đỏ)
    fpr_color = "#52c41a"  # green
    if live_fpr > 25.0:
        fpr_color = "#ff4d4f"  # red
    elif live_fpr > 10.0:
        fpr_color = "#faad14"  # orange/yellow

    html_kpi = (
        f'<div class="kpi-container">'
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #177ddc;">{total_raw_logs}</div>'
        f'    <div class="kpi-label">Logs thô đầu vào</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #ff4d4f;">{total_alerts}</div>'
        f'    <div class="kpi-label">Cảnh báo Escalated</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #52c41a;">{noise_reduction:.1f}%</div>'
        f'    <div class="kpi-label">Tỷ lệ giảm tải (Noise Reduction)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #faad14;">{pending_rules}</div>'
        f'    <div class="kpi-label">Luật chờ duyệt (HITL)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: #13c2c2;">{active_rules}</div>'
        f'    <div class="kpi-label">Luật đang chặn (Active)</div>'
        f"  </div>"
        f'  <div class="kpi-card">'
        f'    <div class="kpi-val" style="color: {fpr_color};">{live_fpr:.1f}%</div>'
        f'    <div class="kpi-label">Tỷ lệ cảnh báo sai (Live FPR)</div>'
        f"  </div>"
        f"</div>"
    )
    st.markdown(html_kpi, unsafe_allow_html=True)


def render_threat_intel_tables(high_risk_ips, known_entities):
    """Hiển thị bảng Threat Intelligence với màu sắc neon trực quan. Hỗ trợ chọn hàng để điều tra."""
    col1, col2 = st.columns(2)
    selected_ip = None

    with col1:
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
                    df_high_risk.style.map(
                        color_score, subset=["Điểm danh tiếng (Reputation)"]
                    ).format({"Điểm danh tiếng (Reputation)": "{:.1f}"}),
                ),
                on_select="rerun",
                selection_mode="single-row",
                key="threat_actor_table_select",
            )

            select_data = selection.get("selection", {}) if selection else {}
            rows = select_data.get("rows", [])
            if rows:
                row_idx = rows[0]
                selected_ip = df_high_risk.iloc[row_idx]["Địa chỉ IP"]

    with col2:
        st.subheader("🟢 Thực thể mạng nội bộ tin tưởng (Known Entities)")
        if not known_entities:
            st.info("Chưa có thực thể nội bộ nào.")
        else:
            df_entities = pd.DataFrame(known_entities, columns=["Thiết bị / IP", "Vai trò / Mô tả"])  # type: ignore
            st.dataframe(df_entities, width="stretch")

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
