"""
Các component giao diện dùng lại cho Streamlit Dashboard.
"""

import streamlit as st
import pandas as pd
import html as html_lib
import re
from datetime import datetime


def render_alert_card(alert, is_l3_manager=False, on_whitelist=None):
    """Hiển thị một cảnh báo bảo mật từ audit_trail với UI Premium."""
    timestamp = alert.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted_time = html_lib.escape(str(timestamp))

    action = str(alert.get("action", "UNKNOWN")).upper()
    target = html_lib.escape(str(alert.get("target", "N/A")))
    raw_reason = str(alert.get("reason", "N/A"))

    # Bóc tách Regex từ chuỗi Reason (Do DB chỉ lưu text trơn)
    mitre_tech = "N/A"
    confidence = "Chưa rõ"
    
    mitre_match = re.search(r'MITRE:\s*([^\s\]]+)', raw_reason, re.IGNORECASE)
    if mitre_match:
        mitre_tech = mitre_match.group(1).strip()
    elif t_match := re.search(r'(T\d{4}(?:\.\d{3})?)', raw_reason):
        mitre_tech = t_match.group(1)
        
    conf_match = re.search(r'(?:Confidence|Độ\s+tin\s+cậy):\s*([01]?\.\d+|1(?:\.0)?|\d+%)', raw_reason, re.IGNORECASE)
    if conf_match:
        try:
            val_str = conf_match.group(1)
            if val_str.endswith('%'):
                confidence = val_str
            else:
                val = float(val_str)
                confidence = f"{val * 100:.0f}%"
        except ValueError:
            pass

    # Việt hóa tiêu đề hành động
    action_translations = {
        "BLOCK_IP": "CHẶN IP (BLOCK)",
        "QUARANTINE": "CÁCH LY (QUARANTINE)",
        "ALERT": "CẢNH BÁO (ALERT)",
        "AWAIT_HITL": "CHỜ DUYỆT (HITL)",
        "LOG": "GHI LOG (LOG)"
    }
    action_display = action_translations.get(action, action)

    # Gán class CSS dựa trên Severity
    css_class = "severity-info"
    icon = "ℹ️"
    if action == "BLOCK_IP":
        css_class = "severity-critical"
        icon = "🛑"
    elif action == "QUARANTINE":
        css_class = "severity-critical"
        icon = "☣️"
    elif action == "ALERT":
        css_class = "severity-high"
        icon = "⚠️"
    elif action == "AWAIT_HITL":
        css_class = "severity-medium"
        icon = "🧑‍💻"

    clean_reason = html_lib.escape(raw_reason)

    # Hiển thị UI bằng Markdown + HTML nội suy (loại bỏ xuống dòng thừa tránh lỗi Streamlit Markdown)
    html_content = (
        f'<div class="soc-card {css_class}">'
        f'    <div class="soc-card-header">'
        f'        <h4 class="soc-card-title">{icon} {action_display}</h4>'
        f'        <span class="soc-timestamp">{formatted_time}</span>'
        f'    </div>'
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">IP Mục tiêu:</span>'
        f'        <code>{target}</code>'
        f'    </div>'
        f'    <div class="soc-detail-row">'
        f'        <span class="soc-label">Ngữ cảnh:</span>'
        f'        <span class="soc-badge soc-mitre-badge">MITRE: {mitre_tech}</span>'
        f'        <span class="soc-badge soc-conf-badge">Độ tin cậy AI: {confidence}</span>'
        f'    </div>'
        f'    <div class="soc-reasoning-box">'
        f'        {clean_reason}'
        f'    </div>'
        f'</div>'
    )
    # Strip any extra newlines/tabs inside HTML to prevent Streamlit from adding paragraphs
    clean_html = "".join([line.strip() for line in html_content.split("\n")])
    st.markdown(clean_html, unsafe_allow_html=True)
    
    # Nút Approve as Pentest (chỉ hiển thị nếu có IP hợp lệ và người dùng là L3_Manager)
    if on_whitelist and target not in ["N/A", "UNKNOWN_TARGET"] and is_l3_manager:
        if action in ["ALERT", "AWAIT_HITL"]:
            if st.button(f"✅ Phê duyệt làm Pentest / IP Nội bộ ({target})", key=f"wl_{target}_{timestamp}"):
                on_whitelist(target)
                st.success(f"IP {target} đã được thêm vào Whitelist. Agent sẽ bỏ qua IP này trong tương lai.")
                st.rerun()


def render_ioc_table(iocs):
    """Hiển thị danh sách IOC trích xuất được."""
    if not iocs:
        st.info("Không có IOC nào được ghi nhận.")
        return

    df = pd.DataFrame(iocs)
    st.dataframe(df, use_container_width=True)


def render_metrics_header(total_alerts, pending_rules, active_rules):
    """Hiển thị Header KPI."""
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Tổng số Sự cố (Alerts)", value=total_alerts)
    with col2:
        st.metric(
            label="Luật Đang Chờ (Pending)",
            value=pending_rules,
            delta=f"+{pending_rules}" if pending_rules > 0 else None,
            delta_color="inverse",
        )
    with col3:
        st.metric(label="Luật Đang Hoạt Động (Active)", value=active_rules)
    st.markdown("---")

def render_threat_intel_tables(high_risk_ips, known_entities):
    """Hiển thị bảng Threat Intelligence."""
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔴 IP Nguy cơ cao (APT Tracker)")
        if not high_risk_ips:
            st.info("Chưa ghi nhận IP nguy hiểm nào.")
        else:
            df_high_risk = pd.DataFrame(high_risk_ips, columns=["Địa chỉ IP", "Điểm danh tiếng (Reputation)"]) # type: ignore
            # Define styling function
            def color_score(val):
                color = 'red' if val >= 70 else 'orange' if val >= 40 else 'green'
                return f'color: {color}; font-weight: bold'
            st.dataframe(df_high_risk.style.map(color_score, subset=["Điểm danh tiếng (Reputation)"]), use_container_width=True)

    with col2:
        st.subheader("🟢 Thực thể mạng nội bộ (Known Entities)")
        if not known_entities:
            st.info("Chưa có thực thể nội bộ nào.")
        else:
            df_entities = pd.DataFrame(known_entities, columns=["Thiết bị / IP", "Vai trò / Mô tả"]) # type: ignore
            st.dataframe(df_entities, use_container_width=True)

def render_apt_events_table(events):
    """Hiển thị bảng chuỗi tấn công APT từ DAPT2020."""
    st.subheader("🎯 Nhật ký chuỗi tấn công APT (DAPT2020 Tracker)")
    if not events:
        st.info("Chưa ghi nhận sự kiện chuỗi APT nào.")
        return
        
    df = pd.DataFrame(events)
    # Rename columns for Vietnamese UI
    df = df.rename(columns={
        "id": "ID",
        "src_ip": "IP Nguồn",
        "dst_ip": "IP Đích",
        "apt_phase": "Giai đoạn APT",
        "apt_day": "Ngày tấn công",
        "label": "Nhãn",
        "timestamp": "Thời gian xảy ra"
    })
    st.dataframe(df, use_container_width=True)
