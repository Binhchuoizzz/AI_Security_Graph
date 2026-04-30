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
    confidence = "N/A"
    
    mitre_match = re.search(r'MITRE:\s*([^\s\]]+)', raw_reason, re.IGNORECASE)
    if mitre_match:
        mitre_tech = mitre_match.group(1).strip()
    elif re.search(r'(T\d{4}(?:\.\d{3})?)', raw_reason):
        mitre_tech = re.search(r'(T\d{4}(?:\.\d{3})?)', raw_reason).group(1)
        
    conf_match = re.search(r'Confidence:\s*([01]?\.\d+|1(?:\.0)?)', raw_reason, re.IGNORECASE)
    if conf_match:
        try:
            val = float(conf_match.group(1))
            confidence = f"{val * 100:.0f}%"
        except ValueError:
            pass

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

    # Hiển thị UI bằng Markdown + HTML nội suy
    st.markdown(
        f"""
        <div class="soc-card {css_class}">
            <div class="soc-card-header">
                <h4 class="soc-card-title">{icon} {action}</h4>
                <span class="soc-timestamp">{formatted_time}</span>
            </div>
            <div class="soc-detail-row">
                <span class="soc-label">Target IP:</span> 
                <code>{target}</code>
            </div>
            <div class="soc-detail-row">
                <span class="soc-label">Context:</span> 
                <span class="soc-badge soc-mitre-badge">MITRE: {mitre_tech}</span>
                <span class="soc-badge soc-conf-badge">AI Confidence: {confidence}</span>
            </div>
            <div class="soc-reasoning-box">
                {clean_reason}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # Nút Approve as Pentest (chỉ hiển thị nếu có IP hợp lệ và người dùng là L3_Manager)
    if on_whitelist and target not in ["N/A", "UNKNOWN_TARGET"] and is_l3_manager:
        if action in ["ALERT", "AWAIT_HITL"]:
            if st.button(f"✅ Approve as Pentest / Internal ({target})", key=f"wl_{target}_{timestamp}"):
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
        st.subheader("🔴 High Risk IPs (APT Tracker)")
        if not high_risk_ips:
            st.info("Chưa ghi nhận IP nguy hiểm nào.")
        else:
            df_high_risk = pd.DataFrame(high_risk_ips, columns=["IP", "Reputation Score"])
            # Define styling function
            def color_score(val):
                color = 'red' if val >= 70 else 'orange' if val >= 40 else 'green'
                return f'color: {color}; font-weight: bold'
            st.dataframe(df_high_risk.style.map(color_score, subset=['Reputation Score']), use_container_width=True)

    with col2:
        st.subheader("🟢 Known Entities (Whitelist / Internal)")
        if not known_entities:
            st.info("Chưa có cấu hình tổ chức nào.")
        else:
            df_entities = pd.DataFrame(known_entities, columns=["Entity/IP", "Role"])
            st.dataframe(df_entities, use_container_width=True)
