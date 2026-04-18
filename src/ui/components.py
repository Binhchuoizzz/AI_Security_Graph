"""
Các component giao diện dùng lại cho Streamlit Dashboard.
"""
import streamlit as st
import pandas as pd
import html as html_lib
from datetime import datetime

def render_alert_card(alert):
    """Hiển thị một cảnh báo bảo mật từ audit_trail (XSS-safe)."""
    timestamp = alert.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp)
        formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        formatted_time = html_lib.escape(str(timestamp))

    action = html_lib.escape(str(alert.get("action", "UNKNOWN")))
    target = html_lib.escape(str(alert.get("target", "N/A")))
    reason = html_lib.escape(str(alert.get("reason", "N/A")))
    
    color = "grey"
    icon = ""
    if action == "BLOCK_IP":
        color = "red"
        icon = ""
    elif action == "QUARANTINE":
        color = "orange"
        icon = ""
    elif action == "ALERT":
        color = "yellow"
        icon = ""

    st.markdown(f"""
    <div style="border:1px solid {color}; border-left: 5px solid {color}; border-radius: 5px; padding: 10px; margin-bottom: 10px; background-color: rgba(255,255,255,0.05);">
        <h4 style="margin-top: 0; color: {color}">{icon} {action} - {formatted_time}</h4>
        <b>Target:</b> {target}<br/>
        <b>Reasoning:</b> {reason}
    </div>
    """, unsafe_allow_html=True)

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
        st.metric(label="Luật Đang Chờ (Pending)", value=pending_rules, delta=f"+{pending_rules}" if pending_rules>0 else None, delta_color="inverse")
    with col3:
        st.metric(label="Luật Đang Hoạt Động (Active)", value=active_rules)
    st.markdown("---")
