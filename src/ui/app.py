"""
SENTINEL - Main Dashboard
Khởi chạy bằng lệnh: streamlit run src/ui/app.py
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import streamlit as st
import time
from streamlit_autorefresh import st_autorefresh

from src.ui.auth import require_auth, logout
from src.ui.components import render_alert_card, render_metrics_header
from src.response.executor import get_audit_trail
from src.tier1_filter.feedback_listener import FeedbackListener

# Cấu hình trang
st.set_page_config(
    page_title="SENTINEL AI Security",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 1. Bắt buộc đăng nhập
require_auth()

feedback_mgr = FeedbackListener()

def main_dashboard():
    # Tự động refresh trang mỗi 3000ms (3 giây)
    # Giúp dashboard tự cập nhật log mới theo thời gian thực (SIEM style)
    count = st_autorefresh(interval=3000, limit=10000, key="siem_dashboard_refresh")
    
    # Sidebar
    with st.sidebar:
        st.markdown(f"###  User: `{st.session_state.get('username')}`")
        st.markdown(f"###  Role: `{st.session_state.get('role')}`")
        if st.button(" Đăng xuất"):
            logout()
            
        st.markdown("---")
        st.markdown("## Về SENTINEL")
        st.info("Hệ thống phát hiện xâm nhập thông minh sử dụng **Advanced Hybrid RAG** và **LangGraph Agent**.")
        st.caption(f"Refreshes: {count}")

    st.title(" SENTINEL AI Security Operations Center")

    # Lấy dữ liệu
    alerts = get_audit_trail(limit=20)
    active_rules = feedback_mgr.get_active_dynamic_rules()
    pending_rules = feedback_mgr.get_pending_rules()

    render_metrics_header(len(alerts), len(pending_rules), len(active_rules))

    tab1, tab2 = st.tabs([" SIEM & Audit Trail", " HITL Rule Approval"])

    with tab1:
        st.subheader("Cảnh báo & Hành động Gần đây")
        if not alerts:
            st.success("Hệ thống an toàn. Không có sự cố nào được ghi nhận.")
        else:
            for alert in alerts:
                render_alert_card(alert)

    with tab2:
        st.subheader("Phê duyệt Luật Tường lửa (Dynamic Rules)")
        if not pending_rules:
            st.info("Không có luật nào đang chờ phê duyệt.")
        else:
            for rule in pending_rules:
                with st.expander(f"Luật chờ duyệt: {rule.get('pattern')} (Mức độ: {rule.get('score')})", expanded=True):
                    st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                    st.write(f"**Lý do (LLM):** {rule.get('reason')}")
                    st.write(f"**Tạo lúc:** {rule.get('created_at')}")
                    
                    if st.session_state.get('role') == 'L3_Manager':
                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if st.button(" Phê duyệt (Approve)", key=f"app_{rule.get('pattern')}"):
                                feedback_mgr.approve_rule(rule.get('pattern'))
                                st.success(f"Đã duyệt luật {rule.get('pattern')}")
                                time.sleep(0.5)
                                st.rerun()
                        with col2:
                            if st.button(" Từ chối (Reject)", key=f"rej_{rule.get('pattern')}"):
                                feedback_mgr.reject_rule(rule.get('pattern'))
                                st.warning(f"Đã từ chối luật {rule.get('pattern')}")
                                time.sleep(0.5)
                                st.rerun()
                    else:
                        st.warning("Bạn không có quyền L3_Manager để phê duyệt.")

if __name__ == "__main__":
    main_dashboard()
