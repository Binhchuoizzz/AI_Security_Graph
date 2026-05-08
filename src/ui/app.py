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
from src.agent.threat_memory import threat_memory

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
    with open(css_path, "r") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# 1. Bắt buộc đăng nhập
require_auth()

feedback_mgr = FeedbackListener()


def handle_whitelist_approval(ip: str):
    """Callback xử lý thêm IP vào Whitelist (Pentest/Internal)."""
    feedback_mgr.add_to_whitelist(ip)
    st.session_state[f"whitelisted_{ip}"] = True

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
        st.info(
            "Hệ thống phát hiện xâm nhập thông minh sử dụng **Advanced Hybrid RAG** và **LangGraph Agent**."
        )
        st.caption(f"Refreshes: {count}")

    st.title(" SENTINEL AI Security Operations Center")

    # Lấy dữ liệu
    alerts = get_audit_trail(limit=20)
    active_rules = feedback_mgr.get_active_dynamic_rules()
    pending_rules = feedback_mgr.get_pending_rules()

    render_metrics_header(len(alerts), len(pending_rules), len(active_rules))

    tab1, tab2 = st.tabs([" SIEM & Audit Trail", " HITL Rule Approval"])

    with tab1:
        st.subheader("Phân tích Ngữ cảnh & Cảnh báo")
        if not alerts:
            st.success("Hệ thống an toàn. Không có sự cố nào được ghi nhận.")
        else:
            for alert in alerts:
                # Kiểm tra xem IP này đã được whitelist trong session này chưa
                target_ip = alert.get("target", "N/A")
                is_whitelisted = st.session_state.get(f"whitelisted_{target_ip}", False)
                
                # Gọi hàm render component, truyền thêm callback
                render_alert_card(
                    alert, 
                    is_l3_manager=(st.session_state.get("role") == "L3_Manager"),
                    on_whitelist=handle_whitelist_approval if not is_whitelisted else None
                )

    with tab2:
        st.subheader("Phê duyệt Luật Tường lửa (Dynamic Rules)")
        if not pending_rules:
            st.info("Không có luật nào đang chờ phê duyệt.")
        else:
            for rule in pending_rules:
                with st.expander(
                    f"Luật chờ duyệt: {rule.get('pattern')} (Mức độ: {rule.get('score')})",
                    expanded=True,
                ):
                    st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                    st.write(f"**Lý do (LLM):** {rule.get('reason')}")
                    st.write(f"**Tạo lúc:** {rule.get('created_at')}")

                    if st.session_state.get("role") == "L3_Manager":
                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if st.button(
                                " Phê duyệt (Approve)", key=f"app_{rule.get('pattern')}"
                            ):
                                feedback_mgr.approve_rule(rule.get("pattern"))
                                st.success(f"Đã duyệt luật {rule.get('pattern')}")
                                time.sleep(0.5)
                                st.rerun()
                        with col2:
                            if st.button(
                                " Từ chối (Reject)", key=f"rej_{rule.get('pattern')}"
                            ):
                                feedback_mgr.reject_rule(rule.get("pattern"))
                                st.warning(f"Đã từ chối luật {rule.get('pattern')}")
                                time.sleep(0.5)
                                st.rerun()
                    else:
                        st.warning("Bạn không có quyền L3_Manager để phê duyệt.")

        st.markdown("---")
        st.subheader("Luật Đang Hoạt Động (Active Rules)")
        if not active_rules:
            st.info("Không có luật nào đang hoạt động.")
        else:
            for rule in active_rules:
                with st.expander(
                    f"Luật Active: {rule.get('pattern')} (Mức độ: {rule.get('score')})",
                    expanded=False,
                ):
                    st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                    st.write(f"**Lý do (LLM):** {rule.get('reason')}")
                    st.write(f"**Tạo lúc:** {rule.get('created_at')}")
                    
                    if st.session_state.get("role") == "L3_Manager":
                        if st.button(" Hoàn tác (Revoke/Reject)", key=f"rev_{rule.get('pattern')}"):
                            feedback_mgr.reject_rule(rule.get("pattern"))
                            st.warning(f"Đã hoàn tác và vô hiệu hóa luật {rule.get('pattern')}")
                            time.sleep(0.5)
                            st.rerun()

        st.markdown("---")
        st.subheader("Quản lý IP Đặc cách (Whitelisted IPs)")
        whitelisted_ips = feedback_mgr.get_whitelisted_ips()
        if not whitelisted_ips:
            st.info("Chưa có IP nào trong danh sách Whitelist.")
        else:
            for ip in whitelisted_ips:
                with st.expander(f"✅ IP Nội bộ / Pentest: {ip}", expanded=False):
                    st.write(f"Hệ thống (Tier 1) sẽ bỏ qua mọi đánh giá và Rule Engine đối với IP `{ip}`.")
                    if st.session_state.get("role") == "L3_Manager":
                        if st.button(" Gỡ Whitelist (Remove)", key=f"rmwl_{ip}"):
                            feedback_mgr.remove_from_whitelist(ip)
                            st.warning(f"Đã gỡ IP {ip} khỏi danh sách Whitelist.")
                            time.sleep(0.5)
                            st.rerun()

if __name__ == "__main__":
    main_dashboard()
