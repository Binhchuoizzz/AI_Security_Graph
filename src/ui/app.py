"""
SENTINEL - Main Dashboard
Khởi chạy bằng lệnh: streamlit run src/ui/app.py
"""

import sys
import os
import math
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import streamlit as st
import time
from streamlit_autorefresh import st_autorefresh

from src.ui.auth import require_auth, logout
from src.ui.components import render_alert_card, render_metrics_header, render_threat_intel_tables, render_apt_events_table
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
        st.markdown(f"### 👤 Tài khoản: `{st.session_state.get('username')}`")
        st.markdown(f"### 🔑 Vai trò: `{st.session_state.get('role')}`")
        if st.button("🚪 Đăng xuất"):
            logout()

        st.markdown("---")
        st.markdown("### 🔍 Bộ lọc Sự cố")
        
        # Lọc theo hành động
        action_filter = st.selectbox(
            "Phân loại Hành động",
            options=["Tất cả", "BLOCK_IP", "ALERT", "AWAIT_HITL", "QUARANTINE"],
            index=0,
            key="action_filter_sb"
        )
        
        # Tìm kiếm theo IP Mục tiêu
        search_ip = st.text_input("Tìm kiếm IP mục tiêu", placeholder="Nhập IP để lọc...").strip()
        
        # Số dòng trên một trang
        page_size = st.slider("Số lượng hiển thị / trang", min_value=5, max_value=50, value=5, step=5)
        
        st.markdown("---")
        st.markdown("### ⚙️ Quản lý Lịch sử")
        
        # Nút xóa lịch sử quét
        if st.button("🗑️ Xóa Lịch sử Cảnh báo", help="Xóa sạch toàn bộ lịch sử trong audit_trail"):
            from src.response.executor import DB_PATH as AUDIT_DB
            import sqlite3
            try:
                with sqlite3.connect(AUDIT_DB) as conn:
                    conn.execute("DELETE FROM audit_trail")
                    conn.commit()
                st.success("Đã xóa sạch lịch sử cảnh báo!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(f"Lỗi khi xóa: {e}")

        st.markdown("---")
        st.markdown("## Về SENTINEL")
        st.info(
            "Hệ thống phát hiện xâm nhập thông minh sử dụng **Advanced Hybrid RAG** và **LangGraph Agent**."
        )
        st.caption(f"Lượt tải lại: {count}")

    st.title("🛡️ Trung tâm Điều hành An ninh Mạng SENTINEL AI SOC")

    # Lấy toàn bộ dữ liệu để lọc và phân trang (tối đa 2000 dòng lịch sử)
    all_alerts = get_audit_trail(limit=2000)
    active_rules = feedback_mgr.get_active_dynamic_rules()
    pending_rules = feedback_mgr.get_pending_rules()

    # Tính toán bộ lọc sự cố
    filtered_alerts = all_alerts
    if action_filter != "Tất cả":
        filtered_alerts = [a for a in filtered_alerts if a.get("action") == action_filter]
    if search_ip:
        filtered_alerts = [a for a in filtered_alerts if search_ip in a.get("target", "")]

    total_filtered = len(filtered_alerts)
    
    # Hiển thị số lượng sự cố (Metrics)
    render_metrics_header(len(all_alerts), len(pending_rules), len(active_rules))

    tab1, tab2, tab3 = st.tabs(["📊 Nhật ký SIEM & Audit Trail", "🧑‍💻 Phê duyệt Luật (HITL)", "🎯 Giám sát APT & Threat Intel"])

    with tab1:
        st.subheader("Phân tích Ngữ cảnh & Cảnh báo")
        
        # Xuất dữ liệu CSV để lưu trữ lịch sử
        if filtered_alerts:
            df_download = pd.DataFrame(filtered_alerts)
            df_download = df_download.rename(columns={
                "timestamp": "Thời gian",
                "action": "Hành động",
                "target": "Đối tượng (Target)",
                "reason": "Lý do & Lập luận"
            })
            csv_data = df_download.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Tải xuống lịch sử lọc (CSV)",
                data=csv_data,
                file_name="sentinel_scan_history.csv",
                mime="text/csv"
            )
            
        if not filtered_alerts:
            st.success("Không có sự cố nào khớp với bộ lọc hoặc cơ sở dữ liệu trống.")
        else:
            # Phân trang
            total_pages = max(1, math.ceil(total_filtered / page_size))
            if "current_page" not in st.session_state:
                st.session_state["current_page"] = 1
            if st.session_state["current_page"] > total_pages:
                st.session_state["current_page"] = total_pages
                
            start_idx = (st.session_state["current_page"] - 1) * page_size
            end_idx = start_idx + page_size
            page_alerts = filtered_alerts[start_idx:end_idx]
            
            # Hiển thị các Alert Cards cho trang hiện tại
            for alert in page_alerts:
                target_ip = alert.get("target", "N/A")
                is_whitelisted = st.session_state.get(f"whitelisted_{target_ip}", False)
                
                render_alert_card(
                    alert, 
                    is_l3_manager=(st.session_state.get("role") == "L3_Manager"),
                    on_whitelist=handle_whitelist_approval if not is_whitelisted else None
                )
                
            # Điều hướng trang
            st.write("")
            col_prev, col_page, col_next = st.columns([1, 2, 1])
            with col_prev:
                if st.button("⬅️ Trang trước", disabled=(st.session_state["current_page"] == 1), key="btn_prev_page"):
                    st.session_state["current_page"] -= 1
                    st.rerun()
            with col_page:
                st.markdown(f"<div style='text-align: center; padding-top: 5px; font-weight: bold;'>Trang {st.session_state['current_page']} / {total_pages} (Tổng cộng {total_filtered} sự cố)</div>", unsafe_allow_html=True)
            with col_next:
                if st.button("Trang sau ➡️", disabled=(st.session_state["current_page"] == total_pages), key="btn_next_page"):
                    st.session_state["current_page"] += 1
                    st.rerun()

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
                                " Phê duyệt", key=f"app_{rule.get('pattern')}"
                            ):
                                feedback_mgr.approve_rule(rule.get("pattern"))
                                st.success(f"Đã duyệt luật {rule.get('pattern')}")
                                time.sleep(0.5)
                                st.rerun()
                        with col2:
                            if st.button(
                                " Từ chối", key=f"rej_{rule.get('pattern')}"
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
                    f"Luật đang hoạt động: {rule.get('pattern')} (Mức độ: {rule.get('score')})",
                    expanded=False,
                ):
                    st.write(f"**Trường dữ liệu:** {rule.get('field')}")
                    st.write(f"**Lý do (LLM):** {rule.get('reason')}")
                    st.write(f"**Tạo lúc:** {rule.get('created_at')}")
                    
                    if st.session_state.get("role") == "L3_Manager":
                        if st.button(" Vô hiệu hóa / Hoàn tác", key=f"rev_{rule.get('pattern')}"):
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
                        if st.button(" Gỡ khỏi Whitelist", key=f"rmwl_{ip}"):
                            feedback_mgr.remove_from_whitelist(ip)
                            st.warning(f"Đã gỡ IP {ip} khỏi danh sách Whitelist.")
                            time.sleep(0.5)
                            st.rerun()

    with tab3:
        st.subheader("Giám sát Chuỗi APT & Danh tiếng IP")
        
        # Lấy danh sách IP nguy hiểm từ Long-term Memory
        high_risk_ips = threat_memory.get_high_risk_ips(min_score=1.0)
        high_risk_data = [[r["ip"], r["reputation_score"]] for r in high_risk_ips]
        
        # Lấy danh sách Known Entities nội bộ
        known_entities = threat_memory.get_all_known_entities()
        known_entities_data = [[e["entity_value"], f"{e['entity_type']} - {e['description']}"] for e in known_entities]
        
        # Hiển thị bảng danh tiếng và whitelist
        render_threat_intel_tables(high_risk_data, known_entities_data)
        
        st.markdown("---")
        
        # Lấy và hiển thị chuỗi sự kiện APT (DAPT2020)
        apt_events = threat_memory.get_all_threat_events()
        render_apt_events_table(apt_events)

if __name__ == "__main__":
    main_dashboard()
