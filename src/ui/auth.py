"""
Xác thực cơ bản cho giao diện HITL Dashboard.
Sử dụng st.session_state để demo 2 Role: L1_Analyst và L3_Manager.
"""
import streamlit as st

def login_screen():
    """Hiển thị màn hình đăng nhập giả lập."""
    st.title("🔐 SENTINEL Đăng nhập")
    
    st.markdown("""
    **Demo Credentials:**
    - L1 Analyst (Chỉ xem): `analyst` / `password`
    - L3 Manager (Được duyệt Rule): `manager` / `password`
    """)

    import hashlib

    # Demo Credentials (Hashed with SHA-256 for Security Hardening)
    # Plain: "password"
    DEMO_PASSWORD_HASH = hashlib.sha256("password".encode()).hexdigest()

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Đăng nhập")

        if submit:
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if username == "analyst" and input_hash == DEMO_PASSWORD_HASH:
                st.session_state['authenticated'] = True
                st.session_state['role'] = 'L1_Analyst'
                st.session_state['username'] = username
                st.rerun()
            elif username == "manager" and input_hash == DEMO_PASSWORD_HASH:
                st.session_state['authenticated'] = True
                st.session_state['role'] = 'L3_Manager'
                st.session_state['username'] = username
                st.rerun()
            else:
                st.error("Sai thông tin đăng nhập!")

def require_auth():
    """Hàm bao bọc để bắt buộc đăng nhập trước khi xem app."""
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        login_screen()
        st.stop()  # Dừng việc render các thành phần bên dưới
        
def logout():
    """Hủy session hiện tại."""
    st.session_state['authenticated'] = False
    st.session_state['role'] = None
    st.session_state['username'] = None
    st.rerun()
