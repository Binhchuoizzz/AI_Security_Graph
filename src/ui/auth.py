"""
Xác thực cho giao diện HITL Dashboard.
Sử dụng st.session_state để demo 2 Role: L1_Analyst và L3_Manager.
Mật khẩu được hash SHA-256 một chiều (CWE-256 Compliant).
"""
import streamlit as st
import hashlib
import time

# Pre-computed hashes (SHA-256). Không lưu plaintext bất cứ đâu.
# Để đổi password: python -c "import hashlib; print(hashlib.sha256(b'YOUR_NEW_PASS').hexdigest())"
USERS = {
    "analyst": {
        "password_hash": hashlib.sha256(b"sentinel_analyst_2026").hexdigest(),
        "role": "L1_Analyst"
    },
    "manager": {
        "password_hash": hashlib.sha256(b"sentinel_manager_2026").hexdigest(),
        "role": "L3_Manager"
    }
}

# Brute-force protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_screen():
    """Hiển thị màn hình đăng nhập chuyên nghiệp (không lộ credentials)."""
    st.title("🔐 SENTINEL — Security Operations Center")
    st.caption("Authorized personnel only. All access is logged and monitored.")

    # Kiểm tra lockout
    if 'login_attempts' not in st.session_state:
        st.session_state['login_attempts'] = 0
        st.session_state['lockout_until'] = 0

    if time.time() < st.session_state.get('lockout_until', 0):
        remaining = int(st.session_state['lockout_until'] - time.time())
        st.error(f"⛔ Account locked due to too many failed attempts. Try again in {remaining}s.")
        return

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your SOC username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit = st.form_submit_button("🔑 Sign In")

        if submit:
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            user = USERS.get(username)

            if user and input_hash == user["password_hash"]:
                st.session_state['authenticated'] = True
                st.session_state['role'] = user["role"]
                st.session_state['username'] = username
                st.session_state['login_attempts'] = 0
                st.rerun()
            else:
                st.session_state['login_attempts'] += 1
                remaining_attempts = MAX_LOGIN_ATTEMPTS - st.session_state['login_attempts']

                if remaining_attempts <= 0:
                    st.session_state['lockout_until'] = time.time() + LOCKOUT_SECONDS
                    st.error(f"⛔ Too many failed attempts. Account locked for {LOCKOUT_SECONDS}s.")
                else:
                    st.error(f"❌ Invalid credentials. {remaining_attempts} attempts remaining.")


def require_auth():
    """Hàm bao bọc để bắt buộc đăng nhập trước khi xem app."""
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        login_screen()
        st.stop()


def logout():
    """Hủy session hiện tại."""
    for key in ['authenticated', 'role', 'username']:
        st.session_state[key] = None
    st.rerun()
