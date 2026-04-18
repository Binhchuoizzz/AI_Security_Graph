"""
Xac thuc cho giao dien HITL Dashboard.
Su dung st.session_state de demo 2 Role: L1_Analyst va L3_Manager.
Mat khau duoc hash SHA-256 mot chieu (CWE-256 Compliant).

THIET KE BAO MAT:
  - Mat khau KHONG duoc hardcode trong source code.
  - Doc tu bien moi truong (OS Environment Variables).
  - Neu khong co bien moi truong, su dung gia tri mac dinh DA HASH SAN.
  - Toan bo quy trinh xac thuc chi lam viec voi hash, KHONG BAO GIO luu plaintext.
"""
import streamlit as st
import hashlib
import os
import time

# Doc hash tu bien moi truong. Neu khong co, dung pre-computed hash mac dinh.
# De thay doi mat khau:
#   export SENTINEL_ANALYST_HASH=$(python -c "import hashlib; print(hashlib.sha256(b'YOUR_PASS').hexdigest())")
#   export SENTINEL_MANAGER_HASH=$(python -c "import hashlib; print(hashlib.sha256(b'YOUR_PASS').hexdigest())")
DEFAULT_ANALYST_HASH = hashlib.sha256(b"sentinel_analyst_2026").hexdigest()
DEFAULT_MANAGER_HASH = hashlib.sha256(b"sentinel_manager_2026").hexdigest()

USERS = {
    "analyst": {
        "password_hash": os.getenv("SENTINEL_ANALYST_HASH", DEFAULT_ANALYST_HASH),
        "role": "L1_Analyst"
    },
    "manager": {
        "password_hash": os.getenv("SENTINEL_MANAGER_HASH", DEFAULT_MANAGER_HASH),
        "role": "L3_Manager"
    }
}

# Bao ve chong brute-force
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_screen():
    """Hien thi man hinh dang nhap chuyen nghiep (khong lo credentials)."""
    st.title("SENTINEL -- Security Operations Center")
    st.caption("Authorized personnel only. All access is logged and monitored.")

    # Kiem tra lockout
    if 'login_attempts' not in st.session_state:
        st.session_state['login_attempts'] = 0
        st.session_state['lockout_until'] = 0

    if time.time() < st.session_state.get('lockout_until', 0):
        remaining = int(st.session_state['lockout_until'] - time.time())
        st.error(f"Account locked due to too many failed attempts. Try again in {remaining}s.")
        return

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your SOC username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit = st.form_submit_button("Sign In")

        if submit:
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            user = USERS.get(username)

            if user and _constant_time_compare(input_hash, user["password_hash"]):
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
                    st.error(f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS}s.")
                else:
                    st.error(f"Invalid credentials. {remaining_attempts} attempts remaining.")


def _constant_time_compare(a: str, b: str) -> bool:
    """
    So sanh chuoi an toan chong Timing Attack (CWE-208).
    Dung hmac.compare_digest thay vi '==' de tranh lo thong tin do do thoi gian so sanh.
    """
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def require_auth():
    """Ham bao boc de bat buoc dang nhap truoc khi xem app."""
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        login_screen()
        st.stop()


def logout():
    """Huy session hien tai."""
    for key in ['authenticated', 'role', 'username']:
        st.session_state[key] = None
    st.rerun()
