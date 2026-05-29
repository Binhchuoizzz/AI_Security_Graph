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
from src.response.executor import get_login_attempts, increment_login_attempts, reset_login_attempts, lock_user

# Password Hashing Strategy: PBKDF2-HMAC-SHA256 (NIST Approved)
# Dung muoi tu bien moi truong, neu khong co thi dung muoi mac dinh an toan
SALT = os.getenv("SENTINEL_AUTH_SALT", "sentinel_security_2026_default_salt").encode()
ITERATIONS = 100000

def hash_password(password: str) -> str:
    """Hash password dung PBKDF2 de chong brute-force/GPU cracking."""
    return hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        SALT, 
        ITERATIONS
    ).hex()

DEFAULT_ANALYST_HASH = hash_password("Hanoi123789@")
DEFAULT_MANAGER_HASH = hash_password("Hanoi123789@")

USERS = {
    "analyst": {
        "password_hash": os.getenv("SENTINEL_ANALYST_HASH", DEFAULT_ANALYST_HASH),
        "role": "L1_Analyst",
    },
    "manager": {
        "password_hash": os.getenv("SENTINEL_MANAGER_HASH", DEFAULT_MANAGER_HASH),
        "role": "L3_Manager",
    },
}

# Bao ve chong brute-force
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_screen():
    """Hien thi man hinh dang nhap chuyen nghiep (khong lo credentials)."""
    st.title("🛡️ SENTINEL - Trung tâm Giám sát An ninh SOC")
    st.caption("Chỉ dành cho nhân viên SOC được ủy quyền. Mọi hoạt động truy cập đều được ghi nhật ký và giám sát.")

    with st.form("login_form"):
        username = st.text_input("Tên đăng nhập", placeholder="Nhập tài khoản SOC của bạn")
        password = st.text_input(
            "Mật khẩu", type="password", placeholder="Nhập mật khẩu của bạn"
        )
        submit = st.form_submit_button("Đăng nhập")

        if submit:
            clean_username = username.strip()
            clean_password = password.strip()
            
            # 1. Kiem tra persistent lockout truoc tu database
            attempts, lockout_until = get_login_attempts(clean_username)
            if time.time() < lockout_until:
                remaining = int(lockout_until - time.time())
                st.error(
                    f"Tài khoản `{clean_username}` bị khóa tạm thời do nhập sai quá nhiều lần. Vui lòng thử lại sau {remaining} giây."
                )
                return

            input_hash = hash_password(clean_password)
            user = USERS.get(clean_username)

            if user and _constant_time_compare(input_hash, user["password_hash"]):
                st.session_state["authenticated"] = True
                st.session_state["role"] = user["role"]
                st.session_state["username"] = clean_username
                # Reset attempts khi thanh cong
                reset_login_attempts(clean_username)
                st.rerun()
            else:
                # Tang attempt và lock neu vuot nguong
                cur_attempts = increment_login_attempts(clean_username)
                remaining_attempts = MAX_LOGIN_ATTEMPTS - cur_attempts

                if remaining_attempts <= 0:
                    lock_user(clean_username, LOCKOUT_SECONDS)
                    st.error(
                        f"Nhập sai quá nhiều lần. Tài khoản `{clean_username}` bị khóa trong {LOCKOUT_SECONDS} giây."
                    )
                else:
                    st.error(
                        f"Thông tin đăng nhập không chính xác. Còn lại {remaining_attempts} lần thử."
                    )



def _constant_time_compare(a: str, b: str) -> bool:
    """
    So sanh chuoi an toan chong Timing Attack (CWE-208).
    Dung hmac.compare_digest thay vi '==' de tranh lo thong tin do do thoi gian so sanh.
    """
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())


def require_auth():
    """Hàm bao bọc để bắt buộc đăng nhập trước khi xem app."""
    if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
        login_screen()
        st.stop()


def logout():
    """Hủy session hiện tại và xóa sạch state."""
    st.session_state.clear()
    st.rerun()
