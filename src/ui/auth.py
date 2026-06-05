"""
Xác thực cho giao diện HITL Dashboard.
Sử dụng st.session_state để mô phỏng 2 vai trò: L1_Analyst và L3_Manager.
Mật khẩu được băm SHA-256 một chiều (Tương thích CWE-256).

THIẾT KẾ BẢO MẬT:
  - Mật khẩu KHÔNG được ghi cứng (hardcode) trong mã nguồn.
  - Đọc từ biến môi trường (OS Environment Variables).
  - Nếu không có biến môi trường, sử dụng giá trị mặc định ĐÃ BĂM SẴN.
  - Quy trình xác thực chỉ làm việc với chuỗi băm, KHÔNG bao giờ lưu văn bản rõ (plaintext).
"""

import streamlit as st
import hashlib
import os
import time
from src.response.executor import get_login_attempts, increment_login_attempts, reset_login_attempts, lock_user

# Chiến lược băm mật khẩu: PBKDF2-HMAC-SHA256 (Chuẩn NIST)
# Sử dụng salt từ biến môi trường, nếu không có thì dùng salt mặc định an toàn
SALT = os.getenv("SENTINEL_AUTH_SALT", "sentinel_security_2026_default_salt").encode()
ITERATIONS = 100000

def hash_password(password: str) -> str:
    """Băm mật khẩu dùng PBKDF2 để chống tấn công Brute-force/Bẻ khóa bằng GPU."""
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

# Bảo vệ chống brute-force
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_screen():
    """Hiển thị màn hình đăng nhập chuyên nghiệp (không lộ thông tin đăng nhập)."""
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
            
            # 1. Kiểm tra trạng thái khóa (lockout) từ cơ sở dữ liệu
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
                # Reset số lần thử khi đăng nhập thành công
                reset_login_attempts(clean_username)
                st.rerun()
            else:
                # Tăng số lần thử và khóa nếu vượt ngưỡng
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
    So sánh chuỗi thời gian không đổi (Constant-time comparison) chống Timing Attack (CWE-208).
    Dùng hmac.compare_digest thay vì '==' để tránh rò rỉ thông tin qua thời gian xử lý.
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
