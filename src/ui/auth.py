"""
Xác thực cho giao diện HITL Dashboard.
Sử dụng st.session_state để mô phỏng 2 vai trò: L1_Analyst và L3_Manager.
Mật khẩu được băm PBKDF2-HMAC-SHA256 (Tương thích CWE-916 & CWE-259).

THIẾT KẾ BẢO MẬT:
  - KHÔNG ghi cứng mật khẩu DẠNG RÕ (plaintext) trong mã nguồn (CWE-798): chỉ lưu
    HASH đã tính sẵn. Mật khẩu rõ của bộ demo nằm trong tài liệu triển khai
    (docs/guides/RUN_PROJECT.md), KHÔNG nằm trong source.
  - Ưu tiên đọc HASH + SALT từ biến môi trường (OS Environment Variables).
  - Khi rơi về HASH/SALT demo mặc định -> CẢNH BÁO rõ ràng (không dùng cho production).
  - Quy trình xác thực chỉ làm việc với chuỗi băm, KHÔNG bao giờ lưu văn bản rõ.
"""

import hashlib
import hmac
import logging
import os
import re
import time

import streamlit as st  # type: ignore

from src.response.executor import (
    get_login_attempts,
    increment_login_attempts,
    lock_user,
    reset_login_attempts,
)

logger = logging.getLogger(__name__)

# Chiến lược băm mật khẩu: PBKDF2-HMAC-SHA256 (Chuẩn NIST SP 800-132)
# SALT đọc từ biến môi trường; salt demo mặc định CHỈ để chạy thử ngay được.
_DEFAULT_DEMO_SALT = "sentinel_security_2026_default_salt"
SALT = os.getenv("SENTINEL_AUTH_SALT", _DEFAULT_DEMO_SALT).encode()
ITERATIONS = 100000


def hash_password(password: str) -> str:
    """Băm mật khẩu dùng PBKDF2 để chống tấn công Brute-force/Bẻ khóa bằng GPU."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, ITERATIONS).hex()


# HASH DEMO TÍNH SẴN (PBKDF2-HMAC-SHA256, salt demo mặc định, 100k vòng).
# KHÔNG còn plaintext password trong source. Mật khẩu rõ của bộ demo được tài liệu
# hóa riêng trong RUN_PROJECT.md; production PHẢI đặt SENTINEL_*_HASH + SENTINEL_AUTH_SALT.
_DEFAULT_ANALYST_HASH = "0999ca36c62e69601515210699602ce665f6ff1ffd452fcd136d351b73fb86fb"
_DEFAULT_MANAGER_HASH = "edf6fd717ffe8e326b1d4becb7e22a4f0781c81cb1b7cd419944c2be530207d1"

USERS = {
    "analyst": {
        "password_hash": os.getenv("SENTINEL_ANALYST_HASH", _DEFAULT_ANALYST_HASH),
        "role": "L1_Analyst",
    },
    "manager": {
        "password_hash": os.getenv("SENTINEL_MANAGER_HASH", _DEFAULT_MANAGER_HASH),
        "role": "L3_Manager",
    },
}

# Fail-loud: nếu đang chạy bằng HASH/SALT demo (chưa cấu hình env) -> cảnh báo để
# người triển khai biết KHÔNG được dùng cấu hình này cho môi trường thật.
if (
    SALT == _DEFAULT_DEMO_SALT.encode()
    or USERS["analyst"]["password_hash"] == _DEFAULT_ANALYST_HASH
    or USERS["manager"]["password_hash"] == _DEFAULT_MANAGER_HASH
):
    logger.warning(
        "[AUTH] Đang dùng thông tin đăng nhập DEMO mặc định. Production PHẢI đặt "
        "SENTINEL_AUTH_SALT + SENTINEL_ANALYST_HASH + SENTINEL_MANAGER_HASH."
    )

# Bảo vệ chống brute-force
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def login_screen():
    """Hiển thị màn hình đăng nhập chuyên nghiệp (không lộ thông tin đăng nhập)."""
    st.title("🛡️ SENTINEL - Trung tâm Giám sát An ninh SOC")
    st.caption(
        "Chỉ dành cho nhân viên SOC được ủy quyền. Mọi hoạt động truy cập đều được ghi nhật ký và giám sát."
    )

    with st.form("login_form"):
        username = st.text_input("Tên đăng nhập", placeholder="Nhập tài khoản SOC của bạn")
        password = st.text_input("Mật khẩu", type="password", placeholder="Nhập mật khẩu của bạn")
        submit = st.form_submit_button("Đăng nhập")

        if submit:
            clean_username = username.strip()
            clean_password = password.strip()

            # Xác thực định dạng tài khoản tránh chèn ký tự lạ (Input Injection Prevention)
            if not re.match(r"^[a-zA-Z0-9_]{1,30}$", clean_username):
                st.error(
                    "Tên đăng nhập không hợp lệ (chỉ chấp nhận chữ cái, "
                    "chữ số và dấu gạch dưới, tối đa 30 ký tự)."
                )
                return

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
