"""
Unit tests cho lớp xác thực Dashboard (PBKDF2-HMAC-SHA256 + constant-time compare).

Chỉ test các hàm thuần (hash/compare/cấu hình RBAC) — KHÔNG test luồng Streamlit UI
(login_screen cần session_state, thuộc phạm vi kiểm thử thủ công/demo).
"""

import pytest  # type: ignore

from src.ui.auth import (
    ITERATIONS,
    MAX_LOGIN_ATTEMPTS,
    USERS,
    _constant_time_compare,
    hash_password,
)


class TestHashPassword:
    def test_deterministic_same_input_same_hash(self):
        assert hash_password("S3cret!") == hash_password("S3cret!")

    def test_different_passwords_different_hashes(self):
        assert hash_password("S3cret!") != hash_password("S3cret?")

    def test_output_is_sha256_hex(self):
        h = hash_password("anything")
        assert len(h) == 64
        int(h, 16)  # hex hợp lệ (raise nếu không)

    def test_plaintext_never_in_hash(self):
        pw = "HanoiAnalyst2026@"
        assert pw not in hash_password(pw)

    def test_iterations_meet_nist_minimum(self):
        # NIST SP 800-132 khuyến nghị >= 10k vòng; project dùng 100k
        assert ITERATIONS >= 100_000


class TestConstantTimeCompare:
    def test_equal_strings_true(self):
        h = hash_password("x")
        assert _constant_time_compare(h, h) is True

    def test_unequal_strings_false(self):
        assert _constant_time_compare(hash_password("x"), hash_password("y")) is False


class TestRBACConfig:
    def test_two_roles_configured(self):
        assert USERS["analyst"]["role"] == "L1_Analyst"
        assert USERS["manager"]["role"] == "L3_Manager"

    def test_stored_credentials_are_hashes_not_plaintext(self):
        for user in USERS.values():
            h = user["password_hash"]
            assert len(h) == 64
            int(h, 16)

    def test_lockout_threshold_sane(self):
        assert 3 <= MAX_LOGIN_ATTEMPTS <= 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
