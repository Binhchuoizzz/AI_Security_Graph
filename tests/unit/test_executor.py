"""
Unit Tests for Executor Module (Action Validation, Audit Trail Integrity, Login Lockout)
"""

import pytest # type: ignore
import sqlite3
import time

import src.response.executor as executor
from src.response.executor import (
    block_ip,
    quarantine_host,
    raise_alert,
    get_audit_trail,
    get_audit_trail_for_ip,
    verify_audit_trail_integrity,
    get_login_attempts,
    increment_login_attempts,
    reset_login_attempts,
    lock_user,
    ActionValidator,
)


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path, monkeypatch):
    """CÔ LẬP audit DB vào file TẠM — tuyệt đối KHÔNG đụng config/audit_trail.db
    production (trước đây fixture xóa thẳng bảng trên DB thật -> chạy pytest là
    trắng audit demo). Mọi hàm executor đọc DB_PATH module-global tại call-time
    nên monkeypatch là đủ."""
    test_db = str(tmp_path / "audit_test.db")
    monkeypatch.setattr(executor, "DB_PATH", test_db)
    executor._init_db()
    yield


def test_action_validator_allowed_actions():
    assert ActionValidator.validate_action("BLOCK_IP") is True
    assert ActionValidator.validate_action("QUARANTINE") is True
    assert ActionValidator.validate_action("INVALID_ACTION") is False


def test_action_validator_sanitize_target():
    # Normal target should remain untouched
    assert ActionValidator.sanitize_target("192.168.1.1") == "192.168.1.1"
    
    # Target containing command injection patterns should be sanitized (characters stripped)
    dangerous = "192.168.1.1; rm -rf /"
    sanitized = ActionValidator.sanitize_target(dangerous)
    assert ";" not in sanitized
    assert " " in sanitized


def test_action_validator_sanitize_reason():
    # Normal reason should remain untouched
    assert ActionValidator.sanitize_reason("Port scanning detected") == "Port scanning detected"
    
    # Dangerous pattern in reason should be sanitized
    dangerous = "Detected anomaly & EDR alert | shutdown"
    sanitized = ActionValidator.sanitize_reason(dangerous)
    assert "|" not in sanitized


def test_logging_actions_to_db():
    block_ip("10.0.0.5", "Malicious activity")
    quarantine_host("host-xyz", "Compromised credential")
    raise_alert("High memory usage", "Possible DoS")

    trail = get_audit_trail(limit=10)
    assert len(trail) == 3
    
    # Order is DESC, so raise_alert is first
    assert trail[0]["action"] == "ALERT"
    assert trail[0]["target"] == "High memory usage"
    
    assert trail[1]["action"] == "QUARANTINE"
    assert trail[1]["target"] == "host-xyz"

    assert trail[2]["action"] == "BLOCK_IP"
    assert trail[2]["target"] == "10.0.0.5"


def test_get_audit_trail_for_ip():
    block_ip("192.168.1.50", "Port scan")
    block_ip("192.168.1.60", "Brute force")
    
    trail = get_audit_trail_for_ip("192.168.1.50")
    assert len(trail) == 1
    assert trail[0]["target"] == "192.168.1.50"
    assert trail[0]["reason"] == "Port scan"


def test_audit_trail_integrity_verification():
    # Write some logs
    block_ip("192.168.1.1", "Initial compromise")
    block_ip("192.168.1.2", "Lateral movement")
    
    is_valid, msg = verify_audit_trail_integrity()
    assert is_valid is True
    assert "toàn vẹn" in msg.lower() or "integrity" in msg.lower()

    # Tamper with the database manually to simulate log tampering
    with sqlite3.connect(executor.DB_PATH) as conn:
        conn.execute("UPDATE audit_trail SET reason = 'Modified reason' WHERE id = (SELECT min(id) FROM audit_trail)")
        conn.commit()

    is_valid, msg = verify_audit_trail_integrity()
    assert is_valid is False
    assert "giả mạo" in msg.lower() or "tamper" in msg.lower() or "chèn" in msg.lower()


def test_login_attempts_and_lockout():
    username = "test_analyst"
    
    # Initially 0 attempts
    attempts, lockout = get_login_attempts(username)
    assert attempts == 0
    assert lockout == 0.0
    
    # Increment
    assert increment_login_attempts(username) == 1
    attempts, lockout = get_login_attempts(username)
    assert attempts == 1
    
    # Lock user
    lock_user(username, 5) # Lock for 5 seconds
    attempts, lockout = get_login_attempts(username)
    assert attempts == 5
    assert lockout > time.time()
    
    # Reset
    reset_login_attempts(username)
    attempts, lockout = get_login_attempts(username)
    assert attempts == 0
    assert lockout == 0.0
