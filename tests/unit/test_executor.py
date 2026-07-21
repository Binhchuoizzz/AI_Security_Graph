"""
Unit Tests for Executor Module (Action Validation, Audit Trail Integrity, Login Lockout)
"""

import sqlite3
import time

import pytest  # type: ignore

import src.response.executor as executor
from src.response.executor import (
    ActionValidator,
    block_ip,
    get_audit_trail,
    get_audit_trail_for_ip,
    get_login_attempts,
    increment_login_attempts,
    lock_user,
    raise_alert,
    reset_login_attempts,
    verify_audit_trail_integrity,
)


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path, monkeypatch):
    """CÔ LẬP audit DB VÀ threat_memory DB vào file TẠM — tuyệt đối KHÔNG đụng
    config/audit_trail.db & config/threat_memory.db production. raise_alert/block_ip
    lazy-import singleton `threat_memory` MỖI lần gọi nên monkeypatch module-attr là đủ."""
    test_db = str(tmp_path / "audit_test.db")
    monkeypatch.setattr(executor, "DB_PATH", test_db)
    executor._init_db()

    import src.agent.threat_memory as tm_mod

    fresh_tm = tm_mod.ThreatMemoryStore(db_path=str(tmp_path / "threat_memory_test.db"))
    monkeypatch.setattr(tm_mod, "threat_memory", fresh_tm)
    yield


def test_action_validator_allowed_actions():
    assert ActionValidator.validate_action("BLOCK_IP") is True
    # QUARANTINE đã bị gỡ khỏi kiến trúc Two-Tier (không còn mock EDR) -> KHÔNG hợp lệ nữa.
    assert ActionValidator.validate_action("QUARANTINE") is False
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
    raise_alert("High memory usage", "Possible DoS")

    trail = get_audit_trail(limit=10)
    assert len(trail) == 2

    # Order is DESC, so raise_alert is first
    assert trail[0]["action"] == "ALERT"
    assert trail[0]["target"] == "High memory usage"

    assert trail[1]["action"] == "BLOCK_IP"
    assert trail[1]["target"] == "10.0.0.5"


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
        conn.execute(
            "UPDATE audit_trail SET reason = 'Modified reason' WHERE id = (SELECT min(id) FROM audit_trail)"
        )
        conn.commit()

    is_valid, msg = verify_audit_trail_integrity()
    assert is_valid is False
    assert "giả mạo" in msg.lower() or "tamper" in msg.lower() or "chèn" in msg.lower()


def test_raise_alert_first_time_returns_alert():
    """Lần đầu một IP bị CẢNH BÁO -> action='ALERT', ghi audit ALERT + tăng total_alerts."""
    action = raise_alert("203.0.113.7", "Anomaly rủi ro trung bình")
    assert action == "ALERT"
    trail = get_audit_trail(limit=5)
    assert trail[0]["action"] == "ALERT"
    assert trail[0]["target"] == "203.0.113.7"

    import src.agent.threat_memory as tm_mod

    rep = tm_mod.threat_memory.get_ip_reputation("203.0.113.7")
    assert rep is not None and rep["total_alerts"] == 1


def test_raise_alert_repeat_offender_escalates_to_block():
    """IP đã ALERT 1 lần -> lần ALERT thứ 2 TỰ LEO THANG thành BLOCK_IP (repeat-offender)."""
    ip = "203.0.113.8"
    first = raise_alert(ip, "Cảnh báo lần 1")
    assert first == "ALERT"

    second = raise_alert(ip, "Cảnh báo lần 2 — cùng IP")
    assert second == "BLOCK_IP"

    # Audit gần nhất phải là BLOCK_IP cho đúng IP; reputation đẩy lên known-bad (=100).
    trail = get_audit_trail_for_ip(ip, limit=5)
    assert trail[0]["action"] == "BLOCK_IP"

    import src.agent.threat_memory as tm_mod

    rep = tm_mod.threat_memory.get_ip_reputation(ip)
    assert rep is not None and rep["reputation_score"] >= 100.0


def test_raise_alert_whitelisted_ip_never_escalates(monkeypatch):
    """IP whitelist: dù đã cảnh báo trước vẫn CHỈ ALERT, KHÔNG bao giờ auto-block."""
    ip = "10.0.0.99"
    monkeypatch.setattr(executor, "_whitelisted_ips", lambda: frozenset({ip}))
    assert raise_alert(ip, "lần 1") == "ALERT"
    assert raise_alert(ip, "lần 2") == "ALERT"


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
    lock_user(username, 5)  # Lock for 5 seconds
    attempts, lockout = get_login_attempts(username)
    assert attempts == 5
    assert lockout > time.time()

    # Reset
    reset_login_attempts(username)
    attempts, lockout = get_login_attempts(username)
    assert attempts == 0
    assert lockout == 0.0


# ==============================================================================
# TÁI PHẠM — chỉ CẢNH BÁO ĐỦ MẠNH mới được tích luỹ thành lệnh chặn
# ==============================================================================
def test_weak_alert_does_not_feed_repeat_offender_counter():
    """Cảnh báo YẾU (dải ALERT của Cổng ML, 0.40–0.65) KHÔNG bao giờ tự leo thang thành chặn.

    HỒI QUY LỖI THẬT: đo trên demo 5.000 sự kiện, dải ALERT yếu chỉ chính xác 5,21%; nạp
    vào luật tái phạm khiến 10 IP LÀNH TÍNH bị chặn và KHÔNG bắt đúng ca nào (0/10).
    """
    ip = "203.0.113.90"
    assert raise_alert(ip, "ML yếu lần 1", confidence=0.45) == "ALERT"
    assert raise_alert(ip, "ML yếu lần 2", confidence=0.50) == "ALERT"
    assert raise_alert(ip, "ML yếu lần 3", confidence=0.62) == "ALERT"

    import src.agent.threat_memory as tm_mod

    rep = tm_mod.threat_memory.get_ip_reputation(ip)
    # Không có cảnh báo nào được tính -> không có IP nào bị chặn oan.
    assert rep is None or int(rep["total_alerts"]) == 0


def test_strong_alert_still_escalates_on_repeat():
    """Cảnh báo MẠNH (>= 0.65, gồm mọi ALERT của LLM) VẪN leo thang — không làm hỏng tính năng."""
    ip = "203.0.113.91"
    assert raise_alert(ip, "mạnh lần 1", confidence=0.70) == "ALERT"
    assert raise_alert(ip, "mạnh lần 2", confidence=0.80) == "BLOCK_IP"


def test_unknown_confidence_preserves_legacy_behaviour():
    """confidence=None (caller chưa cập nhật) -> giữ nguyên hành vi cũ, không đổi ngầm."""
    ip = "203.0.113.92"
    assert raise_alert(ip, "không rõ độ tin cậy lần 1") == "ALERT"
    assert raise_alert(ip, "không rõ độ tin cậy lần 2") == "BLOCK_IP"


def test_weak_alert_still_recorded_in_audit_trail():
    """Cảnh báo yếu VẪN phải vào audit trail — không tính tái phạm ≠ giấu khỏi analyst."""
    ip = "203.0.113.93"
    raise_alert(ip, "cảnh báo yếu cần analyst thấy", confidence=0.42)
    trail = get_audit_trail_for_ip(ip, limit=5)
    assert trail and trail[0]["action"] == "ALERT"
