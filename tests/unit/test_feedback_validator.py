"""
Unit Tests for FeedbackValidator
"""

from src.guardrails.feedback_validator import FeedbackValidator


def test_feedback_validator_rule():
    validator = FeedbackValidator()
    # Quy tắc hợp lệ
    v1, err1 = validator.validate_rule("src_ip", "192.168.1.100", 80)
    assert v1 is True

    # Chặn quy tắc wildcard
    v2, err2 = validator.validate_rule("src_ip", "0.0.0.0/0", 80)
    assert v2 is False
    assert any("Wildcard" in e for e in err2)

    # Chặn hành vi tự chặn SOC host
    v3, err3 = validator.validate_rule("src_ip", "10.0.0.99", 100)
    assert v3 is False
    assert any("critical" in e.lower() for e in err3)


def test_feedback_validator_whitelist_ip():
    validator = FeedbackValidator()
    # Whitelist HOST cụ thể ở BẤT KỲ dải nào đều hợp lệ (mọi luồng demo/vận hành):
    for ip in ["192.168.1.200", "8.8.8.8", "198.51.100.113", "203.0.113.5", "209.147.138.11"]:
        ok, _ = validator.validate_whitelist_ip(ip)
        assert ok is True, f"host {ip} phải whitelist được"

    # CHẶN wildcard toàn Internet
    v_wild, err_wild = validator.validate_whitelist_ip("0.0.0.0/0")
    assert v_wild is False
    assert any("wildcard" in e.lower() for e in err_wild)

    # CHẶN dải CIDR quá rộng (prefix < /16)
    v_big, err_big = validator.validate_whitelist_ip("8.0.0.0/8")
    assert v_big is False
    assert any("quá rộng" in e.lower() or "/16" in e for e in err_big)

    # CHO phép dải nhỏ (/24) và host /32
    ok_small, _ = validator.validate_whitelist_ip("203.0.113.0/24")
    assert ok_small is True

    # Định dạng sai -> reject
    v_bad, _ = validator.validate_whitelist_ip("not-an-ip")
    assert v_bad is False


def test_feedback_validator_invalid_regex():
    validator = FeedbackValidator()
    # Thử truyền regex sai cú pháp cho trường URI
    v1, err1 = validator.validate_rule("URI", "[invalid-regex", 50)
    assert v1 is False
    assert any("Invalid regex syntax" in e for e in err1)

    # Thử truyền regex đúng cú pháp cho trường URI
    v2, err2 = validator.validate_rule("URI", "^/admin/.*$", 50)
    assert v2 is True


def test_score_out_of_range():
    validator = FeedbackValidator()
    # score = -1 phải bị reject
    v1, err1 = validator.validate_rule("src_ip", "192.168.1.100", -1)
    assert v1 is False
    assert any("must be clamped between 0 and 100" in e for e in err1)

    # score = 101 phải bị reject
    v2, err2 = validator.validate_rule("src_ip", "192.168.1.100", 101)
    assert v2 is False
    assert any("must be clamped between 0 and 100" in e for e in err2)


def test_cidr_too_broad():
    validator = FeedbackValidator()
    # CIDR quá rộng /4 (prefix < 8) phải bị reject
    v1, err1 = validator.validate_rule("src_ip", "1.0.0.0/4", 80)
    assert v1 is False
    assert any("too broad" in e for e in err1)

    # CIDR /8 phải hợp lệ
    v2, err2 = validator.validate_rule("src_ip", "10.0.0.0/8", 80)
    assert v2 is True
