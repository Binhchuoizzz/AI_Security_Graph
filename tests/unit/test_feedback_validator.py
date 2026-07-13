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
    # Whitelist IP nội bộ/tin cậy
    v1, err1 = validator.validate_whitelist_ip("192.168.1.200")
    assert v1 is True

    # Chặn whitelist IP ngoài Internet (ví dụ: public DNS)
    v2, err2 = validator.validate_whitelist_ip("8.8.8.8")
    assert v2 is False
    assert any("allowed whitelist ranges" in e for e in err2)

    # Cho phép whitelist dải TEST-NET tài liệu (RFC 5737) dùng cho demo adversarial
    v3, _ = validator.validate_whitelist_ip("198.51.100.113")
    assert v3 is True
    v4, _ = validator.validate_whitelist_ip("203.0.113.5")
    assert v4 is True

    # Vẫn CHẶN IP công cộng thật (không phải TEST-NET), vd DAPT public IP
    v5, _ = validator.validate_whitelist_ip("209.147.138.11")
    assert v5 is False


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
