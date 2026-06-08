"""
Unit Tests for DecisionValidator
"""

import pytest
from src.guardrails.decision_validator import DecisionValidator


def test_decision_validator_allowed_actions():
    validator = DecisionValidator()
    # Khớp action hợp lệ
    d1 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "1.2.3.4"}
    res1 = validator.validate_decision(d1)
    assert res1["action"] == "BLOCK_IP"
    
    # Action lạ phải chuyển thành AWAIT_HITL
    d2 = {"action": "HACK_BACK", "confidence": 0.9, "target": "1.2.3.4"}
    res2 = validator.validate_decision(d2)
    assert res2["action"] == "AWAIT_HITL"


def test_decision_validator_confidence_gate():
    validator = DecisionValidator()
    # Confidence thấp (< 0.5) phải hạ cấp xuống AWAIT_HITL
    d = {"action": "BLOCK_IP", "confidence": 0.4, "target": "1.2.3.4"}
    res = validator.validate_decision(d)
    assert res["action"] == "AWAIT_HITL"


def test_decision_validator_critical_shield():
    validator = DecisionValidator()
    # Chặn localhost hoặc SOC host phải chuyển thành ALERT
    d1 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "127.0.0.1"}
    res1 = validator.validate_decision(d1)
    assert res1["action"] == "ALERT"

    d2 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "10.0.0.99"}
    res2 = validator.validate_decision(d2)
    assert res2["action"] == "ALERT"

    # Kiểm tra chặn dải CIDR chồng lấn với subnet tin cậy (Self-DoS Prevention)
    d3 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "10.0.0.0/24"}
    res3 = validator.validate_decision(d3)
    assert res3["action"] == "ALERT"

    # Kiểm tra chặn IP được biểu diễn ở dạng Hex (0x7f000001 = 127.0.0.1)
    d4 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "0x7f000001"}
    res4 = validator.validate_decision(d4)
    assert res4["action"] == "ALERT"

    # Kiểm tra chặn IP dạng Integer (2130706433 = 127.0.0.1)
    d5 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "2130706433"}
    res5 = validator.validate_decision(d5)
    assert res5["action"] == "ALERT"

    # Kiểm tra chặn IP dạng Octal (017700000001 = 127.0.0.1)
    d6 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "017700000001"}
    res6 = validator.validate_decision(d6)
    assert res6["action"] == "ALERT"


def test_decision_validator_reasoning_sanitization():
    validator = DecisionValidator()
    d = {
        "action": "ALERT",
        "confidence": 0.8,
        "target": "1.2.3.4",
        "reasoning": "Attempting image leak ![leak](http://evil.com/x.jpg)",
        "mitre_technique": "T1046 <script>alert(1)</script>"
    }
    res = validator.validate_decision(d)
    assert "evil.com" not in res["reasoning"]
    assert "[IMG_STRIPPED]" in res["reasoning"]
    assert "[SCRIPT_STRIPPED]" in res["mitre_technique"]
