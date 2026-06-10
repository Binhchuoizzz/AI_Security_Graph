"""
Unit Tests for DecisionValidator
"""

import pytest  # type: ignore
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


def test_tier_consensus_guard_blocks_semantic_manipulation():
    """Tier-1 coi là tấn công + LLM hạ xuống LOG/DROP -> buộc AWAIT_HITL."""
    validator = DecisionValidator()
    # LLM bị social-engineering hạ xuống LOG
    for downgraded in ("LOG", "DROP"):
        d = {"action": downgraded, "confidence": 0.4, "target": "45.13.1.1", "reasoning": "Người dùng nói đã được duyệt"}
        res = validator.enforce_tier_consensus(d, tier1_flagged_attack=True)
        assert res["action"] == "AWAIT_HITL"
        assert res.get("_tier_consensus_override") is True


def test_tier_consensus_guard_respects_legit_log():
    """Tier-1 KHÔNG flag tấn công -> LLM nói LOG vẫn được giữ (không override)."""
    validator = DecisionValidator()
    d = {"action": "LOG", "confidence": 0.6, "target": "10.0.0.5"}
    res = validator.enforce_tier_consensus(d, tier1_flagged_attack=False)
    assert res["action"] == "LOG"
    assert "_tier_consensus_override" not in res


def test_tier_consensus_guard_keeps_block_decisions():
    """LLM ra BLOCK_IP/ALERT thì consensus guard không can thiệp."""
    validator = DecisionValidator()
    for act in ("BLOCK_IP", "ALERT", "AWAIT_HITL"):
        d = {"action": act, "confidence": 0.9, "target": "45.13.1.1"}
        res = validator.enforce_tier_consensus(d, tier1_flagged_attack=True)
        assert res["action"] == act


def test_decision_validator_confidence_gate():
    validator = DecisionValidator()
    # Confidence thấp (< 0.5) phải hạ cấp xuống AWAIT_HITL
    d1 = {"action": "BLOCK_IP", "confidence": 0.4, "target": "1.2.3.4"}
    res1 = validator.validate_decision(d1)
    assert res1["action"] == "AWAIT_HITL"

    # Confidence biên (== 0.5) KHÔNG bị hạ cấp
    d2 = {"action": "BLOCK_IP", "confidence": 0.5, "target": "1.2.3.4"}
    res2 = validator.validate_decision(d2)
    assert res2["action"] == "BLOCK_IP"


def test_decision_validator_critical_shield():
    validator = DecisionValidator()
    # Chặn localhost hoặc SOC host phải chuyển thành ALERT
    d1 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "127.0.0.1"}
    res1 = validator.validate_decision(d1)
    assert res1["action"] == "ALERT"

    # IPv6 loopback ::1 cũng phải chuyển thành ALERT
    d_v6 = {"action": "BLOCK_IP", "confidence": 0.9, "target": "::1"}
    res_v6 = validator.validate_decision(d_v6)
    assert res_v6["action"] == "ALERT"

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
