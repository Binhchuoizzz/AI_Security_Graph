"""
Unit tests — Chính sách độ-tin-cậy THỐNG NHẤT (decision_policy).

Kiểm 4 dải Cổng ML (C>=0.85 BLOCK · 0.65–0.85 ESCALATE · 0.40–0.65 ALERT · <0.40 DROP)
và ánh xạ LLM (>=0.85 BLOCK · 0.65–0.85 ALERT · <0.65 AWAIT_HITL; sạch -> DROP).
"""

from src.guardrails import decision_policy as dp


class TestClassifyML:
    def test_block_band(self):
        assert dp.classify_ml(0.85) == "BLOCK_IP"
        assert dp.classify_ml(0.99) == "BLOCK_IP"

    def test_escalate_band(self):
        assert dp.classify_ml(0.65) == "ESCALATE"
        assert dp.classify_ml(0.84) == "ESCALATE"

    def test_alert_band(self):
        assert dp.classify_ml(0.40) == "ALERT"
        assert dp.classify_ml(0.64) == "ALERT"

    def test_pass_drop_band(self):
        assert dp.classify_ml(0.39) == "DROP"
        assert dp.classify_ml(0.0) == "DROP"

    def test_boundaries_are_inclusive_lower(self):
        # Ranh giới dưới thuộc dải cao hơn (>=).
        assert dp.classify_ml(dp.ML_BLOCK_CONF) == "BLOCK_IP"
        assert dp.classify_ml(dp.ML_ESCALATE_CONF) == "ESCALATE"
        assert dp.classify_ml(dp.ML_ALERT_CONF) == "ALERT"


class TestClassifyLLM:
    def test_clean_verdict_always_drops(self):
        # Log sạch -> DROP bất kể confidence.
        assert dp.classify_llm(is_threat=False, confidence=0.99) == "DROP"
        assert dp.classify_llm(is_threat=False, confidence=0.10) == "DROP"

    def test_threat_block_band(self):
        assert dp.classify_llm(True, 0.85) == "BLOCK_IP"
        assert dp.classify_llm(True, 0.95) == "BLOCK_IP"

    def test_threat_alert_band(self):
        assert dp.classify_llm(True, 0.65) == "ALERT"
        assert dp.classify_llm(True, 0.84) == "ALERT"

    def test_threat_low_conf_goes_hitl(self):
        # Đây chính là ca "0.75 cũ auto-block" -> nay 0.75 = ALERT, còn <0.65 -> người.
        assert dp.classify_llm(True, 0.64) == "AWAIT_HITL"
        assert dp.classify_llm(True, 0.30) == "AWAIT_HITL"

    def test_075_is_alert_not_block(self):
        """Hồi quy trực tiếp cho lỗi '75% đã chặn ở LLM'."""
        assert dp.classify_llm(True, 0.75) == "ALERT"


def test_policy_invariants():
    # alert <= escalate <= block (ML) ; alert <= block (LLM).
    assert dp.ML_ALERT_CONF <= dp.ML_ESCALATE_CONF <= dp.ML_BLOCK_CONF
    assert dp.LLM_ALERT_CONF <= dp.LLM_BLOCK_CONF
