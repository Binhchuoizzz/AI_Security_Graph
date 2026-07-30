"""
Automated AI Red Teaming: Adversarial ML Evasion Benchmark
==========================================================
Kiểm thử tính năng Anti-Evasion / Out-of-Distribution Guardrail của Tier 1 ML Gateway
trước các mẫu tấn công làm trễ/gây nhiễu đặc trưng (Feature Perturbation).
"""

import pytest

from src.tier1_filter.ml_gateway import MLGateway


def test_redteam_adversarial_feature_evasion_triggers_abstain():
    """Kiểm tra nếu kẻ tấn công chèn nhiễu z-score cực đoan (>30% features >6σ) -> ML Gateway từ chối phán quyết (Abstain) và đẩy lên LLM."""
    engine = MLGateway()

    if not engine.pipeline:
        pytest.skip("LightGBM model not loaded")

    # Giả lập log chứa 35% ô bị nhiễu cực đoan không thể parse float
    features = engine.pipeline.get("features", [])
    adversarial_log = {"Flow Duration": "1000", "Total Fwd Packets": "500", "Flow Pkts/s": "100"}

    # Bơm 35% ô đặc trưng bất thường
    for f_name in features[: int(len(features) * 0.35)]:
        adversarial_log[f_name] = "999999999_INF_INVALID"

    action, reasoning, confidence, sec = engine.evaluate_detailed(adversarial_log)

    # Nếu n_sanitized hoặc low coverage -> sec['skipped'] là True (escalate LLM / None action)
    assert action is None or sec.get("ood_abstain") is True or sec.get("skipped") is True
    assert sec.get("sanitized", 0) > 0
