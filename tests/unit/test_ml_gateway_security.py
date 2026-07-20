"""Unit tests cho LỚP BẢO MẬT Cổng ML (chống né-tránh / evasion).

Bối cảnh: Cổng ML (Tier-1, LightGBM) là bộ RA QUYẾT ĐỊNH tự động (auto BLOCK_IP). Khác
với LLM có cả rừng guardrail, ML gate trước đây KHÔNG có phòng thủ nào — kẻ tấn công bơm
Inf/NaN hoặc giá trị cực đoan để né ML block hoặc lật nhãn. Ba tuyến phòng thủ:
  1. Sanitize NaN/±Inf -> mean (không để scaler raise).
  2. Clamp z-score về ±CLIP_SIGMA (1 feature cực đoan không chi phối dự đoán).
  3. OOD abstain khi quá nhiều feature lệch -> trả None (escalate LLM), không tin ML.

Bất biến QUAN TRỌNG: trên input SẠCH, phòng thủ KHÔNG được kích hoạt (giữ bypass rate).
"""

import json
import os

import pytest  # type: ignore

from experiments.unified_dataset import map_cicids
from src.tier1_filter.ml_gateway import CLIP_SIGMA, OOD_FRACTION, MLGateway

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")

_MODEL_PATH = os.path.join(ROOT, "ml_lab", "tier_2_model.pkl")
pytestmark = pytest.mark.skipif(
    not os.path.exists(_MODEL_PATH), reason="ml_lab/tier_2_model.pkl không có (binary gitignore)"
)


@pytest.fixture(scope="module")
def gateway():
    return MLGateway()


@pytest.fixture(scope="module")
def clean_flow():
    """1 flow THẬT có đủ feature số từ ground_truth (map sang schema CICIDS)."""
    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    sample = next(s for s in gt if s.get("input", {}).get("network_layer"))
    return map_cicids(sample["input"]["network_layer"])


def test_clean_input_does_not_trigger_defenses(gateway, clean_flow):
    """Input SẠCH: KHÔNG sanitize, KHÔNG clamp, KHÔNG abstain (giữ nguyên bypass)."""
    action, _reason, conf, sec = gateway.evaluate_detailed(clean_flow)
    assert sec["sanitized"] == 0
    assert sec["clamped"] == 0
    assert sec["ood_abstain"] is False
    # Flow thật đủ đặc trưng -> ML vẫn ra quyết định (không bị phòng thủ chặn nhầm).
    # 4 dải mới: BLOCK_IP / ALERT / DROP (log sạch); ESCALATE trả None.
    assert action in ("BLOCK_IP", "ALERT", "DROP", None) or conf == 0.0


def test_infinity_is_sanitized_not_crash(gateway, clean_flow):
    """Bơm 'Infinity' vào feature: scaler KHÔNG raise, được sanitize, pipeline vẫn chạy."""
    evil = dict(clean_flow)
    evil["Flow Duration"] = "Infinity"
    action, _reason, _conf, sec = gateway.evaluate_detailed(evil)
    assert sec["sanitized"] >= 1
    assert sec["reason"] != "scale_error"  # không vỡ ở bước scale
    # Kết quả vẫn hợp lệ (một action hoặc abstain=None), KHÔNG ném exception.
    assert action in ("BLOCK_IP", "ALERT", "DROP", None)


def test_nan_is_sanitized(gateway, clean_flow):
    evil = dict(clean_flow)
    evil["Total Fwd Packets"] = float("nan")
    _action, _reason, _conf, sec = gateway.evaluate_detailed(evil)
    assert sec["sanitized"] >= 1


def test_single_extreme_feature_is_clamped(gateway, clean_flow):
    """1 feature giá trị cực đoan -> bị CLAMP (không lật được nhãn của flow tấn công rõ)."""
    evil = dict(clean_flow)
    evil["Total Length of Bwd Packets"] = 1e18
    _action, _reason, _conf, sec = gateway.evaluate_detailed(evil)
    assert sec["clamped"] >= 1


def test_broad_extreme_input_triggers_ood_abstain(gateway, clean_flow):
    """Bơm cực đoan HÀNG LOẠT feature (đối kháng) -> OOD abstain -> trả None (escalate LLM)."""
    evil = dict(clean_flow)
    n = 0
    for k, v in list(clean_flow.items()):
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            evil[k] = 1e15
            n += 1
    assert n >= 5, "flow test cần đủ feature số để mô phỏng đối kháng rộng"
    action, _reason, _conf, sec = gateway.evaluate_detailed(evil)
    assert sec["ood_fraction"] > OOD_FRACTION
    assert sec["ood_abstain"] is True
    assert action is None  # KHÔNG tin ML -> escalate LLM


def test_clamp_sigma_bounds_are_sane():
    """Ngưỡng phòng thủ phải hợp lý (không quá chặt làm hỏng data sạch)."""
    assert CLIP_SIGMA >= 5.0
    assert 0.1 < OOD_FRACTION < 0.6


def test_evaluate_wrapper_returns_three_tuple(gateway, clean_flow):
    """evaluate() (subscriber gọi) vẫn giữ chữ ký 3-tuple sau khi thêm bảo mật."""
    out = gateway.evaluate(clean_flow)
    assert isinstance(out, tuple) and len(out) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
