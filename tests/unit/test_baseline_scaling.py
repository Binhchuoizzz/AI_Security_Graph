"""Test biến đổi log1p cho baseline Welford (`rule_engine.scale_feature`).

Log-transform chỉ ĐÚNG khi áp NHẤT QUÁN ở cả hai phía (học baseline + tính Z). Các test
dưới khoá lại đúng những tính chất đó, và chốt an toàn từ chối baseline thang cũ.
"""

import math

from src.tier1_filter.rule_engine import (
    BASELINE_TRANSFORM_ID,
    LOG_SCALE_FEATURES,
    RunningStats,
    scale_feature,
)


def test_log_scale_features_are_transformed():
    """Đặc trưng đuôi dài -> log1p; log1p(x) = ln(1+x)."""
    for key in LOG_SCALE_FEATURES:
        assert scale_feature(key, 0.0) == 0.0, "log1p(0) phải = 0, không cần epsilon"
        assert scale_feature(key, math.e - 1) == 1.0
        assert scale_feature(key, 999.0) == math.log1p(999.0)


def test_non_log_features_stay_linear():
    """Trường cờ / kích thước giao thức KHÔNG bị log-hoá (bị chặn, không lệch đuôi)."""
    for key in ("PSH Flag Cnt", "Fwd Seg Size Min", "Init Bwd Win Byts", "Bwd Pkt Len Min"):
        assert key not in LOG_SCALE_FEATURES
        assert scale_feature(key, 42.0) == 42.0


def test_negative_values_stay_linear_even_for_log_features():
    """Giá trị âm (dữ liệu bẩn / sentinel -1) giữ tuyến tính vì log1p không xác định ở đó."""
    key = next(iter(LOG_SCALE_FEATURES))
    assert scale_feature(key, -5.0) == -5.0


def test_log_transform_compresses_heavy_tail():
    """Mục đích chính: nén đuôi dài để sd/mean gần 1 hơn (hợp giả định Gauss của Z-score)."""
    raw = [10.0, 20.0, 30.0, 40.0, 5_000_000.0]  # một outlier đuôi phải cực đoan
    key = "Flow Pkts/s"
    lin = RunningStats()
    log = RunningStats()
    for x in raw:
        lin.push(x)
        log.push(scale_feature(key, x))
    cv_lin = lin.std_dev() / lin.mean()
    cv_log = log.std_dev() / log.mean()
    assert cv_log < cv_lin, "log-transform PHẢI kéo hệ số biến thiên xuống"


def test_transform_id_is_stable():
    """Cờ transform ổn định — chốt an toàn của RuleEngine so khớp chuỗi này."""
    assert BASELINE_TRANSFORM_ID == "log1p-v1"
