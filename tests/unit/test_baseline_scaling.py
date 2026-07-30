"""Test biến đổi log1p cho baseline Welford (`rule_engine.scale_feature`).

Log-transform chỉ ĐÚNG khi áp NHẤT QUÁN ở cả hai phía (học baseline + tính Z). Các test
dưới khoá lại đúng những tính chất đó, và chốt an toàn từ chối baseline thang cũ.
"""

import math

import pytest

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


# ── Hồi quy: đường CẬP NHẬT ONLINE phải ở CÙNG thang với đường TÍNH Z ────────────────
# Các test trên chỉ soi `scale_feature` biệt lập nên KHÔNG bắt được lỗi thật đã xảy ra:
# `RuleEngine.evaluate()` push giá trị THÔ vào baseline vốn học ở thang log1p. Hai test
# dưới đi qua evaluate() thật — đó là nơi lỗi sống.


def _engine_with_empty_stats():
    """RuleEngine với Welford RỖNG (bỏ seed golden) để quan sát riêng đường học online."""
    from src.tier1_filter.rule_engine import RuleEngine

    engine = RuleEngine()
    for k in engine.global_stats:
        engine.global_stats[k] = RunningStats()
    return engine


def test_evaluate_updates_baseline_in_log_space():
    """Log benign đi qua evaluate() phải để lại baseline ở THANG LOG, không phải thô."""
    engine = _engine_with_empty_stats()
    duration = 1_000_000.0  # 1s tính bằng micro-giây — giá trị flow đời thật

    for _ in range(20):
        engine.evaluate(
            {
                "Source IP": "10.1.2.3",
                "Destination Port": 443,  # không nhạy cảm -> DROP/LOG -> baseline được học
                "Flow Duration": duration,
                "Total Fwd Packets": 10,
            }
        )

    learned = engine.global_stats["Flow Duration"].mean()
    assert learned == pytest.approx(math.log1p(duration), rel=1e-6), (
        "Baseline online phải học ở thang log1p — push giá trị thô làm phương sai nổ "
        "và mọi Z-score sụp về 0 (hỏng âm thầm, không có exception)."
    )
    assert learned < 20, f"mean={learned} đang ở thang tuyến tính -> Z-score vô nghĩa"


def test_welford_still_flags_outlier_after_learning_benign():
    """Học nền benign rồi thì một outlier cực trị vẫn PHẢI vượt ngưỡng Z.

    Đây chính là hành vi bị lỗi thang đo giết chết: sd nổ 23.000 lần sau vài trăm log
    benign nên zero-day exfil rơi từ Z=4.58 xuống Z=0.07.
    """
    engine = _engine_with_empty_stats()

    # MỖI log một IP khác nhau: baseline chỉ học từ phán quyết DROP/LOG, mà dồn dập cùng
    # một IP sẽ kích "tần suất yêu cầu cao" của SessionBaseline (+20 -> ESCALATE) nên không
    # log nào được học. Nhiều nguồn cũng đúng với cách dựng baseline benign ngoài đời.
    # Phương sai phải THẬT: engine bỏ qua Z khi sd <= 0.01 (dữ liệu phẳng).
    def _log(i, bwd_bytes):
        return {
            "Source IP": f"10.1.{i // 254}.{i % 254}",
            "Destination Port": 443,
            "Total Fwd Packets": 10,
            "Total Length of Bwd Packets": bwd_bytes,
        }

    for i in range(engine.warmup_count + 50):
        engine.evaluate(_log(i, 500.0 + (i % 16) * 500))

    outlier = engine.evaluate(_log(9999, 50_000_000.0))
    assert outlier["tier1_z_score"] > engine.z_threshold, (
        f"Z={outlier['tier1_z_score']:.2f} <= ngưỡng {engine.z_threshold}: Welford đã mù "
        f"với đặc trưng khối lượng — dấu hiệu baseline bị bơm sai thang."
    )
