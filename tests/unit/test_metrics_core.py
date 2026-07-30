"""Unit tests cho `experiments/metrics_core.py`.

Các test dưới KHOÁ LẠI đúng những tính chất khiến bộ chỉ số mới đáng tin hơn bộ cũ —
đặc biệt là tính chất "một hệ đoán một lớp phải bị chấm 0", thứ mà Accuracy và F1 không
làm được và là lý do luận văn từng có những con số đẹp vô nghĩa.
"""

import math

import pytest

import experiments.metrics_core as mc
from experiments.metrics_core import (
    alert_burden,
    balanced_accuracy,
    bootstrap_ci,
    cohens_kappa,
    confusion_report,
    evidence_grounding,
    evidence_grounding_rate,
    majority_baseline,
    mcc,
    per_class_report,
    resource_cost,
    throughput,
    weakest_classes,
    wilson_ci,
)

# ==============================================================================
# MCC — tính chất khiến nó thay được Accuracy
# ==============================================================================


def test_mcc_zero_for_always_positive_regardless_of_class_balance():
    """LÕI VẤN ĐỀ: hệ luôn hô 'tấn công' phải bị chấm 0, dù tập lệch cỡ nào.

    Đây chính là ca đã sinh ra 'F1 = 0,967' vô nghĩa trong luận văn: trên tập 94% tấn
    công, một hàm `return True` được F1 rất cao. MCC phải trả 0 ở CẢ hai tỉ lệ lớp.
    """
    # Tập 94% tấn công: hô "tấn công" hết -> tn=fn=0
    assert mcc(tp=940, fp=60, tn=0, fn=0) == 0.0
    # Tập 2% tấn công: vẫn hô "tấn công" hết
    assert mcc(tp=20, fp=980, tn=0, fn=0) == 0.0


def test_mcc_zero_for_always_negative():
    """Đối xứng: hệ luôn hô 'lành tính' (đạt accuracy 0,98 trên tập lệch) cũng phải = 0."""
    assert mcc(tp=0, fp=0, tn=980, fn=20) == 0.0


def test_accuracy_is_fooled_where_mcc_is_not():
    """Đối chứng trực tiếp: cùng một hệ vô dụng, Accuracy khen, MCC không."""
    rep = confusion_report(tp=0, fp=0, tn=980, fn=20)
    assert rep["accuracy"] == 0.98, "Accuracy bị tỉ lệ lớp đánh lừa"
    assert rep["mcc"] == 0.0, "MCC phải vạch ra là không có năng lực phân biệt"
    assert rep["accuracy_beats_baseline"] is False


def test_mcc_perfect_and_inverted():
    assert mcc(tp=50, fp=0, tn=50, fn=0) == 1.0
    assert mcc(tp=0, fp=50, tn=0, fn=50) == -1.0


def test_mcc_symmetric_under_class_swap():
    """MCC không đổi khi hoán vị hai lớp — F1 thì đổi. Tính chất này khiến MCC trung lập."""
    assert mcc(tp=30, fp=10, tn=45, fn=15) == mcc(tp=45, fp=15, tn=30, fn=10)


def test_balanced_accuracy_gives_half_for_degenerate_guess():
    assert balanced_accuracy(tp=940, fp=60, tn=0, fn=0) == 0.5


def test_majority_baseline_equals_positive_rate():
    assert majority_baseline(940, 1000) == 0.94


def test_confusion_report_flags_when_accuracy_only_matches_baseline():
    """Ca thật của Tier-2: accuracy bằng ĐÚNG base rate => không có năng lực phân biệt."""
    rep = confusion_report(tp=19, fp=781, tn=0, fn=0)
    assert rep["accuracy"] == rep["majority_baseline"]
    assert rep["accuracy_beats_baseline"] is False
    assert rep["mcc"] == 0.0


# ==============================================================================
# Khoảng tin cậy
# ==============================================================================


def test_wilson_ci_wide_for_tiny_n():
    """'3/3 = 1,00' KHÔNG phải 'hoàn hảo' — cận dưới phải thấp rõ rệt."""
    lo, hi = wilson_ci(3, 3)
    assert hi == 1.0
    assert lo < 0.5, f"cận dưới {lo} phải phản ánh n=3 quá nhỏ để kết luận"


def test_wilson_ci_narrows_as_n_grows():
    lo_s, hi_s = wilson_ci(30, 30)
    lo_l, hi_l = wilson_ci(3000, 3000)
    assert (hi_l - lo_l) < (hi_s - lo_s)


def test_wilson_ci_stays_inside_unit_interval_at_extremes():
    for k, n in ((0, 10), (10, 10), (0, 1)):
        lo, hi = wilson_ci(k, n)
        assert 0.0 <= lo <= hi <= 1.0


def test_wilson_ci_handles_zero_n():
    assert wilson_ci(0, 0) == (0.0, 0.0)


def test_bootstrap_ci_is_deterministic_for_fixed_seed():
    """Tất định theo seed — chạy lại luận văn phải ra đúng số cũ."""
    data = [1] * 60 + [0] * 40

    def mean(s):
        return sum(s) / len(s)

    assert bootstrap_ci(data, mean, n_resamples=200, seed=42) == bootstrap_ci(
        data, mean, n_resamples=200, seed=42
    )


def test_bootstrap_ci_brackets_the_point_estimate():
    data = [1] * 60 + [0] * 40

    def mean(s):
        return sum(s) / len(s)

    lo, hi = bootstrap_ci(data, mean, n_resamples=500, seed=7)
    assert lo <= 0.60 <= hi


def test_bootstrap_ci_degenerate_input():
    assert bootstrap_ci([], lambda s: 0.0) == (0.0, 0.0)
    assert bootstrap_ci([1], lambda s: 0.0) == (0.0, 0.0)


# ==============================================================================
# Bóc theo lớp
# ==============================================================================


def _rec(label, is_threat, flagged):
    return {"label": label, "is_threat": is_threat, "flagged": flagged}


def test_per_class_report_exposes_blind_spot_hidden_by_pooled_recall():
    """Recall gộp 0,5 che mất việc một lớp bị bỏ sót SẠCH — đây là lý do phải bóc lớp."""
    records = [_rec("DoS", True, True) for _ in range(10)]
    records += [_rec("Infiltration", True, False) for _ in range(10)]

    pooled = sum(1 for r in records if r["flagged"]) / len(records)
    assert pooled == 0.5, "nhìn gộp thì tưởng trung bình khá"

    rep = per_class_report(records)
    assert rep["DoS"]["recall"] == 1.0
    assert rep["Infiltration"]["recall"] == 0.0
    assert rep["Infiltration"]["missed"] == 10


def test_per_class_report_reports_specificity_for_benign_class():
    records = [_rec("Benign", False, False) for _ in range(8)]
    records += [_rec("Benign", False, True) for _ in range(2)]
    rep = per_class_report(records)
    assert rep["Benign"]["specificity"] == 0.8
    assert rep["Benign"]["false_positives"] == 2
    assert "recall" not in rep["Benign"]


def test_per_class_report_attaches_ci():
    rep = per_class_report([_rec("Bot", True, True) for _ in range(3)])
    assert rep["Bot"]["recall"] == 1.0
    assert rep["Bot"]["recall_ci95"][0] < 0.5, "n=3 phải kèm CI rộng"


def test_weakest_classes_orders_by_recall():
    records = (
        [_rec("A", True, True) for _ in range(10)]
        + [_rec("B", True, False) for _ in range(10)]
        + [_rec("C", True, True) for _ in range(5)]
        + [_rec("C", True, False) for _ in range(5)]
    )
    assert weakest_classes(per_class_report(records), k=2) == [("B", 0.0), ("C", 0.5)]


# ==============================================================================
# Hiệu năng vận hành
# ==============================================================================


def test_throughput_and_zero_guard():
    assert throughput(1000, 4.0) == 250.0
    assert throughput(1000, 0.0) == 0.0


def test_alert_burden_converts_to_soc_units():
    """1 giờ chạy, 120 cảnh báo trong đó 30 sai -> ca 8h gánh 960 cảnh báo."""
    b = alert_burden(n_false_positives=30, n_total_alerts=120, elapsed_seconds=3600)
    assert b["alerts_per_hour"] == 120.0
    assert b["false_alerts_per_hour"] == 30.0
    assert b["alerts_per_shift"] == 960.0


def test_alert_burden_zero_guard():
    assert alert_burden(0, 0, 0)["alerts_per_hour"] == 0.0


# ==============================================================================
# Neo bằng chứng — thay cho audit_completeness vốn luôn 100%
# ==============================================================================

_LOG = {"Destination Port": 22, "Total Fwd Packets": 900, "Source IP": "10.0.0.5"}


def test_grounding_detects_verified_citation():
    g = evidence_grounding("Brute force on `Destination Port=22` with Total Fwd Packets=900", _LOG)
    assert g["n_citations"] == 2
    assert g["n_verified"] == 2
    assert g["grounded"] is True


def test_grounding_rejects_fabricated_value():
    """Model bịa số phải KHÔNG được tính là có bằng chứng — đây là điểm khác cốt lõi
    so với audit_completeness (vốn chỉ đếm trường có mặt, không kiểm giá trị)."""
    g = evidence_grounding("Observed Destination Port=443 which is benign", _LOG)
    assert g["n_citations"] == 1
    assert g["n_verified"] == 0
    assert g["grounded"] is False


def test_grounding_zero_for_empty_appeal_to_authority():
    """Lập luận rỗng mà prompt CẤM tường minh -> phải trượt, và bị đếm là 'viện dẫn'."""
    g = evidence_grounding(
        "This is dangerous and confirmed by MITRE ATT&CK, must be blocked.", _LOG
    )
    assert g["grounded"] is False
    assert g["n_appeals"] >= 2


def test_grounding_matches_numeric_value_across_formats():
    assert evidence_grounding("Total Fwd Packets=900.0", _LOG)["n_verified"] == 1


def test_grounding_tolerates_field_name_spacing_variants():
    """Model hay viết `total_fwd_packets` thay vì `Total Fwd Packets` — vẫn phải khớp."""
    assert evidence_grounding("total_fwd_packets=900", _LOG)["n_verified"] == 1


def test_grounding_empty_reasoning():
    g = evidence_grounding("", _LOG)
    assert g["grounded"] is False and g["n_citations"] == 0


def test_grounding_rate_aggregates_with_ci():
    pairs = [("Destination Port=22", _LOG)] * 3 + [("it is malicious", _LOG)] * 1
    r = evidence_grounding_rate(pairs)
    assert r["n"] == 4
    assert r["grounding_rate"] == 0.75
    assert len(r["grounding_rate_ci95"]) == 2


def test_grounding_rate_empty():
    assert evidence_grounding_rate([]) == {"n": 0}


# ==============================================================================
# Cohen's kappa — kiểm định trọng tài LLM
# ==============================================================================


def test_kappa_one_for_identical_ratings():
    assert cohens_kappa([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]) == 1.0


def test_kappa_near_zero_for_chance_agreement():
    """Hai người chấm độc lập, cùng phân bố -> đồng thuận chỉ do may rủi -> κ ≈ 0."""
    a = [1, 2] * 25
    b = [1, 1, 2, 2] * 12 + [1, 2]
    assert abs(cohens_kappa(a, b)) < 0.3


def test_kappa_negative_for_systematic_disagreement():
    assert cohens_kappa([1] * 5 + [2] * 5, [2] * 5 + [1] * 5) < 0


def test_kappa_empty_and_constant_input():
    assert cohens_kappa([], []) == 0.0
    # Cả hai chấm cùng một hạng cho mọi mẫu: đồng thuận hoàn toàn do may rủi.
    assert cohens_kappa([3, 3, 3], [3, 3, 3]) == 1.0


# ==============================================================================
# Chi phí tài nguyên
# ==============================================================================


def test_resource_cost_scales_with_llm_call_rate():
    """Cùng khối lượng sự kiện, gọi LLM ít hơn -> chi phí thấp hơn. Đây chính là đại
    lượng mà kiến trúc hai tầng tác động, nên nó phải phản ứng đúng chiều."""
    heavy = resource_cost(
        n_events=1000, n_llm_calls=1000, mean_prompt_tokens=2000, mean_completion_tokens=300
    )
    light = resource_cost(
        n_events=1000, n_llm_calls=100, mean_prompt_tokens=2000, mean_completion_tokens=300
    )
    assert light["avoided_api_usd_per_1k_events"] < heavy["avoided_api_usd_per_1k_events"]
    assert light["llm_call_rate"] == 0.1
    assert heavy["llm_call_rate"] == 1.0


def test_resource_cost_zero_guard():
    assert resource_cost(0, 0, 0, 0) == {"n_events": 0}


def test_resource_cost_reports_pricing_assumption():
    """Con số $ vô nghĩa nếu không kèm mốc giá — bắt buộc phải xuất ra cùng kết quả."""
    c = resource_cost(
        n_events=10, n_llm_calls=10, mean_prompt_tokens=1000, mean_completion_tokens=100
    )
    assert "reference_api_pricing_usd_per_mtok" in c
    assert "avoided" in c["note"].lower() or "TRÁNH ĐƯỢC" in c["note"]


@pytest.mark.parametrize("bad", [(0, 0, 0, 0)])
def test_all_zero_confusion_does_not_crash(bad):
    rep = confusion_report(*bad)
    assert rep["mcc"] == 0.0 and rep["f1"] == 0.0
    assert not math.isnan(rep["accuracy"])


# ==============================================================================
# Hiệu chuẩn độ tin cậy
# ==============================================================================


def test_brier_perfect_and_worst():
    """Dự báo hoàn hảo -> 0; dự báo ngược hoàn toàn -> 1."""
    assert mc.brier_score([1.0, 0.0, 1.0], [True, False, True]) == 0.0
    assert mc.brier_score([0.0, 1.0], [True, False]) == 1.0


def test_brier_penalises_overconfidence_more_than_hedging():
    """Sai mà nói chắc phải bị phạt NẶNG hơn sai mà lưỡng lự.

    Đây chính là tính chất khiến Brier hơn accuracy khi thẩm định chính sách 4 dải: một
    lệnh tự động BLOCK ở độ tin cậy 0,95 mà sai tốn kém hơn hẳn một ca lưỡng lự 0,55.
    """
    confident_wrong = mc.brier_score([0.95], [False])
    hedged_wrong = mc.brier_score([0.55], [False])
    assert confident_wrong > hedged_wrong


def test_ece_zero_when_perfectly_calibrated():
    """Nói chắc 70% và đúng đúng 70% -> ECE = 0, dù accuracy chỉ 0,7."""
    conf = [0.7] * 10
    outcomes = [True] * 7 + [False] * 3
    rep = mc.expected_calibration_error(conf, outcomes, n_bins=10)
    assert rep["ece"] == 0.0


def test_ece_detects_overconfidence():
    """Luôn hô 0,99 nhưng chỉ đúng một nửa -> ECE ~0,49 và bị gắn cờ QUÁ TỰ TIN."""
    conf = [0.99] * 100
    outcomes = [True] * 50 + [False] * 50
    rep = mc.expected_calibration_error(conf, outcomes, n_bins=10)
    assert rep["ece"] > 0.45
    assert all(b["overconfident"] for b in rep["bins"])


def test_ece_weights_by_sample_count_not_bin_count():
    """Khoảng RỖNG không được làm loãng ECE.

    Hai mẫu, mỗi mẫu lệch 0,05, nằm ở hai khoảng khác nhau; 8 khoảng còn lại rỗng. Đáp số
    đúng là 0,05 (trung bình có trọng số theo SỐ MẪU). Nếu ai đó cài nhầm thành chia cho
    `n_bins` thì ra 0,01 — nghe như hiệu chuẩn tốt gấp 5 lần thực tế, đúng kiểu sai lệch
    âm thầm mà không ai soi ra từ một con số đơn lẻ.
    """
    rep = mc.expected_calibration_error([0.05, 0.95], [False, True], n_bins=10)
    assert rep["ece"] == pytest.approx(0.05)
    assert len(rep["bins"]) == 2, "khoảng rỗng không được xuất hiện trong báo cáo"


def test_calibration_report_isolates_auto_block_band():
    """Dải >=0,85 phải được bóc riêng: ECE gộp đẹp vẫn có thể che một dải BLOCK hỏng."""
    # 90 ca thấp và hiệu chuẩn tốt + 10 ca "chắc chắn" mà sai sạch.
    conf = [0.1] * 90 + [0.9] * 10
    outcomes = [False] * 90 + [False] * 10
    rep = mc.calibration_report(conf, outcomes)
    assert rep["high_conf_n"] == 10
    assert rep["high_conf_accuracy"] == 0.0
    assert rep["high_conf_accuracy_ci95"][1] < 0.35  # CI không chạm mức chấp nhận được


def test_calibration_report_handles_empty_input():
    rep = mc.calibration_report([], [])
    assert rep["n"] == 0 and rep["high_conf_n"] == 0
    assert rep["high_conf_accuracy"] is None


# ==============================================================================
# Ngăn chặn mức IP
# ==============================================================================


def test_containment_counts_ip_not_events():
    """Chặn kẻ tấn công ở sự kiện thứ 3 là THÀNH CÔNG, dù 497 flow sau vẫn chảy qua.

    Đây chính là điều mà F1 mức-sự-kiện không diễn đạt được: nó phạt 497 lần cho một ca mà
    vận hành thật coi là đã xử lý xong.
    """
    evs = [{"ip": "1.1.1.1", "is_attack": True, "blocked": i == 2} for i in range(500)]
    rep = mc.ip_containment(evs)
    assert rep["n_attacker_ips"] == 1
    assert rep["containment_rate"] == 1.0
    assert rep["leak_rate"] == 0.0
    assert rep["events_before_containment"]["median"] == 2, "2 sự kiện lọt trước lệnh chặn"


def test_containment_reports_leak_rate():
    """Ba IP tấn công, chặn được hai -> lọt 1/3."""
    evs = [
        {"ip": "a", "is_attack": True, "blocked": True},
        {"ip": "b", "is_attack": True, "blocked": True},
        {"ip": "c", "is_attack": True, "blocked": False},
    ]
    rep = mc.ip_containment(evs)
    assert rep["containment_rate"] == pytest.approx(2 / 3, abs=1e-4)
    assert rep["leak_rate"] == pytest.approx(1 / 3, abs=1e-4)


def test_block_everything_is_caught_by_false_block_counterweight():
    """Chặn sạch mọi IP đạt containment 1,00 — chỉ đối trọng mới lộ ra là hỏng.

    Không có `benign_ip_false_block_rate` thì một hệ `return BLOCK` trông hoàn hảo.
    """
    evs = [{"ip": f"atk{i}", "is_attack": True, "blocked": True} for i in range(5)]
    evs += [{"ip": f"ben{i}", "is_attack": False, "blocked": True} for i in range(20)]
    rep = mc.ip_containment(evs)
    assert rep["containment_rate"] == 1.0, "trông như hoàn hảo…"
    assert rep["benign_ip_false_block_rate"] == 1.0, "…nhưng chặn oan 100% IP lành tính"


def test_benign_ip_never_attacking_is_not_counted_as_attacker():
    evs = [
        {"ip": "ben", "is_attack": False, "blocked": False},
        {"ip": "atk", "is_attack": True, "blocked": False},
    ]
    rep = mc.ip_containment(evs)
    assert rep["n_attacker_ips"] == 1 and rep["n_benign_ips"] == 1
    assert rep["benign_ip_false_block_rate"] == 0.0


def test_compromised_host_sending_both_counts_as_attacker():
    """Host bị chiếm quyền gửi cả lưu lượng lành lẫn tấn công vẫn là KẺ TẤN CÔNG.

    Đây là hình thái THẬT trong DAPT2020 và là ca khó nhất — không được xếp nhầm sang phía
    lành tính chỉ vì phần lớn lưu lượng của nó vô hại.
    """
    evs = [
        {"ip": "h", "is_attack": False, "blocked": False},
        {"ip": "h", "is_attack": False, "blocked": False},
        {"ip": "h", "is_attack": True, "blocked": True},
    ]
    rep = mc.ip_containment(evs)
    assert rep["n_attacker_ips"] == 1 and rep["n_benign_ips"] == 0
    assert rep["events_before_containment"]["median"] == 0, "chặn ngay sự kiện tấn công đầu"


def test_containment_handles_empty_input():
    rep = mc.ip_containment([])
    assert rep["n_attacker_ips"] == 0
    assert rep["containment_rate"] is None and rep["leak_rate"] is None
