"""Unit tests cho chấm-theo-hành-động (`experiments/action_scoring.py`).

VÌ SAO QUAN TRỌNG: đây là thước đo CHÍNH của ablation — xương sống bằng chứng Chương 4.
Thước đo nhị phân cũ khiến A ≡ F và B ≡ C ≡ D ≡ E *từng bit*, tức ablation không chứng
minh được gì. Các test dưới khoá lại đúng những tính chất khiến thước đo mới phân biệt được.
"""

from experiments.action_scoring import (
    _canon_action,
    score_actions,
)


# ==============================================================================
# HỒI QUY LỖI GỐC: hai cấu hình khác hẳn nhau phải cho điểm KHÁC nhau
# ==============================================================================
def test_discriminates_configs_that_binary_metric_collapsed():
    """Ca THẬT: A treo ở ESCALATE, F tự quyết — thước đo cũ cho hai bên F1 GIỐNG HỆT."""
    expected = ["ALERT"] * 770 + ["AWAIT_HITL"] * 80 + ["BLOCK_IP"] * 320 + ["LOG"] * 80
    # A: không có tầng sau -> mọi ca đều treo ở ESCALATE (chưa phân giải)
    cfg_a = ["ESCALATE"] * 1250
    # F: 2 tầng đủ -> quyết đúng nhóm BLOCK, hoãn phần còn lại
    cfg_f = ["AWAIT_HITL"] * 770 + ["AWAIT_HITL"] * 80 + ["BLOCK_IP"] * 320 + ["AWAIT_HITL"] * 80

    sa = score_actions(expected, cfg_a)
    sf = score_actions(expected, cfg_f)

    assert sa["action_accuracy"] != sf["action_accuracy"], "thước đo PHẢI tách được A và F"
    assert sa["unresolved_rate"] == 1.0, "A không có tầng sau -> 100% chưa phân giải"
    assert sa["autonomy_rate"] == 0.0, "treo ở ESCALATE KHÔNG phải tự quyết"
    assert sf["autonomy_rate"] > 0.0, "F có tự quyết được một phần"


def test_escalate_is_never_counted_as_detection():
    """`ESCALATE` = 'chưa quyết xong', không bao giờ được tính là tự quyết/đúng."""
    sc = score_actions(["BLOCK_IP", "ALERT"], ["ESCALATE", "ESCALATE"])
    assert sc["action_accuracy"] == 0.0
    assert sc["autonomy_rate"] == 0.0
    assert sc["unresolved_rate"] == 1.0
    assert sc["autonomous_precision"] is None, "không tự quyết ca nào -> không có tỉ lệ"


def test_await_hitl_is_a_correct_answer_when_expected():
    """AWAIT_HITL là ĐÁP ÁN ĐÚNG cho 80 mẫu trong ground_truth — không phải luôn sai."""
    sc = score_actions(["AWAIT_HITL", "AWAIT_HITL"], ["AWAIT_HITL", "AWAIT_HITL"])
    assert sc["action_accuracy"] == 1.0, "hoãn cho người đôi khi CHÍNH LÀ hành động đúng"
    assert sc["defer_rate"] == 1.0
    assert sc["autonomy_rate"] == 0.0, "đúng nhưng vẫn là hoãn, không phải tự quyết"


def test_deferring_when_action_was_expected_is_wrong():
    """Hoãn trong khi lẽ ra phải CHẶN thì KHÔNG được tính đúng."""
    sc = score_actions(["BLOCK_IP"] * 4, ["AWAIT_HITL"] * 4)
    assert sc["action_accuracy"] == 0.0
    assert sc["defer_rate"] == 1.0


# ==============================================================================
# autonomous_precision — câu hỏi vận hành: "khi hệ dám tự quyết, nó có đáng tin?"
# ==============================================================================
def test_autonomous_precision_ignores_deferrals():
    """Chỉ chấm trên các ca hệ TỰ QUYẾT; ca hoãn không kéo tỉ lệ này lên/xuống."""
    expected = ["BLOCK_IP", "BLOCK_IP", "ALERT", "AWAIT_HITL"]
    actual = ["BLOCK_IP", "ALERT", "ALERT", "AWAIT_HITL"]  # 3 tự quyết, 2 đúng
    sc = score_actions(expected, actual)
    assert sc["n_terminal"] == 3
    assert sc["autonomous_precision"] == round(2 / 3, 4)
    assert sc["action_accuracy"] == round(3 / 4, 4)  # ca hoãn ĐÚNG vẫn tính vào accuracy


def test_perfect_autonomy_and_accuracy():
    expected = ["BLOCK_IP", "ALERT", "LOG"]
    sc = score_actions(expected, list(expected))
    assert sc["action_accuracy"] == 1.0
    assert sc["autonomy_rate"] == 1.0
    assert sc["autonomous_precision"] == 1.0
    assert sc["unresolved_rate"] == 0.0


# ==============================================================================
# Chuẩn hoá tên hành động
# ==============================================================================
def test_drop_and_log_are_the_same_verdict():
    """ground_truth dùng nhãn di sản `LOG`; hệ sinh ra `DROP`. Phải coi là một."""
    assert _canon_action("DROP") == "LOG"
    assert _canon_action("TIER1_DROP") == "LOG"
    assert score_actions(["LOG"], ["DROP"])["action_accuracy"] == 1.0


def test_tier1_prefix_is_stripped():
    """Config F ghi `TIER1_BLOCK_IP` khi gate không escalate — vẫn phải khớp `BLOCK_IP`."""
    assert _canon_action("TIER1_BLOCK_IP") == "BLOCK_IP"
    assert score_actions(["BLOCK_IP"], ["TIER1_BLOCK_IP"])["action_accuracy"] == 1.0


def test_missing_action_does_not_crash():
    """Bản ghi thiếu trường (None) không được làm hỏng cả lượt chấm."""
    sc = score_actions(["BLOCK_IP", "ALERT"], [None, "ALERT"])
    assert sc["n"] == 2
    assert sc["action_accuracy"] == 0.5


def test_empty_input_returns_safely():
    assert score_actions([], [])["n"] == 0


def test_confusion_table_shows_how_it_fails():
    """Bảng chéo phải cho biết hệ sai KIỂU gì, không chỉ sai bao nhiêu."""
    sc = score_actions(["BLOCK_IP", "BLOCK_IP", "LOG"], ["ALERT", "ALERT", "LOG"])
    assert sc["confusion"]["BLOCK_IP"]["ALERT"] == 2, "hạ cấp BLOCK->ALERT phải hiện ra"
    assert sc["confusion"]["LOG"]["LOG"] == 1
