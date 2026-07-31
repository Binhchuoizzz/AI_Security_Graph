"""Bất biến: MẪU DO TÁC GIẢ BIÊN SOẠN không được vào bất kỳ TỈ LỆ nào của luận văn.

VÌ SAO CÓ FILE NÀY. `unified_dataset.NON_CLASSIFIED_SOURCES` đã tuyên bố đúng chính sách
này từ lâu — `adversarial` là "đầu vào biên soạn — không tính vào tỉ lệ". Nhưng nó lọc theo
khoá `source`, mà khoá đó CHỈ tồn tại trên vỏ bọc của `build_stream()`. `ground_truth.json`
là artefact khác, dựng bởi `scripts/fetch_and_build_dataset.py`, và tệp đó cố ý chèn 50 mẫu
đối địch tự viết (dòng ~502, mục đích ban đầu là để thử Guardrails). Chúng KHÔNG mang khoá
`source`, nên chính sách trên không chạm tới được.

Hậu quả đo được trước khi vá: trong 300 mẫu "chấm được quy kết" (có bằng chứng tầng ứng
dụng + có mã ATT&CK), 50 mẫu là tự viết — 16,7% — và cả 50 cùng một đáp án `T1190`, đẩy
T1190 từ 52 lên 102 mẫu. Thước đo quy kết vì thế vừa thưởng cho việc khớp khuôn mẫu của
chính tác giả, vừa thưởng cho thiên vị đúng một mã.

Các test dưới đây khoá cả hai chiều: bộ lọc phải bắt đúng mẫu biên soạn, VÀ mọi script sinh
tỉ lệ từ `ground_truth.json` phải thực sự gọi bộ lọc ấy.
"""

import json
import pathlib
import re

import pytest

from experiments.unified_dataset import (
    AUTHORED_GT_LABELS,
    drop_authored,
    is_authored_sample,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
GT_PATH = ROOT / "experiments" / "ground_truth.json"
TECH_RE = re.compile(r"T\d{4}")


@pytest.fixture(scope="module")
def ground_truth():
    if not GT_PATH.exists():
        pytest.skip("ground_truth.json chưa được dựng")
    with open(GT_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def test_authored_samples_are_detected():
    """Nhận diện theo `cicids_label`, không theo chuỗi mô tả."""
    authored = {"input": {"cicids_label": "Adversarial"}}
    real = {"input": {"cicids_label": "SQL Injection"}}
    assert is_authored_sample(authored)
    assert not is_authored_sample(real)
    # Mẫu thiếu hẳn khoá `input` không được làm vỡ bộ lọc.
    assert not is_authored_sample({})


def test_drop_authored_reports_how_many_it_removed():
    """Loại mẫu trong IM LẶNG là cách làm mẫu số đổi mà không ai biết."""
    samples = [
        {"input": {"cicids_label": "Adversarial"}},
        {"input": {"cicids_label": "SQL Injection"}},
        {"input": {"cicids_label": "Adversarial"}},
    ]
    kept, n_dropped = drop_authored(samples)
    assert n_dropped == 2
    assert len(kept) == 1
    assert kept[0]["input"]["cicids_label"] == "SQL Injection"


def test_ground_truth_still_contains_authored_samples(ground_truth):
    """Chúng PHẢI còn trong tệp — `evaluate_adversarial.py` cần chúng làm tập thử tiêm nhiễm.

    Bản vá là LỌC KHI CHẤM, không phải xoá dữ liệu. Nếu ai đó xoá thẳng khỏi tệp thì test
    này đỏ để nhắc rằng cách sửa đó làm mất tập thử guardrail.
    """
    authored = [s for s in ground_truth if is_authored_sample(s)]
    assert authored, "mẫu đối địch đã biến mất khỏi ground_truth.json"


def test_attribution_pool_contains_no_authored_sample(ground_truth):
    """Bất biến CỐT LÕI: tập chấm quy kết của `run_ablation --mode bcde` phải sạch."""
    from experiments.run_ablation import attributable

    pool = attributable(ground_truth, None)
    dirty = [s for s in pool if is_authored_sample(s)]
    assert not dirty, f"{len(dirty)} mẫu biên soạn lọt vào tập chấm quy kết"
    assert pool, "tập chấm quy kết rỗng — bộ lọc đã vét cạn"


def test_attribution_pool_is_not_dominated_by_one_answer(ground_truth):
    """Chính 50 mẫu tự viết đã làm `T1190` chiếm gần một phần ba tập.

    Sau khi lọc, không mã nào được chiếm quá 60% — nếu vượt thì "đoán bừa mã phổ biến nhất"
    tự nó đã là một điểm số cao, và tỉ lệ khớp mất hết ý nghĩa.
    """
    from collections import Counter

    from experiments.run_ablation import attributable

    pool = attributable(ground_truth, None)
    counts = Counter(str(s.get("expected_mitre_technique")) for s in pool)
    top_id, top_n = counts.most_common(1)[0]
    share = top_n / len(pool)
    assert share <= 0.60, f"{top_id} chiếm {share:.1%} tập chấm — thước đo bị một mã lấn át"


@pytest.mark.parametrize(
    "script",
    [
        "experiments/run_ablation.py",
        "experiments/evaluate_rag_retrieval.py",
        "experiments/run_llm_robustness.py",
        "experiments/run_context_stress.py",
        "scripts/eval_attack_mapper.py",
    ],
)
def test_every_ground_truth_consumer_filters_authored(script):
    """Quét CHUNG: script nào đọc `ground_truth.json` cũng phải gọi `drop_authored`.

    Đây là phần bắt được lỗi TƯƠNG LAI. Thêm một script đo mới mà quên lọc thì danh sách
    này phải được cập nhật, và việc cập nhật buộc người viết phải nghĩ về dân số chấm điểm.
    """
    text = (ROOT / script).read_text(encoding="utf-8")
    assert "ground_truth.json" in text, f"{script} không còn đọc ground_truth.json"
    assert "drop_authored" in text, f"{script} đọc ground_truth.json mà KHÔNG lọc mẫu biên soạn"


def test_authored_labels_are_declared_not_guessed():
    """Bộ nhãn phải tường minh — dò theo chuỗi con 'adversarial' là cách vỡ trong im lặng."""
    assert "Adversarial" in AUTHORED_GT_LABELS
