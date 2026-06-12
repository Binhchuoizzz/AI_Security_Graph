"""
Unit tests cho Subscriber — CHỐNG LỘ NHÃN dataset vào prompt LLM (label leakage).

Bối cảnh: luồng gộp online (`experiments/stream_unified_online.py`) mang metadata
nhãn (gt_*/apt_*/zd_*) để subscriber ghi APT emergent và collector đối chiếu hậu
kiểm. Nhưng TRƯỚC khi batch ESCALATE được đưa lên Agent/LLM, mọi khóa nhãn phải
bị loại — nếu không prompt sẽ chứa sẵn "đáp án" (gt_expected_action, zd_mitre...)
và demo online mất giá trị khoa học.
"""

import pytest  # type: ignore

from src.streaming.subscriber import _DATASET_LABEL_KEYS, _strip_dataset_labels


class TestStripDatasetLabels:
    def test_removes_every_dataset_label_key(self):
        """Mọi khóa trong strip-set phải biến mất; trường hệ thống phải GIỮ."""
        log = {k: "leak" for k in _DATASET_LABEL_KEYS}
        log.update({
            "Source IP": "1.2.3.4",
            "Destination Port": 443,
            "tier1_action": "ESCALATE",
            "tier1_score": 55,
            "tier1_reasons": ["APT chain emergent: 2 ngày"],
            "gt_id": "GT-001",          # định danh mờ — giữ để đối chiếu hậu kiểm
            "apt_emergent": True,        # enrichment HỆ THỐNG tự suy ra — giữ
            "apt_phases": "Recon,Lateral",
            "log_source": "queue_waf",
        })
        out = _strip_dataset_labels(log)

        for k in _DATASET_LABEL_KEYS:
            assert k not in out, f"khóa nhãn '{k}' vẫn lọt lên LLM"
        for k in ("Source IP", "Destination Port", "tier1_action", "tier1_score",
                  "tier1_reasons", "gt_id", "apt_emergent", "apt_phases", "log_source"):
            assert k in out, f"trường hệ thống '{k}' bị strip nhầm"

    def test_answer_bearing_keys_are_in_strip_set(self):
        """Các khóa mang 'đáp án' kinh điển bắt buộc nằm trong strip-set."""
        for k in ("gt_expected_action", "gt_expected_mitre", "gt_cicids_label",
                  "expected_threat", "apt_is_attack", "zd_mitre"):
            assert k in _DATASET_LABEL_KEYS

    def test_does_not_mutate_original(self):
        log = {"gt_expected_action": "BLOCK_IP", "Source IP": "1.1.1.1"}
        _ = _strip_dataset_labels(log)
        assert "gt_expected_action" in log  # bản gốc (đi queue_decisions) còn nguyên


def test_online_enrich_labels_fully_covered_by_strip_set():
    """HỢP ĐỒNG CHỐNG REGRESSION giữa publisher online và subscriber:

    Mọi khóa mà `enrich()` THÊM vào log (trừ provenance vô hại) phải nằm trong
    `_DATASET_LABEL_KEYS`. Nếu sau này enrich thêm khóa nhãn mới mà quên bổ sung
    strip-set -> test này ĐỎ, chặn việc lộ đáp án âm thầm.
    """
    from experiments.stream_unified_online import enrich

    PROVENANCE_OK = {"dataset_source", "unified_source"}  # nguồn gốc, không phải đáp án
    sample_events = [
        {"source": "cicids", "log": {"Destination Port": 80},
         "expected_threat": True, "label": "Bot"},
        {"source": "dapt", "log": {"Source IP": "10.1.1.1"}, "phase": "Reconnaissance",
         "day": 2, "label": "Network Scan", "is_attack": True, "timestamp": "t1"},
        {"source": "zeroday", "log": {"Destination Port": 443}, "id": "ZD-001",
         "mitre": "T1048", "name": "ZD hợp đồng"},
    ]
    for ev in sample_events:
        added = set(enrich(ev)) - set(ev["log"])
        leak = added - PROVENANCE_OK - _DATASET_LABEL_KEYS
        assert not leak, (
            f"[{ev['source']}] enrich() thêm khóa nhãn CHƯA có trong strip-set "
            f"của subscriber: {leak} -> sẽ lộ vào prompt LLM"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
