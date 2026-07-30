"""
Unit tests cho Subscriber — CHỐNG LỘ NHÃN dataset vào prompt LLM (label leakage).

Bối cảnh: luồng gộp online (`experiments.unified_dataset.enrich` → scripts
build_datatest/demo) mang metadata
nhãn (gt_*/apt_*/zd_*) để subscriber ghi APT emergent và collector đối chiếu hậu
kiểm. Nhưng TRƯỚC khi batch ESCALATE được đưa lên Agent/LLM, mọi khóa nhãn phải
bị loại — nếu không prompt sẽ chứa sẵn "đáp án" (gt_expected_action, zd_mitre...)
và demo online mất giá trị khoa học.
"""

import pytest  # type: ignore

from src.streaming.subscriber import (
    _DATASET_LABEL_KEYS,
    OFFLOAD_MARKERS,
    _apply_blacklist_memory,
    _is_dataset_label_key,
    _strip_dataset_labels,
    classify_offload_mechanisms,
    primary_offload_mechanism,
)


class TestBlacklistMemory:
    """TRÍ NHỚ Tier-1: IP trong blacklist (đã bị chặn gần đây) -> chặn thẳng lần sau,
    KHÔNG leo thang Tier-2 lại. Whitelist & log đang BLOCK được giữ nguyên."""

    def test_blacklisted_benign_flow_forced_block(self):
        log = {"tier1_action": "DROP", "tier1_reasons": []}
        assert _apply_blacklist_memory("DROP", log, is_blacklisted=True) == "BLOCK_IP"
        assert log["tier1_action"] == "BLOCK_IP"
        assert any("TRÍ NHỚ" in r for r in log["tier1_reasons"])

    def test_blacklisted_escalate_downgraded_to_block_no_llm(self):
        """Đang định ESCALATE (tốn LLM) nhưng IP đã bị chặn -> ép BLOCK, KHÔNG leo thang."""
        log = {"tier1_action": "ESCALATE"}
        assert _apply_blacklist_memory("ESCALATE", log, is_blacklisted=True) == "BLOCK_IP"

    def test_whitelisted_not_overridden(self):
        """Whitelist ưu tiên cao hơn blacklist -> KHÔNG bị ép BLOCK."""
        log = {"tier1_action": "WHITELIST_DROP", "is_whitelisted": True}
        assert (
            _apply_blacklist_memory("WHITELIST_DROP", log, is_blacklisted=True) == "WHITELIST_DROP"
        )

    def test_not_blacklisted_unchanged(self):
        log = {"tier1_action": "DROP"}
        assert _apply_blacklist_memory("DROP", log, is_blacklisted=False) == "DROP"

    def test_already_block_not_duplicated(self):
        log = {"tier1_action": "BLOCK_IP", "tier1_reasons": ["WAF"]}
        assert _apply_blacklist_memory("BLOCK_IP", log, is_blacklisted=True) == "BLOCK_IP"
        assert log["tier1_reasons"] == ["WAF"]  # không thêm lý do trùng


class TestStripDatasetLabels:
    def test_removes_every_dataset_label_key(self):
        """Mọi khóa trong strip-set phải biến mất; trường hệ thống phải GIỮ."""
        log: dict[str, object] = {k: "leak" for k in _DATASET_LABEL_KEYS}
        log.update(
            {
                "Source IP": "1.2.3.4",
                "Destination Port": 443,
                "tier1_action": "ESCALATE",
                "tier1_score": 55,
                "tier1_reasons": ["APT chain emergent: 2 ngày"],
                "gt_id": "GT-001",  # định danh mờ — giữ để đối chiếu hậu kiểm
                "apt_emergent": True,  # enrichment HỆ THỐNG tự suy ra — giữ
                "apt_phases": "Recon,Lateral",
                "log_source": "queue_waf",
            }
        )
        out = _strip_dataset_labels(log)

        for k in _DATASET_LABEL_KEYS:
            assert k not in out, f"khóa nhãn '{k}' vẫn lọt lên LLM"
        for k in (
            "Source IP",
            "Destination Port",
            "tier1_action",
            "tier1_score",
            "tier1_reasons",
            "gt_id",
            "apt_emergent",
            "apt_phases",
            "log_source",
        ):
            assert k in out, f"trường hệ thống '{k}' bị strip nhầm"

    def test_answer_bearing_keys_are_stripped(self):
        """Các khóa mang 'đáp án' bắt buộc bị loại.

        Kiểm qua VỊ TỪ `_is_dataset_label_key()`, không qua tập phẳng: cơ chế lọc nay là
        QUY TẮC TIỀN TỐ chứ không phải danh sách đen liệt kê tay. Đổi cách kiểm không phải
        nới lỏng — chính danh sách đen mới là thứ đã hở, vì mỗi nguồn dữ liệu thêm sau lại
        cần một dòng mới mà không gì báo động khi quên.
        """
        for k in (
            "gt_expected_action",
            "gt_expected_mitre",
            "gt_cicids_label",
            "gt_label",
            "expected_threat",
            "apt_is_attack",
            "apt_mitre_ttp",
            "zd_mitre",
            "gz_mitre",  # từng LỌT: vùng xám thêm sau khi danh sách đen ra đời
            "adv_id",  # từng LỌT: chỉ vô hại tình cờ vì một lỗi làm nó luôn rỗng
            "adv_source",
            "unified_source",  # từng LỌT: tự khai 'zeroday'/'adversarial'/'grayzone'
        ):
            assert _is_dataset_label_key(k), f"khóa mang đáp án '{k}' KHÔNG bị loại"

    def test_does_not_mutate_original(self):
        log = {"gt_expected_action": "BLOCK_IP", "Source IP": "1.1.1.1"}
        _ = _strip_dataset_labels(log)
        assert "gt_expected_action" in log  # bản gốc (đi queue_decisions) còn nguyên


def test_online_enrich_labels_fully_covered_by_strip_set():
    """HỢP ĐỒNG CHỐNG REGRESSION giữa publisher online và subscriber:

    Mọi khóa mà `enrich()` THÊM vào log phải bị `_is_dataset_label_key()` loại. Nếu sau
    này enrich thêm khóa nhãn mới mà quy tắc lọc không phủ -> test này ĐỎ, chặn việc lộ
    đáp án âm thầm.
    """
    from experiments.unified_dataset import enrich

    # `unified_source` TỪNG nằm trong danh sách "provenance vô hại" này — và đó chính là
    # lỗ hổng: giá trị của nó là 'zeroday' / 'adversarial' / 'grayzone', tức tự khai đáp án
    # cho LLM. Nay nó bị loại, nên danh sách miễn trừ rỗng.
    PROVENANCE_OK: set[str] = set()
    sample_events: list[dict] = [
        {
            "source": "cicids",
            "log": {"Destination Port": 80},
            "expected_threat": True,
            "label": "Bot",
        },
        {
            "source": "dapt",
            "log": {"Source IP": "10.1.1.1"},
            "phase": "Reconnaissance",
            "day": 2,
            "label": "Network Scan",
            "is_attack": True,
            "timestamp": "t1",
        },
        {
            "source": "zeroday",
            "log": {"Destination Port": 443},
            "id": "ZD-001",
            "mitre": "T1048",
            "name": "ZD hợp đồng",
        },
    ]
    for ev in sample_events:
        added = set(enrich(ev)) - set(ev["log"])
        leak = {k for k in added - PROVENANCE_OK if not _is_dataset_label_key(k)}
        assert not leak, (
            f"[{ev['source']}] enrich() thêm khóa nhãn mà subscriber KHÔNG loại: "
            f"{leak} -> sẽ lộ vào prompt LLM"
        )


# ── PHÂN BỔ GIẢM TẢI ─────────────────────────────────────────────────────────
# Bộ đếm này là bằng chứng DUY NHẤT trả lời "đẩy lần 2 có nhẹ hơn lần 1 không, nhờ cơ chế
# nào" — sự kiện bị chặn ở Tier-1 KHÔNG sinh dòng tracer nào nên hậu kiểm không có đường
# khác. Nó phân loại bằng CHUỖI lý do, mà chuỗi thì dễ bị sửa lời cho 'dễ đọc' rồi lặng lẽ
# rơi hết về `t1_other`. Các test dưới đây chốt giao ước đó lại.


@pytest.mark.parametrize(
    "reason,expected",
    [
        ("TRÍ NHỚ Tier-1: IP đã bị chặn gần đây (blacklist TTL 1h)", "t1_blacklist_memory"),
        (
            "IP có tiền sử NGUY HIỂM (điểm danh tiếng 100 ≥ 70) → chặn tự động",
            "t1_reputation_block",
        ),
        ("IP có tiền sử đáng ngờ (điểm danh tiếng 55 ≥ 50)", "t1_reputation_escalate"),
        ("WAF: Phát hiện SQL Injection trong 'uri'", "t1_waf_signature"),
        ("Prompt Injection Pattern: Phát hiện 'ignore' trong 'msg'", "t1_injection_signature"),
        ("Jailbreak Pattern: Phát hiện 'DAN' trong 'msg'", "t1_injection_signature"),
        ("Luật động [từ Tác tử]: Source IP='1.2.3.4'", "t1_dynamic_rule"),
        ("APT chain emergent: 3 ngày (phases=recon,exfil)", "t1_apt_chain"),
        ("Phát hiện dị biệt thống kê Zero-day [Total Fwd Packets]: Giá trị 240.0", "t1_zscore"),
        ("Truy cập cổng nhạy cảm (Cổng 445)", "t1_other"),
    ],
)
def test_classify_offload_mechanism_nhan_dien_dung_tung_co_che(reason, expected):
    assert primary_offload_mechanism({"tier1_reasons": [reason]}) == expected


def test_classify_offload_uu_tien_tri_nho_hon_dau_hieu_noi_dung():
    """Một sự kiện thường mang NHIỀU lý do. Nhãn CHÍNH phải quy cho cơ chế THỰC SỰ quyết
    định: hai lớp trí nhớ ghi đè action nên phải thắng."""
    log = {
        "tier1_reasons": [
            "Phát hiện dị biệt thống kê Zero-day [Total Fwd Packets]: Giá trị 240.0",
            "WAF: Phát hiện SQL Injection trong 'uri'",
            "TRÍ NHỚ Tier-1: IP đã bị chặn gần đây (blacklist TTL 1h)",
        ]
    }
    assert primary_offload_mechanism(log) == "t1_blacklist_memory"


def test_classify_offload_giu_DU_moi_co_che_da_khai_hoa():
    """HỒI QUY (đo trên 2 lượt đẩy thật): bản một-nhãn khiến chữ ký WAF báo 337 -> 0 và trí
    nhớ blacklist 106 -> 0 ở lượt warm, chỉ vì nhãn 'danh tiếng' đứng trước và che hết. Bảng
    cơ chế khi đó KHÔNG so được giữa các lượt — đúng bảng dùng để trả lời RQ1."""
    log = {
        "tier1_reasons": [
            "IP có tiền sử NGUY HIỂM (điểm danh tiếng 100 ≥ 70) → chặn tự động",
            "WAF: Phát hiện SQL Injection trong 'uri'",
            "TRÍ NHỚ Tier-1: IP đã bị chặn gần đây (blacklist TTL 1h)",
        ]
    }
    got = classify_offload_mechanisms(log)
    assert "t1_waf_signature" in got, "chữ ký WAF bị nhãn danh tiếng che mất"
    assert "t1_blacklist_memory" in got
    assert "t1_reputation_block" in got


def test_classify_offload_khong_no_khi_thieu_du_lieu():
    for log in ({}, {"tier1_reasons": None}, {"tier1_reasons": []}, {"tier1_reasons": "chuỗi"}):
        assert primary_offload_mechanism(log) == "t1_other"
        assert classify_offload_mechanisms(log) == ["t1_other"]


def test_moi_dau_hieu_offload_deu_con_ton_tai_trong_rule_engine():
    """CHỐNG TRÔI CHỮ: nếu ai đó sửa lời một lý do trong rule_engine/subscriber mà quên bảng
    dấu hiệu, bộ đếm sẽ âm thầm dồn hết về `t1_other` và báo cáo giảm tải thành vô nghĩa —
    không có gì đỏ lên để báo. Test này bắt đúng ca đó."""
    from pathlib import Path

    src = Path("src/tier1_filter/rule_engine.py").read_text(encoding="utf-8") + Path(
        "src/streaming/subscriber.py"
    ).read_text(encoding="utf-8")
    missing = [m for _k, m in OFFLOAD_MARKERS if m not in src]
    assert not missing, f"dấu hiệu không còn khớp mã nguồn: {missing}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
