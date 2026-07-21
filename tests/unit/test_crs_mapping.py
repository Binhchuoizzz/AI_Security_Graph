"""Bảo đảm ánh xạ chữ ký WAF → OWASP CRS KHÔNG BAO GIỜ trôi khỏi code thật.

Ánh xạ này là câu trả lời cho phản biện "luật do các anh tự nghĩ ra". Nếu ai đó thêm một
họ chữ ký mà quên ánh xạ, bảng sẽ âm thầm không còn phủ hết — test này bắt ngay.
"""

from src.tier1_filter.crs_mapping import (
    CRS_MAPPING,
    OUT_OF_CRS_SCOPE,
    coverage_summary,
)
from src.tier1_filter.rule_engine import _WAF_PATTERNS


def test_every_signature_family_has_a_mapping():
    """MỌI họ chữ ký trong rule_engine PHẢI có mục ánh xạ — không sót cái nào."""
    missing = sorted(set(_WAF_PATTERNS) - set(CRS_MAPPING))
    assert not missing, f"Họ chữ ký thiếu ánh xạ CRS: {missing}"


def test_no_orphan_mapping_entries():
    """Không có mục ánh xạ cho họ chữ ký ĐÃ BỊ XOÁ (bảng không được phình rác)."""
    orphans = sorted(set(CRS_MAPPING) - set(_WAF_PATTERNS))
    assert not orphans, f"Ánh xạ trỏ tới họ không còn tồn tại: {orphans}"


def test_crs_files_follow_official_naming():
    """Tên file CRS phải đúng quy ước `REQUEST-9xx-...` của CRS 3.x (chống bịa định danh)."""
    for family, ref in CRS_MAPPING.items():
        if ref.crs_file == OUT_OF_CRS_SCOPE:
            continue
        assert ref.crs_file.startswith("REQUEST-9"), f"{family}: tên file CRS lạ '{ref.crs_file}'"


def test_out_of_scope_entries_name_an_alternative_framework():
    """Họ nằm ngoài CRS PHẢI nêu khung thay thế — không được để trống rồi lờ đi."""
    for family, ref in CRS_MAPPING.items():
        if ref.crs_file != OUT_OF_CRS_SCOPE:
            continue
        assert any(k in ref.note for k in ("Sigma", "ATT&CK")), (
            f"{family}: ngoài phạm vi CRS thì phải nêu khung đối ứng (Sigma/ATT&CK)"
        )


def test_every_entry_explains_itself():
    """Mỗi ánh xạ phải có ghi chú lý do — bảng không lời giải thích thì không kiểm chứng được."""
    for family, ref in CRS_MAPPING.items():
        assert ref.note.strip(), f"{family}: thiếu ghi chú lý do ánh xạ"


def test_coverage_summary_is_consistent():
    """Con số trích vào luận văn phải ĐẾM TỪ BẢNG, không nhập tay."""
    s = coverage_summary()
    assert s["total"] == len(_WAF_PATTERNS)
    assert s["mapped_to_crs"] + s["beyond_crs_scope"] == s["total"]
    assert s["mapped_to_crs"] > 0 and s["distinct_crs_files"] > 0
