"""Khoá bộ dựng badge của Dashboard — chống tái phát giá trị BỊA trên màn hình.

VÌ SAO CÓ TỆP NÀY. Cùng một logic badge từng có BA bản chép tay (thẻ cảnh báo, cụm HITL,
thẻ chặn Tier-1). Chúng trôi dạt khỏi nhau, và bốn giá trị bịa phải sửa HAI LẦN ở hai tệp
mới hết. Nay logic gom về `src/ui/components.py`; test này khoá cả hành vi lẫn việc không
ai chép lại bản thứ hai.

Bốn giá trị bịa đã bị loại (giữ tên ở đây làm mốc hồi quy):
  1. `Threat Memory: 13 sự cố (10 Block · 3 HITL/Audit) · Risk: 100.0/100` hardcode, kích
     hoạt một phần bởi việc chuỗi IP demo "198.51.100" xuất hiện trong target;
  2. `default_top5` độn 5 mã vào panel dán nhãn "Top-5 Ứng viên RAG Truy xuất (FAISS+BM25)"
     dù chúng chưa từng qua RAG;
  3. in `T1190 - Exploit Public-Facing Application` khi hệ thật sự trả `N/A`;
  4. `Live GPU (TTFT 0.3s)` — con số không đến từ phép đo nào.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

from src.ui import components as C

SRC_DIR = Path(__file__).resolve().parents[2] / "src" / "ui"


# ── parse_mitre_technique ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("Agent: SQLi [MITRE: T1190] Confidence: 0.9", "T1190"),
        ("[MITRE: T1059.007 [Tự suy luận]]", "T1059.007 [Tự suy luận]"),  # ngoặc lồng
        ("phát hiện AML.T0051 prompt injection", "AML.T0051"),
        ("chỉ có mã trần T1595.003 trong câu", "T1595.003"),
        ("không có mã kỹ thuật nào ở đây", "N/A"),
        ("", "N/A"),
    ],
)
def test_parse_mitre_technique(reason, expected):
    assert C.parse_mitre_technique(reason) == expected


def test_khong_ma_thi_khong_duoc_doan_thanh_t1190():
    """Lỗi cũ: N/A bị thay bằng T1190 — màn hình công bố kỹ thuật hệ chưa hề kết luận."""
    for reason in ("hệ không quy kết được", "unmappable", "Confidence: 0.31"):
        assert "T1190" not in C.parse_mitre_technique(reason)


# ── build_threat_memory_badge ──────────────────────────────────────────────────────
def test_threat_memory_khong_co_du_lieu_thi_noi_la_khong_co():
    html = C.build_threat_memory_badge("Agent: cảnh báo thường, không có lịch sử")
    assert "chưa có dữ liệu uy tín" in html
    for bia in ("100.0", "13 sự cố", "Risk:", "1 sự cố"):
        assert bia not in html, f"badge bịa lại giá trị {bia!r}"


def test_threat_memory_chi_hien_phan_parse_duoc():
    """Có sự cố nhưng KHÔNG có điểm uy tín ⇒ không được tự gắn Risk."""
    html = C.build_threat_memory_badge("IP này có 7 incidents 4 blocks")
    assert "7 sự cố" in html and "4 Block" in html and "3 HITL/Audit" in html
    assert "Risk:" not in html


def test_threat_memory_day_du():
    html = C.build_threat_memory_badge("5 incidents 5 blocks reputation score of 92.5/100")
    assert "5 sự cố (5 Block)" in html and "Risk: 92.5/100" in html
    assert "HITL/Audit" not in html  # 5-5=0 ⇒ không hiện phần dư


def test_threat_memory_khong_suy_tu_chuoi_ip_demo():
    """IP demo trong nội dung KHÔNG được tự sinh ra lịch sử uy tín."""
    html = C.build_threat_memory_badge("truy cập từ 198.51.100.15 tới cổng 22")
    assert "chưa có dữ liệu uy tín" in html


# ── build_technique_codes_html ─────────────────────────────────────────────────────
def test_khong_co_ma_thi_an_han_khoi():
    assert C.build_technique_codes_html("không có mã nào") == ""


def test_khong_don_ma_cho_du_nam():
    """Lỗi cũ: độn default_top5 rồi dán nhãn 'RAG truy xuất'."""
    html = C.build_technique_codes_html("chỉ nêu T1190 thôi")
    assert html.count("<code") == 1
    for don in ("T1595.003", "T1059.007", "T1083", "T1046"):
        assert don not in html, f"vẫn độn {don}"
    assert "(1)" in html  # số hiện ra phải là số mã THẬT


def test_nhan_khong_duoc_noi_la_rag_truy_xuat():
    """Các mã này đọc từ chuỗi phán quyết, KHÔNG phải đầu ra của FAISS/BM25."""
    html = C.build_technique_codes_html("T1190 và T1083")
    assert "FAISS" not in html and "BM25" not in html and "Top-5" not in html


def test_khu_trung_va_cat_nam():
    html = C.build_technique_codes_html(" ".join(f"T1{i:03d}" for i in range(100, 110)) + " T1100")
    assert html.count("<code") == 5  # cắt đúng 5, không nhiều hơn


# ── build_origin_badge ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("reason", "mong_doi"),
    [
        ("PHÁN QUYẾT TÁI SỬ DỤNG từ ResponseCache", "Semantic Cache Hit"),
        ("suy luận mới trên GPU", "Live GPU"),
    ],
)
def test_origin_badge(reason, mong_doi):
    html = C.build_origin_badge(reason)
    assert mong_doi in html
    assert "TTFT" not in html, "badge nguồn không đo thời gian — không được gắn số"


# ── build_grounding_badge · build_guardrail_note ───────────────────────────────────
def test_grounding_theo_ma_ky_thuat():
    _, gr = C.build_grounding_badge("Agent: [MITRE: T1190]", "T1190")
    assert gr is True
    html, gr = C.build_grounding_badge("unmappable technique", "N/A")
    assert gr is False and "DEGRADED SAFEGUARD" in html


def test_guardrail_note_chi_hien_cho_await_hitl():
    assert C.build_guardrail_note(True, "T1190", "BLOCK_IP") == ""
    assert "AWAIT_HITL" in C.build_guardrail_note(True, "T1190", "AWAIT_HITL")


# ── build_tier1_block_badge ────────────────────────────────────────────────────────
def test_tier1_badge_khong_dan_nhan_phan_tram_cho_diem_luat():
    """`tier1_score` là bộ CỘNG DỒN không chặn trên (+50/+40/+30/+100/+z…).

    Bản cũ in `Risk: {score}/100` nên hai luật cùng khớp là ra "Risk: 150/100" — một phần
    trăm bất khả thi. Thang 0–100 là của `reputation_score` (Threat Memory), không phải của
    `tier1_score`.
    """
    html = C.build_tier1_block_badge(count=3, tier1_score=150)
    assert "/100" not in html
    assert "150" in html and "3 lần chặn" in html


def test_tier1_badge_khong_nhan_nham_la_threat_memory():
    """Nguồn là ring buffer `tier1_blocks.json` TTL 1h, không phải kho uy tín SQLite."""
    html = C.build_tier1_block_badge(count=1, tier1_score=20)
    assert "Threat Memory" not in html
    assert "Tier-1 Rule Engine" in html


def test_tier1_badge_khong_in_mot_bien_thanh_hai_so():
    """Bản cũ: `{count} sự cố ({count} Block)` — cùng một biến, trông như hai số độc lập."""
    html = C.build_tier1_block_badge(count=4, tier1_score=60)
    assert html.count("4") == 1


# ── Quét mã nguồn: không ai chép lại bản thứ hai ───────────────────────────────────
def _ma_thuc_thi(duong_dan: Path) -> str:
    """Trả mã ĐANG CHẠY, đã bỏ chú thích và docstring.

    Phải lọc bằng AST chứ không lọc dòng `#`: các tên bịa cũ CỐ Ý được nhắc lại trong
    docstring của `components.py` để ghi vết lỗi. Lọc thô sẽ báo động giả trên chính phần
    tài liệu hoá. `ast.unparse` bỏ chú thích sẵn; docstring thì gỡ tay.
    """
    cay = ast.parse(duong_dan.read_text(encoding="utf-8"))
    for nut in ast.walk(cay):
        if isinstance(nut, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            than = nut.body
            if (
                than
                and isinstance(than[0], ast.Expr)
                and isinstance(than[0].value, ast.Constant)
                and isinstance(than[0].value.value, str)
            ):
                than.pop(0)
                if not than:
                    than.append(ast.Pass())
    return ast.unparse(cay)


@pytest.mark.parametrize("ten_tep", ["app.py", "components.py"])
@pytest.mark.parametrize(
    "dau_hieu",
    [
        r"default_top5",
        r"TTFT\s*0\.3\s*s",
        r"13\s+sự\s+cố",
        r"['\"]198\.51\.100['\"]\s+in\b",
        r"T1190\s*-\s*Exploit Public-Facing Application",
        r"Top-5 Ứng viên RAG Truy xuất",
    ],
)
def test_khong_con_dau_hieu_gia_tri_bia(ten_tep, dau_hieu):
    ma = _ma_thuc_thi(SRC_DIR / ten_tep)
    assert not re.search(dau_hieu, ma), f"{ten_tep} bịa lại {dau_hieu!r}"


def test_app_khong_tu_dung_badge_ma_goi_bo_dung_chung():
    """Chống chép bản thứ hai: app.py phải GỌI components chứ không tự ghép chuỗi badge."""
    ma = (SRC_DIR / "app.py").read_text(encoding="utf-8")
    for ten in ("GROUNDED IN RAG", "DEGRADED SAFEGUARD", "Semantic Cache Hit"):
        assert ten not in ma, f"app.py chép lại badge {ten!r} — phải gọi components.build_*"


def test_render_alert_card_dung_bo_dung_chung():
    src = inspect.getsource(C.render_alert_card)
    for ham in (
        "build_grounding_badge",
        "build_origin_badge",
        "build_threat_memory_badge",
        "build_technique_codes_html",
        "build_guardrail_note",
    ):
        assert ham in src, f"render_alert_card không dùng {ham}"


def test_sidecar_tier1_ghi_cung_mot_hinh_dang():
    """Hai nhánh (Cổng ML và rule engine) phải cùng đi qua `_tier1_block_record`.

    Lỗi cũ: nhánh Cổng ML append thẳng `evaluated_log` (khoá "Source IP"), còn bên đọc
    `_get_tier1_blocks()` lọc bằng `b.get("ip")` ⇒ mọi IP do Cổng ML chặn bị bỏ lặng lẽ,
    không bao giờ hiện trên Dashboard.
    """
    ma = (Path(__file__).resolve().parents[2] / "src" / "streaming" / "subscriber.py").read_text(
        encoding="utf-8"
    )
    appends = re.findall(r"tier1_recent_blocks\.append\(\s*([^\n]*)", ma)
    assert len(appends) >= 2, "chờ ít nhất 2 chỗ append"
    for a in appends:
        assert "_tier1_block_record" in a or a.strip() == "", (
            f"append không qua _tier1_block_record: {a!r}"
        )
