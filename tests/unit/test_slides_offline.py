"""Deck bảo vệ phải chạy được KHÔNG CẦN MẠNG và trình bày số theo quy ước Việt.

VÌ SAO CÓ TỆP NÀY. Deck từng nạp 6 tài nguyên từ CDN (Google Fonts, Font Awesome, KaTeX
CSS + 2 JS). Phòng bảo vệ mất mạng, chặn CDN, hay dính captive portal là hỏng đúng lúc
không sửa được: 40 công thức hiện nguyên `$\\mathcal{O}(1)$` giữa slide, 65 icon thành ô
trống, chữ Việt rơi về font hệ thống. Không có cảnh báo nào — deck vẫn "mở được", chỉ là
xấu và sai.

Ba phép kiểm dưới đây đo SẢN PHẨM (tệp HTML và các tệp assets có thật trên đĩa), không đọc
dòng khai báo.
"""

import html as html_lib
import os
import re
from pathlib import Path

import pytest

DECK = Path(__file__).resolve().parents[2] / "docs" / "Thesis" / "slides" / "index.html"


@pytest.fixture(scope="module")
def deck() -> str:
    return DECK.read_text(encoding="utf-8")


def _phan_hien_thi(raw: str) -> str:
    """Chỉ phần người xem ĐỌC ĐƯỢC: bỏ <style>/<script> rồi bóc thẻ."""
    body = re.sub(r"<style.*?</style>", "", raw, flags=re.S)
    body = re.sub(r"<script.*?</script>", "", body, flags=re.S)
    return re.sub(r"\s+", " ", html_lib.unescape(re.sub(r"<[^>]+>", " ", body)))


def test_deck_khong_goi_ra_mang(deck):
    """0 tài nguyên ngoài. Thêm CDN mới thì vendor vào `assets/`, đừng trỏ URL."""
    ngoai = sorted(set(re.findall(r'(?:href|src)="(https?://[^"]+)"', deck)))
    assert not ngoai, "deck còn phụ thuộc mạng:\n  " + "\n  ".join(ngoai)


def test_moi_tai_nguyen_cuc_bo_ton_tai_that(deck):
    """Trỏ vào `assets/` chưa đủ — tệp phải CÓ THẬT, và CSS con cũng phải phân giải hết."""
    thieu = []
    goc = DECK.parent

    for p in sorted(set(re.findall(r'(?:href|src)="(assets/[^"]+)"', deck))):
        if not (goc / p).is_file():
            thieu.append(f"{DECK.name} -> {p}")

    # đệ quy một cấp: mỗi CSS tự tham chiếu woff2 của nó
    for css in goc.glob("assets/**/*.css"):
        txt = css.read_text(encoding="utf-8", errors="replace")
        assert not re.findall(r"url\(https?://", txt), f"{css.name} còn url() ra mạng"
        for u in set(re.findall(r'url\(["\']?(?!https?:|data:)([^)"\']+)["\']?\)', txt)):
            đích = os.path.normpath(os.path.join(css.parent, u.split("?")[0].split("#")[0]))
            if not os.path.isfile(đích):
                thieu.append(f"{css.name} -> {u}")

    assert not thieu, "tài nguyên khai báo nhưng không có trên đĩa:\n  " + "\n  ".join(thieu)


def test_so_trinh_bay_theo_quy_uoc_viet(deck):
    """Deck tiếng Việt thì dấu thập phân là PHẨY, ở mọi chỗ.

    Bản cũ trộn cả hai trong cùng một bảng — `97.5%` cạnh `9,8%` — và vài giá trị xuất hiện
    hai kiểu (`59.2%` lẫn `59,2%`). Chỉ tính phần hiển thị: CSS (`font-size: 15.5px`) và mã
    JS giữ nguyên dấu chấm là đúng.
    """
    lech = sorted(set(re.findall(r"\b\d+\.\d+\s*%", _phan_hien_thi(deck))))
    assert not lech, f"còn dấu thập phân kiểu Anh trong nội dung hiển thị: {lech}"
