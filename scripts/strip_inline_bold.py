#!/usr/bin/env python3
"""Gỡ in đậm GIỮA ĐOẠN khỏi luận văn, giữ lại phần in đậm mang chức năng tiêu đề.

QUY TẮC (theo yêu cầu: "không in đậm chữ nào trong đoạn trừ tiêu đề hoặc chỉ mục"):

  GIỮ   nhãn dẫn đoạn — `\\textbf{...}` đứng ở ĐẦU dòng, ví dụ
        `\\textbf{Phân công kiến trúc giữa hai tầng.} Một kết quả...`
        Chương 4 cố ý không có mục con (theo góp ý của thầy), nên các nhãn này
        là cấu trúc điều hướng duy nhất của chương.
  GIỮ   nhãn đầu hàng bảng — cùng dạng "đứng đầu dòng", là chỉ mục của hàng.
  GIỮ   TOÀN BỘ hàng tiêu đề bảng — nhận diện bằng: mọi ô ngăn bởi `&` đều
        thuần `\\textbf{...}`. Không thể chỉ giữ ô đầu, vì khi đó hàng tiêu đề
        sẽ có một ô đậm và các ô còn lại nhạt.
  GỠ    mọi trường hợp còn lại: nhấn mạnh giữa câu, số liệu bôi đậm trong ô bảng.

CẨN TRỌNG VỀ NGOẶC LỒNG: `\\textbf{... \\texttt{x} ...}` phải cắt đúng ngoặc đóng
KHỚP CẶP, không phải dấu `}` đầu tiên gặp. Cắt sai một chỗ là hỏng cả tệp LaTeX,
và lỗi kiểu này thường chỉ lộ ra ở tận lượt biên dịch.

Chạy thử (không ghi):  .venv/bin/python scripts/strip_inline_bold.py --dry-run
Ghi thật:              .venv/bin/python scripts/strip_inline_bold.py
"""

from __future__ import annotations

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEX = os.path.join(ROOT, "docs", "Thesis", "latex")
LANGS = ("thesis_latex_en", "thesis_latex_vi")

BOLD = r"\textbf{"


def match_close(s: str, open_idx: int) -> int:
    """Chỉ số của `}` khớp cặp với `{` tại `open_idx`. Trả -1 nếu không cân bằng."""
    depth = 0
    i = open_idx
    while i < len(s):
        c = s[i]
        if c == "\\":  # bỏ qua ký tự được thoát: \{ \} \\
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def is_table_header(line: str) -> bool:
    """KHÔNG DÙNG NỮA — giữ lại để nêu rõ vì sao cách cũ sai.

    Cách cũ nhận diện hàng tiêu đề bằng "mọi ô đều thuần \\textbf{...}". Sai cả
    hai chiều, và cả hai chiều đều đã xảy ra thật:
      • hàng tiêu đề có `\\multicolumn` (Bảng 4.2) hoặc có ô `$n$` không bọc đậm
        (Bảng 4.6) thì KHÔNG khớp -> bị gỡ đậm oan;
      • hàng TỔNG toàn chữ đậm ("Cộng dồn", "Toàn bộ kỹ thuật") thì lại KHỚP ->
        được giữ, đúng thứ cần gỡ.
    Thay bằng `header_zone`: vùng giữa \\toprule và \\midrule đầu tiên của bảng.
    """
    body = line.strip()
    if "&" not in body:
        return False
    body = re.sub(r"\\\\\s*$", "", body).strip()
    cells = [c.strip() for c in body.split("&")]
    if len(cells) < 2:
        return False
    return all(re.fullmatch(r"\\textbf\{[^{}]*\}", c) for c in cells)


def strip_all(text: str) -> tuple[str, int]:
    """Gỡ mọi `\\textbf{...}` trong `text`. Trả (kết quả, số chỗ đã gỡ)."""
    removed = 0
    while True:
        idx = text.find(BOLD)
        if idx == -1:
            return text, removed
        close = match_close(text, idx + len(BOLD) - 1)
        if close == -1:  # ngoặc không cân bằng -> để nguyên, không đoán mò
            return text, removed
        text = text[:idx] + text[idx + len(BOLD) : close] + text[close + 1 :]
        removed += 1


def strip_line(line: str, in_header: bool) -> tuple[str, int, int]:
    """Trả (dòng đã xử lý, số chỗ giữ, số chỗ gỡ).

    `in_header`: dòng nằm trong vùng tiêu đề bảng (giữa \\toprule và \\midrule
    đầu tiên). Trong vùng đó, chữ đậm là tiêu đề cột nên giữ nguyên.
    """
    if in_header:
        return line, line.count(BOLD), 0

    # CHÍNH SÁCH HIỆN HÀNH: chữ đậm CHỈ được tồn tại ở hàng tiêu đề bảng. Nhãn dẫn
    # đoạn in đậm ("\textbf{Độ trễ.} Trên 500 sự kiện...") đã bị loại theo yêu cầu
    # "không in đậm linh tinh trong đoạn văn"; tiêu đề mục do \section lo, không cần
    # đậm thủ công. Xoá trắng nhãn thì đoạn còn lại vẫn đủ câu, nhưng phải ĐỌC LẠI:
    # vài nhãn mang mệnh đề chính (ví dụ "Quy kết: thêm tầng suy luận thì xấu đi")
    # nên đã được nhập vào câu đầu chứ không xoá.
    out, removed = strip_all(line)
    return out, 0, removed


def _unused_old_branch(line: str) -> tuple[str, int, int]:  # pragma: no cover
    # Ô DỮ LIỆU BẢNG: gỡ sạch, kể cả chỗ đứng đầu dòng. Một hàng có `&` mà không
    # phải hàng tiêu đề thì mọi chữ đậm trong đó là nhấn mạnh số liệu hoặc nhãn
    # hàng, không phải tiêu đề — đúng thứ mà yêu cầu "trong đoạn văn không in đậm
    # trừ tiêu đề" loại bỏ. Hàng tiêu đề đã được chặn ở nhánh trên.
    # CHỈ tính `&` KHÔNG được thoát. `\&` trong "MITRE ATT\&CK" là chữ, không phải
    # dấu ngăn cột; nhầm hai thứ này sẽ gỡ oan nhãn dẫn đoạn của mọi đoạn có nhắc
    # ATT&CK (đo được: Ch1 và Ch5 mất nhãn ở lượt chạy đầu).
    if re.search(r"(?<!\\)&", line):
        out, removed = strip_all(line)
        return out, 0, removed

    # Nhãn dẫn đoạn: giữ đúng MỘT chỗ ở đầu dòng.
    keep_until = 0
    stripped = line.lstrip()
    if stripped.startswith(BOLD):
        start = len(line) - len(stripped)
        close = match_close(line, start + len(BOLD) - 1)
        if close != -1:
            keep_until = close + 1

    head, tail = line[:keep_until], line[keep_until:]
    tail, removed = strip_all(tail)
    return head + tail, (1 if keep_until else 0), removed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="chỉ báo cáo, không ghi")
    args = ap.parse_args()

    total_kept = total_removed = 0
    for lang in LANGS:
        base = os.path.join(TEX, lang, "chapters")
        for name in sorted(os.listdir(base)):
            if not name.endswith(".tex"):
                continue
            path = os.path.join(base, name)
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().split("\n")

            out, kept, removed = [], 0, 0
            in_header = False  # giữa \toprule và \midrule đầu tiên của mỗi bảng
            for line in lines:
                if "\\toprule" in line:
                    in_header = True
                elif "\\midrule" in line or "\\bottomrule" in line:
                    in_header = False
                new, k, r = strip_line(line, in_header)
                out.append(new)
                kept += k
                removed += r

            if not args.dry_run and removed:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(out))

            total_kept += kept
            total_removed += removed
            print(f"  {lang[-2:]}/{name:38s} giữ {kept:3d}  gỡ {removed:3d}")

    print(f"\nTỔNG: giữ {total_kept} (tiêu đề/chỉ mục) · gỡ {total_removed} (giữa đoạn)")
    if args.dry_run:
        print("(chạy thử — chưa ghi tệp nào)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
