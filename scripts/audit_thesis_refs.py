#!/usr/bin/env python3
"""Kiểm TRÍCH NGUỒN của luận văn — phần mà `audit_thesis_numbers.py` không với tới.

Bộ kiểm số lo chuyện "con số trong .tex có khớp JSON không". Bộ kiểm này lo chuyện khác hẳn
và cũng nguy hiểm không kém: **nguồn có đúng, có đủ, có chuẩn không**. Rà tay ngày 06/08/2026
tìm được bốn mục sai (một mục BỊA hoàn toàn: tác giả, nhan đề, nơi công bố, năm đều không có
thật), bảy mục nằm trong danh mục mà không ai trích, và bộ dữ liệu gánh gần trọn phần bằng
chứng tầng ứng dụng thì **không có mục tài liệu nào**. Không phép kiểm nào bắt được những
thứ đó, nên phải có tệp này.

NĂM PHÉP KIỂM:
  1. MỒ CÔI      — `\\bibitem` không ai `\\cite`. Chuẩn IEEE không cho phép.
  2. TREO        — `\\cite` không có `\\bibitem` tương ứng (LaTeX in ra `[?]`).
  3. GƯƠNG       — danh mục EN và VI phải trùng khoá, trùng thứ tự, trùng nội dung. Tài liệu
                   tham khảo KHÔNG dịch, nên lệch một ký tự là một bản đã sửa còn bản kia chưa.
  4. DỮ LIỆU     — mọi bộ dữ liệu gọi đích danh trong luận văn đều phải kèm `\\cite`.
  5. ĐÃ TRA      — mọi khoá phải có mặt trong `docs/Thesis/CITATION_AUDIT.md`, tức đã có người
                   mở nguồn gốc ra đối chiếu chứ không phải chép lại bản ghi cũ.

Phép kiểm 5 là phép quan trọng nhất về lâu dài. Bốn phép trên bắt lỗi CƠ HỌC; chỉ phép 5 bắt
được lỗi "mục này trông rất chuẩn nhưng chưa ai kiểm nó có thật không".

Chạy:  .venv/bin/python scripts/audit_thesis_refs.py
Đọc-thuần, không gọi mạng, không gọi mô hình.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEX = os.path.join(ROOT, "docs", "Thesis", "latex")
LEDGER = os.path.join(ROOT, "docs", "Thesis", "CITATION_AUDIT.md")
LANGS = ("thesis_latex_en", "thesis_latex_vi")

# Bộ dữ liệu nào gọi tên là phải dẫn nguồn. Khoá = biến thể chính tả gặp trong .tex.
# CSIC 2010 nằm đây vì nó từng bị gọi tên suốt Chương 4 mà không có lấy một `\cite`.
DATASETS = {
    "CSE-CIC-IDS2018": "ids2018",
    "CSIC 2010": "csic2010",
    "DAPT2020": "dapt2020",
    "AdvBench": "advbench2023",
    "deepset": "deepset2023",
    "jackhhao": "jackhhao2023",
}

RE_BIBITEM = re.compile(r"\\bibitem\{([^}]*)\}")
RE_CITE = re.compile(r"\\cite\{([^}]*)\}")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def sources(lang: str) -> dict[str, str]:
    """main.tex + mọi chương, giữ theo tên tệp để báo lỗi còn chỉ được chỗ."""
    base = os.path.join(TEX, lang)
    out = {"main.tex": read(os.path.join(base, "main.tex"))}
    chapters = os.path.join(base, "chapters")
    for name in sorted(os.listdir(chapters)):
        if name.endswith(".tex"):
            out[name] = read(os.path.join(chapters, name))
    return out


def cited_keys(docs: dict[str, str]) -> dict[str, set[str]]:
    """khoá -> tập tệp có trích nó."""
    out: dict[str, set[str]] = {}
    for fname, text in docs.items():
        for group in RE_CITE.findall(text):
            for key in group.split(","):
                key = key.strip()
                if key:
                    out.setdefault(key, set()).add(fname)
    return out


def bib_entries(main_tex: str) -> list[tuple[str, str]]:
    """[(khoá, nội dung đã chuẩn hoá khoảng trắng)] theo đúng thứ tự xuất hiện."""
    body = main_tex.split(r"\begin{thebibliography}", 1)
    if len(body) < 2:
        return []
    body = body[1].split(r"\end{thebibliography}", 1)[0]
    parts = re.split(r"\\bibitem\{([^}]*)\}", body)
    out = []
    for i in range(1, len(parts) - 1, 2):
        out.append((parts[i], " ".join(parts[i + 1].split())))
    return out


def main() -> int:
    print("=" * 78)
    print("KIỂM TRÍCH NGUỒN LUẬN VĂN")
    print("=" * 78)
    fail = 0

    per_lang: dict[str, tuple[list[tuple[str, str]], dict[str, set[str]]]] = {}
    for lang in LANGS:
        docs = sources(lang)
        per_lang[lang] = (bib_entries(docs["main.tex"]), cited_keys(docs))

    # ── 1 & 2: mồ côi và treo ────────────────────────────────────────────────
    for lang in LANGS:
        entries, cites = per_lang[lang]
        keys = [k for k, _ in entries]
        orphan = [k for k in keys if k not in cites]
        dangling = sorted(k for k in cites if k not in keys)
        dup = sorted({k for k in keys if keys.count(k) > 1})

        print(f"\n── {lang}: {len(keys)} mục · {len(cites)} khoá được trích ──")
        if orphan:
            fail += 1
            print(f"  ✗ MỒ CÔI ({len(orphan)}): " + ", ".join(orphan))
            print("    (mục nằm trong danh mục mà không ai trích — IEEE không cho phép)")
        else:
            print("  ✓ không có mục mồ côi")
        if dangling:
            fail += 1
            print(f"  ✗ TREO ({len(dangling)}): " + ", ".join(dangling))
        else:
            print("  ✓ không có tham chiếu treo")
        if dup:
            fail += 1
            print(f"  ✗ TRÙNG KHOÁ: {', '.join(dup)}")

    # ── 3: gương EN ⇄ VI ─────────────────────────────────────────────────────
    en, vi = per_lang["thesis_latex_en"][0], per_lang["thesis_latex_vi"][0]
    print("\n── Gương danh mục EN ⇄ VI ──")
    if [k for k, _ in en] != [k for k, _ in vi]:
        fail += 1
        only_en = [k for k, _ in en if k not in {k for k, _ in vi}]
        only_vi = [k for k, _ in vi if k not in {k for k, _ in en}]
        print(f"  ✗ khoá lệch — chỉ EN: {only_en or '—'} · chỉ VI: {only_vi or '—'}")
    else:
        diff = [k for (k, a), (_, b) in zip(en, vi, strict=True) if a != b]
        if diff:
            fail += 1
            print(f"  ✗ NỘI DUNG LỆCH ({len(diff)}): {', '.join(diff)}")
            print("    (tài liệu tham khảo KHÔNG dịch — hai bản phải giống từng ký tự)")
        else:
            print(f"  ✓ {len(en)} mục trùng khớp khoá, thứ tự và nội dung")

    # ── 4: bộ dữ liệu gọi tên thì phải dẫn nguồn ─────────────────────────────
    print("\n── Bộ dữ liệu gọi đích danh phải có \\cite ──")
    missing_ds = []
    for lang in LANGS:
        _, cites = per_lang[lang]
        docs = sources(lang)
        blob = "\n".join(docs.values())
        for name, key in DATASETS.items():
            if name in blob and key not in cites:
                missing_ds.append(f"{lang}: {name} -> thiếu \\cite{{{key}}}")
    if missing_ds:
        fail += 1
        for m in missing_ds:
            print(f"  ✗ {m}")
    else:
        print(f"  ✓ cả {len(DATASETS)} bộ dữ liệu đều được dẫn nguồn")

    # ── 5: số lượng mục kho tri thức phải khớp kho THẬT ──────────────────────
    # Bắt được lỗi thật ngày 07/08: tóm tắt ghi "107 quy trình NIST SP 800-61r2" trong khi
    # kho chỉ có 13 control (193 đoạn đã lập chỉ mục). Con số 107 KHÔNG có nguồn ở bất kỳ đâu
    # trong repo — nó trôi vào từ một ghi chú cũ. Kho tri thức nằm ngoài `experiments/results/`
    # nên bộ kiểm số không với tới; phải canh ở đây.
    print("\n── Số mục kho tri thức trong luận văn ⇄ kho thật ──")
    kb = os.path.join(ROOT, "knowledge_base")
    try:
        import json

        with open(os.path.join(kb, "mitre_attack.json"), encoding="utf-8") as fh:
            n_mitre = len(json.load(fh))
        with open(os.path.join(kb, "nist_800_61r2.json"), encoding="utf-8") as fh:
            n_nist = len(json.load(fh)["controls"])
    except (OSError, KeyError, ValueError) as exc:
        fail += 1
        print(f"  ✗ không đọc được kho tri thức: {exc}")
    else:
        blob = "\n".join(v for lang in LANGS for v in sources(lang).values())
        # Mọi số đứng ngay trước "MITRE ATT&CK" / "NIST SP 800-61" đều phải là số thật.
        bad = []
        for label, truth, pattern in (
            (
                "MITRE ATT&CK",
                n_mitre,
                # `STIX` có thể đi kèm SỐ PHIÊN BẢN ("STIX 2.1 MITRE ATT&CK"). Số ấy là
                # phiên bản chuẩn, không phải số mục trong kho, nên phải nuốt cả nó vào
                # phần tuỳ chọn thay vì để nó rơi vào nhóm bắt. Không có `[\d.]*` ở đây
                # thì câu "433 STIX 2.1 MITRE ATT&CK entries" bị đọc thành "21 mục MITRE".
                r"(\d[\d.,]*)\s*(?:STIX[^\s]*\s+(?:[\d.]+\s+)?)?(?:mục\s+)?(?:kỹ thuật\s+)?MITRE",
            ),
            ("NIST SP 800-61", n_nist, r"(\d[\d.,]*)\s*(?:quy trình\s+)?NIST SP 800-61"),
        ):
            for m in re.finditer(pattern, blob):
                got = int(m.group(1).replace(".", "").replace(",", ""))
                if got != truth:
                    bad.append(f"{label}: luận văn ghi {got}, kho thật có {truth}")
        if bad:
            fail += 1
            for b in sorted(set(bad)):
                print(f"  ✗ {b}")
        else:
            print(f"  ✓ MITRE {n_mitre} · NIST {n_nist} control — mọi số nêu đều khớp kho")

    # ── 6: đã có người tra nguồn gốc chưa ────────────────────────────────────
    print("\n── Đối chiếu sổ tra nguồn gốc ──")
    if not os.path.exists(LEDGER):
        fail += 1
        print(f"  ✗ THIẾU {os.path.relpath(LEDGER, ROOT)} — không có bằng chứng đã tra mục nào")
    else:
        ledger = read(LEDGER)
        untraced = [k for k, _ in en if f"`{k}`" not in ledger]
        if untraced:
            fail += 1
            print(f"  ✗ CHƯA TRA ({len(untraced)}): {', '.join(untraced)}")
            print("    (thêm mục mới thì phải mở nguồn gốc ra đối chiếu rồi ghi vào sổ)")
        else:
            print(f"  ✓ cả {len(en)} mục đều có trong sổ tra")

    # ── 7: danh mục phải xếp theo THỨ TỰ TRÍCH LẦN ĐẦU (kiểu số IEEE) ────────
    # Phép kiểm này sinh ra sau một lần hỏng thật: nén lại văn ở các chương làm
    # đổi chỗ lần trích đầu tiên, và 25/38 vị trí lệch đi mà không có gì báo.
    print("\n── Thứ tự danh mục ⇄ thứ tự trích lần đầu (IEEE) ──")
    order_files = (
        "main.tex",
        "ch1_introduction.tex",
        "ch2_theoretical_background.tex",
        "ch3_system_design.tex",
        "ch4_experiments_evaluation.tex",
        "ch5_conclusion.tex",
    )
    for lang in LANGS:
        docs = sources(lang)
        entries, _ = per_lang[lang]
        listed = [k for k, _ in entries]
        first: list[str] = []
        for fname in order_files:
            text = docs.get(fname, "")
            # main.tex: chỉ phần TRƯỚC danh mục mới tính là trích trong thân bài
            if fname == "main.tex":
                text = text.split(r"\begin{thebibliography}", 1)[0]
            for group in RE_CITE.findall(text):
                for key in (k.strip() for k in group.split(",")):
                    if key and key not in first:
                        first.append(key)
        # strict=False có chủ ý: nếu hai danh sách lệch độ dài thì đó là mục mồ côi
        # hoặc tham chiếu treo, và phép kiểm 1-2 ở trên đã báo rõ ràng hơn nhiều so
        # với một ValueError ném ra từ đây.
        off = [i for i, (a, b) in enumerate(zip(listed, first, strict=False), 1) if a != b]
        if off:
            fail += 1
            i = off[0]
            print(f"  ✗ {lang}: {len(off)}/{len(listed)} vị trí lệch — đầu tiên ở số [{i}]:")
            print(f"      danh mục ghi '{listed[i - 1]}' nhưng nơi trích trước là '{first[i - 1]}'")
        else:
            print(f"  ✓ {lang}: {len(listed)} mục đúng thứ tự trích lần đầu")

    print("\n" + "=" * 78)
    if fail:
        print(f"{fail} nhóm phép kiểm KHÔNG ĐẠT — xem chi tiết ở trên.")
    else:
        print(
            "TẤT CẢ ĐẠT: 0 mồ côi · 0 treo · 0 lệch gương · 0 dữ liệu thiếu nguồn "
            "· 0 chưa tra · 0 lệch thứ tự IEEE"
        )
    print("=" * 78)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
