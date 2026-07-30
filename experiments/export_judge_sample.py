"""SENTINEL — Hạ tầng KIỂM ĐỊNH trọng tài LLM bằng NGƯỜI (Cohen's κ).

VẤN ĐỀ ĐANG GIẢI: điểm LLM-as-Judge hiện dựa vào MỘT trọng tài duy nhất (Llama-3 chấm
Gemma-2) và KHÔNG mẫu nào được người đối chiếu. Hệ quả: khi Context Precision thấp, ta
KHÔNG phân biệt được hai khả năng hoàn toàn khác nhau —
    (a) tác tử suy luận kém thật, hay
    (b) trọng tài chấm sai.
Cho người chấm một mẫu con rồi tính Cohen's κ là cách rẻ nhất để biết điểm của trọng tài
có đáng tin không. Thiếu bước này, mọi kết luận rút từ điểm trọng tài đều treo lơ lửng.

QUY TRÌNH HAI BƯỚC
  1. export — lấy mẫu PHÂN TẦNG theo điểm trọng tài (để dải điểm nào cũng có đại diện,
     không chỉ toàn ca dễ) rồi ghi CSV. Cột điểm để TRỐNG cho người điền.
       .venv/bin/python experiments/export_judge_sample.py export --n 50
  2. kappa — sau khi người chấm xong, đọc lại CSV và tính κ cho từng chiều.
       .venv/bin/python experiments/export_judge_sample.py kappa --rated <file>.csv

CHỐNG THIÊN VỊ NGƯỜI CHẤM: CSV xuất ra **cố ý KHÔNG chứa điểm của trọng tài**. Nhìn thấy
điểm máy trước khi chấm là kiểu mồi (anchoring) kinh điển — κ sẽ bị thổi lên một cách giả
tạo và mất sạch giá trị kiểm định. Điểm trọng tài nằm ở file `.key.json` đi kèm, chỉ được
đọc ở bước tính κ.

Thang đọc κ (Landis & Koch): <0,20 rất kém · 0,21–0,40 kém · 0,41–0,60 vừa ·
0,61–0,80 tốt · >0,80 rất tốt. κ thấp KHÔNG tự động nghĩa là trọng tài sai — nó nghĩa là
điểm trọng tài chưa đủ tin cậy để đứng một mình trong luận văn.
"""

import argparse
import csv
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import cohens_kappa  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JUDGE_RESULTS = os.path.join(ROOT, "experiments", "results", "reasoning_eval_results.json")
OUT_CSV = os.path.join(ROOT, "experiments", "results", "judge_human_sample.csv")
OUT_KEY = os.path.join(ROOT, "experiments", "results", "judge_human_sample.key.json")
OUT_KAPPA = os.path.join(ROOT, "experiments", "results", "judge_agreement_results.json")

DIMENSIONS = ("context_precision", "answer_relevancy", "faithfulness", "context_recall")


def do_export(n: int) -> None:
    if not os.path.exists(JUDGE_RESULTS):
        print(f"[-] Chưa có {JUDGE_RESULTS} — chạy experiments/evaluate_reasoning.py trước.")
        sys.exit(1)
    with open(JUDGE_RESULTS, encoding="utf-8") as f:
        data = json.load(f)
    scores = data.get("scores", [])
    if not scores:
        print("[-] File kết quả trọng tài rỗng.")
        sys.exit(1)

    # PHÂN TẦNG theo điểm trung bình của trọng tài: nếu lấy ngẫu nhiên thuần, mẫu sẽ bị
    # dải điểm phổ biến nhất chi phối và κ chỉ phản ánh mỗi vùng đó.
    def _mean(entry) -> float:
        s = entry.get("scores", {})
        vals = [s.get(d) for d in DIMENSIONS if isinstance(s.get(d), (int, float))]
        return sum(vals) / len(vals) if vals else 0.0

    buckets: dict[int, list] = {}
    for e in scores:
        buckets.setdefault(int(round(_mean(e))), []).append(e)
    per_bucket = max(1, n // max(1, len(buckets)))

    picked = []
    for _b, items in sorted(buckets.items()):
        picked.extend(items[:per_bucket])  # tất định: không random, tái lập được
    picked = picked[:n]

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", *[f"human_{d}" for d in DIMENSIONS], "human_notes"])
        for e in picked:
            w.writerow([e.get("sample_id", ""), "", "", "", "", ""])  # để TRỐNG cho người điền

    # Khoá đáp án của trọng tài — tách riêng để người chấm không bị mồi.
    with open(OUT_KEY, "w", encoding="utf-8") as f:
        json.dump(
            {
                e.get("sample_id", ""): {d: e.get("scores", {}).get(d) for d in DIMENSIONS}
                for e in picked
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"[+] Đã xuất {len(picked)} mẫu phân tầng -> {OUT_CSV}")
    print(f"[+] Khoá điểm trọng tài (ĐỪNG mở trước khi chấm) -> {OUT_KEY}")
    print(
        "\nHƯỚNG DẪN CHẤM: điền 1–5 cho từng chiều theo ĐÚNG rubric trong\n"
        "`evaluate_reasoning.py` (JUDGE_USER_TEMPLATE). Chấm xong chạy:\n"
        f"    .venv/bin/python experiments/export_judge_sample.py kappa --rated {OUT_CSV}"
    )


def do_kappa(rated_csv: str) -> None:
    if not os.path.exists(rated_csv) or not os.path.exists(OUT_KEY):
        print(f"[-] Cần cả {rated_csv} (người đã chấm) và {OUT_KEY} (khoá trọng tài).")
        sys.exit(1)
    with open(OUT_KEY, encoding="utf-8") as f:
        key = json.load(f)

    human: dict[str, dict] = {}
    with open(rated_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sid = row.get("sample_id", "")
            vals = {}
            for d in DIMENSIONS:
                raw = (row.get(f"human_{d}") or "").strip()
                if raw:
                    try:
                        vals[d] = int(float(raw))
                    except ValueError:
                        pass
            if vals:
                human[sid] = vals

    if not human:
        print("[-] Chưa có dòng nào được chấm — điền cột human_* rồi chạy lại.")
        sys.exit(1)

    by_dim: dict[str, dict] = {}
    print(f"\n{'Chiều':22s} {'n':>4s} {'κ':>8s}  Diễn giải")
    print("-" * 62)
    for d in DIMENSIONS:
        pairs = [
            (human[s][d], key[s][d])
            for s in human
            if d in human[s] and s in key and key[s].get(d) is not None
        ]
        if not pairs:
            continue
        k = cohens_kappa([a for a, _ in pairs], [b for _, b in pairs])
        interp = (
            "rất tốt"
            if k > 0.80
            else "tốt"
            if k > 0.60
            else "vừa"
            if k > 0.40
            else "kém"
            if k > 0.20
            else "RẤT KÉM — điểm trọng tài chưa đứng một mình được"
        )
        by_dim[d] = {"n": len(pairs), "kappa": k, "interpretation": interp}
        print(f"{d:22s} {len(pairs):>4d} {k:>8.4f}  {interp}")

    ks = [v["kappa"] for v in by_dim.values()]
    mean_kappa = round(sum(ks) / len(ks), 4) if ks else 0.0
    out = {
        "n_rated": len(human),
        "by_dimension": by_dim,
        "mean_kappa": mean_kappa,
        "note": (
            "κ thấp KHÔNG chứng minh trọng tài sai; nó chứng minh điểm trọng tài chưa đủ "
            "tin cậy để trích một mình. Khi κ thấp, phải báo cả điểm người lẫn điểm máy."
        ),
    }
    with open(OUT_KAPPA, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nκ trung bình: {mean_kappa}\n[+] JSON: {OUT_KAPPA}")


def main():
    ap = argparse.ArgumentParser(description="Kiểm định trọng tài LLM bằng người (Cohen's κ)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pe = sub.add_parser("export", help="Xuất mẫu phân tầng cho người chấm")
    pe.add_argument("--n", type=int, default=50)
    pk = sub.add_parser("kappa", help="Tính κ sau khi người đã chấm")
    pk.add_argument("--rated", default=OUT_CSV)
    args = ap.parse_args()

    if args.cmd == "export":
        do_export(args.n)
    else:
        do_kappa(args.rated)


if __name__ == "__main__":
    main()
