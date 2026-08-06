"""Gom mọi chỉ số RQ2 từ các tệp kết quả JSON ra MỘT báo cáo Markdown.

Cùng khuôn và cùng nguyên tắc với `collect_rq1_report.py`: đọc THẲNG từ JSON, không ai chép tay ở
giữa. **KHÔNG BỊA** — khoá thiếu thì in `—` và ghi rõ thiếu ở đâu, không suy ra, không điền mặc định.

RQ2 có một đặc thù phải tôn trọng khi đọc: mấy chỉ số ở đây đi theo CẶP, tách ra là mất nghĩa.
  · 2.a (chặn mẫu tấn công)  ↔  2.d (báo nhầm log lành)
  · 2.f (bắt được giả mạo)   ↔  2.g (chỗ KHÔNG bắt được)
Báo cáo vì thế in chúng cạnh nhau và nhắc lại điều đó ở từng mục.

Chạy:  .venv/bin/python scripts/collect_rq2_report.py [--ledger logs/rq2/_ledger_*.tsv]
"""

import argparse
import json
import os
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "experiments", "results")
OUT = os.path.join(ROOT, "reports")

# (mã, tên, tệp JSON, [(nhãn, đường-dẫn-khoá)]) + ghi chú TUỲ CHỌN in dưới tiêu đề.
CHI_SO: list[tuple] = [
    (
        "2.a",
        "Rào chắn TĨNH chặn được bao nhiêu",
        "robustness_results.json",
        [
            ("Tổng mẫu đối kháng", "summary.total"),
            ("Chặn được", "summary.blocked"),
            ("TỈ LỆ CHẶN (%)", "summary.block_rate_pct"),
            ("Tỉ lệ lọt (%)", "summary.bypass_rate_pct"),
            ("BẢNG THEO NHÓM", "@dict:summary.by_category"),
        ],
        "⚠️ Đọc kèm **2.d** ngay dưới. Tỉ lệ chặn không có vế âm là tỉ lệ không diễn giải được — "
        "một lớp gắn cờ MỌI thứ cũng đạt chặn 100%.",
    ),
    (
        "2.d",
        "Báo động giả trên log LÀNH (cặp bắt buộc của 2.a)",
        "adversarial_negative_results.json",
        [
            ("n log lành", "n_benign"),
            ("Bị gắn cờ nhầm", "n_false_flagged"),
            ("TỈ LỆ BÁO NHẦM (%)", "false_flag_rate_pct"),
            ("Theo lớp phòng thủ", "false_flag_by_layer"),
            ("Nguồn", "nguon"),
            ("Cách đọc", "cach_doc"),
        ],
    ),
    (
        "2.b",
        "Tier-2 có bị thao túng không",
        "adversarial_pipeline_results.json",
        [
            ("TỈ LỆ KHÁNG (%)", "resistance_rate_pct"),
            ("Đã thử", "n_tested"),
            ("Tổng mẫu khó có sẵn", "n_available_hard"),
            ("ĐỘ PHỦ (%)", "coverage_pct"),
            ("metric_valid", "metric_valid"),
            ("Giữ được quyết định", "resisted"),
            ("Bị ép thành lành", "compromised"),
            ("Phạm vi", "scope_note"),
        ],
        "⚠️ `metric_valid=false` nghĩa là **chưa phủ hết mẫu khó** — tỉ lệ kháng khi đó KHÔNG "
        "trích được. Chạy đủ bằng `RQ2_WITH_LLM=1 bash scripts/run_rq2_all.sh` (~4,3 giờ).",
    ),
    (
        "2.c",
        "Rào chắn theo VỊ TRÍ TRƯỜNG",
        "robustness_results.json",
        [
            ("Nhóm field_injection", "summary.by_category.field_injection"),
        ],
        "Cơ chế đóng gói nonce bọc **theo trường**, nên vị trí trường quyết định payload nằm "
        'trong hay ngoài vùng bọc. 603 mẫu cũ đều gán cứng `payload_field="payload"` nên không '
        "kiểm được điều này; bộ `field_injection` rải qua 4 trường (URI · User-Agent · message · "
        "payload) chính là để kiểm.",
    ),
    (
        "2.f",
        "HMAC phát hiện giả mạo",
        "audit_tamper_results.json",
        [
            ("Số dòng nhật ký", "n_audit_rows"),
            ("Số lần thử mỗi kiểu", "trials_per_mode"),
            ("PHÁT HIỆN (3 kiểu chính) (%)", "overall_detection_rate_core"),
            ("Ba kiểu chính", "core_modes"),
            ("Khoá HMAC là khoá mặc định?", "key_is_default"),
            ("Đối chứng âm (bản chưa đụng)", "negative_control"),
            ("metric_valid", "metric_valid"),
            ("BẢNG THEO KIỂU GIẢ MẠO", "@dict:by_mode"),
        ],
        "⚠️ Đọc kèm **2.g** ngay dưới. Nêu tỉ lệ 100% mà giấu chỗ không bắt được là nêu nửa sự thật.",
    ),
    (
        "2.g",
        "Lỗ hổng cắt đuôi chuỗi (nêu RIÊNG, không gộp vào 2.f)",
        "audit_tamper_results.json",
        [
            ("Kiểu `xoá_dòng_cuối`", "by_mode.xoá_dòng_cuối"),
            ("Vì sao tách riêng", "note_tail_deletion"),
        ],
        "Đây là tính chất NGUYÊN LÝ của log-chaining, không phải lỗi cài đặt: cắt đuôi chuỗi thì "
        "không còn mắt xích nào phía sau để lộ ra chỗ đứt. Tự nêu trước khi bị hỏi.",
    ),
    (
        "2.h",
        "Tất định + đổi seed của LLM",
        "llm_robustness_results.json",
        [
            ("Tất định — hành động giống nhau?", "determinism.action_identical"),
            ("Tất định — số lượt chạy", "determinism.n_runs"),
            ("Tất định — số đầu ra thô khác nhau", "determinism.distinct_raw_outputs"),
            ("Đổi seed — n mẫu", "seed_variance.n_samples"),
            ("Đổi seed — số ca đổi phán quyết", "seed_variance.n_flipped"),
            ("Đổi seed — FLIP RATE", "seed_variance.flip_rate"),
            ("Đổi seed — CI95", "seed_variance.flip_rate_ci95"),
            ("Suy biến an toàn — có sập không", "graceful_degradation.crashed"),
            ("Suy biến an toàn — phán quyết", "graceful_degradation.degraded_action"),
        ],
        "⚠️ Script này chạy trên `ground_truth.json` và đo **tất định/đổi seed**. Nó KHÔNG đo "
        "kháng tiêm nhiễm — đừng quy gán nhầm (bản cũ của tài liệu từng nhầm).",
    ),
    (
        "2.i",
        "Kháng né tránh ở lớp ML (mô hình đe doạ KHÁC 2.a–2.e)",
        "ml_gate_results.json",
        [
            ("Số mẫu tấn công ML bắt được", "evasion_resistance.attack_samples_ml_caught"),
            ("BẢNG THEO KIỂU NÉ TRÁNH", "@dict:evasion_resistance.by_mode"),
        ],
        "2.a–2.e đo tấn công qua **ngôn ngữ** (nhắm vào LLM). 2.i đo tấn công qua **không gian "
        'đặc trưng**: bơm giá trị cực đoan/Inf ép LightGBM nói "lành". Hai tầng, hai cách tấn '
        'công, hai cách phòng — RQ2 hỏi *"các rủi ro đối kháng"*, tiêm nhiễm prompt chỉ là ví dụ '
        "điển hình chứ không phải phạm vi.",
    ),
]


def lay(d, duong_dan: str):
    """Đi theo `a.b.c`. Trả `None` nếu đứt ở bất kỳ đâu — KHÔNG suy đoán giá trị."""
    cur = d
    for k in duong_dan.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


def dinh_dang(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "✅ true" if v else "❌ false"
    if isinstance(v, float):
        return f"{v:.4f}".rstrip("0").rstrip(".")
    if isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False)
        return f"`{s[:200]}`" + ("…" if len(s) > 200 else "")
    return f"`{v}`" if isinstance(v, str) and len(str(v)) < 110 else str(v)


def bang_tu_dict(dong: list, nhan: str, o):
    """Bung `{tên: {chỉ số: giá trị}}` thành bảng thật — mỗi khoá con một cột."""
    dong.append(f"\n**{nhan}**\n")
    if not isinstance(o, dict) or not o:
        dong.append("— *(chưa có dữ liệu)*\n")
        return
    cot: list[str] = []
    for v in o.values():
        if isinstance(v, dict):
            for k in v:
                if k not in cot and k not in ("details", "missed_examples"):
                    cot.append(k)
    if not cot:
        dong.append(dinh_dang(o) + "\n")
        return
    dong.append("| nhóm | " + " | ".join(cot) + " |")
    dong.append("| :-- | " + " | ".join(":--" for _ in cot) + " |")
    for ten, v in o.items():
        if isinstance(v, dict):
            dong.append(f"| `{ten}` | " + " | ".join(dinh_dang(v.get(c)) for c in cot) + " |")


def main():
    ap = argparse.ArgumentParser(description="Gom chỉ số RQ2 ra báo cáo Markdown")
    ap.add_argument("--ledger", default="", help="TSV thời lượng/mã thoát do run_rq2_all.sh ghi")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    ngay = datetime.now().strftime("%Y-%m-%d_%H%M")
    out = args.out or os.path.join(OUT, f"RQ2_KET_QUA_{ngay}.md")

    cache: dict[str, dict | None] = {}
    dong: list[str] = []
    thieu: list[str] = []

    dong.append("# RQ2 — Kết quả đo\n")
    dong.append(
        f"> Sinh tự động bởi `scripts/collect_rq2_report.py` lúc "
        f"{datetime.now().strftime('%F %T')}.\n"
    )
    dong.append("> Mọi số đọc THẲNG từ `experiments/results/*.json` — không ai chép tay ở giữa.\n")
    dong.append("> `—` = khoá không có trong tệp. Nghĩa là **chưa đo được**, không phải bằng 0.\n")
    dong.append(
        "> **Hai cặp không được tách:** 2.a ↔ 2.d (chặn ↔ báo nhầm) · 2.f ↔ 2.g (bắt được ↔ "
        "chỗ không bắt được).\n"
    )

    for muc in CHI_SO:
        ma, ten, tep, khoa = muc[0], muc[1], muc[2], muc[3]
        ghi_chu = muc[4] if len(muc) > 4 else ""
        duong = os.path.normpath(os.path.join(RES, tep))
        if tep not in cache:
            try:
                with open(duong, encoding="utf-8") as f:
                    cache[tep] = json.load(f)
            except (OSError, ValueError) as e:
                cache[tep] = None
                thieu.append(f"{tep} — {type(e).__name__}")
        d = cache[tep]

        dong.append(f"\n## {ma} · {ten}\n")
        if ghi_chu:
            dong.append(f"> {ghi_chu}\n")
        if d is None:
            dong.append(
                f"⚠️ **Không đọc được** `{os.path.relpath(duong, ROOT)}` — chưa chạy "
                "hoặc script hỏng. Xem `logs/rq2/`.\n"
            )
            continue
        dong.append(f"*Nguồn: `{os.path.relpath(duong, ROOT)}`*\n")

        vo_huong = [(n, k) for n, k in khoa if not k.startswith("@dict:")]
        bang = [(n, k[len("@dict:") :]) for n, k in khoa if k.startswith("@dict:")]
        if vo_huong:
            dong.append("| chỉ số | giá trị |")
            dong.append("| :-- | :-- |")
            for nhan, dd in vo_huong:
                dong.append(f"| {nhan} | {dinh_dang(lay(d, dd))} |")
        for nhan, dd in bang:
            bang_tu_dict(dong, nhan, lay(d, dd))

    if args.ledger and os.path.exists(args.ledger):
        dong.append("\n## Nhật ký lượt chạy\n")
        dong.append("| bước | mã thoát | giây | bắt đầu |")
        dong.append("| :-- | --: | --: | :-- |")
        with open(args.ledger, encoding="utf-8") as f:
            for i, ln in enumerate(f):
                if i == 0:
                    continue
                c = ln.rstrip("\n").split("\t")
                if len(c) == 4:
                    ma = "✅ 0" if c[1] == "0" else f"❌ {c[1]}"
                    dong.append(f"| {c[0]} | {ma} | {c[2]} | {c[3]} |")

    if thieu:
        dong.append("\n## Tệp KHÔNG đọc được\n")
        for t in thieu:
            dong.append(f"- `{t}`")
        dong.append("")

    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(dong) + "\n")
    print(f"[+] Báo cáo: {os.path.relpath(out, ROOT)}")
    if thieu:
        print(f"[!] {len(thieu)} tệp không đọc được: {', '.join(thieu)}")


if __name__ == "__main__":
    main()
