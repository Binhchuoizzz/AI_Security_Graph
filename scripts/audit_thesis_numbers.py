"""Đối chiếu TỪNG CON SỐ trong luận văn với đúng khoá JSON đã sinh ra nó.

VÌ SAO CÓ TỆP NÀY (06/08/2026). Người dùng đặt một ràng buộc nghiệm thu: *"Đừng để lần sau tôi
nói đồng bộ lại, check lại, lại soi thấy lỗi."* Rà bằng mắt không đáp ứng được ràng buộc đó — mỗi
lượt chạy lại benchmark là hàng chục con số đổi, nằm rải trong 10 tệp `.tex` của hai ngôn ngữ, và
số cũ thì trông y hệt số mới.

Cách duy nhất bền là biến việc "đồng bộ" thành một phép kiểm chạy được. Bảng `CLAIMS` dưới đây
khai báo: mỗi tuyên bố số trong luận văn ⇄ đúng tệp kết quả và đúng khoá sinh ra nó. Script dựng
lại chuỗi mà `.tex` PHẢI chứa (dạng EN `90.6\\%` và dạng VI `90{,}6\\%`) rồi tìm trong đúng những
tệp đã khai.

BA TRẠNG THÁI:
  OK      — chuỗi đúng có mặt ở mọi tệp đã khai.
  THIẾU   — JSON có giá trị này, `.tex` không nhắc tới. Hoặc quên đồng bộ, hoặc khai thừa.
  NGHI CŨ — không tìm thấy giá trị mới, NHƯNG trong tệp có số khác cùng phần nguyên. Gần như
            chắc chắn đó là giá trị của lượt đo trước còn sót lại. Đây là ca nguy hiểm nhất, vì
            đọc lên vẫn thấy hợp lý.

Phép kiểm thứ hai, độc lập: đối chiếu TOÀN BỘ token số giữa bản EN và bản VI. Hai bản là gương
1:1 nên mọi con số phải trùng khớp; lệch một token là một bản đã sửa còn bản kia thì chưa.

Chạy:  .venv/bin/python scripts/audit_thesis_numbers.py
Đọc-thuần, ~2 giây, không gọi mô hình.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "experiments", "results")
TEX = os.path.join(ROOT, "docs", "Thesis", "latex")
OUT_JSON = os.path.join(R, "thesis_number_audit.json")


# ── bộ định dạng: JSON -> chuỗi mà .tex phải chứa ────────────────────────────
def pct(nd=1, scale=1.0):
    """Tỉ lệ phần trăm, nd chữ số thập phân. scale=100 khi JSON lưu dạng 0..1."""
    return lambda v: f"{v * scale:.{nd}f}\\%"


def num(nd=0, thousands=True):
    """Số thường. Dấu phần nghìn khác nhau giữa hai ngôn ngữ nên xử lý ở `render`."""
    return lambda v: f"{v:,.{nd}f}" if thousands else f"{v:.{nd}f}"


def dec(nd=3):
    """Số thập phân không phần trăm (MCC, Recall@3, ...)."""
    return lambda v: f"{v:.{nd}f}"


EN_ALL = ["ch4", "ch5", "main"]

# (nhãn, tệp kết quả, đường dẫn khoá, hàm định dạng, các tệp .tex phải xuất hiện)
CLAIMS = [
    # ── RQ1 ──
    (
        "xả tải benchmark",
        "offload_vs_baserate_stream.json",
        "offload_tong",
        pct(1, 100),
        ["ch4", "ch5", "main"],
    ),
    (
        "xả tải luồng SOC",
        "offload_vs_baserate_demo.json",
        "offload_tong",
        pct(1, 100),
        ["ch4", "ch5"],
    ),
    (
        "Tier-1 benchmark",
        "offload_vs_baserate_stream.json",
        "ti_le_chan_tier1",
        pct(1, 100),
        ["ch4"],
    ),
    (
        "Cổng ML luồng SOC",
        "offload_vs_baserate_demo.json",
        "ti_le_chan_cong_ml",
        pct(1, 100),
        ["ch4"],
    ),
    (
        "xả tải ca lành benchmark",
        "offload_vs_baserate_stream.json",
        "theo_nhan.lanh_tinh.offload_rate",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "xả tải ca tấn công benchmark",
        "offload_vs_baserate_stream.json",
        "theo_nhan.tan_cong.offload_rate",
        pct(2, 100),
        ["ch4"],
    ),
    ("Cổng ML MCC", "ml_gate_results.json", "classification.mcc", dec(3), ["ch4"]),
    (
        "Cổng ML mẫu số thật",
        "ml_gate_results.json",
        "classification.n_decided_by_ml",
        num(0),
        ["ch4"],
    ),
    (
        "Cổng ML thông lượng",
        "ml_gate_results.json",
        "classification.throughput_eps",
        num(0),
        ["ch4"],
    ),
    ("auto-BLOCK số lệnh", "ml_gate_results.json", "classification.auto_block_n", num(0), ["ch4"]),
    ("cache tỉ lệ trúng", "cache_efficiency_results.json", "hit_rate", pct(1, 100), ["ch4"]),
    ("độ trễ TB hai tầng", "latency_benchmark.json", "two_tier_mean_ms", num(1), ["ch4"]),
    (
        "độ trễ trung vị đơn tầng",
        "latency_benchmark.json",
        "baseline_median_ms",
        num(1),
        ["ch4", "ch5", "main"],
    ),
    (
        "độ trễ trung vị hai tầng",
        "latency_benchmark.json",
        "two_tier_median_ms",
        num(2),
        ["ch4", "ch5", "main"],
    ),
    ("p95 hai tầng", "latency_benchmark.json", "two_tier_p95_ms", num(0), ["ch4"]),
    (
        "né tránh Cổng ML chế độ khó",
        "ml_gate_results.json",
        "evasion_resistance.headline_hard_mode.resistance_rate",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "báo nhầm trên log lành",
        "adversarial_negative_results.json",
        "false_flag_rate_pct",
        pct(1),
        ["ch4"],
    ),
    ("số log lành đối chứng âm", "adversarial_negative_results.json", "n_benign", num(0), ["ch4"]),
    ("HMAC số bản ghi đối chứng", "audit_tamper_results.json", "n_audit_rows", num(0), ["ch4"]),
    (
        "Tier-2 kháng mẫu khó",
        "adversarial_pipeline_results.json",
        "n_tested",
        num(0),
        ["ch4", "ch5", "main"],
    ),
    (
        "quy kết chỉ truy xuất",
        "attack_mapper_eval_rrf_payload.json",
        "technique_exact_match_pct",
        pct(1),
        ["ch4"],
    ),
    (
        "quy kết toàn tuyến",
        "attack_mapper_eval_e2e_payload.json",
        "technique_exact_match_pct",
        pct(1),
        ["ch4"],
    ),
    (
        "quy kết chiến thuật toàn tuyến",
        "attack_mapper_eval_e2e_payload.json",
        "tactic_match_pct",
        pct(1),
        ["ch4"],
    ),
    (
        "trần truy xuất Recall@3",
        "rag_retrieval_results_payload.json",
        "achievable.recall_at_k.@3",
        dec(3),
        ["ch4"],
    ),
    (
        "truy xuất lát all Recall@3",
        "rag_retrieval_results.json",
        "achievable.recall_at_k.@3",
        dec(3),
        ["ch4"],
    ),
    ("neo bằng chứng bad", "evidence_grounding_results.json", "bad", num(0), ["ch4"]),
    (
        "neo bằng chứng mẫu số",
        "evidence_grounding_results.json",
        "n_khang_dinh_ky_thuat",
        num(0),
        ["ch4", "ch5"],
    ),
    (
        "lá chắn kích hoạt",
        "evidence_grounding_results.json",
        "la_chan_ty_le_pct",
        pct(2),
        ["ch4", "ch5"],
    ),
    (
        "BLOCK_IP bị chặn lại",
        "evidence_grounding_results.json",
        "block_ip_bi_chan_lai",
        num(0),
        ["ch4", "ch5"],
    ),
    (
        "triage cảnh báo vào",
        "tier2_decision_results.json",
        "summary.triage.n_alerts_in",
        num(0),
        ["ch4"],
    ),
    (
        "triage FP trên phần khẳng định",
        "tier2_decision_results.json",
        "summary.triage.fp_rate_on_confirmed",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "triage tỉ lệ hoãn",
        "tier2_decision_results.json",
        "summary.triage.defer_rate",
        pct(2, 100),
        ["ch4", "ch5"],
    ),
    (
        "triage làm giàu",
        "tier2_decision_results.json",
        "summary.triage.deferred_enrichment_x",
        dec(2),
        ["ch4", "ch5"],
    ),
    (
        "triage giảm khối lượng",
        "tier2_decision_results.json",
        "summary.triage.workload_reduction",
        pct(2, 100),
        ["ch4", "ch5"],
    ),
    (
        "triage giữ đe doạ",
        "tier2_decision_results.json",
        "summary.triage.threat_recall_in_deferred",
        pct(1, 100),
        ["ch4", "ch5"],
    ),
    (
        "lập luận ctx-precision",
        "reasoning_eval_results.json",
        "aggregate.context_precision.mean",
        dec(2),
        ["ch4"],
    ),
    (
        "lập luận relevancy",
        "reasoning_eval_results.json",
        "aggregate.answer_relevancy.mean",
        dec(2),
        ["ch4"],
    ),
    (
        "lập luận faithfulness",
        "reasoning_eval_results.json",
        "aggregate.faithfulness.mean",
        dec(2),
        ["ch4"],
    ),
    (
        "lập luận ctx-recall",
        "reasoning_eval_results.json",
        "aggregate.context_recall.mean",
        dec(2),
        ["ch4"],
    ),
    (
        "lập luận trung bình",
        "reasoning_eval_results.json",
        "aggregate.overall_mean",
        dec(2),
        ["ch4"],
    ),
    (
        "lập luận số lô",
        "reasoning_eval_results.json",
        "metadata.escalated_samples",
        num(0),
        ["ch4"],
    ),
    (
        "neo bằng chứng lời biện giải",
        "reasoning_eval_results.json",
        "aggregate.evidence_grounding.grounding_rate",
        pct(1, 100),
        ["ch4", "ch5"],
    ),
    # ── Bóc tách thành phần (chấm theo hành động, đã loại mẫu tự soạn) ──
    (
        "ablation A đúng hành động",
        "ablation_action_scores.json",
        "configs.A.action_accuracy",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation F đúng hành động",
        "ablation_action_scores.json",
        "configs.F.action_accuracy",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation A c.xác tự quyết",
        "ablation_action_scores.json",
        "configs.A.autonomous_precision",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation F c.xác tự quyết",
        "ablation_action_scores.json",
        "configs.F.autonomous_precision",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation A bỏ ngỏ",
        "ablation_action_scores.json",
        "configs.A.unresolved_rate",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation F hoãn",
        "ablation_action_scores.json",
        "configs.F.defer_rate",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation A tự quyết",
        "ablation_action_scores.json",
        "configs.A.autonomy_rate",
        pct(2, 100),
        ["ch4"],
    ),
    (
        "ablation F tự quyết",
        "ablation_action_scores.json",
        "configs.F.autonomy_rate",
        pct(2, 100),
        ["ch4"],
    ),
]


def dig(obj, path):
    """Đi theo đường dẫn khoá. Chấp nhận cả CHỈ SỐ MẢNG: `sweep.3.noticed_rate` lấy phần tử
    thứ 4 của danh sách `sweep`. Cần thiết vì các phép quét (ngưỡng ML, k-sigma zero-day) lưu
    kết quả dạng danh sách chứ không dạng từ điển."""
    for k in path.split("."):
        if isinstance(obj, dict) and k in obj:
            obj = obj[k]
        elif isinstance(obj, list) and k.lstrip("-").isdigit() and -len(obj) <= int(k) < len(obj):
            obj = obj[int(k)]
        else:
            return None
    return obj


def render(s: str, lang: str) -> list[str]:
    """Chuỗi dạng EN (1,234.5) -> MỌI dạng hợp lệ của ngôn ngữ đích.

    Bản VI dùng dấu chấm phần nghìn và dấu phẩy thập phân. Trong LaTeX, dấu phẩy thập phân
    được bọc `{,}` khi ở CHẾ ĐỘ TOÁN (để TeX không chèn khoảng trắng sau nó) nhưng viết
    trần trong văn xuôi. Cả hai đều đúng, nên chấp nhận cả hai — nếu chỉ chấp nhận một dạng
    thì bộ kiểm sẽ báo động giả hàng loạt và người đọc sẽ học cách phớt lờ nó.
    """
    if lang == "en":
        return [s]
    thousands = s.replace(",", "\x00").replace(".", "\x01").replace("\x00", ".")
    return [thousands.replace("\x01", "{,}"), thousands.replace("\x01", ",")]


def tex_files(lang, keys):
    base = os.path.join(TEX, f"thesis_latex_{lang}")
    m = {
        "ch1": "chapters/ch1_introduction.tex",
        "ch2": "chapters/ch2_theoretical_background.tex",
        "ch3": "chapters/ch3_system_design.tex",
        "ch4": "chapters/ch4_experiments_evaluation.tex",
        "ch5": "chapters/ch5_conclusion.tex",
        "main": "main.tex",
    }
    return [(k, os.path.join(base, m[k])) for k in keys]


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def nghi_cu(body: str, want: str, lang: str):
    """Không thấy giá trị mới — có số nào CÙNG PHẦN NGUYÊN trong tệp không?

    Đây là dấu hiệu của giá trị lượt đo trước còn sót: `2{,}68` khi đáng ra phải là `2{,}54`.
    """
    dsep = r"(?:\{,\}|,)" if lang == "vi" else r"\."
    m = re.match(rf"^([0-9][0-9.,]*?)(?:{dsep}([0-9]+))?(\\\\%)?$", want)
    if not m:
        return []
    head = m.group(1)
    if not m.group(2):
        return []
    pat = re.compile(rf"(?<![0-9]){re.escape(head)}(?:{dsep})([0-9]+)(\\%)?")
    found = {mm.group(0) for mm in pat.finditer(body) if mm.group(0) != want}
    return sorted(found)[:4]


def main() -> int:
    print("=" * 78)
    print("ĐỐI CHIẾU SỐ TRONG LUẬN VĂN ⇄ TỆP KẾT QUẢ")
    print("=" * 78)
    rows, n_ok, n_missing, n_stale = [], 0, 0, 0
    cache = {}

    for label, fname, path, fmt, files in CLAIMS:
        fp = os.path.join(R, fname)
        if fp not in cache:
            cache[fp] = json.load(open(fp, encoding="utf-8")) if os.path.exists(fp) else None
        data = cache[fp]
        if data is None:
            print(f"  ⚠  {label}: thiếu {fname}")
            continue
        raw = dig(data, path)
        if raw is None:
            print(f"  ⚠  {label}: {fname} không có khoá `{path}`")
            continue
        base = fmt(raw)

        for lang in ("en", "vi"):
            variants = render(base, lang)
            want = variants[0]
            for key, tp in tex_files(lang, files):
                if not os.path.exists(tp):
                    continue
                body = read(tp)
                if any(v in body for v in variants):
                    n_ok += 1
                    rows.append(
                        {
                            "chi_so": label,
                            "lang": lang,
                            "tep": key,
                            "trang_thai": "OK",
                            "gia_tri": want,
                        }
                    )
                else:
                    cands = []
                    for v in variants:
                        cands += nghi_cu(body, v, lang)
                    cands = sorted(set(cands))[:4]
                    st = "NGHI_CU" if cands else "THIEU"
                    n_stale += st == "NGHI_CU"
                    n_missing += st == "THIEU"
                    rows.append(
                        {
                            "chi_so": label,
                            "lang": lang,
                            "tep": key,
                            "trang_thai": st,
                            "gia_tri": want,
                            "so_nghi_cu": cands,
                            "nguon": f"{fname} → {path}",
                        }
                    )
                    tag = "NGHI CŨ" if cands else "THIẾU "
                    extra = f"  ← trong tệp đang có {', '.join(cands)}" if cands else ""
                    print(f"  {tag} [{lang}/{key}] {label}: cần `{want}`{extra}")
                    print(f"          nguồn: {fname} → {path}")

    # ── gương EN ↔ VI ────────────────────────────────────────────────────────
    print("\n── Gương EN ↔ VI: mọi token số phải trùng ──")

    def toks(p):
        s = read(p)
        s = s.replace("{,}", ",")
        # Bỏ các con số THUỘC VỀ TRÌNH BÀY, không phải dữ liệu: bề rộng cột, tỉ lệ hình.
        s = re.sub(r"[0-9.]+\s*(cm|pt|em|ex|in|mm)\b", " ", s)
        s = re.sub(r"(width|height|scale)\s*=\s*[0-9.]+", " ", s)
        s = re.sub(r"\\[a-zA-Z]+", " ", s)  # bỏ lệnh LaTeX (\ref, \textbf, ...)
        s = re.sub(r"[^0-9,.]+", " ", s)
        out = []
        for t in s.split():
            t = t.strip(".,")
            # chỉ so token "có nghĩa": >=2 chữ số hoặc có phần thập phân
            if re.fullmatch(r"[0-9][0-9.,]*", t) and (len(re.sub(r"[.,]", "", t)) >= 2):
                out.append(t.replace(",", "."))
        return out

    n_mirror = 0
    for ch in (
        "ch1_introduction",
        "ch2_theoretical_background",
        "ch3_system_design",
        "ch4_experiments_evaluation",
        "ch5_conclusion",
    ):
        pe = os.path.join(TEX, "thesis_latex_en", "chapters", f"{ch}.tex")
        pv = os.path.join(TEX, "thesis_latex_vi", "chapters", f"{ch}.tex")
        if not (os.path.exists(pe) and os.path.exists(pv)):
            continue
        from collections import Counter

        ce, cv = Counter(toks(pe)), Counter(toks(pv))
        diff = {
            k: (ce.get(k, 0), cv.get(k, 0))
            for k in set(ce) | set(cv)
            if ce.get(k, 0) != cv.get(k, 0)
        }
        if diff:
            n_mirror += len(diff)
            print(
                f"  LỆCH {ch}: "
                + " · ".join(f"{k} (EN×{a}, VI×{b})" for k, (a, b) in sorted(diff.items())[:8])
            )
        else:
            print(f"  OK   {ch}")

    print("\n" + "=" * 78)
    print(f"{n_ok} đúng · {n_stale} NGHI CŨ · {n_missing} THIẾU · {n_mirror} token lệch EN↔VI")
    print("NGHI CŨ là ca nguy hiểm nhất: số của lượt đo trước còn sót, đọc lên vẫn hợp lý.")
    print("=" * 78)

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "n_ok": n_ok,
                "n_nghi_cu": n_stale,
                "n_thieu": n_missing,
                "n_token_lech_guong": n_mirror,
                "chi_tiet": rows,
            },
            fh,
            ensure_ascii=False,
            indent=1,
        )
    print(f"[+] Đã ghi: {OUT_JSON}")
    return 1 if (n_stale or n_mirror) else 0


if __name__ == "__main__":
    sys.exit(main())
