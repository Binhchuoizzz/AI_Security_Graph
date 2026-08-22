"""Gom mọi chỉ số RQ1 từ các tệp kết quả JSON ra MỘT báo cáo Markdown.

VÌ SAO CÓ TỆP NÀY. Chín script RQ1 ghi ra chín tệp JSON với chín cách đặt tên khoá khác nhau.
Đọc tay từng tệp rồi chép số vào tài liệu là đúng cái quy trình đã sinh ra lỗi "trôi số" trước
đây (giao diện ghi 83.8% trong khi JSON ghi 80.59%). Script này đọc THẲNG từ JSON, không ai chép
tay ở giữa.

Nguyên tắc: KHÔNG BỊA. Khoá thiếu -> in `—` và ghi rõ thiếu ở đâu, chứ không suy ra hay điền
giá trị mặc định. Tệp thiếu -> nói tệp thiếu.

Chạy:  .venv/bin/python scripts/collect_rq1_report.py [--ledger logs/rq1/_ledger_*.tsv]
"""

import argparse
import json
import os
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "experiments", "results")
OUT = os.path.join(ROOT, "reports")

# Mỗi dòng: (mã chỉ số, tên, tệp JSON, [(nhãn, đường-dẫn-khoá)]) + ghi chú TUỲ CHỌN.
# Đường dẫn khoá dùng dấu chấm; `a.b` = d["a"]["b"].
# Ghi chú in ngay dưới tiêu đề mục, dùng cho chỉ số đang chờ chạy lại — để người đọc biết vì sao
# trống mà không phải đi mò trong `logs/`.
CHI_SO: list[tuple] = [
    (
        "1.a",
        "Chất lượng phân loại Cổng ML",
        "ml_gate_results.json",
        [
            ("MCC", "classification.mcc"),
            ("Balanced accuracy", "classification.balanced_accuracy"),
            ("F1", "classification.f1"),
            ("F1 CI95 (bootstrap)", "classification.f1_ci95_bootstrap"),
            ("Precision", "classification.precision"),
            ("Recall", "classification.recall"),
            ("Specificity", "classification.specificity"),
            ("Accuracy", "classification.accuracy"),
            ("ZeroR accuracy", "classification.zero_r_accuracy"),
            ("Vượt mốc đoán hằng?", "classification.accuracy_beats_baseline"),
            ("metric_valid", "classification.metric_valid"),
            ("Ma trận nhầm lẫn (mẫu ML quyết)", "classification.confusion_matrix_on_decided"),
            ("ECE (hiệu chuẩn)", "classification.confidence_calibration.ece"),
            ("Brier", "classification.confidence_calibration.brier"),
            ("Lệch lớn nhất", "classification.confidence_calibration.max_gap"),
            ("Dải >=0.85: n", "classification.confidence_calibration.high_conf_n"),
            (
                "Dải >=0.85: nói chắc",
                "classification.confidence_calibration.high_conf_mean_confidence",
            ),
            ("Dải >=0.85: đúng thật", "classification.confidence_calibration.high_conf_accuracy"),
            ("3 lớp yếu nhất", "classification.weakest_classes"),
        ],
    ),
    (
        "1.b",
        "Độ chính xác auto-BLOCK",
        "ml_gate_results.json",
        [
            ("Auto-BLOCK precision", "classification.auto_block_precision"),
            ("Số lệnh auto-BLOCK", "classification.auto_block_n"),
            ("FP trong auto-BLOCK", "classification.auto_block_fp"),
        ],
    ),
    (
        "1.d",
        "Thông lượng Cổng ML",
        "ml_gate_results.json",
        [
            ("Thông lượng (sự kiện/s)", "classification.throughput_eps"),
            ("Độ trễ TB (ms)", "classification.mean_latency_ms"),
            ("Thời gian tường (s)", "classification.wall_seconds"),
            ("Bypass rate (ML tự quyết)", "classification.bypass_rate"),
            ("Abstain rate (-> LLM)", "classification.abstain_rate"),
        ],
    ),
    # 1.e TÁCH khỏi 1.h từ 04/08/2026. Trước đó cả hai đọc chung `latency_benchmark.json`, nên
    # muốn biết tỉ lệ xả tải phải chờ hết lượt đo độ trễ ~3,3 giờ — trong khi xả tải là đại lượng
    # THUẦN ĐỊNH TUYẾN, đo offline trong vài phút là xong. Tách ra thì chỉ còn ĐÚNG MỘT chỉ số
    # phải chờ lâu. `measure_offload_vs_baserate.py` cũng đếm đúng chuẩn `subscriber.py`
    # (mọi hành động != ESCALATE là đã gỡ tải), thay vì chỉ tính DROP như bản cũ.
    (
        "1.e",
        "Xả tải khỏi LLM — luồng benchmark (26% tấn công)",
        "offload_vs_baserate_stream.json",
        [
            ("n sự kiện", "n_events"),
            ("Tỉ lệ tấn công của luồng", "attack_rate_do_duoc"),
            ("XẢ TẢI TỔNG", "offload_tong"),
            ("CI95", "offload_tong_ci95"),
            ("— Tier-1 chặn", "ti_le_chan_tier1"),
            ("— Cổng ML chặn", "ti_le_chan_cong_ml"),
            ("— tới LLM", "ti_le_toi_llm"),
            ("Xả tải trên ca LÀNH", "theo_nhan.lanh_tinh.offload_rate"),
            ("Xả tải trên ca TẤN CÔNG", "theo_nhan.tan_cong.offload_rate"),
            ("Công thức chiếu", "cong_thuc"),
            ("Cách đọc", "cach_doc"),
            ("CHIẾU SANG BASE-RATE KHÁC", "@table:chieu_base_rate"),
        ],
    ),
    (
        "1.e",
        "Xả tải khỏi LLM — 100k sự kiện dạng SOC thật (9,8% tấn công)",
        "offload_vs_baserate_demo.json",
        [
            ("n sự kiện", "n_events"),
            ("Tỉ lệ tấn công của luồng", "attack_rate_do_duoc"),
            ("XẢ TẢI TỔNG", "offload_tong"),
            ("CI95", "offload_tong_ci95"),
            ("— Tier-1 chặn", "ti_le_chan_tier1"),
            ("— Cổng ML chặn", "ti_le_chan_cong_ml"),
            ("— tới LLM", "ti_le_toi_llm"),
            ("Xả tải trên ca LÀNH", "theo_nhan.lanh_tinh.offload_rate"),
            ("Xả tải trên ca TẤN CÔNG", "theo_nhan.tan_cong.offload_rate"),
        ],
    ),
    (
        "1.h",
        "Độ trễ 2 tầng vs LLM-only",
        "latency_benchmark.json",
        [
            ("n sự kiện", "n_events"),
            ("GIẢM ĐỘ TRỄ (%)", "latency_reduction_pct"),
            ("Xả tải trong chính lượt đo", "stage_breakdown.offload_pct"),
            ("Dừng ở Tier-1", "stage_breakdown.escaped_at.tier1_drop"),
            ("Dừng ở Cổng ML", "stage_breakdown.escaped_at.ml_gate"),
            ("Tới LLM", "stage_breakdown.escaped_at.llm"),
            ("ms TB — Tier-1", "stage_breakdown.mean_ms_by_stage.tier1_drop"),
            ("ms TB — Cổng ML", "stage_breakdown.mean_ms_by_stage.ml_gate"),
            ("ms TB — LLM", "stage_breakdown.mean_ms_by_stage.llm"),
            ("Hai tầng — median (ms)", "two_tier_median_ms"),
            ("Hai tầng — mean (ms)", "two_tier_mean_ms"),
            ("Hai tầng — P95 (ms)", "two_tier_p95_ms"),
            ("LLM-only — median (ms)", "baseline_median_ms"),
            ("LLM-only — mean (ms)", "baseline_mean_ms"),
            ("LLM-only — P95 (ms)", "baseline_p95_ms"),
            ("Mann-Whitney U", "mannwhitney_u"),
            ("Mann-Whitney p", "mannwhitney_p"),
            ("p < 0.05?", "significant_p05"),
            ("metric_valid", "metric_valid"),
            ("Lý do", "metric_valid_reason"),
            ("Cách lấy mẫu", "sampling"),
            ("Bộ đệm RAG — hit rate", "stage_breakdown.rag_cache.hit_rate"),
        ],
        "⏳ **Chờ chạy lại** — `RQ1_WITH_LATENCY=1 bash scripts/run_rq1_all.sh` (~3,3 giờ, cần LLM). "
        "Lượt cũ đã bị loại vì đếm xả tải sai (chỉ tính `DROP`, bỏ sót `BLOCK_IP`/`ALERT`/`AWAIT_HITL` "
        "vốn cũng kết thúc tại Tier-1). "
        "**Tỉ lệ xả tải nay đọc ở 1.e**, không đọc ở đây.",
    ),
    (
        "1.f",
        "Tỉ lệ gỡ tải riêng của Cổng ML",
        "ablation_mlgate_results.json",
        [
            ("ML bypass rate", "ml_bypass_rate"),
            ("n mẫu", "dataset_size"),
            ("Ca sẽ phải gọi LLM nếu không có Cổng ML", "n_escalated_would_call_llm"),
            ("Số ca ML tự quyết", "n_ml_bypass"),
            ("F1 trên phần ML quyết", "ml_f1_on_bypass"),
            ("Precision", "ml_precision_on_bypass"),
            ("Recall", "ml_recall_on_bypass"),
            ("Cách đọc", "note"),
        ],
    ),
    (
        "1.g",
        "Bộ đệm ngữ nghĩa Tầng 1.75",
        "cache_efficiency_results.json",
        [
            ("Hit rate", "hit_rate"),
            ("Tăng tốc (x)", "speedup_x"),
            ("Số truy vấn", "n_queries"),
            ("Truy vấn duy nhất", "n_distinct_queries"),
            ("Trúng / trượt", "n_hits"),
            ("Evictions", "cache_stats.evictions"),
            ("ms TB — có cache", "mean_ms_hit"),
            ("ms TB — không cache", "mean_ms_miss"),
            ("ms tiết kiệm tổng", "ms_saved_total"),
            ("Phễu — quét", "funnel_to_rag.scanned"),
            ("Phễu — Tier-1 loại", "funnel_to_rag.tier1_drop"),
            ("Phễu — Cổng ML loại", "funnel_to_rag.ml_gate"),
            ("Phễu — tới RAG", "funnel_to_rag.reached_rag"),
            ("Khoá cache", "key_strategy"),
            ("Phạm vi", "scope_note"),
        ],
    ),
    (
        "1.i",
        "Toàn tuyến trên luồng gộp",
        "unified_stream_results.json",
        [
            ("CICIDS — MCC", "summary.classification_cicids.mcc"),
            ("CICIDS — F1", "summary.classification_cicids.f1"),
            ("CICIDS — F1 CI95", "summary.classification_cicids.f1_ci95_bootstrap"),
            ("CICIDS — Precision", "summary.classification_cicids.precision"),
            ("CICIDS — Recall", "summary.classification_cicids.recall"),
            ("CICIDS — Balanced acc", "summary.classification_cicids.balanced_accuracy"),
            (
                "CICIDS — vượt mốc đoán hằng?",
                "summary.classification_cicids.accuracy_beats_baseline",
            ),
            ("n chấm được", "summary.stream.n_scored"),
            (
                "Khống chế IP — DAPT thật",
                "summary.ip_containment.real_ips_dapt2020.containment_rate",
            ),
            (
                "Khống chế IP — IP tổng hợp",
                "summary.ip_containment.synthetic_ips_other.containment_rate",
            ),
            (
                "Zero-day — Welford bắt được (luật tĩnh trượt)",
                "summary.zeroday.caught_by_welford_static_missed",
            ),
            ("Zero-day — tổng", "summary.zeroday.total"),
            ("APT — chuỗi phát hiện", "summary.apt_dapt.detected"),
            ("APT — tổng chuỗi", "summary.apt_dapt.apt_truth_ips"),
            ("APT — recall", "summary.apt_dapt.recall"),
            ("APT — độ trễ TB (sự kiện)", "summary.apt_dapt.avg_detection_lag_events"),
        ],
    ),
    (
        "1.j",
        "Đối chứng nền (trong nhà)",
        "baseline_comparison_results.json",
        [
            ("Tập", "dataset"),
            ("n sự kiện", "n_events"),
            ("BẢNG ĐỐI CHỨNG (H0/H1/H2/H3 + SENTINEL)", "@table:baselines"),
            ("H3 LLM-only — cỡ mẫu con", "llm_subset_comparison.n_subset"),
            ("H3 — bảng trên mẫu con", "@table:llm_subset_comparison.rows"),
        ],
    ),
    (
        "1.k",
        "Vòng phản hồi Tier-2 → luật → Tier-1",
        "feedback_loop_results.json",
        [
            ("Tier-1 hấp thụ thêm (ca)", "delta.n_absorbed_by_tier1"),
            ("GIẢM LEO THANG (%)", "delta.escalation_reduction_pct"),
            ("CI95 hấp thụ", "delta.absorption_ci95"),
            ("Δ tỉ lệ leo thang (tuyệt đối)", "delta.escalation_rate_abs"),
            ("Δ MCC", "delta.mcc_delta"),
            ("Δ Recall", "delta.recall_delta"),
            ("Δ Precision", "delta.precision_delta"),
            ("PHÁT HIỆN CÒN NGUYÊN?", "delta.detection_preserved"),
            ("Vòng 1 — tỉ lệ leo thang", "round1_no_rules.escalation_rate"),
            ("Vòng 2 — tỉ lệ leo thang", "round2_with_rules.escalation_rate"),
            ("Vòng 1 — ca leo thang", "round1_no_rules.n_escalated"),
            ("Vòng 2 — ca leo thang", "round2_with_rules.n_escalated"),
            ("Vòng 1 — tải HITL", "round1_no_rules.n_await_hitl"),
            ("Vòng 2 — tải HITL", "round2_with_rules.n_await_hitl"),
            ("Δ tải HITL (ca)", "delta.n_hitl_delta"),
            ("Cách đọc", "interpretation"),
            ("meta", "meta"),
        ],
    ),
    (
        "1.m",
        "Độ nhạy ngưỡng Cổng ML",
        "ml_threshold_sweep_results.json",
        [
            ("Điểm vận hành", "operating_point"),
            ("n sự kiện", "n_events"),
            ("n abstain", "n_abstain"),
            ("BẢNG QUÉT NGƯỠNG", "@table:sweep"),
        ],
    ),
    (
        "1.n",
        "Nguồn gốc chất lượng mô hình ML",
        "../../ml_lab/train_1m_metrics.json",
        [
            ("Model thắng", "best_model"),
            ("F1 hold-out", "best_test_f1"),
            ("Precision", "precision"),
            ("Recall", "recall"),
            ("FPR", "fpr"),
            ("n huấn luyện", "n_train"),
            ("n hold-out", "n_test"),
            ("Thời điểm train", "trained_at"),
            ("Dữ liệu", "dataset"),
            ("BẢNG 5 MODEL", "@table:results"),
        ],
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
        return f"`{s[:160]}`" + ("…" if len(s) > 160 else "")
    return f"`{v}`" if isinstance(v, str) and len(str(v)) < 90 else str(v)


def main():
    ap = argparse.ArgumentParser(description="Gom chỉ số RQ1 ra báo cáo Markdown")
    ap.add_argument("--ledger", default="", help="TSV thời lượng/mã thoát do run_rq1_all.sh ghi")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    ngay = datetime.now().strftime("%Y-%m-%d_%H%M")
    out = args.out or os.path.join(OUT, f"RQ1_KET_QUA_{ngay}.md")

    cache: dict[str, dict | None] = {}
    dong: list[str] = []
    thieu: list[str] = []

    dong.append("# RQ1 — Kết quả đo\n")
    dong.append(
        f"> Sinh tự động bởi `scripts/collect_rq1_report.py` lúc "
        f"{datetime.now().strftime('%F %T')}.\n"
    )
    dong.append("> Mọi số đọc THẲNG từ `experiments/results/*.json` — không ai chép tay ở giữa.\n")
    dong.append("> `—` = khoá không có trong tệp. Nghĩa là **chưa đo được**, không phải bằng 0.\n")

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
                "hoặc script hỏng. Xem `logs/rq1/`.\n"
            )
            continue
        dong.append(f"*Nguồn: `{os.path.relpath(duong, ROOT)}`*\n")
        vo_huong = [(n, k) for n, k in khoa if not k.startswith("@table:")]
        bang = [(n, k[len("@table:") :]) for n, k in khoa if k.startswith("@table:")]

        if vo_huong:
            dong.append("| chỉ số | giá trị |")
            dong.append("| :-- | :-- |")
            for nhan, dd in vo_huong:
                dong.append(f"| {nhan} | {dinh_dang(lay(d, dd))} |")

        # Vài script trả về DANH SÁCH hàng (bảng quét ngưỡng, bảng đối chứng). Nhét cả list vào
        # một ô thì không đọc được — bung thành bảng thật, mỗi khoá một cột.
        for nhan, dd in bang:
            rows = lay(d, dd)
            dong.append(f"\n**{nhan}**\n")
            if not isinstance(rows, list) or not rows:
                dong.append("— *(chưa có dữ liệu)*\n")
                continue
            cot: list[str] = []
            for r in rows:
                if isinstance(r, dict):
                    for k in r:
                        if k not in cot:
                            cot.append(k)
            if not cot:
                dong.append(dinh_dang(rows) + "\n")
                continue
            dong.append("| " + " | ".join(cot) + " |")
            dong.append("| " + " | ".join(":--" for _ in cot) + " |")
            for r in rows:
                if isinstance(r, dict):
                    dong.append("| " + " | ".join(dinh_dang(r.get(c)) for c in cot) + " |")

    # 1.l KHÔNG ghi JSON — `audit_offload_mechanisms.py` chỉ in ra màn hình. Trích thẳng từ log
    # thay vì để trống: ba cơ chế gỡ tải là bằng chứng RQ1, không phải phụ lục.
    dong.append("\n## 1.l · Ba cơ chế gỡ tải, kiểm riêng từng cái\n")
    log_1l = os.path.join(ROOT, "logs", "rq1", "offload_mechanisms.log")
    if os.path.exists(log_1l):
        with open(log_1l, encoding="utf-8", errors="replace") as f:
            noi_dung = f.read().strip().splitlines()
        dong.append(
            "*Nguồn: `logs/rq1/offload_mechanisms.log` — script này in ra màn hình, "
            "không ghi JSON.*\n"
        )
        dong.append("```text")
        dong.extend(noi_dung[-40:])
        dong.append("```")
    else:
        dong.append("⚠️ Chưa có `logs/rq1/offload_mechanisms.log` — bước này chưa chạy.\n")

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
                    ok = "✅" if c[1] == "0" else "❌"
                    dong.append(f"| {c[0]} | {ok} {c[1]} | {c[2]} | {c[3]} |")

    if thieu:
        dong.append("\n## Tệp không đọc được\n")
        for t in thieu:
            dong.append(f"- `{t}`")

    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(dong) + "\n")
    print(f"[+] Báo cáo: {os.path.relpath(out, ROOT)}")
    if thieu:
        print(f"[!] {len(thieu)} tệp không đọc được: {', '.join(thieu)}")


if __name__ == "__main__":
    main()
