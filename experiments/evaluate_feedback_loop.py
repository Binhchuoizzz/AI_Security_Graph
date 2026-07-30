"""SENTINEL — Đo VÒNG PHẢN HỒI (Tier-2 → luật động → Tier-1).

KHOẢNG TRỐNG ĐANG LẤP: README gọi đây là *"The loop that matters"* và Chương 3 mô tả kiến
trúc chi tiết, nhưng rà toàn bộ `experiments/` thì **không có một phép đo nào**. Tức đóng
góp trung tâm được TUYÊN BỐ mà chưa từng được CHỨNG MINH bằng số. Script này lấp đúng chỗ đó.

GIẢ THUYẾT KIỂM ĐỊNH
    Sau khi analyst duyệt các luật do Tier-2 đề xuất, Tier-1 hấp thụ được phần lưu lượng
    mà trước đó phải leo thang — nên **tỉ lệ leo thang giảm** và **tải LLM giảm**, trong
    khi **năng lực phát hiện không tụt**.

THIẾT KẾ (hai vòng trên CÙNG một luồng, cùng hạt giống)
    Vòng 1 — luật động RỖNG, danh tiếng RỖNG. Ghi tỉ lệ leo thang nền.
    Nạp luật — mô phỏng analyst DUYỆT: mỗi IP bị Tier-1 kết luận đáng chặn ở vòng 1 trở
      thành một luật `Source IP` `status=ACTIVE`, đúng dạng mà `FeedbackListener` sinh ra
      trong hệ thật (xem `src/tier1_filter/feedback_listener.py`).
    Vòng 2 — cùng luồng, engine mới mang luật vừa duyệt. Đo Δ.

CÁCH LY (quan trọng — nếu không sẽ làm hỏng hệ đang chạy)
    KHÔNG đụng `config/system_settings.yaml` thật và KHÔNG đụng `threat_memory.db` thật.
    Luật được tiêm THẲNG vào thuộc tính của `RuleEngine` trong bộ nhớ, danh tiếng tắt hẳn.
    Nhờ vậy script an toàn khi chạy song song với demo/dịch vụ.

ĐỌC KẾT QUẢ CHO ĐÚNG
    Đây là cận TRÊN lạc quan của vòng phản hồi: analyst được giả định duyệt ĐÚNG mọi luật,
    và luồng vòng 2 y hệt vòng 1 (kẻ tấn công không đổi IP). Nó chứng minh CƠ CHẾ hoạt
    động và đo được, KHÔNG phải dự báo mức giảm tải ngoài đời. Phải nêu đúng như vậy.

Thuần Tier-1, KHÔNG cần LLM. Chạy:
    .venv/bin/python experiments/evaluate_feedback_loop.py
"""

import argparse
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import confusion_report, wilson_ci  # noqa: E402
from experiments.unified_dataset import ROOT, build_stream, score_stream  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(ROOT, "experiments", "results", "feedback_loop_results.json")

# Hành động chứng tỏ Tier-1 đã TỰ kết luận IP này đáng chặn -> ứng viên sinh luật.
BLOCKWORTHY = {"BLOCK_IP"}
# Điểm luật IP đã duyệt — khớp `FeedbackListener.receive_new_rule(score=100)` ở đường thật.
APPROVED_RULE_SCORE = 100


def _fresh_engine() -> RuleEngine:
    """Engine CÁCH LY: luật động rỗng + TẮT danh tiếng.

    Tắt reputation là bắt buộc: nếu bật, `threat_memory.db` THẬT sẽ can thiệp vào phán
    quyết và ta không còn phân biệt được "Tier-1 hấp thụ nhờ LUẬT vừa duyệt" với "Tier-1
    chặn nhờ tiền sử tích luỹ từ những lần chạy trước" — tức là đo nhầm thứ.
    """
    engine = RuleEngine()
    engine.dynamic_ip_blocks = set()
    engine.dynamic_behavioral_rules = []
    engine.reputation_enforcement = False
    return engine


def _run_round(engine, warmup, main) -> dict:
    """Một vòng chấm + thống kê định tuyến. Tái dùng `score_stream()` dùng chung."""
    scored = score_stream(engine, warmup, main, collect_zeroday=False)
    cls = scored["confusion"]
    rep = confusion_report(cls["tp"], cls["fp"], cls["tn"], cls["fn"])
    n_events = scored["n_stream_events"]
    return {
        "n_stream_events": n_events,
        "n_flagged": scored["n_flagged"],
        "escalation_rate": round(scored["n_flagged"] / n_events, 4) if n_events else 0.0,
        "detection": rep,
        "records": scored["records"],
    }


def _harvest_rules(engine, warmup, main) -> tuple[set, dict]:
    """Chạy lại luồng để THU các IP mà Tier-1 tự kết luận đáng chặn = luật analyst sẽ duyệt.

    Cần một lượt riêng vì `score_stream()` chỉ trả phán quyết đã gộp, không trả IP nguồn.
    Engine truyền vào phải là engine ĐÃ chạy vòng 1 (baseline đã ấm) để phán quyết khớp.
    """
    ips: set[str] = set()
    n_seen = 0
    for ev in main:
        log = dict(ev["log"])
        res = engine.evaluate(log)
        if res.get("tier1_action") in BLOCKWORTHY:
            ip = res.get("Source IP") or res.get("src_ip")
            if ip:
                ips.add(str(ip))
        n_seen += 1
    return ips, {"n_events_scanned": n_seen}


def run(limit_rules: int | None = None) -> dict:
    print("=" * 84)
    print("  SENTINEL — VÒNG PHẢN HỒI: luật đã duyệt có thực sự giảm tải Tier-2 không?")
    print("=" * 84)

    warmup, main, _apt_truth, _n_chains = build_stream()
    print(f"[*] Luồng: {len(warmup)} warmup + {len(main)} sự kiện chính\n")

    # ---- VÒNG 1: chưa có luật nào -------------------------------------------- #
    print("[1/3] Vòng 1 — luật động RỖNG (nền đối chứng)…")
    engine1 = _fresh_engine()
    r1 = _run_round(engine1, warmup, main)
    print(
        f"      leo thang {r1['escalation_rate']:.2%} "
        f"({r1['n_flagged']}/{r1['n_stream_events']}) · MCC={r1['detection']['mcc']}"
    )

    # ---- Thu luật + "analyst duyệt" ------------------------------------------ #
    print("[2/3] Thu luật Tier-1 tự đề xuất, mô phỏng analyst DUYỆT…")
    harvested, meta = _harvest_rules(engine1, warmup, main)
    rules = sorted(harvested)
    if limit_rules:
        rules = rules[:limit_rules]
    print(f"      {len(rules)} luật Source IP được duyệt (ACTIVE, score={APPROVED_RULE_SCORE})")

    # ---- VÒNG 2: engine mới MANG luật đã duyệt ------------------------------- #
    print("[3/3] Vòng 2 — cùng luồng, Tier-1 đã học luật…")
    engine2 = _fresh_engine()
    engine2.dynamic_ip_blocks = set(rules)  # đúng dạng RuleEngine nạp từ YAML
    r2 = _run_round(engine2, warmup, main)
    print(
        f"      leo thang {r2['escalation_rate']:.2%} "
        f"({r2['n_flagged']}/{r2['n_stream_events']}) · MCC={r2['detection']['mcc']}"
    )

    # ---- Δ ------------------------------------------------------------------- #
    # "Hấp thụ" = ca vòng 1 phải leo thang lên Tier-2 mà vòng 2 Tier-1 tự xử xong.
    # Đây chính là đại lượng mà tuyên bố "vòng phản hồi giảm tải LLM" nói tới.
    esc1, esc2 = r1["n_flagged"], r2["n_flagged"]
    absorbed = max(0, esc1 - esc2)
    d1, d2 = r1["detection"], r2["detection"]

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "n_rules_approved": len(rules),
        "round1_no_rules": {
            "escalation_rate": r1["escalation_rate"],
            "n_flagged": esc1,
            "mcc": d1["mcc"],
            "recall": d1["recall"],
            "precision": d1["precision"],
        },
        "round2_with_rules": {
            "escalation_rate": r2["escalation_rate"],
            "n_flagged": esc2,
            "mcc": d2["mcc"],
            "recall": d2["recall"],
            "precision": d2["precision"],
        },
        "delta": {
            # Chỉ số ĐẦU BẢNG của vòng phản hồi.
            "escalation_rate_abs": round(r2["escalation_rate"] - r1["escalation_rate"], 4),
            "escalation_reduction_pct": round(100 * absorbed / esc1, 2) if esc1 else 0.0,
            "n_absorbed_by_tier1": absorbed,
            "absorption_ci95": list(wilson_ci(absorbed, esc1)) if esc1 else None,
            # Chốt an toàn: giảm tải mà mất khả năng phát hiện thì KHÔNG phải cải thiện.
            "mcc_delta": round(d2["mcc"] - d1["mcc"], 4),
            "recall_delta": round(d2["recall"] - d1["recall"], 4),
            "detection_preserved": d2["recall"] >= d1["recall"] - 0.01,
        },
        "meta": meta,
        "interpretation": (
            "Cận TRÊN lạc quan: giả định analyst duyệt đúng mọi luật và kẻ tấn công KHÔNG "
            "đổi IP giữa hai vòng. Chứng minh cơ chế vòng phản hồi hoạt động và ĐO ĐƯỢC, "
            "KHÔNG phải dự báo mức giảm tải ngoài đời thực."
        ),
    }

    d = summary["delta"]
    print("\n" + "-" * 84)
    print(f"  Tier-1 hấp thụ thêm : {d['n_absorbed_by_tier1']} ca (CI95 {d['absorption_ci95']})")
    print(f"  Giảm leo thang      : {d['escalation_reduction_pct']}%")
    print(
        f"  Phát hiện giữ nguyên: {'CÓ' if d['detection_preserved'] else 'KHÔNG — cảnh báo!'} "
        f"(ΔMCC={d['mcc_delta']:+}, ΔRecall={d['recall_delta']:+})"
    )
    print("-" * 84)
    if not d["detection_preserved"]:
        print("[!] Recall TỤT sau khi nạp luật — vòng phản hồi đang đánh đổi sai. Điều tra.")

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n[+] JSON: {OUT_JSON}")
    return summary


def main():
    ap = argparse.ArgumentParser(description="Đo vòng phản hồi Tier-2 -> luật -> Tier-1")
    ap.add_argument(
        "--limit-rules",
        type=int,
        default=None,
        help="Chỉ duyệt N luật đầu (khảo sát đường cong 'duyệt bao nhiêu thì đủ')",
    )
    args = ap.parse_args()
    run(limit_rules=args.limit_rules)


if __name__ == "__main__":
    main()
