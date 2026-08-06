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
    Nạp luật — mô phỏng analyst DUYỆT: mỗi IP mà **Cổng ML** phán `BLOCK_IP` (trên các ca
      Tier-1 đã ESCALATE) trở thành một luật `Source IP` `status=ACTIVE` — khớp từng bước
      với `subscriber.py:535`. Đây là một trong ba nguồn sinh luật CÓ THẬT; hai nguồn còn
      lại là tác tử Tier-2 (`nodes.py:1627`) và analyst bấm UI (`app.py:263`), đều cần LLM
      nên nằm ngoài phép đo offline này -> kết quả là cận DƯỚI.
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
from experiments.unified_dataset import (  # noqa: E402
    ESCALATE_ACTION,
    ROOT,
    build_stream,
    score_stream,
)
from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402
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
    # LEO THANG = số ca Tier-1 KHÔNG tự xử được, phải đẩy lên Cổng ML/LLM — tức đúng
    # `action == "ESCALATE"`. KHÔNG dùng `n_flagged`: nó gộp cả `BLOCK_IP`, vốn là điểm
    # CUỐI tại Tier-1. Lấy `n_flagged` thì mỗi luật mới biến một ca escalate thành BLOCK_IP
    # (vòng phản hồi THÀNH CÔNG, tải LLM về 0) lại làm "leo thang" TĂNG — thước đo tăng
    # đúng lúc thứ nó đo được cải thiện, nên kết luận ngược dấu.
    n_esc = scored["n_escalated"]
    return {
        "n_stream_events": n_events,
        "n_escalated": n_esc,
        "n_await_hitl": scored["n_await_hitl"],
        "n_flagged": scored["n_flagged"],  # giữ để đối chiếu: PHÁT HIỆN, không phải TẢI
        "escalation_rate": round(n_esc / n_events, 4) if n_events else 0.0,
        "hitl_rate": round(scored["n_await_hitl"] / n_events, 4) if n_events else 0.0,
        "action_counts": scored["action_counts"],
        "detection": rep,
        "records": scored["records"],
    }


def _harvest_rules(engine, warmup, main, rule_source: str = "ml_gate") -> tuple[set, dict]:
    """Chạy lại luồng để THU các IP sẽ trở thành luật động — MÔ PHỎNG ĐÚNG nguồn của hệ thật.

    Cần một lượt riêng vì `score_stream()` chỉ trả phán quyết đã gộp, không trả IP nguồn.
    Engine truyền vào phải là engine ĐÃ chạy vòng 1 (baseline đã ấm) để phán quyết khớp.

    `rule_source="ml_gate"` (MẶC ĐỊNH, đúng hệ thật)
        Chỉ ca Tier-1 ĐẨY LÊN (`action == "ESCALATE"`) mới tới Cổng ML; Cổng ML phán
        `BLOCK_IP` thì sinh luật. Khớp từng bước với `subscriber.py:535`
        (`FeedbackListener().receive_new_rule(..., source="ml_triage")`).

    `rule_source="tier1"` (hành vi CŨ, giữ để đối chiếu — KHÔNG dùng để trích số)
        Thu từ chính `BLOCK_IP` của Tier-1. Đây là LỖI MÔ HÌNH: rà `receive_new_rule` trong
        `src/` cho đúng ba nơi gọi — tác tử Tier-2 (`nodes.py:1627`), Cổng ML
        (`subscriber.py:535`), analyst bấm UI (`app.py:263`). KHÔNG nơi nào sinh luật từ
        phán quyết của Tier-1. Lấy nguồn precision 0,356 thay cho nguồn precision ~99,9%
        nên tập luật nạp vào toàn rác mà hệ thật không bao giờ tạo ra (đo được: 54,8% luật
        chặn nhầm IP lành tính, kéo MCC vòng 2 xuống -0,16).

    KHÔNG bao gồm đường LLM: thực nghiệm này chạy offline, không gọi Tier-2. Vì vậy tập luật
    thu được là TẬP CON của tập hệ thật sinh ra -> kết quả là cận DƯỚI của vòng phản hồi.
    """
    ips: set[str] = set()
    n_seen = n_escalated = n_ml_block = 0
    gateway = MLGateway() if rule_source == "ml_gate" else None

    for ev in main:
        log = dict(ev["log"])
        res = engine.evaluate(log)
        act = res.get("tier1_action")
        ip = res.get("Source IP") or res.get("src_ip")
        n_seen += 1

        if rule_source == "tier1":
            if act in BLOCKWORTHY and ip:
                ips.add(str(ip))
            continue

        # Đường THẬT: Tier-1 tự xử xong (BLOCK/DROP/ALERT) thì KHÔNG sinh luật và cũng
        # không tới Cổng ML. Chỉ ESCALATE mới đi tiếp.
        if act != ESCALATE_ACTION:
            continue
        n_escalated += 1
        assert gateway is not None
        ml_action, _reason, _conf = gateway.evaluate(log)
        if ml_action == "BLOCK_IP":
            n_ml_block += 1
            if ip:
                ips.add(str(ip))

    return ips, {
        "n_events_scanned": n_seen,
        "rule_source": rule_source,
        "n_escalated_to_ml": n_escalated,
        "n_ml_gate_blocked": n_ml_block,
    }


def run(limit_rules: int | None = None, rule_source: str = "ml_gate") -> dict:
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
        f"({r1['n_escalated']}/{r1['n_stream_events']}) · HITL {r1['hitl_rate']:.2%} "
        f"· MCC={r1['detection']['mcc']}"
    )

    # ---- Thu luật + "analyst duyệt" ------------------------------------------ #
    _nhan = "Cổng ML (như subscriber.py)" if rule_source == "ml_gate" else "Tier-1 (bản CŨ, sai)"
    print(f"[2/3] Thu luật từ {_nhan}, mô phỏng analyst DUYỆT…")
    harvested, meta = _harvest_rules(engine1, warmup, main, rule_source=rule_source)
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
        f"({r2['n_escalated']}/{r2['n_stream_events']}) · HITL {r2['hitl_rate']:.2%} "
        f"· MCC={r2['detection']['mcc']}"
    )

    # ---- Δ ------------------------------------------------------------------- #
    # "Hấp thụ" = ca vòng 1 phải leo thang lên Tier-2 mà vòng 2 Tier-1 tự xử xong.
    # Đây chính là đại lượng mà tuyên bố "vòng phản hồi giảm tải LLM" nói tới.
    esc1, esc2 = r1["n_escalated"], r2["n_escalated"]
    absorbed = max(0, esc1 - esc2)
    d1, d2 = r1["detection"], r2["detection"]

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "n_rules_approved": len(rules),
        "round1_no_rules": {
            "escalation_rate": r1["escalation_rate"],
            "n_escalated": esc1,
            "hitl_rate": r1["hitl_rate"],
            "n_await_hitl": r1["n_await_hitl"],
            "n_flagged_detection": r1["n_flagged"],
            "action_counts": r1["action_counts"],
            "mcc": d1["mcc"],
            "recall": d1["recall"],
            "precision": d1["precision"],
        },
        "round2_with_rules": {
            "escalation_rate": r2["escalation_rate"],
            "n_escalated": esc2,
            "hitl_rate": r2["hitl_rate"],
            "n_await_hitl": r2["n_await_hitl"],
            "n_flagged_detection": r2["n_flagged"],
            "action_counts": r2["action_counts"],
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
            "hitl_delta_abs": round(r2["hitl_rate"] - r1["hitl_rate"], 4),
            "n_hitl_delta": r2["n_await_hitl"] - r1["n_await_hitl"],
            # Chốt an toàn: giảm tải mà mất khả năng phát hiện thì KHÔNG phải cải thiện.
            #
            # LỖI ĐÃ VÁ: cờ này từng chỉ xét `recall`. Recall CHỈ TĂNG khi gắn cờ nhiều hơn,
            # nên một luật chặn nhầm hàng loạt IP lành tính vẫn làm nó bật "CÓ" — tức cờ
            # không bao giờ bắt được đúng ca hỏng mà nó sinh ra để bắt. Thực tế đo được:
            # nó in "CÓ" trong khi MCC rơi 0,16. Nay phải giữ CẢ recall LẪN MCC, vì MCC là
            # đại lượng duy nhất ở đây phạt cả FP lẫn FN.
            "mcc_delta": round(d2["mcc"] - d1["mcc"], 4),
            "recall_delta": round(d2["recall"] - d1["recall"], 4),
            "precision_delta": round(d2["precision"] - d1["precision"], 4),
            "detection_preserved": (
                d2["recall"] >= d1["recall"] - 0.01 and d2["mcc"] >= d1["mcc"] - 0.01
            ),
        },
        "meta": meta,
        "interpretation": (
            "LEO THANG ở đây = số ca Tier-1 phải đẩy lên Cổng ML/LLM (action='ESCALATE'), "
            "KHÔNG phải số ca bị gắn cờ đe doạ — BLOCK_IP là điểm cuối tại Tier-1. "
            "Luật sinh từ phán quyết BLOCK_IP của Cổng ML trên các ca Tier-1 đã ESCALATE — "
            "khớp subscriber.py:535. Đường LLM (nodes.py:1627) và analyst bấm UI "
            "(app.py:263) cũng sinh luật trong hệ thật nhưng cần Tier-2 nên không có ở phép "
            "đo offline này, vì vậy đây là cận DƯỚI về số luật. Analyst mô phỏng duyệt mọi "
            "đề xuất, không có bước từ chối. Kẻ tấn công giả định KHÔNG đổi IP giữa hai "
            "vòng — điểm này thì lạc quan. Chứng minh cơ chế ĐO ĐƯỢC, không phải dự báo "
            "mức giảm tải ngoài đời."
        ),
    }

    d = summary["delta"]
    print("\n" + "-" * 84)
    print(f"  Tier-1 hấp thụ thêm : {d['n_absorbed_by_tier1']} ca (CI95 {d['absorption_ci95']})")
    print(f"  Giảm leo thang      : {d['escalation_reduction_pct']}%")
    print(
        f"  Tải HITL            : {r1['n_await_hitl']} -> {r2['n_await_hitl']} ca "
        f"({d['n_hitl_delta']:+}, {d['hitl_delta_abs']:+.2%})"
    )
    print(
        f"  Phát hiện giữ nguyên: {'CÓ' if d['detection_preserved'] else 'KHÔNG — cảnh báo!'} "
        f"(ΔMCC={d['mcc_delta']:+}, ΔRecall={d['recall_delta']:+})"
    )
    print("-" * 84)
    if not d["detection_preserved"]:
        # Nêu ĐÚNG vế nào hỏng. Bản trước in cứng "Recall TỤT" cho mọi ca, nên khi thủ phạm
        # là precision (recall còn TĂNG) thì thông điệp chỉ sai đường điều tra.
        ve = []
        if d["recall_delta"] < -0.01:
            ve.append(f"Recall tụt {d['recall_delta']:+.4f}")
        if d["mcc_delta"] < -0.01:
            ve.append(f"MCC tụt {d['mcc_delta']:+.4f} (ΔPrecision={d['precision_delta']:+.4f})")
        print(f"[!] Vòng phản hồi đánh đổi sai — {' · '.join(ve)}. Điều tra chất lượng luật.")

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
    ap.add_argument(
        "--rule-source",
        choices=["ml_gate", "tier1"],
        default="ml_gate",
        help="Nguồn sinh luật. ml_gate = như hệ thật (mặc định); tier1 = bản cũ, chỉ để đối chiếu",
    )
    args = ap.parse_args()
    run(limit_rules=args.limit_rules, rule_source=args.rule_source)


if __name__ == "__main__":
    main()
