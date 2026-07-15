"""
SENTINEL — Tier-2 Escalation Adjudication Accuracy (LLM decision quality)
========================================================================
Câu hỏi mà file này trả lời: "KHI một sự kiện được Tier-1 ĐẨY LÊN LLM (action =
ESCALATE), tác tử Tier-2 phán quyết ĐÚNG hay SAI, tỉ lệ bao nhiêu?"

Vì sao cần chỉ số RIÊNG này (khác F1 phân loại 0.61 ở `evaluate_unified_stream.py`):
  - F1 0.61 đo TẦNG LỌC Tier-1 (rule tĩnh + Welford) trên TOÀN luồng — đa số benign
    bị DROP ngay ở Tier-1, phần lộ rõ bị BLOCK/ALERT/HITL ngay, KHÔNG phiền LLM.
  - Chỉ một tập nhỏ "ĐÁNG NGỜ NHƯNG CHƯA CHẮC" mới mang action ESCALATE → gọi LLM.
    Chỉ số ở đây đo riêng NĂNG LỰC PHÁN QUYẾT của LLM trên đúng tập khó đó, có
    ĐỐI CHIẾU ground-truth — điều F1 tổng thể không tách bạch được.

Phương pháp (điều kiện-hoá theo escalation, KHÔNG bịa dữ liệu):
  1. Dựng CÙNG luồng gộp thật (CICIDS+DAPT+zero-day) qua `unified_dataset.build_stream`.
  2. Chạy qua Tier-1 THẬT (golden baseline bật) → GOM đúng các sự kiện action==ESCALATE.
  3. Mỗi sự kiện escalate → chạy qua Tier-2 THẬT (LangGraph agent: Guardrails → RAG →
     LLM → consensus guard) → lấy action CUỐI.
  4. So với ground-truth theo QUY ƯỚC DƯƠNG đồng nhất của luận văn: một sự kiện được
     coi là "gắn cờ" (flagged) khi LLM KHÔNG hạ cấp im lặng — tức action ∈
     {BLOCK_IP, ALERT, AWAIT_HITL, ESCALATE}. Threat đúng khi flagged; benign (lọt
     Tier-1) đúng khi được hạ cấp {DROP/LOG}.

HAI RÀO CHẮN TÍNH HỢP LỆ (thêm sau sự cố 2026-07-14, xem `n_invoke_errors`):
  - Ca agent KHÔNG cho ra phán quyết (crash / no_decision) bị LOẠI khỏi mẫu số chấm
    điểm và tính riêng thành `agent_reliability`. Trước đây các ca này rơi về mặc
    định AWAIT_HITL và bị tính là "bắt đúng đe doạ" -> recall giả 1.00.
  - `majority_baseline` (= tỉ lệ threat) luôn được in kèm accuracy: một stub luôn hô
    "threat" đạt đúng mốc này, nên accuracy KHÔNG vượt mốc = không có năng lực phân
    biệt. `metric_valid=false` nếu >5% ca lỗi.

Kết quả: accuracy tổng, recall trên threat, specificity trên benign, ma trận nhầm
lẫn, phân bố action LLM, phân rã theo nguồn → `results/tier2_decision_results.json`.

Chạy (CẦN LLM server ở :5000):
    .venv/bin/python experiments/evaluate_tier2_decision.py            # toàn bộ tập escalate
    .venv/bin/python experiments/evaluate_tier2_decision.py --limit 12 # thử nhanh
"""

import argparse
import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.unified_dataset import ROOT, build_stream  # noqa: E402
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402
from src.guardrails import loop_detector  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(ROOT, "experiments", "results", "tier2_decision_results.json")
REPORT_MD = os.path.join(ROOT, "reports", "tier2_decision_report.md")

# Quy ước DƯƠNG đồng nhất với luận văn: KHÔNG hạ cấp im lặng = gắn cờ (positive).
FLAG_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE", "QUARANTINE", "ISOLATE"}


def _ground_truth(ev: dict) -> bool:
    """True = sự kiện THẬT là mối đe doạ (theo nhãn nguồn)."""
    src = ev["source"]
    if src == "cicids":
        return bool(ev.get("expected_threat"))
    if src == "zeroday":
        return True
    if src == "dapt":
        return bool(ev.get("is_attack"))
    if src == "adversarial":
        return True
    return False


def _is_flagged(action: str) -> bool:
    return str(action or "").strip().upper() in FLAG_ACTIONS


def collect_escalated():
    """Chạy Tier-1 thật trên luồng gộp, trả về danh sách sự kiện action==ESCALATE
    (kèm ground-truth + nguồn). Warmup prefix để Welford ấm (golden cũng đã seed)."""
    warmup, main, _apt_truth, _n = build_stream()
    engine = RuleEngine()
    for ev in warmup:
        engine.evaluate(ev["log"])
    escalated = []
    for ev in main:
        res = engine.evaluate(ev["log"])
        if res.get("tier1_action") == "ESCALATE":
            escalated.append(
                {"log": dict(res), "source": ev["source"], "is_threat": _ground_truth(ev)}
            )
    return escalated


def _tier2_decide(item: dict) -> dict:
    """Chạy MỘT sự kiện escalate qua Tier-2 thật, lấy action + confidence cuối."""
    state = SentinelState(
        current_batch_logs=[item["log"]], current_batch_size=1, narrative_summary=""
    )
    action, confidence, err = "AWAIT_HITL", 0.0, ""
    # BẮT BUỘC (giống main.py:66 và eval_attack_mapper.py:162): loop-guard đếm CỘNG DỒN
    # qua các invoke. Bộ đếm là thread-local nên reset ngay trong worker này là đúng phạm vi.
    # Thiếu dòng này => sau max_iterations(=10) invoke/luồng, MỌI invoke sau đều FORCE_STOP
    # -> RuntimeError -> rơi vào nhánh except -> AWAIT_HITL bị TÍNH LÀ "bắt đúng đe doạ".
    loop_detector.reset()
    invoke_error = ""
    try:
        final = agent_app.invoke(state)
        decisions = final.get("decisions", [])
        if decisions:
            d = decisions[-1]
            action = d.get("action", "AWAIT_HITL")
            confidence = float(d.get("confidence", 0.0) or 0.0)
            err = d.get("error", "") or ""
        else:
            # Agent chạy xong nhưng KHÔNG sinh phán quyết nào -> KHÔNG có gì để chấm.
            invoke_error = "no_decision"
    except Exception as exc:  # noqa: BLE001 — 1 sự kiện lỗi không được làm hỏng cả eval
        invoke_error = f"invoke_error:{type(exc).__name__}"
    return {
        "source": item["source"],
        "is_threat": item["is_threat"],
        "llm_action": action,
        "confidence": round(confidence, 3),
        "flagged": _is_flagged(action),
        "error": err,
        # != "" nghĩa là agent KHÔNG cho ra phán quyết hợp lệ. Ca này phải bị LOẠI khỏi
        # mẫu số chất lượng phán quyết — nếu không, một cú crash rơi về mặc định
        # AWAIT_HITL sẽ được tính là "bắt đúng đe doạ" (TP) và bơm recall lên 1.00.
        "invoke_error": invoke_error,
    }


def run(limit: int | None = None, workers: int = 2, out: str | None = None):
    out_path = out or OUT_JSON
    print("=" * 72)
    print("  SENTINEL — TIER-2 ESCALATION ADJUDICATION ACCURACY (chất lượng LLM)")
    print("=" * 72)
    escalated = collect_escalated()
    if limit:
        escalated = escalated[:limit]
    n = len(escalated)
    print(f"[*] Sự kiện Tier-1 ESCALATE: {n} (chạy qua Tier-2 thật, workers={workers})")
    if n == 0:
        print("[!] Không có sự kiện escalate — bỏ qua.")
        return None

    # Xử lý song song (an toàn: agent đã hardened bằng khoá/thread-local); GOM theo
    # index để kết quả TẤT ĐỊNH bất kể thứ tự hoàn thành.
    results: list[dict] = [dict() for _ in range(n)]
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_tier2_decide, escalated[i]): i for i in range(n)}
        for fut, i in list(futures.items()):
            results[i] = fut.result()
            done += 1
            if done % 25 == 0 or done == n:
                print(f"    ... {done}/{n} sự kiện đã phán quyết")

    # --- ĐỘ TIN CẬY của agent: TÁCH khỏi chất lượng phán quyết ------------- #
    # Ca mà agent không cho ra phán quyết (crash / no_decision) KHÔNG có gì để chấm.
    # Trộn chúng vào ma trận nhầm lẫn = tính một cú crash thành "bắt đúng đe doạ".
    errored = [r for r in results if r["invoke_error"]]
    scored = [r for r in results if not r["invoke_error"]]
    n_err = len(errored)
    error_rate = n_err / n if n else 0.0
    agent_reliability = round(1.0 - error_rate, 4)
    err_dist = dict(Counter(r["invoke_error"] for r in errored))
    # Chỉ số chỉ đáng tin khi tuyệt đại đa số ca thực sự được phán quyết.
    metric_valid = error_rate <= 0.05

    # --- Ma trận nhầm lẫn có ĐIỀU KIỆN escalate (CHỈ trên ca chấm được) ---- #
    tp = sum(1 for r in scored if r["is_threat"] and r["flagged"])
    fn = sum(1 for r in scored if r["is_threat"] and not r["flagged"])
    tn = sum(1 for r in scored if not r["is_threat"] and not r["flagged"])
    fp = sum(1 for r in scored if not r["is_threat"] and r["flagged"])
    n_scored = len(scored)
    n_threat, n_benign = tp + fn, tn + fp
    accuracy = (tp + tn) / n_scored if n_scored else 0.0
    threat_recall = tp / n_threat if n_threat else 0.0
    benign_specificity = tn / n_benign if n_benign else 0.0
    # Mốc đối chứng BẮT BUỘC đọc kèm accuracy: một stub luôn hô "threat" đạt đúng
    # base rate. accuracy <= mốc này => chỉ số KHÔNG có năng lực phân biệt.
    majority_baseline = round(n_threat / n_scored, 4) if n_scored else 0.0

    action_dist = Counter(r["llm_action"] for r in scored)
    by_source = {}
    for src in sorted({r["source"] for r in scored}):
        sub = [r for r in scored if r["source"] == src]
        s_tp = sum(1 for r in sub if r["is_threat"] and r["flagged"])
        s_thr = sum(1 for r in sub if r["is_threat"])
        by_source[src] = {
            "n": len(sub),
            "threat": s_thr,
            "threat_flagged": s_tp,
            "threat_recall": round(s_tp / s_thr, 4) if s_thr else None,
        }
    n_parse_fail = sum(1 for r in scored if r["error"] in ("parse_failed", "parse_salvaged"))
    confs = [r["confidence"] for r in scored if r["flagged"]]
    mean_conf_flagged = round(sum(confs) / len(confs), 3) if confs else 0.0

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "metric_valid": metric_valid,
        "n_escalated": n,
        "n_scored": n_scored,
        "n_invoke_errors": n_err,
        "agent_reliability": agent_reliability,
        "invoke_error_distribution": err_dist,
        "n_threat": n_threat,
        "n_benign": n_benign,
        "accuracy": round(accuracy, 4),
        "majority_baseline": majority_baseline,
        "threat_recall": round(threat_recall, 4),
        "benign_specificity": round(benign_specificity, 4),
        "confusion": {"tp": tp, "fn": fn, "tn": tn, "fp": fp},
        "llm_action_distribution": dict(action_dist),
        "mean_confidence_flagged": mean_conf_flagged,
        "n_parse_fallback": n_parse_fail,
        "by_source": by_source,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "details": results}, f, indent=2, ensure_ascii=False)
    _print(summary)
    _write_report(summary)
    print(f"\n[+] JSON: {out_path}\n[+] Report: {REPORT_MD}")
    return summary


def _print(s: dict):
    print("\n" + "-" * 72)
    print(
        f"  Escalate tới LLM      : {s['n_escalated']} (chấm được {s['n_scored']}, lỗi {s['n_invoke_errors']})"
    )
    print(f"  Độ tin cậy agent       : {s['agent_reliability']}  {s['invoke_error_distribution']}")
    print(f"  Tập chấm điểm          : threat {s['n_threat']} / benign {s['n_benign']}")
    print(
        f"  ĐỘ CHÍNH XÁC phán quyết: {s['accuracy']}  (đúng {s['confusion']['tp'] + s['confusion']['tn']}/{s['n_scored']})"
    )
    print(
        f"    ↳ mốc đối chứng (luôn hô 'threat'): {s['majority_baseline']}"
        f"  => {'KHÔNG hơn mốc — không có năng lực phân biệt' if s['accuracy'] <= s['majority_baseline'] else 'vượt mốc'}"
    )
    print(
        f"  Recall trên threat     : {s['threat_recall']}  (bắt {s['confusion']['tp']}/{s['n_threat']})"
    )
    print(
        f"  Specificity trên benign: {s['benign_specificity']}  (hạ cấp {s['confusion']['tn']}/{s['n_benign']})"
    )
    print(
        f"  Ma trận (TP/FN/TN/FP)  : {s['confusion']['tp']}/{s['confusion']['fn']}/{s['confusion']['tn']}/{s['confusion']['fp']}"
    )
    print(f"  Phân bố action LLM     : {s['llm_action_distribution']}")
    print(f"  Fallback parse (an toàn): {s['n_parse_fallback']}")
    print("-" * 72)
    if not s["metric_valid"]:
        print(
            f"\n  {'!' * 68}\n"
            f"  [!] CHỈ SỐ KHÔNG HỢP LỆ — {s['n_invoke_errors']}/{s['n_escalated']} ca agent KHÔNG cho ra\n"
            f"      phán quyết ({s['invoke_error_distribution']}). Ngưỡng cho phép: 5%.\n"
            f"      TUYỆT ĐỐI KHÔNG trích số của lần chạy này vào luận văn/báo cáo.\n"
            f"      Sửa nguyên nhân rồi chạy lại.\n"
            f"  {'!' * 68}\n"
        )


def _write_report(s: dict):
    c = s["confusion"]
    lines = [
        "# Báo Cáo: Độ Chính Xác Phán Quyết Tier-2 (Escalation Adjudication)\n",
        "> Đo RIÊNG năng lực phán quyết của LLM **trên đúng tập sự kiện Tier-1 đẩy lên** "
        "(`action == ESCALATE`), có đối chiếu ground-truth. Bổ trợ cho F1 phân loại "
        "Tier-1 (Bảng phân loại Luồng Gộp) — F1 đó đo tầng LỌC, còn số ở đây đo tầng SUY LUẬN.\n",
        f"> **Sinh lúc:** {s['timestamp']}\n",
        "---\n",
        "## Kết quả\n",
    ]
    if not s["metric_valid"]:
        lines.append(
            f"> 🚨 **CHỈ SỐ KHÔNG HỢP LỆ** — {s['n_invoke_errors']}/{s['n_escalated']} ca agent KHÔNG cho ra "
            f"phán quyết ({s['invoke_error_distribution']}), vượt ngưỡng 5%. **Không trích số dưới đây** "
            f"vào luận văn; sửa nguyên nhân rồi chạy lại.\n"
        )
    lines += [
        f"- Sự kiện escalate tới LLM: **{s['n_escalated']}** — chấm được **{s['n_scored']}**, "
        f"lỗi **{s['n_invoke_errors']}** (độ tin cậy agent **{s['agent_reliability']}**)",
        f"- Tập chấm điểm: threat **{s['n_threat']}** / benign lọt **{s['n_benign']}**",
        f"- **Độ chính xác phán quyết: {s['accuracy']}** (đúng {c['tp'] + c['tn']}/{s['n_scored']})",
        f"  - Mốc đối chứng *luôn hô 'threat'*: **{s['majority_baseline']}** — accuracy chỉ có ý nghĩa "
        f"nếu **vượt** mốc này; bằng mốc = không có năng lực phân biệt.",
        f"- Recall trên threat (không bỏ sót): **{s['threat_recall']}** (bắt {c['tp']}/{s['n_threat']})",
        f"- Specificity trên benign (hạ cấp đúng): **{s['benign_specificity']}** ({c['tn']}/{s['n_benign']})",
        f"- Ma trận nhầm lẫn — TP/FN/TN/FP: **{c['tp']} / {c['fn']} / {c['tn']} / {c['fp']}**",
        f"- Confidence trung bình khi gắn cờ: {s['mean_confidence_flagged']}",
        f"- Số ca dùng fallback parse an toàn (AWAIT_HITL): {s['n_parse_fallback']}\n",
        "## Phân bố hành động LLM\n",
        "| Action | Số ca |",
        "| :--- | :---: |",
    ]
    for a, cnt in sorted(s["llm_action_distribution"].items(), key=lambda x: -x[1]):
        lines.append(f"| {a} | {cnt} |")
    lines.append("\n## Phân rã theo nguồn\n")
    lines.append("| Nguồn | Escalate | Threat | Bắt được | Recall |")
    lines.append("| :--- | :---: | :---: | :---: | :---: |")
    for src, d in s["by_source"].items():
        lines.append(
            f"| {src} | {d['n']} | {d['threat']} | {d['threat_flagged']} | {d['threat_recall']} |"
        )
    lines.append("")
    os.makedirs(os.path.dirname(REPORT_MD), exist_ok=True)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Tier-2 escalation adjudication accuracy")
    ap.add_argument("--limit", type=int, default=None, help="Giới hạn số sự kiện (thử nhanh)")
    ap.add_argument(
        "--workers", type=int, default=2, help="Số luồng song song (khớp llama.cpp -np)"
    )
    ap.add_argument(
        "--out", type=str, default=None, help="Đường dẫn JSON đầu ra (mặc định results/)"
    )
    args = ap.parse_args()
    run(limit=args.limit, workers=args.workers, out=args.out)
