"""
Ablation CÂN BẰNG (Balanced 150/150) — tất cả 6 cấu hình A–F trên cùng tập.
=========================================================================
Ablation gốc (run_ablation_study.py + run_ablation_bcde.py) chạy trên tập phân
tầng 93% tấn công -> mọi cấu hình suy biến về dự đoán toàn-dương (F1 = base rate).
Để PHÉP SO CẤU PHẦN có ý nghĩa, ở đây ta dựng tập CÂN BẰNG:

  150 benign (expected=LOG)  +  150 tấn công (phân tầng đều trên 15 lớp = 10/lớp)

Khi có benign thật, gate Welford/Tier-1 có cơ hội DROP benign (true negative) nên
các cấu hình C/D/E/F không còn buộc phải trùng nhau, và ta đo được:
  - A   : Tier-1 rule-only (không LLM)
  - B   : Pure LLM (mọi mẫu -> LLM, không gate, không RAG)
  - C   : gate Welford + LLM (không RAG)
  - D   : gate + dense RAG + LLM
  - E   : gate + hybrid RAG + LLM
  - F   : SENTINEL đầy đủ (agent_app, có Consensus Guard)

Chạy (cần LLM server):
    .venv/bin/python experiments/run_ablation_balanced.py
"""

import json
import os
import sys
import time

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.run_ablation_bcde import (  # noqa: E402
    build_rag_query,
    dense_only_context,
    hybrid_context,
    llm_action,
    run_gate,
    to_pred,
)
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
OUT_PATH = os.path.join(os.path.dirname(__file__), "results", "ablation_balanced_results.json")

N_BENIGN = 150
N_ATTACK = 150


def load_ground_truth():
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def balanced_subset(dataset):
    """Trả về (subset, warmup_logs).

    subset = 150 benign + 150 attack (phân tầng đều trên các lớp tấn công).
    warmup_logs = 150 benign THẬT GIỮ RIÊNG (disjoint với eval) để hiệu chỉnh baseline
    Welford trên phân phối benign thực — tránh việc warmup tổng hợp (toy) khiến mọi
    flow benign thật bị coi là outlier (báo động nhầm hàng loạt). Tất định.
    """
    benign = [s for s in dataset if s["expected_action"] == "LOG"]
    attack = [s for s in dataset if s["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL")]

    by_label = {}
    for s in attack:
        lbl = s["input"].get("cicids_label", "unknown")
        by_label.setdefault(lbl, []).append(s)
    num_classes = len(by_label)
    per_class = max(1, (N_ATTACK + num_classes - 1) // num_classes)
    attack_sel = []
    for _lbl, samples in by_label.items():
        attack_sel.extend(samples[:per_class])
    attack_sel = attack_sel[:N_ATTACK]

    benign_sel = benign[:N_BENIGN]  # eval benign
    warmup_benign = benign[N_BENIGN : N_BENIGN + 150]  # held-out benign cho warmup
    warmup_logs = [log for s in warmup_benign for log in s.get("logs", [])]

    subset = benign_sel + attack_sel
    return subset, warmup_logs


def main():
    dataset, warmup_logs = balanced_subset(load_ground_truth())
    n_b = sum(1 for s in dataset if s["expected_action"] == "LOG")
    n_a = len(dataset) - n_b
    print(f"[*] Ablation CÂN BẰNG: {len(dataset)} mẫu ({n_b} benign + {n_a} attack)")

    rule_engine = RuleEngine()
    print(f"[*] Warmup baseline Welford trên {len(warmup_logs)} flow benign THẬT (held-out)...")
    for log in warmup_logs:
        rule_engine.evaluate(dict(log))
    print("[+] Warmup complete.")

    R = {c: {"y_true": [], "y_pred": [], "latencies": [], "escalated": []} for c in "ABCDEF"}

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        # --- A: Tier-1 rule-only (không LLM) ---
        t0 = time.time()
        pred_a = 0
        for log in logs:
            if rule_engine.evaluate(log).get("tier1_action") in (
                "BLOCK_IP",
                "ALERT",
                "AWAIT_HITL",
                "ESCALATE",
            ):
                pred_a = 1
                break
        lat_a = time.time() - t0

        # --- Gate Welford dùng chung cho C/D/E/F ---
        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        # --- B: Pure LLM (luôn gọi, không RAG) ---
        a_b, l_b = llm_action(logs, "")
        p_b = to_pred(a_b)

        # --- C/D/E: gate + (no RAG / dense / hybrid) ---
        if needs_llm:
            a_c, l_c = llm_action(logs, "")
            p_c = to_pred(a_c)
            a_d, l_d = llm_action(logs, dense_only_context(query))
            p_d = to_pred(a_d)
            a_e, l_e = llm_action(logs, hybrid_context(query))
            p_e = to_pred(a_e)
        else:
            l_c = l_d = l_e = 0.0006
            p_c = p_d = p_e = tier1_pred

        # --- F: SENTINEL đầy đủ (agent_app + Consensus Guard) ---
        t0 = time.time()
        pred_f = 0
        if needs_llm:
            from src.guardrails import loop_detector

            loop_detector.reset()
            try:
                final_state = agent_app.invoke(
                    SentinelState(
                        current_batch_logs=logs,
                        current_batch_size=len(logs),
                        narrative_summary="",
                    )
                )
                decisions = final_state.get("decisions", [])
                if decisions and decisions[-1].get("action") in (
                    "BLOCK_IP",
                    "ALERT",
                    "AWAIT_HITL",
                    "ESCALATE",
                ):
                    pred_f = 1
            except Exception as e:
                print(f"   [F ERROR] {sample['id']}: {e}")
        else:
            pred_f = tier1_pred
        lat_f = time.time() - t0

        for c, pred, lat, esc in (
            ("A", pred_a, lat_a, 0),
            ("B", p_b, l_b, 1),
            ("C", p_c, l_c, 1 if needs_llm else 0),
            ("D", p_d, l_d, 1 if needs_llm else 0),
            ("E", p_e, l_e, 1 if needs_llm else 0),
            ("F", pred_f, lat_f, 1 if needs_llm else 0),
        ):
            R[c]["y_true"].append(is_attack)
            R[c]["y_pred"].append(pred)
            R[c]["latencies"].append(lat)
            R[c]["escalated"].append(esc)

        print(
            f"[{idx + 1}/{len(dataset)}] {sample['id']} true={is_attack} esc={int(needs_llm)} "
            f"| A={pred_a} B={p_b} C={p_c} D={p_d} E={p_e} F={pred_f}"
        )

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {OUT_PATH}\n")

    print(f"{'Cfg':>3} | {'F1':>6} | {'Prec':>6} | {'Rec':>6} | {'Esc%':>5} | {'Lat(s)':>7}")
    for c in "ABCDEF":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)
        prec = precision_score(yt, yp, zero_division=0)
        rec = recall_score(yt, yp, zero_division=0)
        esc = 100.0 * np.mean(R[c]["escalated"])
        lat = float(np.mean(R[c]["latencies"]))
        print(f"{c:>3} | {f1:>6.4f} | {prec:>6.4f} | {rec:>6.4f} | {esc:>5.1f} | {lat:>7.3f}")


if __name__ == "__main__":
    main()
