"""
Ablation Study — Configs B, C, D, E (chạy thật, không ước tính).

Bổ sung cho run_ablation_study.py (vốn chỉ chạy A và F). Chạy trên CÙNG tập
300 mẫu phân tầng (sampling tất định) để so sánh được với A/F đã có.

  B — Pure LLM       : mọi mẫu -> LLM, KHÔNG gate Welford, KHÔNG RAG, KHÔNG guardrails.
  C — Welford+LLM    : gate Welford; mẫu escalate -> LLM (KHÔNG RAG, KHÔNG guardrails).
  D — Single dense RAG: gate Welford; escalate -> LLM + RAG chỉ-FAISS (dense-only).
  E — Hybrid RAG     : gate Welford; escalate -> LLM + RAG lai (FAISS+BM25+RRF).

Gate Welford được tính MỘT lần/mẫu và dùng chung cho C/D/E => escalation set giống
hệt nhau, nên hiệu số D-C và E-D cô lập đúng đóng góp của từng tầng RAG.

Verdict = action thô do LLM trả về (không áp consensus-guard của F) để đo năng lực
phân loại thuần của LLM theo từng cấu hình.
"""

import json
import os
import sys
import time

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.llm_client import llm_client
from src.agent.nodes import retriever
from src.agent.prompts import build_triage_prompt
from src.tier1_filter.rule_engine import RuleEngine

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
OUT_PATH = os.path.join(os.path.dirname(__file__), "results", "ablation_bcde_results.json")

ATTACK_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}
VALID_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "LOG", "DROP", "ESCALATE"}


def load_ground_truth():
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def stratified(dataset, limit):
    """Cùng logic phân tầng như run_ablation_study.py (tất định)."""
    if not limit:
        return dataset
    by_label = {}
    for sample in dataset:
        lbl = sample["input"].get("cicids_label", "unknown")
        by_label.setdefault(lbl, []).append(sample)
    num_classes = len(by_label)
    per_class = max(1, (limit + num_classes - 1) // num_classes)
    selected = []
    for _lbl, samples in by_label.items():
        selected.extend(samples[:per_class])
    return selected[:limit]


def build_rag_query(logs):
    """Tái dựng truy vấn RAG y như node_rag_context."""
    if not logs:
        return "suspicious network activity"
    first = logs[0]
    parts = []
    msg = (str(first.get("message", "")) + " " + str(first.get("payload", ""))).strip()
    if msg:
        parts.append(msg)
    svc = first.get("service") or first.get("Service")
    if svc:
        parts.append(f"service {svc}")
    port = first.get("Destination Port") or first.get("dst_port")
    if port not in (None, "", 0):
        parts.append(f"destination port {port}")
    uri = first.get("uri") or first.get("URI")
    if uri:
        parts.append(f"uri {uri}")
    for reason in (first.get("tier1_reasons") or [])[:3]:
        parts.append(str(reason))
    q = " ".join(parts).strip() or "suspicious network activity"
    return q[:300]


def dense_only_context(query_text):
    """RAG chỉ-FAISS (dense-only) cho Config D — KHÔNG BM25, KHÔNG RRF."""
    out = {}
    for source_key, source_name in (("mitre", "MITRE ATT&CK"), ("nist", "NIST SP 800-61r2")):
        if source_key not in retriever.faiss_indexes:
            out[source_key] = f"[{source_name}] No relevant matches found."
            continue
        meta = retriever.metadata[source_key]
        fetch_k = min(retriever.top_k, len(meta))
        emb = retriever.model.encode([query_text], normalize_embeddings=True).astype("float32")
        dense = retriever._dense_search(emb, source_key, fetch_k)  # {idx:{score,rank}}
        ranked = sorted(dense.keys(), key=lambda x: dense[x]["score"], reverse=True)[: retriever.top_k]
        if not ranked:
            out[source_key] = f"[{source_name}] No relevant matches found."
            continue
        lines = [f"[{source_name} Context — Top {len(ranked)} matches (dense-only)]"]
        for i, idx in enumerate(ranked, 1):
            safe = retriever.rag_sanitizer.sanitize_retrieve(meta[idx]["text"])
            lines.append(f"\n--- Match {i} (Score: {dense[idx]['score']:.4f}) ---")
            lines.append(safe)
        out[source_key] = "\n".join(lines)
    return f"MITRE ATT&CK:\n{out['mitre']}\n\nNIST SP 800-61r2:\n{out['nist']}"


def hybrid_context(query_text):
    """RAG lai (FAISS+BM25+RRF) cho Config E — qua retriever chính thức."""
    res = retriever.retrieve(query_text)
    return f"MITRE ATT&CK:\n{res.get('mitre_context', '')}\n\nNIST SP 800-61r2:\n{res.get('nist_context', '')}"


def llm_action(logs, rag_context):
    """Gọi LLM trên raw logs (KHÔNG guardrails encapsulation) + RAG tùy chọn."""
    raw_logs_str = "\n".join(str(log) for log in logs)
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_context)
    t0 = time.time()
    try:
        raw = llm_client.invoke(messages=messages, temperature=0.1)
        decision = llm_client.parse_llm_response(raw)
        action = str(decision.get("action", "AWAIT_HITL")).upper().strip()
        if action not in VALID_ACTIONS:
            action = "AWAIT_HITL"
    except Exception as e:
        print(f"   [LLM ERROR] {e}")
        action = "AWAIT_HITL"
    return action, time.time() - t0


def to_pred(action):
    return 1 if action in ATTACK_ACTIONS else 0


def run_gate(logs, rule_engine):
    """Gate Welford/Tier-1 (giống Config F): trả (needs_llm, tier1_verdict)."""
    needs_llm = False
    tier1_verdict = "DROP"
    for log in logs:
        act = rule_engine.evaluate(log).get("tier1_action")
        if act == "ESCALATE":
            needs_llm = True
            break
        elif act in ("BLOCK_IP", "ALERT", "AWAIT_HITL"):
            tier1_verdict = act
    return needs_llm, tier1_verdict


def main(limit=300):
    dataset = stratified(load_ground_truth(), limit)
    print(f"[*] Ablation B-E tren {len(dataset)} mau (cung tap phan tang voi A/F)...")

    rule_engine = RuleEngine()
    print("[*] Warmup Rule Engine baseline...")
    for i in range(110):
        val = 15 + (i % 5) - 2
        rule_engine.evaluate(
            {
                "Source IP": f"192.168.1.{10 + i}",
                "Destination Port": 80,
                "Total Fwd Packets": val,
                "Flow Bytes/s": val * 100,
                "Flow Duration": 1000 + (i % 10) * 10,
            }
        )
    print("[+] Warmup complete.")

    R = {c: {"y_true": [], "y_pred": [], "latencies": [], "escalated": []} for c in "BCDE"}

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        # B — Pure LLM (luon goi LLM, khong RAG)
        a_b, l_b = llm_action(logs, "")
        # C — Welford + LLM (khong RAG)
        if needs_llm:
            a_c, l_c = llm_action(logs, "")
            p_c = to_pred(a_c)
        else:
            l_c, p_c = 0.0006, tier1_pred
        # D — Welford + dense RAG + LLM
        if needs_llm:
            a_d, l_d = llm_action(logs, dense_only_context(query))
            p_d = to_pred(a_d)
        else:
            l_d, p_d = 0.0006, tier1_pred
        # E — Welford + hybrid RAG + LLM
        if needs_llm:
            a_e, l_e = llm_action(logs, hybrid_context(query))
            p_e = to_pred(a_e)
        else:
            l_e, p_e = 0.0006, tier1_pred

        for c, pred, lat in (
            ("B", to_pred(a_b), l_b),
            ("C", p_c, l_c),
            ("D", p_d, l_d),
            ("E", p_e, l_e),
        ):
            R[c]["y_true"].append(is_attack)
            R[c]["y_pred"].append(pred)
            R[c]["latencies"].append(lat)
            R[c]["escalated"].append(1 if (c == "B" or needs_llm) else 0)

        print(
            f"[{idx + 1}/{len(dataset)}] {sample['id']} | true={is_attack} esc={int(needs_llm)} "
            f"| B={to_pred(a_b)} C={p_c} D={p_d} E={p_e}"
        )

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {OUT_PATH}\n")

    for c in "BCDE":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)
        prec = precision_score(yt, yp, zero_division=0)
        rec = recall_score(yt, yp, zero_division=0)
        esc = 100.0 * np.mean(R[c]["escalated"])
        mean_lat = float(np.mean(R[c]["latencies"]))
        print(
            f"[Config {c}] F1={f1:.4f} | Prec={prec:.4f} | Rec={rec:.4f} "
            f"| escalate={esc:.1f}% | mean_lat={mean_lat:.3f}s"
        )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300)
    args = ap.parse_args()
    main(limit=args.limit)
