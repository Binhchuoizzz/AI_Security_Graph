"""
Ablation Study HỢP NHẤT — 6 cấu hình A–F trên 3 chế độ chạy.
=========================================================================
Gộp 3 file cũ (run_ablation_study / run_ablation_bcde / run_ablation_balanced) vào
MỘT entry point. Bản chất thí nghiệm + tên file kết quả GIỮ NGUYÊN (để đối chiếu số
liệu đã trích trong luận văn); đây thuần là tổ chức lại code cho gọn.

  --mode af        Config A (Tier-1 rule-only) vs F (SENTINEL 2 tầng đầy đủ) trên tập
                   phân tầng ground_truth + MLflow.  -> results/ablation_results.json
  --mode bcde      Config B/C/D/E (Pure LLM / Welford+LLM / +dense-RAG / +hybrid-RAG)
                   trên 300 mẫu phân tầng.           -> results/ablation_bcde_results.json
  --mode balanced  6 cấu hình A–F trên tập CÂN BẰNG 150/150 (benign thật để gate Welford
                   có cơ hội DROP true-negative).    -> results/ablation_balanced_results.json
  --mode mlgate    Config G — GIẢM TẢI LLM bằng Cổng ML (KHÔNG cần LLM). Đo bypass-rate +
                   F1 Cổng ML trên phần escalate.    -> results/ablation_mlgate_results.json
  --mode all       Chạy lần lượt af -> bcde -> balanced -> mlgate.

Gate Welford tính MỘT lần/mẫu, dùng chung C/D/E/F => escalation set giống hệt nhau nên
hiệu số D-C, E-D cô lập đúng đóng góp từng tầng RAG. Verdict B-E = action THÔ do LLM trả
(không áp consensus-guard của F) để đo năng lực phân loại thuần.

Chạy (cần LLM server cho mọi mode trừ phần rule-only):
    .venv/bin/python experiments/run_ablation.py --mode balanced
    .venv/bin/python experiments/run_ablation.py --mode af --limit 50
    .venv/bin/python experiments/run_ablation.py --mode bcde --out /tmp/bcde.json
"""

import json
import os
import sys
import time

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.llm_client import llm_client  # noqa: E402
from src.agent.nodes import retriever  # noqa: E402
from src.agent.prompts import build_triage_prompt  # noqa: E402
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine, RunningStats  # noqa: E402

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
OUT_AF = os.path.join(RESULTS_DIR, "ablation_results.json")
OUT_BCDE = os.path.join(RESULTS_DIR, "ablation_bcde_results.json")
OUT_BALANCED = os.path.join(RESULTS_DIR, "ablation_balanced_results.json")
OUT_MLGATE = os.path.join(RESULTS_DIR, "ablation_mlgate_results.json")

ATTACK_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}
VALID_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "LOG", "DROP", "ESCALATE"}
N_BENIGN = 150
N_ATTACK = 150


# =========================================================================
# Helpers dùng chung
# =========================================================================
def load_ground_truth():
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def stratified(dataset, limit):
    """Lấy mẫu phân tầng đều trên các lớp tấn công (tất định)."""
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


def _fresh_engine() -> RuleEngine:
    """RuleEngine CÔ LẬP khỏi golden baseline cho Ablation.

    Ablation là thí nghiệm ĐỐI CHỨNG (so verdict-equivalence + độ trễ theo cấu phần
    trên tập con thiên tấn công), có warmup RIÊNG (synthetic cho af/bcde, benign
    held-out cho balanced). Kể từ khi bật tier1.golden_baseline.enabled=true,
    RuleEngine() tự seed 300 flow benign lúc init — điều đó sẽ LÀM NHIỄU baseline
    có kiểm soát của ablation (gate bỗng DROP true-negative, phá tính tương đương
    phán quyết). Vì thế ablation LUÔN reset Welford về rỗng để tái lập đúng thiết
    kế đối chứng, ĐỘC LẬP với golden (vốn là tính năng của luồng-gộp/triển khai thật)."""
    engine = RuleEngine()
    for _k in engine.global_stats:
        engine.global_stats[_k] = RunningStats()
    return engine


def _synthetic_warmup(rule_engine):
    """Warmup baseline Welford bằng lưu lượng tổng hợp (dùng cho af/bcde)."""
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
        ranked = sorted(dense.keys(), key=lambda x: dense[x]["score"], reverse=True)[
            : retriever.top_k
        ]
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


def calc_fpr(y_true, y_pred):
    """False Positive Rate an toàn với trường hợp 1 lớp."""
    try:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        return fp / (fp + tn) if (fp + tn) > 0 else 0.0
    except ValueError:
        return 0.0


# =========================================================================
# MODE: af  — Config A (rule-only) vs F (SENTINEL đầy đủ) + MLflow
# =========================================================================
def run_af(limit=None, out=None):
    import mlflow

    dataset = stratified(load_ground_truth(), limit) if limit else load_ground_truth()
    out_path = out or OUT_AF

    results = {
        "Config_A": {"y_true": [], "y_pred": [], "latencies": []},
        "Config_F": {
            "y_true": [],
            "y_pred": [],
            "latencies": [],
            "reasoning_outputs": [],
            "actions": [],
        },
    }

    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
    mlflow.set_experiment("Sentinel_Ablation_Study")

    with mlflow.start_run(run_name="Full_Evaluation_Run"):
        mlflow.log_param("dataset_size", len(dataset))
        mlflow.log_param("config_a", "Rule-only (No LLM)")
        mlflow.log_param("config_f", "Full SENTINEL 2-Tier")

        print(f"[*] Chay Ablation Study (A vs F) tren {len(dataset)} mau...")
        rule_engine = _fresh_engine()
        _synthetic_warmup(rule_engine)

        ml_bypassed_count = 0

        for idx, sample in enumerate(dataset):
            is_attack = 1 if sample["expected_action"] in ["BLOCK_IP", "ALERT", "AWAIT_HITL"] else 0
            logs = sample.get("logs", [])
            rule_engine.session_baseline.reset_window()

            # --- Config A: chỉ luật cứng ---
            start_time_a = time.time()
            pred_a = 0
            for log in logs:
                result = rule_engine.evaluate(log)
                if result.get("tier1_action") in ["BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"]:
                    pred_a = 1
                    break
            latency_a = time.time() - start_time_a
            results["Config_A"]["y_true"].append(is_attack)
            results["Config_A"]["y_pred"].append(pred_a)
            results["Config_A"]["latencies"].append(latency_a)

            # --- Config F: SENTINEL 2 tầng đầy đủ ---
            start_time_f = time.time()
            pred_f = 0
            needs_llm = False
            tier1_verdict = "DROP"
            for log in logs:
                act = rule_engine.evaluate(log).get("tier1_action")
                if act == "ESCALATE":
                    needs_llm = True
                    break
                elif act in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
                    tier1_verdict = act

            reasoning_output = {
                "sample_id": sample["id"],
                "expected_action": sample["expected_action"],
                "expected_mitre": sample.get("expected_mitre_technique", ""),
                "narrative_summary": "",
                "decisions": [],
                "escalated_to_llm": needs_llm,
            }

            if needs_llm:
                initial_state = SentinelState(
                    current_batch_logs=logs,
                    current_batch_size=len(logs),
                    narrative_summary="",
                )
                from src.guardrails import loop_detector

                loop_detector.reset()
                try:
                    final_state = agent_app.invoke(initial_state)
                    decisions = final_state.get("decisions", [])
                    reasoning_output["narrative_summary"] = final_state.get("narrative_summary", "")
                    reasoning_output["decisions"] = decisions
                    if decisions:
                        action = decisions[-1].get("action", "UNKNOWN")
                        # Đếm bằng field máy-đọc `ml_model` do node_ml_triage gắn — bản cũ
                        # grep "XGBoost" trong reasoning LUÔN ra 0 vì reasoning thật ghi
                        # "Decision Tree" (model thật là DecisionTreeClassifier).
                        if decisions[-1].get("ml_model"):
                            ml_bypassed_count += 1
                        results["Config_F"]["actions"].append(action)
                        if action in ["BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"]:
                            pred_f = 1
                except Exception as e:
                    print(f"Loi chay Config F cho mau {sample['id']}: {e}")
                    pred_f = 0
                    results["Config_F"]["actions"].append("ERROR")
            else:
                results["Config_F"]["actions"].append(f"TIER1_{tier1_verdict}")
                if tier1_verdict in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
                    pred_f = 1

            latency_f = time.time() - start_time_f
            results["Config_F"]["y_true"].append(is_attack)
            results["Config_F"]["y_pred"].append(pred_f)
            results["Config_F"]["latencies"].append(latency_f)
            results["Config_F"]["reasoning_outputs"].append(reasoning_output)

            print(
                f"[{idx + 1}/{len(dataset)}] {sample['id']} | True: {is_attack} | "
                f"Pred A: {pred_a} ({latency_a:.3f}s) | Pred F: {pred_f} ({latency_f:.3f}s)"
            )

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Da luu ket qua vao {out_path}")

        ya_t, ya_p = results["Config_A"]["y_true"], results["Config_A"]["y_pred"]
        yf_t, yf_p = results["Config_F"]["y_true"], results["Config_F"]["y_pred"]
        f1_a = f1_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec_a = precision_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec_a = recall_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        f1_f = f1_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec_f = precision_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec_f = recall_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]

        fpr_a = calc_fpr(results["Config_A"]["y_true"], results["Config_A"]["y_pred"])
        fpr_f = calc_fpr(results["Config_F"]["y_true"], results["Config_F"]["y_pred"])

        total_f = len(results["Config_F"]["actions"])
        hitl_count = results["Config_F"]["actions"].count("AWAIT_HITL")
        hitl_ratio = (hitl_count / total_f) * 100 if total_f > 0 else 0.0

        cache_stats = (
            retriever.cache.get_stats()
            if hasattr(retriever, "cache") and retriever.cache
            else {"hit_rate": 0.0}
        )
        cache_hit_rate = cache_stats.get("hit_rate", 0.0)

        ml_bypass_rate = (ml_bypassed_count / total_f) * 100 if total_f > 0 else 0.0

        mlflow.log_metric("Config_A_F1", float(f1_a))
        mlflow.log_metric("Config_A_Precision", float(prec_a))
        mlflow.log_metric("Config_A_Recall", float(rec_a))
        mlflow.log_metric("Config_A_FPR", float(fpr_a))
        mlflow.log_metric("MTTD_Proxy_Tier1_sec", float(np.mean(results["Config_A"]["latencies"])))
        mlflow.log_metric("Config_F_F1", float(f1_f))
        mlflow.log_metric("Config_F_Precision", float(prec_f))
        mlflow.log_metric("Config_F_Recall", float(rec_f))
        mlflow.log_metric("Config_F_FPR", float(fpr_f))
        mlflow.log_metric("MTTR_Proxy_Tier2_sec", float(np.mean(results["Config_F"]["latencies"])))
        mlflow.log_metric("HITL_Escalation_Rate_pct", hitl_ratio)
        mlflow.log_metric("RAG_Cache_Hit_Rate_pct", cache_hit_rate)
        mlflow.log_metric("ML_Bypass_Rate_pct", ml_bypass_rate)

        print(
            f"\n[+] Config A: F1={f1_a:.4f} | Prec={prec_a:.4f} | Rec={rec_a:.4f} | "
            f"FPR={fpr_a:.4f} | MTTD_Proxy={np.mean(results['Config_A']['latencies']):.3f}s"
        )
        print(
            f"[+] Config F: F1={f1_f:.4f} | Prec={prec_f:.4f} | Rec={rec_f:.4f} | "
            f"FPR={fpr_f:.4f} | MTTR_Proxy={np.mean(results['Config_F']['latencies']):.3f}s"
        )
        print(
            f"[+] Operational: RAG Cache Hit Rate = {cache_hit_rate:.1f}% | HITL Ratio = {hitl_ratio:.1f}% | ML Bypass Rate = {ml_bypass_rate:.1f}%"
        )
        print(
            "[!] DISCLAIMER: Processing Latency is used as a proxy for MTTD/MTTR under offline "
            "dataset constraints. Real-world ingestion and human review times are not included."
        )
        print("[+] Da ghi metrics len MLflow.")


# =========================================================================
# MODE: bcde  — Config B/C/D/E trên 300 mẫu phân tầng
# =========================================================================
def run_bcde(limit=300, out=None):
    out_path = out or OUT_BCDE
    dataset = stratified(load_ground_truth(), limit)
    print(f"[*] Ablation B-E tren {len(dataset)} mau (cung tap phan tang voi A/F)...")

    rule_engine = _fresh_engine()
    _synthetic_warmup(rule_engine)

    R = {c: {"y_true": [], "y_pred": [], "latencies": [], "escalated": []} for c in "BCDE"}

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        a_b, l_b = llm_action(logs, "")  # B — Pure LLM
        if needs_llm:  # C — Welford + LLM (no RAG)
            a_c, l_c = llm_action(logs, "")
            p_c = to_pred(a_c)
        else:
            l_c, p_c = 0.0006, tier1_pred
        if needs_llm:  # D — Welford + dense RAG
            a_d, l_d = llm_action(logs, dense_only_context(query))
            p_d = to_pred(a_d)
        else:
            l_d, p_d = 0.0006, tier1_pred
        if needs_llm:  # E — Welford + hybrid RAG
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

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {out_path}\n")

    for c in "BCDE":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec = precision_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec = recall_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        esc = 100.0 * np.mean(R[c]["escalated"])
        mean_lat = float(np.mean(R[c]["latencies"]))
        print(
            f"[Config {c}] F1={f1:.4f} | Prec={prec:.4f} | Rec={rec:.4f} "
            f"| escalate={esc:.1f}% | mean_lat={mean_lat:.3f}s"
        )


# =========================================================================
# MODE: balanced  — 6 cấu hình A–F trên tập CÂN BẰNG 150/150
# =========================================================================
def balanced_subset(dataset):
    """Trả về (subset, warmup_logs): 150 benign + 150 attack; 150 benign held-out cho warmup."""
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

    benign_sel = benign[:N_BENIGN]
    warmup_benign = benign[N_BENIGN : N_BENIGN + 150]
    warmup_logs = [log for s in warmup_benign for log in s.get("logs", [])]
    return benign_sel + attack_sel, warmup_logs


def run_balanced(out=None):
    out_path = out or OUT_BALANCED
    dataset, warmup_logs = balanced_subset(load_ground_truth())
    n_b = sum(1 for s in dataset if s["expected_action"] == "LOG")
    n_a = len(dataset) - n_b
    print(f"[*] Ablation CÂN BẰNG: {len(dataset)} mẫu ({n_b} benign + {n_a} attack)")

    rule_engine = _fresh_engine()
    print(f"[*] Warmup baseline Welford trên {len(warmup_logs)} flow benign THẬT (held-out)...")
    for log in warmup_logs:
        rule_engine.evaluate(dict(log))
    print("[+] Warmup complete.")

    R = {c: {"y_true": [], "y_pred": [], "latencies": [], "escalated": []} for c in "ABCDEF"}

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        # --- A: Tier-1 rule-only ---
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

        # --- Gate Welford dùng chung C/D/E/F ---
        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        a_b, l_b = llm_action(logs, "")  # B — Pure LLM
        p_b = to_pred(a_b)

        if needs_llm:  # C/D/E
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

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {out_path}\n")

    print(f"{'Cfg':>3} | {'F1':>6} | {'Prec':>6} | {'Rec':>6} | {'Esc%':>5} | {'Lat(s)':>7}")
    for c in "ABCDEF":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec = precision_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec = recall_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        esc = 100.0 * np.mean(R[c]["escalated"])
        lat = float(np.mean(R[c]["latencies"]))
        print(f"{c:>3} | {f1:>6.4f} | {prec:>6.4f} | {rec:>6.4f} | {esc:>5.1f} | {lat:>7.3f}")


def run_mlgate(limit=None, out=None):
    """Config G — GIẢM TẢI LLM bằng Cổng ML (chiều Performance/Efficiency, KHÔNG cần LLM).

    Mô phỏng đường thật: Tier-1 gate quyết event nào ESCALATE (đáng lẽ gọi LLM); cho phần
    escalate đó qua Cổng ML. ML tự quyết -> BYPASS = tiết kiệm 1 lượt LLM. Đo:
      - ml_bypass_rate = (escalate được ML giải quyết) / (tổng escalate)
      - F1/P/R của Cổng ML trên phần bypass
      - độ trễ TIẾT KIỆM: không-ML mọi escalate tốn ~LLM_MS; có-ML phần bypass chỉ tốn ~ML_MS
    Số LLM_MS/ML_MS là tham chiếu (từ latency_benchmark) chỉ để CHIẾU mức tiết kiệm — không
    phải phép đo latency mới.
    """
    from src.tier1_filter.ml_gateway import MLGateway

    dataset = stratified(load_ground_truth(), limit) if limit else load_ground_truth()
    out_path = out or OUT_MLGATE
    engine = _fresh_engine()
    _synthetic_warmup(engine)
    gw = MLGateway()
    if not gw.pipeline:
        print("[-] Không nạp được Cổng ML — bỏ mode mlgate.")
        return
    LLM_MS = 5000.0  # ~1 lượt LLM (tham chiếu latency_benchmark)
    ML_MS = 0.3  # ~1 lượt Cổng ML

    n = n_escalated = n_bypass = 0
    yt, yp = [], []
    print(f"[*] Chạy Config G (ML offload) trên {len(dataset)} mẫu (không gọi LLM)…")
    for sample in dataset:
        logs = sample.get("logs", [])
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        engine.session_baseline.reset_window()
        needs_llm, _ = run_gate(logs, engine)
        n += 1
        if not needs_llm:
            continue
        n_escalated += 1
        for log in logs:
            a, _r, _c, _s = gw.evaluate_detailed(log)
            if a is not None:
                n_bypass += 1
                yt.append(is_attack)
                yp.append(1 if a in ("BLOCK_IP", "ALERT") else 0)
                break

    bypass_rate = n_bypass / n_escalated if n_escalated else 0.0
    f1 = float(f1_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    prec = float(precision_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    rec = float(recall_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    t_no_ml = n_escalated * LLM_MS
    t_ml = n_bypass * ML_MS + (n_escalated - n_bypass) * LLM_MS
    saved_pct = (1 - t_ml / t_no_ml) * 100 if t_no_ml else 0.0

    result = {
        "dataset_size": n,
        "n_escalated_would_call_llm": n_escalated,
        "n_ml_bypass": n_bypass,
        "ml_bypass_rate": round(bypass_rate, 4),
        "ml_f1_on_bypass": round(f1, 4),
        "ml_precision_on_bypass": round(prec, 4),
        "ml_recall_on_bypass": round(rec, 4),
        "projected_llm_calls_saved": n_bypass,
        "projected_latency_saved_pct": round(saved_pct, 2),
        "ref_llm_ms": LLM_MS,
        "ref_ml_ms": ML_MS,
        "note": "Config G đo GIẢM TẢI LLM của Cổng ML; latency là CHIẾU từ tham chiếu, không đo mới.",
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(
        f"[+] Config G: escalate={n_escalated} | ML bypass={n_bypass} "
        f"({bypass_rate:.1%}) | F1(bypass)={f1:.4f} P={prec:.4f} R={rec:.4f} | "
        f"tiết kiệm LLM≈{saved_pct:.1f}%\n[+] JSON: {out_path}"
    )
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Ablation Study hợp nhất (A–F + G ML offload)")
    ap.add_argument("--mode", choices=["af", "bcde", "balanced", "mlgate", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None, help="Giới hạn số mẫu (af/bcde)")
    ap.add_argument("--out", type=str, default=None, help="Ghi đè path output (chỉ khi 1 mode)")
    args = ap.parse_args()

    if args.out and args.mode == "all":
        ap.error("--out chỉ dùng khi chạy 1 mode (af|bcde|balanced), không dùng với 'all'.")

    if args.mode in ("af", "all"):
        run_af(limit=args.limit, out=args.out)
    if args.mode in ("bcde", "all"):
        run_bcde(limit=args.limit or 300, out=args.out)
    if args.mode in ("balanced", "all"):
        run_balanced(out=args.out)
    if args.mode in ("mlgate", "all"):
        run_mlgate(limit=args.limit, out=args.out if args.mode == "mlgate" else None)
