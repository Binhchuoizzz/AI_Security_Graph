"""
Thử nghiệm Loại trừ (Ablation Study): So sánh Config A (Chỉ luật cứng) và Config F (SENTINEL 2 Lớp đầy đủ).

Script chạy trên tập dữ liệu kiểm thử (Ground Truth) và ghi kết quả ra file JSON + hệ thống MLflow.
"""

import json
import os
import sys
import time
import mlflow
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tier1_filter.rule_engine import RuleEngine
from src.agent.workflow import agent_app
from src.agent.state import SentinelState
from src.agent.nodes import retriever

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, "r") as f:
        return json.load(f)


def run_ablation(limit=None):
    dataset = load_ground_truth()
    if limit:
        # Stratified sampling: Lấy mẫu phân tầng đều từ 15 lớp tấn công khác nhau
        by_label = {}
        for sample in dataset:
            lbl = sample["input"].get("cicids_label", "unknown")
            if lbl not in by_label:
                by_label[lbl] = []
            by_label[lbl].append(sample)
        
        num_classes = len(by_label)
        samples_per_class = max(1, (limit + num_classes - 1) // num_classes)
        
        selected_samples = []
        for lbl, samples in by_label.items():
            selected_samples.extend(samples[:samples_per_class])
        
        dataset = selected_samples[:limit]


    # Lớp Dương tính (Tấn công): expected_action != "LOG"
    # Lớp Âm tính (Lưu lượng sạch): expected_action == "LOG"

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



    # Kết nối hệ thống MLflow
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
    mlflow.set_experiment("Sentinel_Ablation_Study")

    with mlflow.start_run(run_name="Full_Evaluation_Run"):
        mlflow.log_param("dataset_size", len(dataset))
        mlflow.log_param("config_a", "Rule-only (No LLM)")
        mlflow.log_param("config_f", "Full SENTINEL 2-Tier")

        print(f"[*] Chay Ablation Study tren {len(dataset)} mau...")

        # Khởi tạo và warmup RuleEngine toàn cục cho Z-score tracking
        rule_engine = RuleEngine()
        print("[*] Warming up Rule Engine baseline statistics...")
        for i in range(110):
            val = 15 + (i % 5) - 2
            rule_engine.evaluate({
                "Source IP": f"192.168.1.{10+i}",
                "Destination Port": 80,
                "Total Fwd Packets": val,
                "Flow Bytes/s": val * 100,
                "Flow Duration": 1000 + (i % 10) * 10
            })
        print("[+] Warmup complete. Rule Engine baseline established.")

        for idx, sample in enumerate(dataset):
            is_attack = (
                1
                if sample["expected_action"] in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]
                else 0
            )
            logs = sample.get("logs", [])

            # Reset session baseline cho IP profile độc lập của từng mẫu, giữ lại global RunningStats
            rule_engine.session_baseline.reset_window()
            
            # --- Config A: Chỉ sử dụng luật cứng ---
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

            # --- Config F: Sentinel 2 Lớp đầy đủ ---
            start_time_f = time.time()
            pred_f = 0
            needs_llm = False
            tier1_verdict = "DROP"
            for log in logs:
                result = rule_engine.evaluate(log)
                act = result.get("tier1_action")
                if act == "ESCALATE":
                    needs_llm = True
                    break
                elif act in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
                    tier1_verdict = act

            # Lưu vết lập luận để phục vụ đánh giá bằng LLM Judge
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
                # Reset LoopDetector trước mỗi lần chạy đồ thị
                from src.guardrails import loop_detector
                loop_detector.reset()
                try:
                    final_state = agent_app.invoke(initial_state)
                    decisions = final_state.get("decisions", [])
                    reasoning_output["narrative_summary"] = final_state.get(
                        "narrative_summary", ""
                    )
                    reasoning_output["decisions"] = decisions
                    if decisions:
                        latest = decisions[-1]
                        action = latest.get("action", "UNKNOWN")
                        results["Config_F"]["actions"].append(action)
                        if action in [
                            "BLOCK_IP",
                            "ALERT",
                            "AWAIT_HITL",
                            "ESCALATE",
                        ]:
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
                f"[{idx+1}/{len(dataset)}] {sample['id']} | True: {is_attack} | Pred A: {pred_a} ({latency_a:.3f}s) | Pred F: {pred_f} ({latency_f:.3f}s)"
            )

        # Lưu kết quả ra file JSON
        out_path = os.path.join(os.path.dirname(__file__), "results", "ablation_results.json")
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Da luu ket qua vao {out_path}")

        # Tính toán và ghi nhận các chỉ số (metrics) lên MLflow
        f1_a = f1_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,  # type: ignore
        )
        prec_a = precision_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,  # type: ignore
        )
        rec_a = recall_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,  # type: ignore
        )

        f1_f = f1_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,  # type: ignore
        )
        prec_f = precision_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,  # type: ignore
        )
        rec_f = recall_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,  # type: ignore
        )

        # Tính toán False Positive Rate (FPR)
        def calc_fpr(y_true, y_pred):
            try:
                tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                return fp / (fp + tn) if (fp + tn) > 0 else 0.0
            except ValueError:
                # Tránh lỗi nếu chỉ có 1 class trong y_true/y_pred
                return 0.0

        fpr_a = calc_fpr(results["Config_A"]["y_true"], results["Config_A"]["y_pred"])
        fpr_f = calc_fpr(results["Config_F"]["y_true"], results["Config_F"]["y_pred"])

        # Tính toán HITL Ratio (Tỷ lệ cần con người can thiệp)
        total_f = len(results["Config_F"]["actions"])
        hitl_count = results["Config_F"]["actions"].count("AWAIT_HITL")
        hitl_ratio = (hitl_count / total_f) * 100 if total_f > 0 else 0.0

        # Lấy Cache Hit Rate từ Retriever
        cache_stats = retriever.cache.get_stats() if hasattr(retriever, "cache") and retriever.cache else {"hit_rate": 0.0}
        cache_hit_rate = cache_stats.get("hit_rate", 0.0)

        # Ghi nhận các chỉ số lên MLflow
        mlflow.log_metric("Config_A_F1", f1_a)
        mlflow.log_metric("Config_A_Precision", prec_a)
        mlflow.log_metric("Config_A_Recall", rec_a)
        mlflow.log_metric("Config_A_FPR", fpr_a)
        mlflow.log_metric("MTTD_Proxy_Tier1_sec", float(np.mean(results["Config_A"]["latencies"])))

        mlflow.log_metric("Config_F_F1", f1_f)
        mlflow.log_metric("Config_F_Precision", prec_f)
        mlflow.log_metric("Config_F_Recall", rec_f)
        mlflow.log_metric("Config_F_FPR", fpr_f)
        mlflow.log_metric("MTTR_Proxy_Tier2_sec", float(np.mean(results["Config_F"]["latencies"])))
        mlflow.log_metric("HITL_Escalation_Rate_pct", hitl_ratio)
        mlflow.log_metric("RAG_Cache_Hit_Rate_pct", cache_hit_rate)

        print(f"\n[+] Config A: F1={f1_a:.4f} | Prec={prec_a:.4f} | Rec={rec_a:.4f} | FPR={fpr_a:.4f} | MTTD_Proxy={np.mean(results['Config_A']['latencies']):.3f}s")
        print(f"[+] Config F: F1={f1_f:.4f} | Prec={prec_f:.4f} | Rec={rec_f:.4f} | FPR={fpr_f:.4f} | MTTR_Proxy={np.mean(results['Config_F']['latencies']):.3f}s")
        print(f"[+] Operational: RAG Cache Hit Rate = {cache_hit_rate:.1f}% | HITL Ratio = {hitl_ratio:.1f}%")
        print("[!] DISCLAIMER: Processing Latency is used as a proxy for MTTD/MTTR under offline dataset constraints.")
        print("                Real-world ingestion and human review times are not included.")
        print("[+] Da ghi metrics len MLflow.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Gioi han so luong mau de chay nhanh")
    args = parser.parse_args()
    run_ablation(limit=args.limit)

