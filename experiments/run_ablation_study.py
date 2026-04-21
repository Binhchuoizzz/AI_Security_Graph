"""
Ablation Study: So sanh Config A (Rule-only) vs Config F (Full SENTINEL 2-Tier).

Script chay tren tap Ground Truth va ghi ket qua vao JSON + MLflow.
"""

import json
import os
import sys
import time
import mlflow
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tier1_filter.rule_engine import RuleEngine
from src.agent.workflow import agent_app
from src.agent.state import SentinelState

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, "r") as f:
        return json.load(f)


def run_ablation():
    dataset = load_ground_truth()

    # Positive Class (Attack): expected_action != "LOG"
    # Negative Class (Benign): expected_action == "LOG"

    results = {
        "Config_A": {"y_true": [], "y_pred": [], "latencies": []},
        "Config_F": {"y_true": [], "y_pred": [], "latencies": []},
    }

    rule_engine = RuleEngine()

    # Ket noi MLflow
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
    mlflow.set_experiment("Sentinel_Ablation_Study")

    with mlflow.start_run(run_name="Full_Evaluation_Run"):
        mlflow.log_param("dataset_size", len(dataset))
        mlflow.log_param("config_a", "Rule-only (No LLM)")
        mlflow.log_param("config_f", "Full SENTINEL 2-Tier")

        print(f"[*] Chay Ablation Study tren {len(dataset)} mau...")

        for idx, sample in enumerate(dataset):
            is_attack = (
                1
                if sample["expected_action"] in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]
                else 0
            )
            logs = sample.get("logs", [])

            # --- Config A: Rule-only ---
            start_time_a = time.time()
            pred_a = 0
            for log in logs:
                result = rule_engine.evaluate(log)
                if result.get("tier1_action") == "ESCALATE":
                    pred_a = 1
                    break
            latency_a = time.time() - start_time_a

            results["Config_A"]["y_true"].append(is_attack)
            results["Config_A"]["y_pred"].append(pred_a)
            results["Config_A"]["latencies"].append(latency_a)

            # --- Config F: Full Sentinel (2-Tier) ---
            start_time_f = time.time()
            pred_f = 0
            needs_llm = False
            for log in logs:
                result = rule_engine.evaluate(log)
                if result.get("tier1_action") == "ESCALATE":
                    needs_llm = True
                    break

            if needs_llm:
                initial_state = SentinelState(
                    current_batch_logs=logs,
                    current_batch_size=len(logs),
                    narrative_summary="",
                )
                try:
                    final_state = agent_app.invoke(initial_state)
                    decisions = final_state.get("decisions", [])
                    if decisions:
                        latest = decisions[-1]
                        if latest.get("action") in [
                            "BLOCK_IP",
                            "ALERT",
                            "AWAIT_HITL",
                            "ESCALATE",
                        ]:
                            pred_f = 1
                except Exception as e:
                    print(f"Loi chay Config F cho mau {sample['id']}: {e}")
                    pred_f = 0

            latency_f = time.time() - start_time_f

            results["Config_F"]["y_true"].append(is_attack)
            results["Config_F"]["y_pred"].append(pred_f)
            results["Config_F"]["latencies"].append(latency_f)

            print(
                f"[{idx+1}/{len(dataset)}] {sample['id']} | True: {is_attack} | Pred A: {pred_a} ({latency_a:.3f}s) | Pred F: {pred_f} ({latency_f:.3f}s)"
            )

        # Luu ket qua ra JSON
        out_path = os.path.join(os.path.dirname(__file__), "ablation_results.json")
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Da luu ket qua vao {out_path}")

        # Tinh va log metrics len MLflow
        f1_a = f1_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,
        )
        prec_a = precision_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,
        )
        rec_a = recall_score(
            results["Config_A"]["y_true"],
            results["Config_A"]["y_pred"],
            zero_division=0,
        )

        f1_f = f1_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,
        )
        prec_f = precision_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,
        )
        rec_f = recall_score(
            results["Config_F"]["y_true"],
            results["Config_F"]["y_pred"],
            zero_division=0,
        )

        mlflow.log_metric("Config_A_F1", f1_a)
        mlflow.log_metric("Config_A_Precision", prec_a)
        mlflow.log_metric("Config_A_Recall", rec_a)
        mlflow.log_metric(
            "Config_A_Latency_Mean", float(np.mean(results["Config_A"]["latencies"]))
        )

        mlflow.log_metric("Config_F_F1", f1_f)
        mlflow.log_metric("Config_F_Precision", prec_f)
        mlflow.log_metric("Config_F_Recall", rec_f)
        mlflow.log_metric(
            "Config_F_Latency_Mean", float(np.mean(results["Config_F"]["latencies"]))
        )

        print(f"\n[+] Config A: F1={f1_a:.4f} | Prec={prec_a:.4f} | Rec={rec_a:.4f}")
        print(f"[+] Config F: F1={f1_f:.4f} | Prec={prec_f:.4f} | Rec={rec_f:.4f}")
        print("[+] Da ghi metrics len MLflow.")


if __name__ == "__main__":
    run_ablation()
