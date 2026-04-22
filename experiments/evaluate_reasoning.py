"""
LLM-as-Judge: Reasoning Quality Evaluation (Cross-Family)

Sử dụng Llama 3 8B (Meta) làm trọng tài độc lập để đánh giá chất lượng
suy luận của Gemma 9B (Google) — tránh Self-Enhancement Bias.

WORKFLOW:
  1. Chạy run_ablation_study.py với Gemma 9B → lưu reasoning_outputs
  2. Unload Gemma 9B → Load Llama 3 8B trên Oobabooga
  3. Chạy script này → Llama 3 chấm điểm reasoning quality
  4. Kết quả: reasoning_eval_results.json + MLflow metrics

EVALUATION RUBRIC (4 chiều, thang 1-5):
  - MITRE Mapping Accuracy: LLM có xác định đúng kỹ thuật tấn công?
  - Action Correctness: Hành động đề xuất có phù hợp với mối đe dọa?
  - Reasoning Coherence: Phân tích có logic, rõ ràng, có căn cứ?
  - Context Utilization: Có sử dụng RAG context (MITRE/ISO) hiệu quả?
"""

import json
import os
import sys
import time
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Oobabooga OpenAI-compatible API
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5000/v1")

ABLATION_RESULTS_PATH = os.path.join(
    os.path.dirname(__file__), "ablation_results.json"
)
OUTPUT_PATH = os.path.join(
    os.path.dirname(__file__), "reasoning_eval_results.json"
)

JUDGE_SYSTEM_PROMPT = """You are an expert cybersecurity analyst acting as an independent judge.
You will evaluate the reasoning quality of a Security AI Agent's analysis.
You must be STRICT and OBJECTIVE. Score each dimension from 1 (worst) to 5 (best).

IMPORTANT: You are evaluating REASONING QUALITY, not just correctness.
A correct decision with poor reasoning should score low on Coherence.
A wrong decision with excellent reasoning methodology should still score moderate."""

JUDGE_USER_TEMPLATE = """## EVALUATION TASK

### Ground Truth
- **Expected Action:** {expected_action}
- **Expected MITRE Technique:** {expected_mitre}
- **Sample ID:** {sample_id}

### Agent's Output
- **Agent's Narrative Summary:**
{narrative_summary}

- **Agent's Decisions:**
{decisions_text}

### SCORING RUBRIC

Rate each dimension (1-5):

**1. MITRE Mapping Accuracy (1-5)**
- 5: Correctly identified exact MITRE technique (e.g., T1110.001)
- 3: Identified correct tactic but wrong technique
- 1: Completely wrong or no MITRE mapping

**2. Action Correctness (1-5)**
- 5: Action matches expected action perfectly
- 3: Partially correct (e.g., ALERT when BLOCK expected)
- 1: Completely wrong action (e.g., LOG when BLOCK expected)

**3. Reasoning Coherence (1-5)**
- 5: Clear logical chain from evidence to conclusion
- 3: Some reasoning but gaps or unsupported claims
- 1: No reasoning or completely illogical

**4. Context Utilization (1-5)**
- 5: Effectively used MITRE/ISO context in analysis
- 3: Mentioned context but didn't integrate well
- 1: Ignored available context entirely

Respond ONLY in this JSON format:
{{"mitre_accuracy": <int>, "action_correctness": <int>, "reasoning_coherence": <int>, "context_utilization": <int>, "justification": "<brief explanation>"}}"""


def call_llm_judge(system_prompt: str, user_prompt: str) -> dict:
    """Call Oobabooga API (Llama 3 loaded) to judge reasoning quality."""
    import requests

    try:
        response = requests.post(
            f"{LLM_API_BASE}/chat/completions",
            json={
                "model": "judge",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 500,
            },
            timeout=120,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]

        # Parse JSON from response
        # Handle cases where LLM wraps in markdown code blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        return json.loads(content.strip())
    except json.JSONDecodeError:
        print(f"  [!] JSON parse error. Raw response: {content[:200]}")
        return {
            "mitre_accuracy": 1,
            "action_correctness": 1,
            "reasoning_coherence": 1,
            "context_utilization": 1,
            "justification": "PARSE_ERROR",
        }
    except Exception as e:
        print(f"  [!] LLM call error: {e}")
        return {
            "mitre_accuracy": 1,
            "action_correctness": 1,
            "reasoning_coherence": 1,
            "context_utilization": 1,
            "justification": f"API_ERROR: {str(e)}",
        }


def format_decisions(decisions: list) -> str:
    """Format agent decisions for judge prompt."""
    if not decisions:
        return "(No decisions made — sample was not escalated to LLM)"
    parts = []
    for d in decisions:
        parts.append(
            f"  - Action: {d.get('action', 'N/A')}\n"
            f"    Target: {d.get('target', 'N/A')}\n"
            f"    Confidence: {d.get('confidence', 'N/A')}\n"
            f"    MITRE: {d.get('mitre_technique', 'N/A')}\n"
            f"    ISO: {d.get('iso_control', 'N/A')}\n"
            f"    Reasoning: {d.get('reasoning', 'N/A')}"
        )
    return "\n".join(parts)


def run_judge_evaluation():
    """Main evaluation loop: send each reasoning output to Llama 3 Judge."""

    # Check if ablation results exist
    if not os.path.exists(ABLATION_RESULTS_PATH):
        print("[!] ERROR: ablation_results.json not found!")
        print("    Run 'python experiments/run_ablation_study.py' with Gemma 9B first.")
        sys.exit(1)

    with open(ABLATION_RESULTS_PATH, "r") as f:
        ablation_data = json.load(f)

    reasoning_outputs = ablation_data.get("Config_F", {}).get("reasoning_outputs", [])
    if not reasoning_outputs:
        print("[!] ERROR: No reasoning_outputs in ablation_results.json!")
        print("    Re-run ablation study with the updated script to capture outputs.")
        sys.exit(1)

    # Filter: only evaluate samples that were escalated to LLM
    escalated = [r for r in reasoning_outputs if r.get("escalated_to_llm", False)]
    not_escalated = [r for r in reasoning_outputs if not r.get("escalated_to_llm", False)]

    print(f"[*] Total samples: {len(reasoning_outputs)}")
    print(f"    Escalated to LLM (will judge): {len(escalated)}")
    print(f"    Not escalated (Tier 1 only): {len(not_escalated)}")
    print(f"\n[*] Starting LLM-as-Judge evaluation...")
    print(f"    Judge Model: Llama 3 (loaded on Oobabooga at {LLM_API_BASE})")
    print(f"    Agent Model: Gemma 9B (outputs from ablation study)")
    print()

    eval_results = {
        "metadata": {
            "judge_model": "Llama 3 8B Instruct (Meta)",
            "agent_model": "Gemma 2 9B Q6_K (Google)",
            "methodology": "Cross-Family LLM-as-Judge (Zheng et al., 2023)",
            "bias_mitigation": "Different model family eliminates Self-Enhancement Bias",
            "total_samples": len(reasoning_outputs),
            "escalated_samples": len(escalated),
        },
        "scores": [],
        "aggregate": {},
    }

    all_mitre = []
    all_action = []
    all_coherence = []
    all_context = []

    for idx, sample in enumerate(escalated):
        print(f"[{idx+1}/{len(escalated)}] Judging {sample['sample_id']}...", end=" ")

        decisions_text = format_decisions(sample.get("decisions", []))
        narrative = sample.get("narrative_summary", "(empty)")

        user_prompt = JUDGE_USER_TEMPLATE.format(
            expected_action=sample.get("expected_action", "N/A"),
            expected_mitre=sample.get("expected_mitre", "N/A"),
            sample_id=sample.get("sample_id", "N/A"),
            narrative_summary=narrative if narrative else "(empty)",
            decisions_text=decisions_text,
        )

        start = time.time()
        scores = call_llm_judge(JUDGE_SYSTEM_PROMPT, user_prompt)
        elapsed = time.time() - start

        result_entry = {
            "sample_id": sample["sample_id"],
            "scores": scores,
            "judge_latency_s": round(elapsed, 2),
        }
        eval_results["scores"].append(result_entry)

        all_mitre.append(scores.get("mitre_accuracy", 1))
        all_action.append(scores.get("action_correctness", 1))
        all_coherence.append(scores.get("reasoning_coherence", 1))
        all_context.append(scores.get("context_utilization", 1))

        print(
            f"MITRE={scores.get('mitre_accuracy', '?')}/5  "
            f"Action={scores.get('action_correctness', '?')}/5  "
            f"Coherence={scores.get('reasoning_coherence', '?')}/5  "
            f"Context={scores.get('context_utilization', '?')}/5  "
            f"({elapsed:.1f}s)"
        )

    # Aggregate statistics
    if all_mitre:
        eval_results["aggregate"] = {
            "mitre_accuracy": {
                "mean": round(float(np.mean(all_mitre)), 2),
                "std": round(float(np.std(all_mitre)), 2),
                "min": int(min(all_mitre)),
                "max": int(max(all_mitre)),
            },
            "action_correctness": {
                "mean": round(float(np.mean(all_action)), 2),
                "std": round(float(np.std(all_action)), 2),
                "min": int(min(all_action)),
                "max": int(max(all_action)),
            },
            "reasoning_coherence": {
                "mean": round(float(np.mean(all_coherence)), 2),
                "std": round(float(np.std(all_coherence)), 2),
                "min": int(min(all_coherence)),
                "max": int(max(all_coherence)),
            },
            "context_utilization": {
                "mean": round(float(np.mean(all_context)), 2),
                "std": round(float(np.std(all_context)), 2),
                "min": int(min(all_context)),
                "max": int(max(all_context)),
            },
            "overall_mean": round(
                float(
                    np.mean(
                        [np.mean(all_mitre), np.mean(all_action),
                         np.mean(all_coherence), np.mean(all_context)]
                    )
                ),
                2,
            ),
        }

    # Save results
    with open(OUTPUT_PATH, "w") as f:
        json.dump(eval_results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"REASONING QUALITY EVALUATION — RESULTS")
    print(f"{'='*60}")
    if eval_results["aggregate"]:
        agg = eval_results["aggregate"]
        print(f"  MITRE Mapping Accuracy:  {agg['mitre_accuracy']['mean']}/5 (±{agg['mitre_accuracy']['std']})")
        print(f"  Action Correctness:      {agg['action_correctness']['mean']}/5 (±{agg['action_correctness']['std']})")
        print(f"  Reasoning Coherence:     {agg['reasoning_coherence']['mean']}/5 (±{agg['reasoning_coherence']['std']})")
        print(f"  Context Utilization:     {agg['context_utilization']['mean']}/5 (±{agg['context_utilization']['std']})")
        print(f"  ---")
        print(f"  Overall Mean:            {agg['overall_mean']}/5")
    print(f"{'='*60}")
    print(f"[+] Results saved to: {OUTPUT_PATH}")

    # Log to MLflow
    try:
        import mlflow

        mlflow.set_tracking_uri(
            os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001")
        )
        mlflow.set_experiment("Sentinel_Reasoning_Quality")
        with mlflow.start_run(run_name="LLM_Judge_Evaluation"):
            mlflow.log_param("judge_model", "Llama 3 8B Instruct")
            mlflow.log_param("agent_model", "Gemma 2 9B Q6_K")
            mlflow.log_param("escalated_samples", len(escalated))
            if eval_results["aggregate"]:
                agg = eval_results["aggregate"]
                mlflow.log_metric("MITRE_Accuracy_Mean", agg["mitre_accuracy"]["mean"])
                mlflow.log_metric("Action_Correctness_Mean", agg["action_correctness"]["mean"])
                mlflow.log_metric("Reasoning_Coherence_Mean", agg["reasoning_coherence"]["mean"])
                mlflow.log_metric("Context_Utilization_Mean", agg["context_utilization"]["mean"])
                mlflow.log_metric("Overall_Quality_Mean", agg["overall_mean"])
            mlflow.log_artifact(OUTPUT_PATH)
        print("[+] Metrics logged to MLflow (Sentinel_Reasoning_Quality)")
    except Exception as e:
        print(f"[!] MLflow logging failed (non-critical): {e}")


if __name__ == "__main__":
    run_judge_evaluation()
