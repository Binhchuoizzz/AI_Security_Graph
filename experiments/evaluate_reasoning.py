"""
LLM-as-Judge: Reasoning Quality Evaluation (Cross-Family)

Sử dụng Llama 3 8B (Meta) làm trọng tài độc lập để đánh giá chất lượng
suy luận của Gemma 9B (Google) — tránh Self-Enhancement Bias.

WORKFLOW:
  1. Chạy run_ablation_study.py với Gemma 9B → lưu reasoning_outputs
  2. Unload Gemma 9B → Load Llama 3 8B trên Oobabooga
  3. Chạy script này → Llama 3 chấm điểm reasoning quality
  4. Kết quả: reasoning_eval_results.json + MLflow metrics

EVALUATION RUBRIC (4 chiều RAGAS-aligned, thang 1-5):
  - Context Precision: Xác định đúng kỹ thuật tấn công (MITRE)?
  - Answer Relevancy: Hành động đề xuất có giải quyết đúng mối đe dọa?
  - Faithfulness: Phân tích dựa trên sự thật, không bịa đặt (hallucinate)?
  - Context Recall: Trích xuất và sử dụng đúng context ISO/MITRE?

EVAL_SCHEMA_VERSION = "v2_5D"
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

**1. Context Precision (1-5)**
- 5: Correctly identified exact MITRE technique (e.g., T1110.001)
- 3: Identified correct tactic but wrong technique
- 1: Completely wrong or no MITRE mapping

**2. Answer Relevancy (1-5)**
- 5: Action matches expected action perfectly
- 3: Partially correct (e.g., ALERT when BLOCK expected)
- 1: Completely wrong action (e.g., LOG when BLOCK expected)

**3. Faithfulness (1-5)**
- 5: Reasoning is derived purely from logs and context (0% hallucination)
- 3: Mostly factual but includes some unsupported assumptions
- 1: Significant hallucination or completely illogical

**4. Context Recall (1-5)**
- 5: Extracted and effectively used MITRE/ISO context in analysis
- 3: Mentioned context but didn't integrate well
- 1: Ignored available context entirely

Respond ONLY in this JSON format:
{{"context_precision": <int>, "answer_relevancy": <int>, "faithfulness": <int>, "context_recall": <int>, "justification": "<brief explanation>"}}"""


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
            "context_precision": 1,
            "answer_relevancy": 1,
            "faithfulness": 1,
            "context_recall": 1,
            "justification": "PARSE_ERROR",
        }
    except Exception as e:
        print(f"  [!] LLM call error: {e}")
        return {
            "context_precision": 1,
            "answer_relevancy": 1,
            "faithfulness": 1,
            "context_recall": 1,
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

    all_precision = []
    all_relevancy = []
    all_faithfulness = []
    all_recall = []
    all_audit_completeness = []

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

        # Calculate Deterministic Audit Trail Completeness Rate
        latest_decision = sample.get("decisions", [{}])[-1] if sample.get("decisions") else {}
        required_fields = ["action", "confidence", "reasoning", "target", "mitre_technique"]
        present_fields = sum(1 for f in required_fields if latest_decision.get(f) not in [None, "", "UNKNOWN_TARGET", "N/A"])
        audit_completeness = (present_fields / len(required_fields)) * 100

        result_entry = {
            "sample_id": sample["sample_id"],
            "scores": scores,
            "audit_completeness_pct": audit_completeness,
            "judge_latency_s": round(elapsed, 2),
            "schema_version": "v2_5D"
        }
        eval_results["scores"].append(result_entry)

        all_precision.append(scores.get("context_precision", 1))
        all_relevancy.append(scores.get("answer_relevancy", 1))
        all_faithfulness.append(scores.get("faithfulness", 1))
        all_recall.append(scores.get("context_recall", 1))
        all_audit_completeness.append(audit_completeness)

        print(
            f"Precision={scores.get('context_precision', '?')}/5  "
            f"Relevancy={scores.get('answer_relevancy', '?')}/5  "
            f"Faithful={scores.get('faithfulness', '?')}/5  "
            f"Recall={scores.get('context_recall', '?')}/5  "
            f"Audit_Comp={audit_completeness:.0f}%  "
            f"({elapsed:.1f}s)"
        )

    # Aggregate statistics
    if all_precision:
        eval_results["aggregate"] = {
            "context_precision": {
                "mean": round(float(np.mean(all_precision)), 2),
                "std": round(float(np.std(all_precision)), 2),
                "min": int(min(all_precision)),
                "max": int(max(all_precision)),
            },
            "answer_relevancy": {
                "mean": round(float(np.mean(all_relevancy)), 2),
                "std": round(float(np.std(all_relevancy)), 2),
                "min": int(min(all_relevancy)),
                "max": int(max(all_relevancy)),
            },
            "faithfulness": {
                "mean": round(float(np.mean(all_faithfulness)), 2),
                "std": round(float(np.std(all_faithfulness)), 2),
                "min": int(min(all_faithfulness)),
                "max": int(max(all_faithfulness)),
            },
            "context_recall": {
                "mean": round(float(np.mean(all_recall)), 2),
                "std": round(float(np.std(all_recall)), 2),
                "min": int(min(all_recall)),
                "max": int(max(all_recall)),
            },
            "audit_completeness": {
                "mean": round(float(np.mean(all_audit_completeness)), 2),
                "std": round(float(np.std(all_audit_completeness)), 2),
                "min": float(min(all_audit_completeness)),
                "max": float(max(all_audit_completeness)),
            },
            "overall_mean": round(
                float(
                    np.mean(
                        [np.mean(all_precision), np.mean(all_relevancy),
                         np.mean(all_faithfulness), np.mean(all_recall)]
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
        print(f"  Context Precision (MITRE): {agg['context_precision']['mean']}/5 (±{agg['context_precision']['std']})")
        print(f"  Answer Relevancy (Action): {agg['answer_relevancy']['mean']}/5 (±{agg['answer_relevancy']['std']})")
        print(f"  Faithfulness (No Halluc):  {agg['faithfulness']['mean']}/5 (±{agg['faithfulness']['std']})")
        print(f"  Context Recall (RAG Use):  {agg['context_recall']['mean']}/5 (±{agg['context_recall']['std']})")
        print(f"  Audit Completeness Rate:   {agg['audit_completeness']['mean']}% (±{agg['audit_completeness']['std']}%)")
        print(f"  ---")
        print(f"  Overall LLM Mean Score:    {agg['overall_mean']}/5")
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
            mlflow.log_param("disclaimer", "RAGAS-inspired proxy metrics")
            mlflow.log_param("schema_version", "v2_5D")
            if eval_results["aggregate"]:
                agg = eval_results["aggregate"]
                mlflow.log_metric("Context_Precision_Mean", agg["context_precision"]["mean"])
                mlflow.log_metric("Answer_Relevancy_Mean", agg["answer_relevancy"]["mean"])
                mlflow.log_metric("Faithfulness_Mean", agg["faithfulness"]["mean"])
                mlflow.log_metric("Context_Recall_Mean", agg["context_recall"]["mean"])
                mlflow.log_metric("Audit_Completeness_Rate_pct", agg["audit_completeness"]["mean"])
                mlflow.log_metric("Overall_Quality_Mean", agg["overall_mean"])
            mlflow.log_artifact(OUTPUT_PATH)
        print("[+] Metrics logged to MLflow (Sentinel_Reasoning_Quality)")
    except Exception as e:
        print(f"[!] MLflow logging failed (non-critical): {e}")


if __name__ == "__main__":
    run_judge_evaluation()
