"""
LLM-as-Judge: Reasoning Quality Evaluation (Cross-Family)

Một model KHÁC HỌ với model tác tử làm trọng tài độc lập — đó là toàn bộ giá trị của phương
pháp này (Zheng et al., 2023): model chấm chính mình luôn tự cho điểm cao (Self-Enhancement
Bias). Tên model KHÔNG viết cứng ở đâu cả: trọng tài đọc thật từ `/v1/models`, model tác tử
lấy từ `SENTINEL_AGENT_MODEL` (hoặc `LLM_MODEL_FILE`), và `assert_cross_family()` CHẶN CỨNG
khi hai bên trùng nhau.

WORKFLOW:
  1. Chạy run_ablation.py --mode af bằng model TÁC TỬ → `reasoning_outputs` được lưu sẵn
     trong ablation_results.json (bước 3 KHÔNG cần chạy lại ablation)
  2. Nạp model TRỌNG TÀI khác họ lên LLM server. PHẢI xuất biến ra môi trường, không chỉ
     sửa `.env` — docker-compose ưu tiên biến môi trường hơn tệp:
       LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf LLAMA_ARG_CTX_SIZE=32768 \
         docker-compose up -d --force-recreate --no-deps llm
  3. SENTINEL_AGENT_MODEL=<model tác tử> python experiments/evaluate_reasoning.py
  4. Kết quả: reasoning_eval_results.json + MLflow metrics. Đọc kèm
     `run_health.n_incomplete_schema` — lớn hơn 0 nghĩa là lượt đo KHÔNG đáng tin.

EVALUATION RUBRIC (4 chiều RAGAS-aligned, thang 1-5):
  - Context Precision: Xác định đúng kỹ thuật tấn công (MITRE)?
  - Answer Relevancy: Hành động đề xuất có giải quyết đúng mối đe dọa?
  - Faithfulness: Phân tích dựa trên sự thật, không bịa đặt (hallucinate)?
  - Context Recall: Trích xuất và sử dụng đúng context NIST/MITRE?

EVAL_SCHEMA_VERSION = "v2_5D"
"""

import json
import os
import sys
import time

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import evidence_grounding, wilson_ci  # noqa: E402

# API tương thích với OpenAI (Oobabooga / llama.cpp)
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5000/v1")

ABLATION_RESULTS_PATH = os.path.join(os.path.dirname(__file__), "results", "ablation_results.json")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "results", "reasoning_eval_results.json")

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
- 5: Extracted and effectively used MITRE/NIST context in analysis
- 3: Mentioned context but didn't integrate well
- 1: Ignored available context entirely

Respond ONLY in this JSON format:
{{"context_precision": <int>, "answer_relevancy": <int>, "faithfulness": <int>, "context_recall": <int>, "justification": "<brief explanation>"}}"""


def served_model() -> str:
    """Tên model LLM server ĐANG phục vụ — đọc thật từ `/v1/models`, không đoán."""
    import urllib.request

    try:
        with urllib.request.urlopen(f"{LLM_API_BASE}/models", timeout=5) as r:  # noqa: S310
            return str(json.loads(r.read().decode("utf-8", "replace"))["data"][0]["id"])
    except Exception:
        return ""


def assert_cross_family(agent_model: str) -> str:
    """Chặn TRỌNG TÀI CHÍNH LÀ BỊ CÁO. Trả về tên model trọng tài thật.

    LỖI ĐÃ VÁ (phát hiện 2026-07-29): `call_llm_judge` gọi thẳng `LLM_API_BASE` với
    `"model": "judge"`, nhưng llama.cpp BỎ QUA trường đó và phục vụ model đang nạp. Runner
    không hề đổi model — docstring đầu file khi đó liệt kê "Unload … → Load …" như một bước
    của quy trình, nhưng đó là thao tác TAY mà không ai làm. Hệ quả đo được: lượt 2026-07-29
    chạy Foundation-Sec chấm điểm chính Foundation-Sec, trong khi tệp kết quả ghi:

        "bias_mitigation": "Different model family eliminates Self-Enhancement Bias"

    Tức tuyên bố đã loại trừ ĐÚNG cái thiên lệch mà nó đang mắc — và không có gì đỏ lên để
    báo. Điểm số kiểu này chép vào luận văn là hỏng cả chương đánh giá.
    """
    judge = served_model()
    if not judge:
        raise SystemExit(
            f"[!] Không đọc được model tại {LLM_API_BASE}/models — LLM server chưa chạy?"
        )
    norm = lambda s: s.lower().replace(".gguf", "").strip()  # noqa: E731
    if norm(judge) == norm(agent_model):
        raise SystemExit(
            f"[!] TRỌNG TÀI TRÙNG BỊ CÁO: server đang phục vụ '{judge}', cũng chính là model\n"
            f"    đã sinh ra các phán quyết được chấm ('{agent_model}'). Đây là Self-Enhancement\n"
            f"    Bias — thứ mà phương pháp Cross-Family LLM-as-Judge tồn tại để loại trừ.\n"
            f"    Nạp một model KHÁC HỌ rồi chạy lại, ví dụ:\n"
            f"      LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf \\\n"
            f"        docker-compose up -d --force-recreate --no-deps llm"
        )
    return judge


def call_llm_judge(system_prompt: str, user_prompt: str) -> dict:
    """Gọi API LLM Judge (đã nạp model KHÁC HỌ với tác tử) để chấm chất lượng suy luận."""
    import requests

    content = ""

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

        # Phân tích cú pháp JSON từ phản hồi của LLM
        # Xử lý trường hợp LLM bọc kết quả trong markdown block
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
    """Định dạng các quyết định của tác tử để đưa vào prompt đánh giá."""
    if not decisions:
        return "(No decisions made — sample was not escalated to LLM)"
    parts = []
    for d in decisions:
        parts.append(
            f"  - Action: {d.get('action', 'N/A')}\n"
            f"    Target: {d.get('target', 'N/A')}\n"
            f"    Confidence: {d.get('confidence', 'N/A')}\n"
            f"    MITRE: {d.get('mitre_technique', 'N/A')}\n"
            f"    NIST: {d.get('nist_control', 'N/A')}\n"
            f"    Reasoning: {d.get('reasoning', 'N/A')}"
        )
    return "\n".join(parts)


def run_judge_evaluation():
    """Vòng lặp đánh giá chính: gửi từng kết quả suy luận đến Llama 3 Judge."""

    # Kiểm tra xem file kết quả thử nghiệm loại trừ (ablation results) có tồn tại không
    if not os.path.exists(ABLATION_RESULTS_PATH):
        print("[!] ERROR: ablation_results.json not found!")
        print("    Chạy 'python experiments/run_ablation.py --mode af' bằng model TÁC TỬ trước.")
        sys.exit(1)

    with open(ABLATION_RESULTS_PATH) as f:
        ablation_data = json.load(f)

    reasoning_outputs = ablation_data.get("Config_F", {}).get("reasoning_outputs", [])
    if not reasoning_outputs:
        print("[!] ERROR: No reasoning_outputs in ablation_results.json!")
        print("    Re-run ablation study with the updated script to capture outputs.")
        sys.exit(1)

    # Lọc: chỉ đánh giá các mẫu được chuyển tiếp lên lớp LLM (Tier 2)
    escalated = [r for r in reasoning_outputs if r.get("escalated_to_llm", False)]
    not_escalated = [r for r in reasoning_outputs if not r.get("escalated_to_llm", False)]

    print(f"[*] Total samples: {len(reasoning_outputs)}")
    print(f"    Escalated to LLM (will judge): {len(escalated)}")
    print(f"    Not escalated (Tier 1 only): {len(not_escalated)}")
    # Tên model PHẢI đọc từ hệ thống, KHÔNG viết cứng: bản trước ghi cố định "Gemma 2 9B"
    # vào tệp kết quả bất kể model nào thật sự sinh ra phán quyết, nên lượt chạy bằng
    # Foundation-Sec vẫn xuất ra tệp mang tên Gemma. Số đúng + tên sai = vẫn là số sai.
    agent_model = os.getenv("SENTINEL_AGENT_MODEL") or os.getenv("LLM_MODEL_FILE") or "?"
    judge_model = assert_cross_family(agent_model)

    print("\n[*] Starting LLM-as-Judge evaluation...")
    print(f"    Judge Model: {judge_model} (đọc từ {LLM_API_BASE}/models)")
    print(f"    Agent Model: {agent_model} (đã sinh phán quyết trong ablation)")
    print()

    eval_results = {
        "metadata": {
            "judge_model": judge_model,
            "agent_model": agent_model,
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
    all_schema_completeness = []
    all_grounding: list[dict] = []

    for idx, sample in enumerate(escalated):
        print(f"[{idx + 1}/{len(escalated)}] Judging {sample['sample_id']}...", end=" ")

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

        # --- (a) Kiểm tra SCHEMA (đổi tên từ "audit completeness") ---------------------
        # HẠ CẤP CÓ CHỦ ĐÍCH. Chỉ số này đếm 5 trường trong dict do CHÍNH hệ sinh ra, nên
        # nó LUÔN đạt 100% — một phép đo không thể trượt thì không đo được gì. Nó là kiểm
        # tra schema (hữu ích để bắt lỗi hồi quy), KHÔNG phải thước đo chất lượng giải
        # thích. Trước đây nó được trích vào bảng 5D như bằng chứng "Tính giải thích 100%".
        latest_decision = sample.get("decisions", [{}])[-1] if sample.get("decisions") else {}
        required_fields = ["action", "confidence", "reasoning", "target", "mitre_technique"]
        present_fields = sum(
            1
            for f in required_fields
            if latest_decision.get(f) not in [None, "", "UNKNOWN_TARGET", "N/A"]
        )
        schema_completeness = (present_fields / len(required_fields)) * 100

        # --- (b) NEO BẰNG CHỨNG — chỉ số giải thích CHÍNH ------------------------------
        # Prompt triage BẮT BUỘC mỗi luận điểm về hành vi phải kèm ít nhất một giá trị
        # `field=value` TRÍCH NGUYÊN VĂN từ log, và CẤM tường minh kiểu lập luận rỗng
        # "confirmed by MITRE nên phải chặn". Đo tỉ lệ tuân thủ điều đó mới là phép đo
        # thật: nó kiểm chứng giá trị có KHỚP log (chống bịa số) và CÓ THỂ trượt.
        grounding = evidence_grounding(
            str(latest_decision.get("reasoning", "")), sample.get("log", {}) or {}
        )

        result_entry = {
            "sample_id": sample["sample_id"],
            "scores": scores,
            "schema_completeness_pct": schema_completeness,
            "evidence_grounding": grounding,
            "judge_latency_s": round(elapsed, 2),
            "schema_version": "v3_grounding",
        }
        eval_results["scores"].append(result_entry)
        all_grounding.append(grounding)

        all_precision.append(scores.get("context_precision", 1))
        all_relevancy.append(scores.get("answer_relevancy", 1))
        all_faithfulness.append(scores.get("faithfulness", 1))
        all_recall.append(scores.get("context_recall", 1))
        all_schema_completeness.append(schema_completeness)

        print(
            f"Precision={scores.get('context_precision', '?')}/5  "
            f"Relevancy={scores.get('answer_relevancy', '?')}/5  "
            f"Faithful={scores.get('faithfulness', '?')}/5  "
            f"Recall={scores.get('context_recall', '?')}/5  "
            f"Grounded={'Y' if grounding['grounded'] else 'N'}"
            f"({grounding['n_verified']}/{grounding['n_citations']})  "
            f"({elapsed:.1f}s)"
        )

    # Thống kê tổng hợp
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
            # ĐÃ GỠ KHỎI NHÓM CHỈ SỐ. `schema_completeness` đếm 5 trường trong dict do CHÍNH
            # hệ sinh ra nên luôn đạt tối đa — nó khẳng định hàm có trả về đủ khoá, không
            # đo chất lượng gì. Báo nó cạnh bốn chiều LLM-Judge khiến người đọc tưởng đây
            # là chiều thứ năm ("Tính giải thích 100%"). Nay nó sống dưới dạng CỔNG HỢP LỆ:
            # chỉ đếm số ca THIẾU trường. Khác 0 nghĩa là có hồi quy schema và toàn bộ lượt
            # đo phải bị nghi ngờ — đó mới là công dụng thật của nó.
            "run_health": {
                "n_incomplete_schema": sum(1 for v in all_schema_completeness if v < 100.0),
                "n_scored": len(all_schema_completeness),
                "note": (
                    "Cổng hợp lệ, KHÔNG phải chỉ số. n_incomplete_schema > 0 => phán quyết "
                    "thiếu trường bắt buộc => kết quả lượt đo này không đáng tin."
                ),
            },
            # CHỈ SỐ GIẢI THÍCH CHÍNH: lập luận có neo vào giá trị THẬT trong log không.
            "evidence_grounding": {
                "grounding_rate": round(
                    sum(1 for g in all_grounding if g["grounded"]) / len(all_grounding), 4
                ),
                "grounding_rate_ci95": list(
                    wilson_ci(sum(1 for g in all_grounding if g["grounded"]), len(all_grounding))
                ),
                "mean_citations": round(
                    float(np.mean([g["n_citations"] for g in all_grounding])), 2
                ),
                "mean_verified_citations": round(
                    float(np.mean([g["n_verified"] for g in all_grounding])), 2
                ),
                "appeal_rate": round(
                    sum(1 for g in all_grounding if g["n_appeals"] > 0) / len(all_grounding), 4
                ),
                "note": (
                    "grounding_rate = tỉ lệ lập luận có >=1 cặp field=value KHỚP giá trị thật "
                    "trong log. appeal_rate = tỉ lệ viện dẫn thẩm quyền rỗng (prompt cấm)."
                ),
            },
            "overall_mean": round(
                float(
                    np.mean(
                        [
                            np.mean(all_precision),
                            np.mean(all_relevancy),
                            np.mean(all_faithfulness),
                            np.mean(all_recall),
                        ]
                    )
                ),
                2,
            ),
        }

    # Lưu kết quả
    with open(OUTPUT_PATH, "w") as f:
        json.dump(eval_results, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 60}")
    print("REASONING QUALITY EVALUATION — RESULTS")
    print(f"{'=' * 60}")
    if eval_results["aggregate"]:
        agg = eval_results["aggregate"]
        print(
            f"  Context Precision (MITRE): {agg['context_precision']['mean']}/5 (±{agg['context_precision']['std']})"
        )
        print(
            f"  Answer Relevancy (Action): {agg['answer_relevancy']['mean']}/5 (±{agg['answer_relevancy']['std']})"
        )
        print(
            f"  Faithfulness (No Halluc):  {agg['faithfulness']['mean']}/5 (±{agg['faithfulness']['std']})"
        )
        print(
            f"  Context Recall (RAG Use):  {agg['context_recall']['mean']}/5 (±{agg['context_recall']['std']})"
        )
        _rh = agg["run_health"]
        if _rh["n_incomplete_schema"]:
            print(
                f"  [!] CỔNG HỢP LỆ ĐỎ: {_rh['n_incomplete_schema']}/{_rh['n_scored']} phán "
                f"quyết THIẾU trường bắt buộc — kết quả lượt đo này không đáng tin."
            )
        eg = agg["evidence_grounding"]
        print(
            f"  NEO BẰNG CHỨNG (chính):    {eg['grounding_rate']:.1%} "
            f"CI95 {eg['grounding_rate_ci95']}"
        )
        print(
            f"    ↳ trích dẫn TB {eg['mean_citations']} / xác minh được {eg['mean_verified_citations']}"
            f" · viện dẫn rỗng {eg['appeal_rate']:.1%}"
        )
        print("  ---")
        print(f"  Overall LLM Mean Score:    {agg['overall_mean']}/5")
    print(f"{'=' * 60}")
    print(f"[+] Results saved to: {OUTPUT_PATH}")

    # Ghi nhận dữ liệu lên MLflow
    try:
        import mlflow

        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
        mlflow.set_experiment("Sentinel_Reasoning_Quality")
        with mlflow.start_run(run_name="LLM_Judge_Evaluation"):
            mlflow.log_param("judge_model", eval_results["metadata"]["judge_model"])
            mlflow.log_param("agent_model", eval_results["metadata"]["agent_model"])
            mlflow.log_param("escalated_samples", len(escalated))
            mlflow.log_param("disclaimer", "RAGAS-inspired proxy metrics")
            mlflow.log_param("schema_version", "v2_5D")
            if eval_results["aggregate"]:
                agg = eval_results["aggregate"]
                mlflow.log_metric("Context_Precision_Mean", agg["context_precision"]["mean"])
                mlflow.log_metric("Answer_Relevancy_Mean", agg["answer_relevancy"]["mean"])
                mlflow.log_metric("Faithfulness_Mean", agg["faithfulness"]["mean"])
                mlflow.log_metric("Context_Recall_Mean", agg["context_recall"]["mean"])
                mlflow.log_metric(
                    "Incomplete_Schema_Count", agg["run_health"]["n_incomplete_schema"]
                )
                mlflow.log_metric(
                    "Evidence_Grounding_Rate", agg["evidence_grounding"]["grounding_rate"]
                )
                mlflow.log_metric("Appeal_Rate", agg["evidence_grounding"]["appeal_rate"])
                mlflow.log_metric("Overall_Quality_Mean", agg["overall_mean"])
            try:
                mlflow.log_artifact(OUTPUT_PATH)
            except Exception as art_err:
                print(f"[!] Warning: Failed to log artifact to MLflow: {art_err}")
        print("[+] Metrics logged to MLflow (Sentinel_Reasoning_Quality)")
    except Exception as e:
        print(f"[!] MLflow logging failed (non-critical): {e}")


if __name__ == "__main__":
    run_judge_evaluation()
