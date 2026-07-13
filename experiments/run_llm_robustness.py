"""
SENTINEL — Độ Bền LLM & Quy Trình (Determinism + Graceful Degradation)
======================================================================
Hai mối lo phản biện/TS về việc dùng LLM cục bộ trong quy trình SOC:

  (A) TÁI LẬP: temp=0.1 vẫn lấy mẫu — kết quả có lặp lại được không?
      -> Đặt seed cố định (config llm.seed) rồi gọi CÙNG prompt N lần, kiểm tra
         output (và action sau parse) GIỐNG HỆT.

  (B) SUY BIẾN AN TOÀN: nếu LLM cục bộ CHẾT giữa chừng thì sao?
      -> Giả lập LLM ném lỗi, chạy tác tử đầy đủ trên một mẫu tấn công, xác nhận
         hệ KHÔNG vỡ mà suy biến về AWAIT_HITL (Tier-1 vẫn bảo vệ độc lập).

Cần LLM server (Gemma) cho phần (A). Chạy:
    .venv/bin/python experiments/run_llm_robustness.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import llm_client as llm_mod  # noqa: E402
from src.agent.llm_client import llm_client  # noqa: E402
from src.agent.prompts import build_triage_prompt  # noqa: E402
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402

GT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "llm_robustness_results.json")


def test_determinism(n_runs=5):
    """(A) Cùng prompt + seed cố định -> output tất định."""
    print("\n[A] TÁI LẬP (determinism) — cùng prompt, seed cố định")
    log_data = (
        "<escalated_log_data_v1>\n"
        "{'Source IP': '45.13.3.21', 'Destination Port': 22, 'Total Fwd Packets': 8, "
        "'service': 'SSH', 'tier1_reasons': ['Truy cập cổng nhạy cảm (22)']}\n"
        "</escalated_log_data_v1>"
    )
    rag = "MITRE ATT&CK:\nT1110 Brute Force\n\nNIST SP 800-61r2:\nContainment guidance."
    messages = build_triage_prompt(log_data=log_data, rag_context=rag)

    raws, actions = [], []
    for i in range(n_runs):
        raw = llm_client.invoke(messages=messages, temperature=0.1, seed=42)
        raws.append(raw)
        actions.append(str(llm_client.parse_llm_response(raw).get("action", "?")).upper())
        print(f"   run {i + 1}: action={actions[-1]} | len={len(raw)}")

    raw_identical = len(set(raws)) == 1
    action_identical = len(set(actions)) == 1
    print(
        f"   -> raw output giống hệt: {sum(r == raws[0] for r in raws)}/{n_runs} "
        f"({'TẤT ĐỊNH' if raw_identical else 'có biến thiên'})"
    )
    print(f"   -> ACTION giống hệt:     {sum(a == actions[0] for a in actions)}/{n_runs}")
    return {
        "n_runs": n_runs,
        "seed": 42,
        "raw_identical": raw_identical,
        "action_identical": action_identical,
        "distinct_raw_outputs": len(set(raws)),
        "distinct_actions": len(set(actions)),
        "actions": actions,
    }


def test_graceful_degradation():
    """(B) LLM chết -> tác tử suy biến về AWAIT_HITL, KHÔNG vỡ."""
    print("\n[B] SUY BIẾN AN TOÀN (graceful degradation) — giả lập LLM chết")
    with open(GT_PATH) as f:
        gt = json.load(f)
    sample = next(s for s in gt if s["expected_action"] == "BLOCK_IP")
    logs = sample.get("logs", [])

    # Giả lập LLM cục bộ chết: ép invoke ném ConnectionError (như server tắt).
    orig_invoke = llm_mod.llm_client.invoke

    def _boom(*a, **k):
        raise ConnectionError("Giả lập: LLM server không truy cập được")

    llm_mod.llm_client.invoke = _boom
    crashed = False
    action = None
    try:
        from src.guardrails import loop_detector

        loop_detector.reset()
        final = agent_app.invoke(
            SentinelState(
                current_batch_logs=logs, current_batch_size=len(logs), narrative_summary=""
            )
        )
        decisions = final.get("decisions", [])
        action = decisions[-1].get("action") if decisions else None
    except Exception as e:
        crashed = True
        print(f"   [!] HỆ VỠ (không mong muốn): {e}")
    finally:
        llm_mod.llm_client.invoke = orig_invoke  # khôi phục

    safe = (not crashed) and action == "AWAIT_HITL"
    print(f"   -> sample={sample['id']} | LLM chết | action sau suy biến = {action}")
    print(
        f"   -> KẾT QUẢ: {'✅ SUY BIẾN AN TOÀN (AWAIT_HITL, không vỡ)' if safe else '⚠️ chưa an toàn'}"
    )
    return {"sample_id": sample["id"], "crashed": crashed, "degraded_action": action, "safe": safe}


def main():
    print("=" * 70)
    print("  SENTINEL — ĐỘ BỀN LLM & QUY TRÌNH")
    print("=" * 70)

    det = test_determinism()
    deg = test_graceful_degradation()

    # Cache ngữ nghĩa (bonus): tỷ lệ hit giảm tải LLM
    cache = None
    try:
        from src.agent.nodes import retriever

        if hasattr(retriever, "cache") and retriever.cache:
            cache = retriever.cache.get_stats()
    except Exception:
        pass

    out = {"determinism": det, "graceful_degradation": deg, "semantic_cache": cache}
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved -> {OUT_JSON}")
    print(
        f"\n  TỔNG: determinism action={det['action_identical']} · degradation safe={deg['safe']}"
    )


if __name__ == "__main__":
    main()
