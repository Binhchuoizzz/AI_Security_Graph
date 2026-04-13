# Baseline B: LLM-Only (No Tier 1 Pre-filter)
# TODO: Implement for Ablation Config B

"""
Baseline B — LLM-Only IDS

Purpose: Show cost of sending ALL events to LLM without pre-filtering.
         Proves 2-Tier architecture reduces latency.

Pipeline:
  CSV → Redis → Subscriber → (skip Tier 1) → Guardrails → LLM Agent → Decision
  Every single event hits the LLM, including benign traffic.

What it measures:
  - F1/Precision/Recall — expected similar to Config F (same LLM brain)
  - Reasoning Latency — expected MUCH HIGHER than Config F
  - Throughput — expected MUCH LOWER (LLM bottleneck on every event)
  - Cost (GPU hours) — expected prohibitive for production

Expected outcome:
  - F1 ≈ Config F (same reasoning quality)
  - Latency >> Config F (processes 100% events vs ~30% after Tier 1 filter)
  - Proves: 2-Tier doesn't sacrifice accuracy, only reduces unnecessary LLM calls

Key insight for thesis:
  If F1(B) ≈ F1(F) but Latency(B) >> Latency(F):
  → "Tier 1 pre-filtering reduces LLM inference load by ~70% with negligible
     accuracy loss, making real-time SOC deployment feasible on local hardware."

Depends on:
  - src/agent/workflow.py
  - src/rag/retriever.py
  - config/ablation/config_b_llm_only.yaml
"""
