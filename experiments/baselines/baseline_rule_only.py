# Baseline A: IDS thuần luật (Không dùng LLM)
# TODO: Triển khai cho Cấu hình Ablation A

"""
Baseline A — Rule-Only IDS

Purpose: Establish lower bound. How well does pure rule-based detection perform
         WITHOUT any LLM reasoning?

Pipeline:
  CSV → Redis → Subscriber → Tier 1 RuleEngine → Decision (LOG/BLOCK/ALERT)
  No Guardrails, No LLM, No RAG.

What it measures:
  - F1/Precision/Recall based on Tier 1 risk_score vs dataset label
  - Throughput (events/second) — expected to be extremely fast
  - False Positive Rate — expected to be high (rigid rules)
  - False Negative Rate — expected to be high (no semantic understanding)

Expected outcome:
  - High recall for obvious attacks (port 22 brute force, high packet count)
  - Low precision (many false positives from rigid thresholds)
  - Very low latency (no GPU needed)
  - F1 significantly lower than Config F → proves LLM adds value

Depends on:
  - src/tier1_filter/rule_engine.py
  - config/ablation/config_a_rule_only.yaml
"""
