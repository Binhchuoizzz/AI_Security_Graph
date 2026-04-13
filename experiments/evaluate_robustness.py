# Adversarial Evaluation Runner
# TODO: Orchestrates all adversarial experiments across 3 categories

"""
Adversarial Evaluation Pipeline:

1. Load adversarial samples from:
   - experiments/adversarial/structural_attacks/    (300 samples)
   - experiments/adversarial/encoding_bypass/       (200 samples)
   - experiments/adversarial/semantic_confusion/    (500 samples)

2. For each sample:
   a. Inject payload into log entry (specified field)
   b. Pass through Guardrails pipeline (Encapsulation + Pattern Matching)
   c. If not blocked → pass to LLM Agent
   d. Compare Agent decision vs Ground Truth
   e. Record: blocked_by_guardrail, agent_decision_correct, bypass_succeeded

3. Compute metrics per category:
   - Structural: Defeat Rate (expect ~0%)
   - Encoding: Defeat Rate (expect ~0%)
   - Semantic Confusion: Bypass Rate (expect X% — quantified limitation)

4. Compute comparative metrics:
   - Full Encapsulation (Config F) vs No Encapsulation (Config C)
   - Semantic Confusion bypass WITH vs WITHOUT Encapsulation (expect similar)

5. Log all results to MLflow: experiment=sentinel_adversarial

Depends on:
   - src/guardrails/prompt_filter.py (DelimitedDataEncapsulator)
   - src/agent/workflow.py (LangGraph Agent)
   - config/ablation/config_c_no_encapsulation.yaml
   - config/ablation/config_f_full.yaml
"""
