# Chạy đánh giá Ablation
# TODO: Quản lý 6 cấu hình ablation

"""
Ablation Study Runner:

Executes SENTINEL pipeline under 6 configurations and logs comparative metrics.

Configurations (see config/ablation/):
  A: Rule-only           (config_a_rule_only.yaml)
  B: LLM-only            (config_b_llm_only.yaml)
  C: No Encapsulation     (config_c_no_encapsulation.yaml)
  D: MITRE-only RAG       (config_d_mitre_only.yaml)
  E: ISO-only RAG         (config_e_iso_only.yaml)
  F: Full SENTINEL         (config_f_full.yaml)

For each configuration:
  1. Load config override
  2. Initialize pipeline with specified components
  3. Run on:
     - 5,000 stratified samples from CICIDS2017 (all configs)
     - 1,000+ adversarial samples (configs C, F only)
     - 30 reasoning ground truth cases (configs B, D, E, F)
  4. Compute metrics:
     - Classification: F1, Precision, Recall
     - Operational: Reasoning Latency, Cache Hit Rate
     - Robustness: Defeat Rate (where applicable)
     - Context Quality: RAGAS + LLM-as-Judge (where applicable)
     - Reasoning: MITRE Mapping Accuracy, Hallucination Rate (Fix #2)
  5. Log to MLflow: experiment=sentinel_ablation_study, tag=config_{A-F}

Depends on:
  - experiments/reasoning_ground_truth.json (30 MITRE-labeled cases)
  - experiments/ground_truth.json (200 RAGAS GT cases)
  - experiments/adversarial/ (1,000+ samples)
  - All src/ modules
"""
