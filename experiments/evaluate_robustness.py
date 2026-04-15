# Adversarial Evaluation Runner
# TODO: Orchestrates all adversarial experiments across 3 attack categories

"""
Adversarial Evaluation Pipeline

=== GENERATION METHODOLOGY (Option C — Cross-Family) ===

Để tránh Circular Evaluation Bias, adversarial samples được tạo ra theo sơ đồ:

  Generator : Meta Llama 3 8B Instruct  ← sinh attack variants
  Agent     : Gemma 2 9B Q6_K           ← hệ thống SENTINEL đang bị test
  Judge     : Gemma 2 26B Q4_K_M        ← Oracle đánh giá kết quả

  Llama 3 và Gemma thuộc 2 model family khác nhau (Meta vs Google DeepMind),
  khác nhau về pretraining corpus và RLHF alignment → không còn circular bias
  "model tạo attack biết cấu trúc của chính model judge".

  Residual bias (acknowledge trung thực): Cả Llama 3 và Gemma 26B đều là
  RLHF-aligned models → đều có xu hướng tránh payload quá rõ ràng độc hại.
  Bypass rate đo được có thể thấp hơn human red-teamers trong thực tế.

=== PIPELINE PER SAMPLE ===

1. Load adversarial samples từ:
   - experiments/adversarial/structural_attacks/    (300 samples — hand-crafted + PromptBench adapted)
   - experiments/adversarial/encoding_bypass/       (200 samples — encoding variants)
   - experiments/adversarial/semantic_confusion/    (500 samples — Llama 3 generated, cross-family)

2. Với mỗi sample:
   a. Inject payload vào log field (User-Agent, Referer, URI, X-Custom-Header)
   b. Pass qua Guardrails pipeline (Dynamic Delimiter Encapsulation + Pattern Matching)
   c. Nếu không bị block → pass tới Gemma 9B Agent
   d. Gemma 26B Oracle Judge đánh giá: Agent có bị dẫn dắt ra quyết định sai không?
   e. Record: blocked_by_guardrail, bypass_succeeded, severity_downgraded

3. Tính metrics theo từng category:
   - Structural Attacks: Defeat Rate (expect ~0% — Encapsulation blocks all)
   - Encoding Bypass: Defeat Rate (expect ~0% — Neutralization layer)
   - Semantic Confusion: Bypass Rate = X% (quantified open limitation)

4. Tính comparative metrics:
   - Bypass Rate WITH Encapsulation (Config F) vs WITHOUT (Config C)
   - Kỳ vọng: hai kết quả gần bằng nhau cho Semantic Confusion
     → chứng minh Encapsulation không giúp gì cho semantic-level attacks

5. Log toàn bộ kết quả vào MLflow: experiment=sentinel_adversarial

=== DEPENDENCIES ===
   - src/guardrails/prompt_filter.py (DelimitedDataEncapsulator)
   - src/agent/workflow.py (LangGraph Agent — Gemma 9B)
   - config/ablation/config_c_no_encapsulation.yaml (comparative baseline)
   - config/ablation/config_f_full.yaml (full system)
   - experiments/adversarial/semantic_confusion/ (Llama 3 generated samples)
"""
