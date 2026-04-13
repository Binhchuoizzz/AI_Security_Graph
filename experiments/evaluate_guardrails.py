# Context Quality Evaluation (RAGAS + LLM-as-Judge)
# TODO: Implement dual evaluation methodology

"""
Context Quality Evaluation — Dual Methodology:

=== TẦNG 1: RAGAS (200 static Ground Truth samples) ===
  Input: experiments/ground_truth.json (200 labeled incidents)
  Process:
    1. Run SENTINEL pipeline on each GT incident
    2. Capture RAG context retrieved + Agent answer
    3. Compute RAGAS metrics:
       - Context Precision: % retrieved chunks relevant to GT
       - Answer Relevancy: Agent answer aligns with expected decision
       - Faithfulness: Agent answer grounded in retrieved context
  Output: RAGAS score per incident, aggregated metrics

=== TẦNG 2: LLM-as-a-Judge (5,000 stratified samples) ===
  Oracle Model: Gemma 2 26B Q4_K_M (independent judge, different from 9B agent)
  Process:
    1. Sequential model swap: unload 9B agent → load 26B judge
    2. For each of 5,000 stratified samples:
       a. Present: original log + RAG context retrieved + Agent decision
       b. Judge prompt: "Rate context relevance 1-5. Is the decision appropriate?"
       c. Record: relevance_score, decision_appropriateness, reasoning
    3. Compare with stratified sample distribution to validate representativeness
  Output: Mean relevance score, decision accuracy, confidence intervals

=== TẦNG 2.5: Agent Reasoning Accuracy (30 cases) ===    <-- NEW (Fix #2)
  Input: experiments/reasoning_ground_truth.json (30 MITRE-labeled cases)
  Process:
    1. Run Agent on each case
    2. Extract MITRE technique from Agent output
    3. Exact match vs GT technique → MITRE Mapping Accuracy
    4. Tactic-level match → Tactic Accuracy
    5. Benign cases with technique assigned → Hallucination Rate
  Output: Accuracy %, Hallucination %, confusion matrix

Depends on:
  - experiments/ground_truth.json (200 samples)
  - experiments/reasoning_ground_truth.json (30 samples)
  - src/rag/retriever.py (Dual-RAG)
  - src/agent/workflow.py (LangGraph Agent)
"""
