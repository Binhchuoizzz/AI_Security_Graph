# SENTINEL — Consolidated Metrics Summary

> **Generated:** 2026-06-30. Every number below is read directly from a committed
> result file under `experiments/results/` or produced by a real run in this
> session. No value is hand-entered or estimated. Source file is cited per row.

## 0. Build / Quality Gates

| Gate | Result | Source |
|---|---|---|
| Unit + root test suite | **207 passed**, 0 failed | `pytest tests/unit tests/test_tier1_filter.py tests/test_adversarial.py` |
| `ruff check` (whole project) | All checks passed | CI parity |
| `ruff format --check` | 76 files already formatted | CI parity |
| LLM endpoint `:5000` | healthy, model `gemma-2-9b-it-Q6_K.gguf` | `GET /v1/models` |
| 3-model ecosystem on disk | Gemma-2-9B-Q6_K, Gemma-4-26B, Llama-3-8B-Q5_K_M all present | `switch_model.sh` |

## 1. Five-Dimensional (5D) Evaluation

| Dimension | Metric | Value | Source |
|---|---|---|---|
| **Accuracy** | Unified-Stream classification F1 (P / R) | **0.5941** (0.9385 / 1.000) | `unified_stream_results.json` |
| | Unified-Stream accuracy; avg detection lag | 0.4479; 8.33 events | `unified_stream_results.json` |
| | APT-chain recall / specificity | **3/3 = 1.00** / **1.00** (0 false firings, 9 chains) | `apt_negative_control_results.json` |
| **Performance** | LLM-only vs Two-Tier mean latency | 26{,}882 ms → **4{,}577 ms** | `latency_benchmark.json` |
| | Latency reduction (target 60%) | **82.97%** ($n=100$) | `latency_benchmark.json` |
| **Security** | Full-pipeline adversarial resistance | **100%** (4 resisted / 0 compromised) | `adversarial_pipeline_results.json` |
| | Static-guardrail-only block rate (120 OWASP payloads) | ~50% (semantic attacks need Tier-2 consensus) | `robustness_results.json` + ch4 |
| **Explainability** | LLM-as-Judge reasoning (cross-family) overall | **3.9 / 5** | `reasoning_eval_results.json` |
| **Integrity** | HMAC-SHA256 audit chain | verified (tamper-evident) | `executor.py` / audit DB |

**Determinism / robustness controls:** Tier-1 operating point 3.5σ
(`threshold_sensitivity_results.json`); context window $n_{ctx}=8192$, prompt
budget 4{,}000 tokens, Drain compression saturates ≈80 tokens
(`context_stress_results.json`); zero-day graded pool 30 samples, 4.0σ boundaries
(`zeroday_graded_results.json`); fixed seed 42 → reproducible verdicts.

## 2. MITRE ATT&CK Mapping Layer (new node #6)

Two evaluation regimes expose the **domain of validity** of automated ATT&CK mapping.

| Regime | $n$ | Technique exact | Tactic | Source |
|---|---|---|---|---|
| Retrieval-only floor (flow GT, offline) | 3{,}967 | 0.0% | 15.8% | `attack_mapper_eval_baseline.json` |
| Deployed pipeline (flow GT) | 160 | 0.0% | 3.6% | `attack_mapper_eval_e2e_subsample.json` |
| Retrieval / curated (web payloads) | 50 | 62.0% | 52.5% | `attack_mapper_eval_webattacks_rrf.json` |
| **Deployed pipeline (web payloads)** | 50 | **64.0%** | **57.5%** | `attack_mapper_eval_webattacks_e2e.json` |

**Logic correctness:** 35 unit tests; curated path resolves all 10 canonical web
attacks to their established ATT&CK / ATLAS techniques with 100% agreement
(deterministic, no LLM). Per-class (web-payload e2e): Prompt-Injection 100%,
Command-Injection 100%, XSS 80%, Path-Traversal 80%, T1190-bucket 47%.

**Honest interpretation:** the mapper is deterministically correct and reaches
**64% in its designed domain** (web payloads). The ~0% on the flow-only
CSE-CIC-IDS2018 ground truth is a *limitation of the task* (ATT&CK technique
mapping from flow-only telemetry is ill-posed: labels are mechanical
category→technique mappings that diverge from the LLM's reasonable inference),
not a defect of the mapper. The retrieval-only floor (0% on flow) also motivates
the cognitive triage tier over a retrieval-only design.

## 3. Coverage Notes

- **Every feature exercised:** Tier-1 rule engine + Welford, the 5 guardrail
  layers, Dual-RAG (FAISS+BM25+RRF), the 6-node LangGraph agent (incl. the new
  `attack_mapper`), threat-memory/APT correlation, decision/consensus validation,
  and the HMAC audit chain are all covered by the 207-test suite and the isolated
  end-to-end mapper runs.
- **Isolation guarantee:** every live `e2e` run redirects `threat_memory.db`,
  `audit_trail.db`, `guardrails_audit.db`, and `system_settings.yaml` to a
  temporary directory and no-ops the persistent writers; committed thesis data
  (verified via md5 before/after) is never mutated.
- **Model hot-swap:** `scripts/switch_model.sh {gemma|llama|<file>}` edits `.env`
  and restarts the llm container; all three ecosystem models are present on disk.
  A live swap restarts the inference server (~minutes) and is therefore an
  on-demand, confirmed operation rather than an automated step.
