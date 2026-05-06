# SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

[![CI/CD Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

An advanced Autonomous Security Operations Framework integrating Session-Aware Behavioral Baselining (Tier 1) with an Agentic AI driven by Retrieval-Augmented Generation (RAG) and Long-Term Threat Memory (Tier 2). Built as a Master's Thesis to solve the SOC Alert Fatigue paradox.

## Architecture Overview

SENTINEL uses a **2-Tier Funneling Architecture** with strict **Separation of Concerns**, powered by **3 complementary models**:

```text
CSV → Data Publisher → Redis → Tier 1 (Baselining+TTL) → Template Miner → Prompt Filter → Semantic Cache → FAISS RAG → Agent(9B) → HITL
                                 │         ▲                (Compression)   (Dyn.Delimiters)  (Cache Hit?)    (Dual-RAG)                 Dashboard
                                 │         └──────────────── Feedback Loop (Pending Approval / Quarantine) ◀─────────────────────────────┘
                                 ▼
                            DROP (Clean)
```

### The 3 Models (Brains) of SENTINEL

| # | Model | Role | Layer | Runs On |
|---|---|---|---|---|
| **1** | Rule Engine & Session Baseline | Heuristic filter — DROP 99% noise at wire speed | Tier 1 | Python (RAM) |
| **2** | `all-MiniLM-L6-v2` | Embedding model — vectorize logs for FAISS semantic search | Tier 2 (RAG) | `sentence-transformers` (GPU) |
| **3** | `Gemma 2 9B Q6_K` | Reasoning LLM — deep analysis, MITRE mapping, action decisions | Tier 2 (Agent) | Local LLM Server — Oobabooga/llama.cpp (`localhost:5000`) |

**Tier 1 (Speed Layer):** Session-Aware Behavioral Baselining + TTL eviction.

**Guardrails (Two separate modules):**
- `template_miner.py` — Volume Compression ONLY (Drain3). Variables preserved.
- `prompt_filter.py` — Injection Defense ONLY (Dynamic Randomized Delimiters + Encoding Neutralization).

**Tier 2 (Intelligence Layer):** LangGraph Agent (Gemma 2 9B Q6_K) + Semantic Cache + Dual-RAG (MITRE ATT&CK + NIST SP 800-61r2).

## 🛡️ Core Novelty & Defenses

### Delimited Data Encapsulation (Adversarial Defense)
- **Dynamic Randomized Delimiters:** Each request generates a new delimiter using cryptographically secure `secrets.token_hex()`. Prevents *Delimiter Smuggling*.
- **Encoding Neutralization:** Intercepts and decodes Base64/Hex/Unicode before inference.
- **Quantified Limitations:** The Threat Model acknowledges and actively measures the baseline vulnerability against *Semantic Confusion* (an open problem in the field). Evaluations measure this semantic bypass rate at **86.7%**, while successfully blocking **93.3%** of structural attacks and **53.3%** of encoding bypasses.

### HITL Quarantine (Adversarial Rule Injection Defense)
- Agent auto-generates new rules based on context, but they are placed in **Quarantine (Pending Approval)**.
- Streamlit Dashboard with RBAC securely routes rules to an L3 Manager for approval before hot-reloading into the Tier 1 Rule Engine.
- Prevents the agent from being manipulated into blocking legitimate infrastructure.

## 📊 Evaluation & Methodology

SENTINEL employs a **5D Evaluation Framework (v2_5D)** — combining statistical tests, operational SOC metrics, cross-family LLM-as-Judge, and deterministic audit scoring.

### 5-Dimensional Evaluation Framework

| Dimension | What it Measures | Method | Script |
| --- | --- | --- | --- |
| **1. Classification** | F1, Precision, Recall, FPR | McNemar's Test (p<0.05) | `run_ablation_study.py` |
| **2. Operational** | MTTD/MTTR Proxy*, HITL Escalation Rate, RAG Cache Hit Rate | Mann-Whitney U Test (p<0.05) | `run_ablation_study.py` |
| **3. Robustness** | Guardrail Defeat Rate per attack category | 45 curated adversarial samples | `evaluate_robustness.py` |
| **4. Context Quality** | Context Precision, Answer Relevancy, Faithfulness, Context Recall | **RAGAS-inspired LLM-as-Judge** (Llama 3 judges Gemma 9B) | `evaluate_reasoning.py` |
| **5. Explainability** | Audit Trail Completeness Rate (deterministic) | Programmatic field presence check | `evaluate_reasoning.py` |

> **\*Disclaimer:** Processing Latency is used as a proxy for MTTD/MTTR under offline dataset constraints. Real-world ingestion and human review times are not included.

### Key Methodological Decisions
- **Cross-Family LLM-as-Judge:** Using **Llama 3 8B (Meta)** to judge **Gemma 9B (Google)** eliminates Self-Enhancement Bias (different model family, different training data — Zheng et al., NeurIPS 2023).
- **RAGAS-inspired, not RAGAS:** Context Quality metrics are scored via LLM-as-Judge with a RAGAS-aligned rubric. Full computational RAGAS (NLI decomposition) is not feasible on RTX 4060 Ti 16GB. Explicitly tagged as `methodology="RAGAS-inspired LLM-as-Judge"` in MLflow.
- **Deterministic Explainability:** Audit Trail Completeness is calculated programmatically (% of 5 required fields present in output), not via LLM scoring, to avoid circular self-evaluation.
- **Schema Version:** All evaluation outputs are tagged `EVAL_SCHEMA_VERSION = "v2_5D"` for reproducibility.

### Statistical Validity
- **McNemar's Test** for classification accuracy comparison between Config A and Config F.
- **Mann-Whitney U Test** for skewed latency distributions.
- **Test Coverage**: **79/79** unit and integration tests passed in 0.17s.

### Ground Truth
- 101 human-annotated samples (`experiments/ground_truth.json`): 81 attack + 20 benign.
- Labels: `expected_action` and `expected_mitre_technique`, manually assigned by the thesis author (Domain Expert) with cross-reference to the MITRE ATT&CK Framework.
- 45 adversarial samples across 3 categories (structural, encoding, semantic).

### Reproducibility Package
1. `experiments/run_ablation_study.py` — Automated ablation (Config A vs Config F) with 5D metrics + MLflow logging.
2. `experiments/evaluate_reasoning.py` — RAGAS-inspired LLM-as-Judge + Audit Completeness.
3. `experiments/statistical_tests.py` — Automated p-value computation (McNemar + Mann-Whitney U).
4. `experiments/evaluate_robustness.py` — Adversarial Guardrail Defeat Rate evaluation.
5. `experiments/ground_truth.json` — 101 labeled samples for validation.

## 📁 Key Project Structure

```
sentinel/
├── config/
│   ├── ablation/                     # 6 YAML configs (A-F) for ablation study
│   └── system_settings.yaml          # Central config (LLM, Tier1, Guardrails, RAG, Redis)
├── docs/
│   ├── proposal_latex/               # Full thesis proposals in LaTeX (EN & VI)
│   ├── architecture.md               # System architecture diagram
│   ├── threat_model.md               # Adversary profiles & Defense limit matrix
│   ├── research_roadmap.md           # 6-Pillar literature map with reading order
│   └── REPRODUCIBILITY.md            # Execution framework guidelines
├── experiments/
│   ├── adversarial/                  # 45 Curated attack samples (Structural, Encoding, Semantic)
│   ├── ground_truth.json             # 101 labeled samples for Ablation Study
│   ├── run_ablation_study.py         # 5D metrics: F1, FPR, MTTD/MTTR Proxy, HITL, Cache
│   ├── evaluate_reasoning.py         # RAGAS-inspired LLM-as-Judge + Audit Completeness
│   ├── evaluate_robustness.py        # Adversarial Defeat Rate per category
│   ├── statistical_tests.py          # McNemar + Mann-Whitney U p-value computation
│   └── ablation_design.md            # Statistical Hypothesis matrix
├── src/
│   ├── streaming/                    # Pipeline: pub/sub architecture (publisher.py, subscriber.py)
│   ├── tier1_filter/                 # Speed Layer + Feedback Listener & Firewall
│   ├── guardrails/                   # Compression, Validators & Monitor guards
│   ├── rag/                          # Dual-Database Vector retrieval & Cache
│   ├── agent/                        # LangGraph Stateful Reasoning Nodes
│   └── ui/                           # RBAC + Streamlit Dashboard
└── tests/                            # 79 Pytest suites (all passing)
```

## 🚀 Quick Start

See [RUN_PROJECT.md](RUN_PROJECT.md) for a detailed step-by-step guide with explanations.

```bash
# 1. Clone and setup
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph
cp .env.example .env
source .venv/bin/activate && pip install -r requirements.txt

# 2. Start infrastructure
docker-compose up -d redis mlflow

# 3. Ensure LLM server (Oobabooga/llama.cpp) is running at http://localhost:5000 with Gemma 9B loaded

# 4. Start SENTINEL Core (Terminal 1)
python main.py

# 5. Start Dashboard (Terminal 2)
streamlit run src/ui/app.py

# 6. Stream attack traffic (Terminal 3)
python src/streaming/publisher.py
```

## 💻 Hardware Requirements

| Component | Minimum | Details |
|---|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | Gemma 9B (~7GB) + KV Cache (~9GB) |
| RAM | 32GB | For streaming cache overhead |
| Storage | 50GB SSD | Dataset caching + DB logging |
| OS | Linux (Ubuntu 22.04+) | - |

## 📝 License & Authorship

MIT License. See [LICENSE](LICENSE) for details.

**Author**: Nguyễn Đức Bình — Master's Candidate in AI & Machine Learning.
