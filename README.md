# SENTINEL Framework

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

Autonomous AI Security Agent (IDS/SOAR) utilizing LangGraph, Dual-RAG, and Adversarial Guardrails for real-time multi-source log correlation. Built as a Master's Thesis in AI Security Engineering.

## Architecture Overview

SENTINEL uses a **2-Tier Funneling Architecture** with a **Feedback Loop**, designed as a Containerized Modular system:

```
CSV Dataset ──▶ Redis Queue ──▶ Tier 1 (Rule Engine) ──▶ Guardrails ──▶ LangGraph Agent ──▶ HITL Dashboard
                                   │         ▲                              │
                                   │         │                              │
                                   │         └──── Feedback Loop ◀──────────┘
                                   │                (Dynamic Rules)
                                   ▼
                              DROP (Clean Traffic)
```

**Tier 1 (Speed Layer):** Rule-based filter with dynamic rules and random sampling (2% clean traffic for Zero-day detection).

**Tier 2 (Intelligence Layer):** LangGraph Agent with Dual-RAG (MITRE ATT&CK + ISO 27001) powered by local Gemma 26B LLM via Oobabooga API.

## Key Features

### Adversarial Guardrails (AI Self-Defense)
- **Prompt Injection Detection:** Regex + heuristic scanning of all log fields before LLM ingestion.
- **Semantic Pruning (Drain3):** Compresses thousands of duplicate logs into representative Templates with frequency counts.
- **Token Budgeting:** Hard cap at 4,000 tokens for log data. Automatic Top-K sampling when budget is exceeded.
- **Feature Extraction:** DDoS behavioral summarization (~50 tokens instead of 10,000 raw log lines).
- **Context Overflow Guard:** Prevents VRAM exhaustion by monitoring total prompt + log token count.
- **Entropy Scoring:** Prioritizes logs with high character entropy (likely SQLi/XSS payloads).

### Feedback Loop (Adaptive Defense)
- Agent auto-generates new Tier 1 rules when novel attack patterns are confirmed.
- Rules are persisted to `config/system_settings.yaml` for immediate enforcement.

### Human-in-the-Loop (HITL)
- Streamlit Dashboard with RBAC (L1 Analyst: view-only, L3 Manager: can block IP).
- Agent pauses LangGraph state and awaits human approval for high-impact actions.

### MLOps
- Docker Compose orchestration (UI + MLflow + Redis).
- MLflow experiment tracking for Ablation Studies.
- SQLite Audit Trail for forensic analysis.

## Project Structure

```
sentinel/
├── config/
│   ├── system_settings.yaml          # Central config (LLM, Tier1, Guardrails, RAG, Redis)
│   └── rbac_policies.json            # RBAC roles (L1_Analyst, L3_Manager)
├── data/
│   └── raw/                          # Original CSV datasets only (logs stream directly into RAM via Redis)
├── docs/
│   ├── capstone_proposal.md          # Full thesis proposal
│   ├── architecture.md               # SENTINEL architecture diagram + RQ mapping
│   └── literature_review/            # Literature review notes (20 citations)
├── knowledge_base/
│   ├── mitre_attack.json             # MITRE ATT&CK techniques
│   ├── iso_27001_controls.json       # ISO 27001 controls
│   └── faiss_index/                  # FAISS vector index (generated at runtime)
├── src/
│   ├── streaming/                    # Data Engineering Pipeline
│   │   ├── publisher.py              # CSV → Redis Queue (real-time simulation)
│   │   └── subscriber.py            # Redis → Tier 1 (blocking pop)
│   ├── tier1_filter/                 # Speed Layer
│   │   └── rule_engine.py            # Static + Dynamic rules, Random Sampling
│   ├── guardrails/                   # AI Safety Layer
│   │   ├── prompt_filter.py          # Injection detection, Entropy, Template Mining, Token Budget
│   │   ├── state_monitor.py          # Overflow Guard, Loop Detector, Audit Logger
│   │   └── data_validator.py         # Schema validation, Type coercion
│   ├── rag/                          # Knowledge Retrieval
│   │   ├── embedder.py               # Sentence-Transformers → FAISS indexing
│   │   └── retriever.py              # FAISS search → MITRE/ISO context
│   ├── agent/                        # Reasoning Core (Tier 2)
│   │   ├── state.py                  # LangGraph state schema
│   │   ├── prompts.py                # System/analysis prompt templates
│   │   ├── nodes.py                  # Graph nodes (correlate, analyze, decide)
│   │   └── workflow.py               # LangGraph graph definition & compilation
│   ├── response/                     # Action Execution
│   │   └── executor.py               # Block IP, Alert, Log actions
│   └── ui/                           # HITL Dashboard
│       ├── app.py                    # Streamlit main app
│       ├── auth.py                   # RBAC authentication
│       └── components.py             # Dashboard UI components
├── experiments/
│   ├── evaluate_accuracy.py          # F1, Precision, Recall on 3 datasets
│   ├── evaluate_latency.py           # Reasoning Latency (2-Tier vs 1-Tier)
│   ├── evaluate_guardrails.py        # Defeat Rate (1,000+ adversarial samples)
│   └── baselines/                    # Ablation Study baselines
│       ├── baseline_rule_only.py     # Tier 1 only (no LLM)
│       └── baseline_llm_only.py      # LLM only (no Tier 1)
├── tests/
│   ├── unit/                         # Unit tests per module
│   │   ├── test_prompt_filter.py
│   │   ├── test_data_validator.py
│   │   ├── test_entropy_scorer.py
│   │   └── test_template_miner.py
│   ├── integration/                  # End-to-end pipeline tests
│   │   ├── test_end_to_end.py
│   │   └── test_streaming_pipeline.py
│   ├── test_tier1_filter.py
│   ├── test_adversarial.py
│   └── conftest.py                   # Pytest shared fixtures
├── logs/
│   ├── audit_trail.db                # SQLite audit log
│   └── system_debug.log              # Debug output
├── mlruns/                           # MLflow tracking data
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── bug_report.md
│   └── PULL_REQUEST_TEMPLATE.md
├── .env                              # Environment variables
├── .gitignore
├── .gitattributes
├── requirements.txt
├── Dockerfile
├── docker-compose.yml                # 3 services: agent_ui, mlflow, redis
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── main.py                          # Application entry point
```

## 4D Evaluation Framework

SENTINEL is evaluated across 4 dimensions, not just classification accuracy:

| Dimension | Metric | Tool |
|---|---|---|
| **Classification** | Precision, Recall, F1-Score | MLflow + 3 datasets |
| **Operational** | Reasoning Latency (sec/incident) | 2-Tier vs 1-Tier comparison |
| **Robustness** | Guardrail Defeat Rate | 1,000+ Synthetic Adversarial logs |
| **Context Quality** | RAG Context Relevance, Compression Ratio | Semantic Pruning evaluation |

## Tech Stack

| Layer | Technology |
|---|---|
| LLM | Gemma 26B Q4_K_M (Local, Oobabooga API) |
| Agent Framework | LangGraph |
| RAG | Sentence-Transformers + FAISS |
| Guardrails | Drain3 + Custom Entropy/Token Budget |
| Streaming | Redis |
| Dashboard | Streamlit + streamlit-authenticator |
| MLOps | Docker Compose + MLflow |
| Database | SQLite (Audit Trail) |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# Configure environment
cp .env.example .env  # Edit with your settings

# Start all services
docker-compose up --build

# Access
# UI:     http://localhost:8501
# MLflow: http://localhost:5001
```

## Hardware Requirements

| Component | Minimum |
|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM (or equivalent) |
| RAM | 32GB |
| Storage | 50GB SSD |
| OS | Ubuntu 22.04+ |

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

**Nguyễn Đức Bình** — Master's Thesis in AI & Machine Learning
