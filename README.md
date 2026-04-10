# SENTINEL Framework

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

Autonomous AI Security Agent (IDS/SOAR) utilizing LangGraph, Dual-RAG, and Adversarial Guardrails for real-time multi-source log correlation. Built as a Master's Thesis in AI Security Engineering.

## Architecture Overview

SENTINEL uses a **2-Tier Funneling Architecture** with strict **Separation of Concerns**:

```text
CSV → Data Publisher → Redis → Tier 1 (Baselining+TTL) → Template Miner → Prompt Filter → Semantic Cache → FAISS RAG → Agent(9B) → HITL
                                 │         ▲                (Compression)   (Dyn.Delimiters)  (Cache Hit?)    (Dual-RAG)                 Dashboard
                                 │         └──────────────── Feedback Loop (Dynamic Rules) ◀────────────────────────────┘
                                 ▼
                            DROP (Clean)
```

**Tier 1 (Speed Layer):** Session-Aware Behavioral Baselining + TTL eviction. No random sampling.

**Guardrails (Two separate modules):**

- `template_miner.py` — Volume Compression ONLY (Drain3). Variables preserved.
- `prompt_filter.py` — Injection Defense ONLY (Dynamic Randomized Delimiters).

**Tier 2 (Intelligence Layer):** LangGraph Agent (Gemma 2 9B Q6_K) + Semantic Cache + Dual-RAG (MITRE ATT&CK + ISO 27001). Gemma 26B as Oracle Judge for evaluation.

## Key Features

### Guardrails — Separation of Concerns

**Volume Compression (`template_miner.py`):**
- Drain3 compresses thousands of duplicate logs into Templates + frequency.
- Variables (dynamic params containing attack payloads) are **PRESERVED in raw samples**.
- Purpose: Fit data into Context Window. Does NOT defend against injection.

**Injection Defense (`prompt_filter.py`):**

- **Pattern Detection:** Flags known injection strings. Does NOT redact (preserves evidence).
- **Encoding Neutralization:** Defeats Base64/Hex/Unicode bypass tricks.
- **Dynamic Randomized Delimiters:** Each request generates a new delimiter using `secrets.token_hex()`. Attacker cannot predict the hash → prevents Delimiter Smuggling. Raw data sanitized before encapsulation.

### Session Baselining (replaces Random Sampling)

- Tier 1 maintains behavioral profile per Source IP (request count, unique ports, packet volume).
- Escalates on **statistical deviation**, not random chance.
- 100% of traffic is baselined — APT kill-chain evidence is never destroyed.
- **TTL Eviction:** Inactive IPs auto-purged after 600s — prevents RAM OOM on large datasets.

### Semantic Cache (Embedding Latency Optimization)

- LRU + TTL cache for RAG vector queries. Key = template pattern hash.
- Bypasses embedding + FAISS search for previously-seen attack patterns.
- Expected hit rate: >90% for DDoS, >80% for Brute Force.

### Data Publisher (CSV → Redis)

- **3 timing modes:** `replay` (real-time), `accelerated` (compressed x50), `burst` (max throughput).
- **Chunked reading:** Never loads entire CSV into RAM (5,000 rows/chunk).
- **Backpressure control:** Pauses publishing when Redis queue exceeds depth limit.

### Feedback Loop (Explicit Data Flow)
- `LangGraph Agent` → `feedback_listener.py` → `system_settings.yaml` → `RuleEngine.reload_dynamic_rules()`.
- Agent auto-generates new rules, which are **immediately enforceable** at Tier 1.

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
│   │   ├── rule_engine.py            # Static + Dynamic rules, Random Sampling
│   │   └── feedback_listener.py      # Receives new rules from Agent (Feedback Loop)
│   ├── guardrails/                   # AI Safety Layer
│   │   ├── prompt_filter.py          # Injection detection, Feature Extraction
│   │   ├── template_miner.py         # Log Template Mining + Entropy + Token Budget
│   │   ├── state_monitor.py          # Overflow Guard, Loop Detector, Audit Logger
│   │   └── data_validator.py         # Schema validation, Type coercion
│   ├── rag/                          # Knowledge Retrieval
│   │   ├── embedder.py               # Sentence-Transformers → FAISS indexing
│   │   └── retriever.py              # FAISS search → MITRE/ISO context
│   ├── agent/                        # Reasoning Core (Tier 2)
│   │   ├── state.py                  # LangGraph state schema + Summary Memory
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
│   ├── evaluate_guardrails.py        # Guardrails unit effectiveness
│   ├── evaluate_robustness.py        # Defeat Rate (1,000+ adversarial samples)
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
| LLM (Primary) | Gemma 2 9B Q6_K (~7GB VRAM, Local via Oobabooga API) |
| LLM (Ablation) | Gemma 26B Q4_K_M (optional, for quality comparison) |
| Agent Framework | LangGraph (Structured MemoryObject with IOC Registry) |
| RAG | Sentence-Transformers + FAISS (Dual: MITRE ATT&CK + ISO 27001) |
| Guardrails | Drain3 (compression) + Dynamic Delimiters (injection defense) |
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

| Component | Minimum | VRAM Usage |
|---|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | ~7GB model + ~9GB KV Cache |
| RAM | 32GB | |
| Storage | 50GB SSD | |
| OS | Ubuntu 22.04+ | |

> **Why 9B instead of 26B?** Gemma 26B Q4 uses ~15GB VRAM, leaving only 0.5-1.5GB for KV Cache → CUDA OOM when loading System Prompt + RAG + Memory + Logs simultaneously. Gemma 2 9B Q6 uses ~7GB, leaving 9GB — sufficient for the full SENTINEL pipeline.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

**Nguyễn Đức Bình** — Master's Thesis in AI & Machine Learning
