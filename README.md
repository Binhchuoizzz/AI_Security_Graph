# SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

[![CI/CD Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

An advanced Autonomous Security Operations Framework integrating Session-Aware Behavioral Baselining (Tier 1) with an Agentic AI driven by Retrieval-Augmented Generation (RAG) and Long-Term Threat Memory (Tier 2). Built as a Master's Thesis to solve the SOC Alert Fatigue paradox, now upgraded with a **Vulnerability Knowledge Graph (Neo4j)** and **Automated Vulnerability Scanning (Trivy)**.

## Architecture Overview (V2 Hybrid Architecture)

SENTINEL uses a **2-Tier Funneling Architecture** with strict **Separation of Concerns**:

```text
CSV → Data Publisher → Redis → Tier 1 (Baselining+TTL) → Template Miner → Prompt Filter → Semantic Cache → FAISS RAG → Agent(8B/9B) → HITL
                                 │         ▲                (Compression)   (Dyn.Delimiters)  (Cache Hit?)    (Dual-RAG)                  │
                                 │         └──────────────── Feedback Loop (Pending Approval / Quarantine) ◀──────────────────────────────┘
                                 ▼                                                                                                        ▼
                            DROP (Clean)                                                                                              Dashboard
                                 
                                                                                                                ▲
[Trivy Scanner] ───(Scans Infrastructure)───> [Neo4j Knowledge Graph] ◀──(Agent queries graph for context)──────┘
```

### The Core Modules of SENTINEL

| # | Component | Role | Layer | Tech Stack |
|---|---|---|---|---|
| **1** | Rule Engine & Session Baseline | Heuristic filter — DROP 99% noise at wire speed | Tier 1 | Python (RAM) |
| **2** | Vulnerability Scanner | Automated CVE scanning for infrastructure | Tier 1 | Trivy (Subprocess) |
| **3** | `all-MiniLM-L6-v2` | Embedding model — vectorize logs for semantic search | Tier 2 (RAG) | `sentence-transformers` |
| **4** | Knowledge Graph | Stores structural topologies and vulnerabilities | Tier 2 (Memory) | Neo4j Graph DB |
| **5** | LLM Agent | Deep analysis, MITRE mapping, action decisions | Tier 2 (Agent) | LangGraph + Llama-3-8B |

**Tier 1 (Speed Layer):** Session-Aware Behavioral Baselining + TTL eviction + Trivy Vulnerability Assessment.

**Guardrails (Two separate modules):**
- `template_miner.py` — Volume Compression ONLY (Drain3). Variables preserved.
- `prompt_filter.py` — Injection Defense ONLY (Dynamic Randomized Delimiters + Encoding Neutralization).

**Tier 2 (Intelligence Layer):** LangGraph Agent + Semantic Cache + RAG (MITRE ATT&CK + NIST SP 800-61r2) + Neo4j Vulnerability Graph.

## 🛡️ Core Novelty & Defenses

### Delimited Data Encapsulation (Adversarial Defense)
- **Dynamic Randomized Delimiters:** Each request generates a new delimiter using cryptographically secure `secrets.token_hex()`. Prevents *Delimiter Smuggling*.
- **Encoding Neutralization:** Intercepts and decodes Base64/Hex/Unicode before inference.

### HITL Quarantine (Adversarial Rule Injection Defense)
- Agent auto-generates new rules based on context, but they are placed in **Quarantine (Pending Approval)**.
- Streamlit Dashboard with RBAC securely routes rules to an L3 Manager for approval before hot-reloading into the Tier 1 Rule Engine.

### Component-Level Vulnerability Awareness
- Agent correlates active APT attacks with known CVEs stored in **Neo4j**, matching the attacker's target to the system's vulnerable components.

## 📊 Evaluation & Methodology

SENTINEL employs a **5D Evaluation Framework (v2_5D)** — combining statistical tests, operational SOC metrics, cross-family LLM-as-Judge, and deterministic audit scoring.

### 5-Dimensional Evaluation Framework

| Dimension | What it Measures | Method | Script |
| --- | --- | --- | --- |
| **1. Classification** | F1, Precision, Recall, FPR | McNemar's Test (p<0.05) | `run_ablation_study.py` |
| **2. Operational** | MTTD/MTTR Proxy*, HITL Escalation Rate, RAG Hit | Mann-Whitney U Test (p<0.05) | `run_ablation_study.py` |
| **3. Robustness** | Guardrail Defeat Rate per attack category | 45 curated adversarial samples | `evaluate_robustness.py` |
| **4. Context Quality** | Context Precision, Answer Relevancy | **RAGAS-inspired LLM-as-Judge** | `evaluate_reasoning.py` |
| **5. Explainability** | Audit Trail Completeness Rate (deterministic) | Programmatic field presence check | `evaluate_reasoning.py` |

## 📁 Key Project Structure

```
sentinel/
├── config/
│   ├── ablation/                     # 6 YAML configs (A-F) for ablation study
│   └── system_settings.yaml          # Central config (LLM, Tier1, Guardrails, RAG, Redis)
├── data/                             # Trivy outputs, Logs, Datasets (CSE-CIC-IDS2018)
├── demo_outputs/                     # QA Reports, Graph mockups, Pipeline Summaries
├── docs/                             # Architecture diagrams, Threat models, SYNC_REPORT.md
├── experiments/                      # Statistical tests, ground truths, robustness evaluation
├── knowledge_base/                   # MITRE ATT&CK, NIST 800-61r2, FAISS indexes
├── src/
│   ├── streaming/                    # Pipeline: pub/sub architecture (publisher.py, subscriber.py)
│   ├── tier1_filter/                 # Speed Layer + Feedback Listener + Trivy Scanner
│   ├── guardrails/                   # Compression, Validators & Monitor guards
│   ├── rag/                          # Dual-Database Vector retrieval & Neo4j Graph Builder
│   ├── agent/                        # LangGraph Stateful Reasoning Nodes
│   └── ui/                           # RBAC + Streamlit Dashboard
└── tests/                            # 118 Pytest suites (100% Passing Coverage)
```

## 🚀 Quick Start (Production-Ready Demo)

See [RUN_PROJECT.md](RUN_PROJECT.md) for a detailed step-by-step guide with explanations.

### 1. Setup Environment
```bash
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph
cp .env.example .env
# Edit .env to set your LLM_API_BASE and NEO4J_URI
```

### 2. Start Full Infrastructure (Recommended)
This will spin up the Streamlit UI, MLflow, Redis, and ensure the network is securely bridged.
```bash
docker-compose up -d --build
```
- Dashboard: `http://localhost:8501`
- MLflow: `http://localhost:5001`

### 3. Run the Automated Demo Script
This script runs the full E2E pipeline, generating vulnerability graphs, tracking metrics, and outputting to `demo_outputs/`.
```bash
chmod +x demo_script.sh
./demo_script.sh
```

### 4. Or Run Manually via CLI
The project is built with `argparse` for modular execution:
```bash
python main.py --mode scan  # Quét hạ tầng (Trivy + Neo4j)
python main.py --mode server  # Chạy LangGraph Agent lắng nghe Traffic
python main.py --mode full  # Chạy cả 2 chế độ
```

## 💻 Hardware Requirements

| Component | Minimum | Details |
|---|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | Llama-3-8B (~7GB) + KV Cache (~9GB) |
| RAM | 32GB | For streaming cache overhead & Neo4j |
| OS | Linux (Ubuntu 22.04+) | - |

## 📝 License & Authorship

MIT License. See [LICENSE](LICENSE) for details.

**Author**: Nguyễn Đức Bình — Master's Candidate in AI & Machine Learning.
