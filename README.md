# SENTINEL Framework

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

Autonomous AI Security Agent (IDS/SOAR) utilizing LangGraph, Dual-RAG, and Adversarial Guardrails for real-time multi-source log correlation. Built as a Master's Thesis in AI Security Engineering.

## Architecture Overview

SENTINEL uses a **2-Tier Funneling Architecture** with strict **Separation of Concerns**:

```text
CSV → Data Publisher → Redis → Tier 1 (Baselining+TTL) → Template Miner → Prompt Filter → Semantic Cache → FAISS RAG → Agent(9B) → HITL
                                 │         ▲                (Compression)   (Dyn.Delimiters)  (Cache Hit?)    (Dual-RAG)                 Dashboard
                                 │         └──────────────── Feedback Loop (Pending Approval / Quarantine) ◀─────────────────────────────┘
                                 ▼
                            DROP (Clean)
```

**Tier 1 (Speed Layer):** Session-Aware Behavioral Baselining + TTL eviction. 

**Guardrails (Two separate modules):**
- `template_miner.py` — Volume Compression ONLY (Drain3). Variables preserved.
- `prompt_filter.py` — Injection Defense ONLY (Dynamic Randomized Delimiters + Encoding Neutralization).

**Tier 2 (Intelligence Layer):** LangGraph Agent (Gemma 2 9B Q6_K) + Semantic Cache + Dual-RAG (MITRE ATT&CK + ISO 27001). 

## 🛡️ Core Novelty & Defenses

### Delimited Data Encapsulation (Adversarial Defense)
- **Dynamic Randomized Delimiters:** Each request generates a new delimiter using cryptographically secure `secrets.token_hex()`. Prevents *Delimiter Smuggling*.
- **Encoding Neutralization:** Intercepts and decodes Base64/Hex/Unicode before inference.
- **Quantified Limitations:** The Threat Model acknowledges and actively measures the baseline vulnerability against *Semantic Confusion* (an open problem in the field).

### HITL Quarantine (Adversarial Rule Injection Defense)
- Agent auto-generates new rules based on context, but they are placed in **Quarantine (Pending Approval)**.
- Streamlit Dashboard with RBAC securely routes rules to an L3 Manager for approval before hot-reloading into the Tier 1 Rule Engine.
- Prevents the agent from being manipulated into blocking legitimate infrastructure.

## 📊 Evaluation & Methodology

SENTINEL employs a rigorous thesis-grade methodology built for reproducibility and continuous validation.

### 4D Evaluation Framework
| Dimension | Metric | Method / Dataset |
|---|---|---|
| **Classification** | F1, Precision, Recall | CICIDS2017 & UNSW-NB15 across 6 Ablation Configs |
| **Operational** | Reasoning Latency | 2-Tier vs 1-Tier comparison (Mann-Whitney U Test) |
| **Robustness** | Guardrail Defeat Rate | 1,000+ Synthetic Adversarial logs (Structural + Semantic) |
| **Context Quality** | RAG Relevance, MITRE Acc | RAGAS + Gemma 26B Oracle + 30 Ground Truth cases |

### Statistical Validity
All main comparisons are backed by statistical tests to ensure results are not derived from random chance:
- **Paired t-tests / McNemar's tests** for F1-score variance across 6 ablation configurations.
- **Mann-Whitney U tests** for skewed latency distributions.
- **95% Confidence Intervals** for cache hit rates and accuracy mapped via 30 manually labeled reasoning cases.

### Reproducibility Package
This project is engineered for complete scientific reproducibility:
1. `config/ablation/` contains exactly 6 `.yaml` configurations covering the full Ablation Study (from Rule-only to Full-SENTINEL).
2. `experiments/` provides structured Ground Truth sets for validation independent of Circular Model Bias. 
3. Controlled environment orchestration is fully containerized via `docker-compose`.

## 📁 Key Project Structure

```
sentinel/
├── config/
│   ├── system_settings.yaml          # Central config (LLM, Tier1, Guardrails, RAG, Redis)
│   └── ablation/                     # 6 Ablation Study configs (A through F)
├── docs/
│   ├── capstone_proposal.md          # Full thesis proposal
│   ├── literature_review/            # PRISMA-ScR Systematic Review
│   ├── threat_model.md               # Adversary profiles & Defense limit matrix
│   └── REPRODUCIBILITY.md            # Execution framework guidelines
├── experiments/
│   ├── adversarial/                  # ~1000 Independent attack samples
│   ├── baselines/                    # Rule-only and LLM-only runner setups
│   ├── ground_truth.json             # 200 static RAGAS samples
│   ├── reasoning_ground_truth.json   # 30 manually curated MITRE labeled cases
│   ├── ablation_design.md            # Statistical Hypothesis matrix
│   └── vram_benchmark/               # Empirical hardware validation bounds
├── src/
│   ├── streaming/                    # Pipeline: pub/sub architecture
│   ├── tier1_filter/                 # Speed Layer + Feedback Listener & Firewall
│   ├── guardrails/                   # Compression, Validators & Monitor guards
│   ├── rag/                          # Dual-Database Vector retrieval & Cache
│   ├── agent/                        # LangGraph Stateful Reasoning Nodes
│   └── ui/                           # RBAC + Streamlit Dashboard
└── tests/                            # Pytest suites
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# Configure environment
cp .env.example .env  # Edit with your API endpoints if necessary

# Start all core services
docker-compose up --build

# Access
# UI Dashboard: http://localhost:8501
# MLflow Metrics: http://localhost:5001
```

## 💻 Hardware Requirements

| Component | Minimum | VRAM Target Details |
|---|---|---|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | Base Model (~7GB) + Context/KV Cache (~9GB) |
| RAM | 32GB | For streaming cache overhead |
| Storage | 50GB SSD | Dataset caching + DB logging |
| OS | Linux (Ubuntu 22.04+) | - |

> **VRAM Design Consideration**: The system runs Gemma 2 **9B** (Q6_K) instead of 26B, allowing 9GB of safety margin exclusively for KV Cache, avoiding OOM issues observed with deep system prompts + contextual RAG history memory loads on consumer GPU hardware.

## 📝 License & Authorship

MIT License. See [LICENSE](LICENSE) for details.

**Author**: Nguyễn Đức Bình — Master's Candidate in AI & Machine Learning.
