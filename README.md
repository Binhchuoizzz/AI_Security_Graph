# SENTINEL Framework

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

Autonomous AI Security Agent (IDS/SOAR) utilizing LangGraph, Dual-RAG, and Adversarial Guardrails for real-time multi-source log correlation. Built as a Master's Thesis in AI Security Engineering.

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
| **3** | `Gemma 2 9B Q6_K` | Reasoning LLM — deep analysis, MITRE mapping, action decisions | Tier 2 (Agent) | Oobabooga WebUI (`localhost:5000`) |

**Tier 1 (Speed Layer):** Session-Aware Behavioral Baselining + TTL eviction.

**Guardrails (Two separate modules):**
- `template_miner.py` — Volume Compression ONLY (Drain3). Variables preserved.
- `prompt_filter.py` — Injection Defense ONLY (Dynamic Randomized Delimiters + Encoding Neutralization).

**Tier 2 (Intelligence Layer):** LangGraph Agent (Gemma 2 9B Q6_K) + Semantic Cache + Dual-RAG (MITRE ATT&CK + ISO 27001).

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

SENTINEL employs a **Dual Evaluation Methodology** — combining statistical tests with cross-family LLM-as-Judge — for thesis-grade rigor.

### Dual Evaluation Framework
| Dimension | What it Measures | Method |
| --- | --- | --- |
| **Classification Accuracy** | Does the system correctly detect attacks? | F1, Precision, Recall + McNemar's Test (p<0.05) |
| **Operational Performance** | How fast is the 2-Tier vs 1-Tier? | Latency + Mann-Whitney U Test (p<0.05) |
| **Robustness** | Can adversaries fool the guardrails? | 45 curated adversarial samples |
| **Reasoning Quality** | Does the LLM reason intelligently? | **Cross-Family LLM-as-Judge** (Llama 3 judges Gemma 9B) |

### Why Dual? (Addressing Zheng et al., 2023)
- **Statistical Tests** (F1, McNemar) measure **classification performance** — did the system make the right BLOCK/LOG decision?
- **LLM-as-Judge** measures **reasoning quality** — did the LLM identify the correct MITRE technique, provide coherent analysis, and use RAG context effectively?
- Using **Llama 3 (Meta)** to judge **Gemma 9B (Google)** eliminates Self-Enhancement Bias (different model family, different training data).
- Neither method alone is sufficient; together they provide comprehensive evaluation.

### Statistical Validity
- **McNemar's Test** for classification accuracy comparison between Config A and Config F.
- **Mann-Whitney U Test** for skewed latency distributions.
- **Test Coverage**: **79/79** unit and integration tests passed in 0.17s.

### Reproducibility Package
This project is engineered for complete scientific reproducibility:
1. `experiments/run_ablation_study.py` — Automated ablation comparing Rule-only vs Full SENTINEL.
2. `experiments/statistical_tests.py` — Automated p-value computation (McNemar + Mann-Whitney U).
3. `experiments/ground_truth.json` — 101 labeled samples for validation.
4. Controlled environment orchestration is fully containerized via `docker-compose`.

## 📁 Key Project Structure

```
sentinel/
├── config/
│   └── system_settings.yaml          # Central config (LLM, Tier1, Guardrails, RAG, Redis)
├── docs/
│   ├── capstone_proposal.md          # Full thesis proposal
│   ├── architecture.md               # System architecture diagram
│   ├── threat_model.md               # Adversary profiles & Defense limit matrix
│   └── REPRODUCIBILITY.md            # Execution framework guidelines
├── experiments/
│   ├── adversarial/                  # 45 Curated attack samples (Structural, Encoding, Semantic)
│   ├── ground_truth.json             # 101 labeled samples for Ablation Study
│   ├── run_ablation_study.py         # Automated Config A vs Config F evaluation
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

# 3. Ensure Oobabooga is running at http://localhost:5000 with Gemma 9B loaded

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
