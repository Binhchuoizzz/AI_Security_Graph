# SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

[![CI/CD Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

SENTINEL is an enterprise-grade Cognitive Two-Tier Architecture designed for Security Operations Center (SOC) automation. It addresses the **SOC Alert Fatigue Paradox** by combining real-time, low-latency heuristic filtering at Tier 1 with an advanced Agentic AI reasoning pipeline driven by Dual-RAG, Threat Memory, and graph correlation at Tier 2.

---

## 📐 Architecture Overview

SENTINEL operates on a strict **Separation of Concerns** model to minimize processing latency while maintaining deep cognitive analytical capabilities:

```text
                     CSE-CIC-IDS2018 / DAPT2020 / Syslogs
                                     │
                               [ Redis Stream ]
                                     │
    ┌────────────────────────────────┴────────────────────────────────┐
    │ TIER 1 - Stateful/Stateless Rule Engine & Unsupervised Anomaly  │
    │          Detection (Welford's Algorithm - Outliers Z-Score > 3.5)│
    └────────────────────────────────┬────────────────────────────────┘
                                     ├─ Benign (F1=1.0) ──> [ DROP ] (Noise Reduction)
                                     └─ Anomalous / Escalated
                                             │
    ┌────────────────────────────────────────┴────────────────────────────────┐
    │ GUARDRAILS & PRE-PROCESSING LAYER                                       │
    │  1. Nonce-based Delimited Data Encapsulation (Anti Prompt-Injection)   │
    │  2. Encoding Neutralization (URL, Base64, Hex decoding & sanitization)  │
    │  3. Jailbreak & DAN Detector (Critical isolation)                       │
    │  4. Drain3 Log Template Miner (Token compression)                       │
    │  5. Decision Validator + Tier-Consensus Guard (anti social-eng)        │
    └────────────────────────────────────────┬────────────────────────────────┘
                                             │
    ┌────────────────────────────────────────┴────────────────────────────────┐
    │ TIER 2 - LangGraph Agentic Reasoning (Gemma-2-9B-IT via llama.cpp)      │
    └────────────────────┬────────────────────────────────┬───────────────────┘
                         │                                │
        ┌────────────────┴────────────────┐      ┌────────┴────────┐
        │     Dual-RAG Knowledge Retrieval│      │  Threat Memory  │
        │ - MITRE ATT&CK (TTP mapping)    │      │ - SQLite Store  │
        │ - NIST SP 800-61r2 (Playbooks)  │      │ - APT Linker    │
        │ - FAISS + BM25 Hybrid Search   │      └────────┬────────┘
        └────────────────┬────────────────┘               │
                         └────────────────┬───────────────┘
                                          │
                                [ LangGraph Workflow ]
                                 (Few-shot Active Learning)
                                          │
                        ┌─────────────────┼─────────────────┐
                  (Decision: ALERT) (Decision: AWAIT_HITL) (Decision: BLOCK_IP)
                        │                 │                 │
                  [ Dashboard ]     [ HITL Queue ]    [ Response Executor ]
                        │                 │                 │
                        └───────── Approved? ───────────────┘
                                          │
                                   [ Feedback Loop ]
                                          │
                       (Dynamic Rules & Human-in-the-Loop FPR)
                                          │
                                     [ Tier 1 ]
```

### Core Architecture Modules

| ID | Component | Layer | Technology Stack | Core Role |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Rule Engine & Unsupervised Detector** | Tier 1 | Python + Redis | Stateless/stateful filtering + online Welford statistics checking for statistical zero-day anomalies. |
| **2** | **Guardrails Defenses** | Pre/Post-processing | Regex + Delimiter Encapsulation | Delimited Data Encapsulation, Encoding Neutralization, Jailbreak defense, Output Sanitizer, and the Tier-Consensus decision guard. |
| **3** | **Drain3 Template Miner** | Pre-processing | Python Drain3 | Compresses high-volume syslog and network stream tokens before LLM input. |
| **4** | **Dual-RAG Hybrid Search** | Tier 2 (RAG) | FAISS + BM25 + RRF | Fetches context from MITRE ATT&CK and NIST SP 800-61r2 using hybrid indexes. |
| **5** | **LangGraph Agent** | Tier 2 (Reasoning) | LangGraph + Gemma-2-9B-IT | Orchestrates cognitive threat analysis, TTP mapping, and mitigation actions with few-shot learning. |
| **6** | **Threat Memory** | Tier 2 (Memory) | SQLite + Correlation Engine | Tracks long-term host behaviors, correlating multi-day APT attack chains (DAPT2020). |
| **7** | **HMAC Log Chaining** | Integrity | SQLite + HMAC SHA-256 | Cryptographically chains audit logs. Automatically flags DB tampering. |
| **8** | Persist Lockout & Live FPR | Auth / Admin | SQLite + Streamlit UI | Real-time false positive metrics + brute-force protection (max 5 attempts, lockout). |
| **9** | **Trivy & Neo4j KB Graph** | Vulnerability | Neo4j + Trivy + Graphviz | Scans system files and links vulnerabilities into an interactive threat knowledge graph. |
| **10**| **HITL Streamlit Dashboard** | UI/UX | Streamlit + Glassmorphism | SOC Operator control panel, live monitoring, log auditor, and whitelist controls. |

---

## 🛡️ Core Security Novelty & Defensive Controls

SENTINEL implements defense-in-depth, protecting both the protected infrastructure and the AI system itself from adversarial threats:

### 1. Adversarial AI Protection (LLM Guardrails)
* **Delimited Data Encapsulation:** Wraps raw log payloads in dynamic, single-use cryptographic delimiters (`secrets.token_hex(8)`, a fresh nonce per encapsulator instance) to isolate instruction from data. Strips any nested delimiter tokens in raw inputs to prevent **Delimiter Smuggling**.
* **Encoding Neutralizer:** Decodes and sanitizes Base64, Hex, URL, and Unicode homoglyph payloads prior to analysis, neutralising obfuscation bypass techniques.
* **Jailbreak Detection:** Real-time analysis of incoming payloads against signature-based and semantic patterns associated with "Do-Anything-Now" (DAN) roleplay-based attacks.
* **Tier-1 Injection/Jailbreak Pre-screen:** The Tier-1 rule engine signature-matches the *same* `injection_patterns`/`jailbreak_patterns` set used by the Guardrails layer (single source of truth, hot-reloadable). Matches add risk score and `ESCALATE` the event into Tier-2 Guardrails instead of being silently dropped.
* **Tier-1/Tier-2 Decision Consensus Guard:** Defends against **semantic social-engineering** (forged authority / "already-approved" claims embedded in logs). If the deterministic Tier-1 engine flagged an event as an attack but the LLM tries to downgrade it to `LOG`/`DROP`, the validator overrides the decision to `AWAIT_HITL` — the deterministic tier cannot be "talked down" the way an LLM can.
* **Output Sanitizer:** Prevents **Indirect Prompt Injection (Data Exfiltration)** by stripping markdown image links (`![](...)`), malicious HTML/JavaScript tags, and deep Base64/Hex-obfuscated payloads generated by the LLM before they reach the operator UI or the database.

### 2. Infrastructure & Audit Trail Hardening
* **Cryptographic Audit Trail (HMAC Log Chaining):** Response-executor logs written to `config/audit_trail.db` are chained using HMAC-SHA-256 (like a private blockchain). The hash of each log entry depends on the hash of the preceding entry. Any database modification by an intruder breaks the chain and triggers an alert. *(This is distinct from the research-metadata store `logs/guardrails_audit.db` used by the runtime state monitor.)*
* **Persistent Lockout & Lockout Auto-Reset:** Protection against credential brute-forcing stored in SQLite (resistant to session clearing or private window bypass). Once the lockout duration expires, the system automatically resets attempts to `0` for seamless usability.
* **Clickjacking & CSRF Prevention:** Streamlit configuration hardened with `enableCORS = false`, `enableXsrfProtection = true`, and `frameAncestors = ["'none'"]` to prevent unauthorized iframe embedding.

### 3. Vulnerability Management & RAG Integrity
* **RAG Document Checksum Auditor:** Dynamically validates the integrity of raw MITRE ATT&CK and NIST SP 800-61r2 sources using SHA-256 hashing. Prevents document poisoning attacks.
* **Trivy static scan & Neo4j graph representation:** Runs automated container scans on requirements/Dockerfiles, populating a Neo4j Graph DB and visualising structural vulnerabilities dynamically in the UI.

---

## 📊 5-Dimensional Evaluation Framework (5D-EF)

SENTINEL is systematically benchmarked across five analytical axes:

| Axis | Metric / Target | Statistical Evaluation | Verification Script |
| :--- | :--- | :--- | :--- |
| **1. Classification** | F1-Score $\ge 0.90$ (Triage accuracy) | McNemar's Test ($p < 0.05$) | `experiments/run_ablation_study.py` |
| **2. Operational** | Latency Reduction $\ge 60\%$ (Tier 1 filter rate)| Mann-Whitney U Test ($p < 0.05$) | `experiments/measure_latency_baseline.py` |
| **3. Robustness** | Guardrail Bypass Rate $< 10\%$ | 120-sample Adversarial Suite (6 categories) | `evaluate_robustness.py` (static) + `evaluate_adversarial_pipeline.py` (full LLM) |
| **4. Context Quality**| Context Relevance $\ge 0.85$ (RAG context) | LLM-as-a-Judge (Llama 3 8B) | `experiments/evaluate_reasoning.py` |
| **5. Explainability**| Completeness Index $= 100\%$ (Audit Trail) | Deterministic schema checks | `experiments/evaluate_reasoning.py` |

---

## 📂 Datasets

* **CSE-CIC-IDS2018:** Millions of rows of network traffic capturing **14 distinct attack classes** (SSH/FTP brute-force, DoS/DDoS families, Web attacks, Botnet, Infiltration, etc.). Cleaned + stratified-sampled into a **4,267-sample labelled benchmark** (`ground_truth.json`) used to score Tier-1 filtering.
* **DAPT2020:** A multi-day Advanced Persistent Threat (APT) dataset spanning 5 phases (Reconnaissance → Establish Foothold → Lateral Movement → Data Exfiltration). The pipeline correlates per-attacker events into multi-day APT chains (**9 chains / 402 events, 324 malicious**) that feed the SQLite Threat Memory.
* **Adversarial Suite:** **120 curated attack vectors** across 5 generated categories (`encoding_bypass` 45, `structural_attacks` 20, `semantic_confusion` 20, `jailbreak` 20, `rag_poisoning` 15) for Guardrails robustness benchmarking. A 6th category, `rule_injection`, is scaffolded (design README) but not yet generated.
* **MITRE ATT&CK & NIST SP 800-61r2:** Curated textual databases indexed into FAISS vector indexes and BM25 lexicons for hybrid semantic search.

---

## 📁 Directory Structure

```text
AI_Security_Graph/
├── config/
│   ├── ablation/                     # 6 configuration files (A-F) for Ablation studies
│   ├── system_settings.yaml          # Core configuration file (Tier 1 thresholds, DB locations)
│   ├── audit_trail.db                # SQLite audit trail DB (auto-generated)
│   └── threat_memory.db              # SQLite threat memory DB (auto-generated)
├── data/
│   ├── raw/cicids2018/               # Network traffic CSV captures
│   ├── raw/dapt2020/                 # Day-by-day APT events
│   ├── knowledge/                    # Source PDF/TXT playbooks for RAG
│   └── processed/                    # Structured APT chains
├── experiments/
│   ├── adversarial/                  # 120-sample suite across 6 attack categories
│   ├── ground_truth.json             # 4,267-sample labelled benchmark (14 classes + benign + adversarial)
│   ├── adversarial_samples.json      # 50 adversarial vectors (25 structural + 25 semantic)
│   ├── run_ablation_study.py         # Runs ablation tests across A-F configs
│   ├── evaluate_robustness.py        # Static Guardrails bypass benchmark
│   ├── evaluate_adversarial_pipeline.py # Full-LLM-pipeline adversarial resistance test
│   ├── evaluate_reasoning.py         # Runs LLM-as-a-Judge evaluation (Llama 3)
│   ├── evaluate_zeroday.py           # Simulates and evaluates Zero-Day outlier threats
│   ├── measure_latency_baseline.py   # Latency comparison (Tier 1 vs Tier 2 bypass)
│   ├── statistical_tests.py          # McNemar / Mann-Whitney U significance tests
│   └── e2e_test_runner.py            # Automated E2E integration test suite
├── knowledge_base/
│   ├── mitre_attack.json             # Structured MITRE TTPs
│   ├── nist_800_61r2.json            # Structured NIST incident response playbooks
│   └── faiss_index/                  # Embedded FAISS and BM25 vector indexes
├── reports/
│   ├── test_report_FINAL.md          # E2E 20/20 PASS verification report
│   └── zeroday_evaluation_report.md  # Zero-Day threat detection evaluation report
├── scripts/
│   └── switch_model.sh               # Utility script to hot-swap LLM models in Docker
├── src/
│   ├── streaming/                    # Publisher/Subscriber message broker (Redis Streams)
│   ├── tier1_filter/                 # Rule engine, session monitor & feedback logic
│   ├── guardrails/                   # Prompt-injection, jailbreak, & XSS sanitization
│   ├── rag/                          # Embedders, FAISS database client, RAG caching
│   ├── agent/                        # LangGraph workflow engine, agent states, LLM APIs
│   ├── response/                     # Action executor, DB client, lockout, & HMAC log signer
│   └── ui/                           # Glassmorphism Streamlit UI & authentication logic
├── tests/
│   ├── unit/                         # Pytest unit tests
│   └── integration/                  # End-to-end flow tests
├── main.py                           # Application CLI entrypoint
├── requirements.txt                  # Python dependencies
├── Dockerfile                        # Application containerization
└── docker-compose.yml                # Microservices orchestration (Neo4j, Redis, MLflow, LLM)
```

---

## 🚀 Quick Start

For detailed step-by-step instructions on deploying the full stack, please consult [RUN_PROJECT.md](RUN_PROJECT.md).

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# Create and activate a Python 3.10 virtual environment
python3.10 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# drain3 is installed separately: its metadata pins an old cachetools (4.2.1),
# but it works fine with the modern one, so install it without dependencies.
pip install drain3==0.9.11 --no-deps && pip install "jsonpickle>=1.5.1"

# Configure environment variables
cp .env.example .env
```

**Note (VS Code Interpreter):** To avoid linter errors in VS Code (unresolved imports due to lack of virtual environment paths), configure your workspace settings in `.vscode/settings.json`:
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.analysis.extraPaths": ["${workspaceFolder}"]
}
```

### 2. Initialize RAG Vectors & Checksums
Before running tests or deploying, you must initialize the hybrid RAG indexes (FAISS and BM25) and calculate document integrity checksums to prevent validation integrity audit failures:
```bash
python src/rag/embedder.py
```

### 3. Run E2E Integration Suite (Offline Mode)
```bash
python experiments/e2e_test_runner.py --offline
```

### 4. Deploy Infrastructure & Start Server
```bash
# Spin up Neo4j, Redis, MLflow and llama.cpp CUDA server
docker-compose up -d

# Start the SENTINEL streaming subscriber
python main.py --mode server
```

### 5. Launch the SOC Dashboard
```bash
streamlit run src/ui/app.py
```

### 6. (Optional) Hot-Swap the LLM
The reasoning Agent runs **Gemma-2-9B-IT** by default; the 5D-EF *Context Quality* axis uses **Meta-Llama-3-8B-Instruct** as an independent LLM-as-a-Judge. Switch the model served by llama.cpp without rebuilding:
```bash
# scripts/switch_model.sh [gemma | llama | <model_file.gguf>]
./scripts/switch_model.sh llama     # swap to the Llama-3 judge model
./scripts/switch_model.sh gemma     # swap back to the Gemma reasoning model
```

---

## 💻 System & Hardware Requirements

* **GPU:** Nvidia RTX 4060 Ti 16GB VRAM (minimum) / RTX 4090 (recommended) for hosting the quantized Gemma-2-9B-IT model.
* **RAM:** 32 GB.
* **OS:** Linux (Ubuntu 22.04 LTS or newer).
* **Storage:** 50 GB SSD storage.

---

## 📄 License & Authorship

Distributed under the MIT License. See `LICENSE` for details.

* **Author:** Nguyễn Đức Bình
* **Academic Context:** Master's Thesis — AI & Machine Learning Specialization.
