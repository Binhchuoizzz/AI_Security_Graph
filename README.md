# 🛡️ SENTINEL: Cognitive Two-Tier SOC Architecture for Automated Threat Detection & Contextual Response

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Docker: Ready](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)
[![Tests: 15/15 PASS](https://img.shields.io/badge/Validation-15%2F15%20PASS-brightgreen.svg)](experiments/e2e_test_runner.py)
[![LaTeX: Compiled](https://img.shields.io/badge/Thesis-LaTeX%20Compiled-purple.svg)](docs/Thesis/latex/)
[![Slides: 20-Slide Deck](https://img.shields.io/badge/Defense-20--Slide%20Deck-orange.svg)](docs/Thesis/slides/SENTINEL_defense_notebooklm.html)

> **SENTINEL** is a **Cognitive Two-Tier Security Operations Center (SOC) Architecture** designed to resolve the three core bottlenecks of modern automated SOCs: **Alert Fatigue & Latency Crisis**, **SOAR Rigidity & LLM Hallucinations**, and **Adversarial AI Attacks (Prompt Injection / ML Evasion)**.
>
> Operating **100% On-Premises** on a single consumer GPU (NVIDIA RTX 4060 Ti 16GB VRAM), SENTINEL integrates an $\mathcal{O}(1)$ streaming filter (Tier 1), a LightGBM ML Gateway, an ExactMatch Semantic Cache (Tier 1.75), a LangGraph Cognitive Agent (Tier 2), Dual-RAG (FAISS + BM25 RRF), and cryptographic HMAC audit chaining.

---

## 📑 Master's Thesis & Defense Presentation

- 📖 **Vietnamese Thesis (LaTeX PDF):** [`docs/Thesis/latex/thesis_latex_vi/main.pdf`](docs/Thesis/latex/thesis_latex_vi/main.pdf)
- 📖 **English Thesis (LaTeX PDF):** [`docs/Thesis/latex/thesis_latex_en/main.pdf`](docs/Thesis/latex/thesis_latex_en/main.pdf)
- 🖥️ **Interactive Defense Slide Deck:** [`docs/Thesis/slides/SENTINEL_defense_notebooklm.html`](docs/Thesis/slides/SENTINEL_defense_notebooklm.html) *(Press `N` for speaker notes)*
- 🔍 **Audited Metrics Benchmark Reference:** [`experiments/results/thesis_number_audit.json`](experiments/results/thesis_number_audit.json)

---

## 📊 Audited 5D Benchmark Results

Below are the **100% verified, audited empirical results** across all 5 evaluation dimensions (RTX 4060 Ti 16GB VRAM, Local `llama.cpp` CUDA server running `Foundation-Sec-8B-Instruct Q4_K_M`):

| Dimension (5D) | Key Metrics | Audited Value | Scientific Context & Benchmark Baseline |
| :--- | :--- | :--- | :--- |
| **1. Efficiency & Latency** | Offload Rate · Median Latency · ML Throughput | **90.6% – 97.5% · 0.88 ms · 3,452.4 eps** | Offloads 97.5% of noise logs at sub-millisecond median latency (<1ms). LightGBM ML Gate achieves **100.0% Auto-BLOCK Precision** (962/962, 0 FP). |
| **2. AI Security & Integrity** | Prompt Inj. Defense · ML Evasion · HMAC Tamper | **100.0% · 98.75% · 100.0%** | Delimited Nonce Encapsulation blocks 678 hard adversarial samples; HMAC-SHA256 detects 100% log edits, insertions, or deletions. |
| **3. ATT&CK Attribution & RAG** | RAG Recall@3 · RRF Match · Code Hallucination | **93.0% (Recall@3) · 80.0% · 0.0% Bad** | Dual-RAG (FAISS + BM25 RRF $k=60$). Grounding Guardrail intercepted **76 hallucinated `BLOCK_IP` actions** (`bad = 0 / 1,421` code assertions). |
| **4. SOC Triage & HITL Queue** | Analyst Load Reduction · Threat Coverage | **-84.24% Load · 95.0% Threat Coverage** | SOC Analysts only need to inspect the Deferred (`AWAIT_HITL`) queue to catch 95.0% of real attacks, cutting 84.24% of manual review burden. |
| **5. Reasoning & Judge Quality** | MT-Bench Judge · Relevancy Score | **3.78 / 5.0 · 4.52 / 5.0** | Independent cross-family evaluation (`Meta-Llama-3-8B-Instruct` judging `Foundation-Sec-8B`). |

---

## 📐 Architecture Overview

```text
   CSE-CIC-IDS2018 · CSIC 2010 · Real SOC Stream (100k+ events)
                          │
                   [ Redis Streams ]
                          │
   ┌──────────────────────┴──────────────────────┐
   │ TIER 1 — Streaming Rule Engine (O(1)/log)   │
   │ Whitelist (10.0.0.99) → WAF Signatures →    │
   │ Welford Z-score (>3.5σ) → Port Set O(1) →   │
   │ Bounded Cache rep_cache (RAM Protection)    │
   └──────────────────────┬──────────────────────┘
                          │ 90.6% - 97.5% Offload
      ┌────────┬──────────┼──────────┬────────┬──────────┐
    DROP      LOG     BLOCK_IP   AWAIT_HITL  ALERT   ESCALATE
      │                                                 │
   (noise)                        ┌──────────────────────┴──────────┐
                                  │ ML GATEWAY — LightGBM (1M samples)│
                                  │ 3,452 eps · Auto-BLOCK (FP = 0) │
                                  └──────────────────┬──────────────┘
                                                     │ Escalation (~9.4%)
                                  ┌──────────────────┴──────────────┐
                                  │ TIER 1.75 — ExactMatch Cache    │
                                  │ SHA-256 (Payload + Headers)     │
                                  │ 81.33% Hit Rate · 8.9x Speedup  │
                                  └──────────────────┬──────────────┘
                                                     │ Cache Miss (~2.5%)
                                  ┌──────────────────┴──────────────┐
                                  │ GUARDRAILS & NONCE ENCAPSULATION│
                                  │ Delimited Nonce <<<DATA_HASH>>> │
                                  │ 100% Prompt Injection Defense   │
                                  └──────────────────┬──────────────┘
                                                     │
   ┌─────────────────────────────────────────────────┴──────────┐
   │ TIER 2 — LangGraph Cognitive Agent (5 Nodes, 1 GPU 16GB)   │
   │   Foundation-Sec-8B-Instruct Q4_K_M via llama.cpp CUDA   │
   │   Dual-RAG (FAISS + BM25 RRF k=60 · Recall@3 = 93.0%)      │
   │   Threat Memory (SQLite synchronous=NORMAL · APT Linker)   │
   └─────────────────────────────────────────────────┬──────────┘
                                                     │
                                     [ HMAC-SHA256 Audit Chain ]
                                                     │
                        ┌────────────────────────────┼──────────────┐
                      ALERT                     AWAIT_HITL       BLOCK_IP
                        │                            │               │
                  [ Dashboard ] ←────────── [ HITL Queue ] → [ Action Executor ]
                        └────────── Approved? ───────┴───────────────┘
                                             │
                          [ Feedback → Threat Memory IP Reputation ]
```

---

## 🛠️ Core Modules & Stack

| # | Component | Layer | Technology Stack | Key Specification & Performance |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Rule Engine** | Tier 1 | Python + Redis Stream | $\mathcal{O}(1)$ streaming filter + Welford $Z$-score anomaly detection ($Z > 3.5\sigma$). |
| 2 | **ML Gateway** | Tier 1 | LightGBM (`ml_gateway.py`) | Trained on 1M samples; 4-band policy; **3,452.4 eps**; **100.0% Auto-BLOCK Precision**. |
| 3 | **ExactMatch Cache** | Tier 1.75 | SHA-256 + Python Dict | Bypasses LLM for duplicate attacks (**81.33% hit rate**, **8.9x speedup** 9.8ms vs 87.7ms). |
| 4 | **Guardrails & Nonce** | Security | Delimited Nonce + Regex | Encloses untrusted logs in random nonce tags; **100.0% Prompt Injection defense**. |
| 5 | **Dual-RAG** | Tier 2 | FAISS + BM25 + RRF | Hybrid retrieval over 432 STIX MITRE ATT&CK codes (**Recall@3 = 93.0%**). |
| 6 | **Cognitive Agent** | Tier 2 | LangGraph + `Foundation-Sec-8B` | 5-node conditional DAG executing local LLM inference (**7.2GB VRAM**). |
| 7 | **Grounding Guardrail** | Tier 2 | Regex + MITRE Validator | Intercepts hallucinated actions; enforces **0.0% code hallucination rate** (`bad = 0 / 1,421`). |
| 8 | **Threat Memory** | Storage | SQLite (`synchronous=NORMAL`) | Maintains host history & APT links (**No WAL mode** for Docker cross-UID stability). |
| 9 | **HMAC Audit Chain** | Integrity | HMAC-SHA256 | Cryptographic hash chaining ($H_i = \text{HMAC}(D_i \parallel H_{i-1}, K)$); **100% tamper detection**. |
| 10 | **Backpressure Manager**| Infrastructure | Redis Consumer Group | Manages stream ingestion by consumer group **`lag`** via `XREADGROUP` & `XACK`. |
| 11 | **SOC Dashboard** | UI | Streamlit (`src/ui/app.py`) | Real-time funnel visualizer, live log auditor, and **1-Click HITL approval queue**. |

---

## 🚀 Quick Start Guide

Detailed deployment documentation: **[`RUN_PROJECT.md`](docs/Codebase/guides/RUN_PROJECT.md)**.

### 1. Prerequisites & Environment Setup

- **GPU:** NVIDIA RTX 4060 Ti 16GB VRAM (Minimum) / RTX 4090 (Recommended)
- **RAM:** 32 GB RAM
- **OS:** Linux (Ubuntu 22.04 LTS recommended)
- **Storage:** 50 GB SSD space

```bash
# Clone repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# Set up Python virtual environment
python3.10 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Copy configuration
cp .env.example .env

# Build RAG indexes (FAISS + BM25)
python src/rag/embedder.py
```

### 2. Launch Full One-Command System Demo

```bash
./scripts/run_demo.sh
```

Access the Streamlit SOC Dashboard at: **`http://localhost:8501`**

### 3. Run Deterministic E2E & Offline Benchmarks

```bash
# Run 15/15 E2E validation test suite
python experiments/e2e_test_runner.py --offline

# Run Unified Stream Benchmark
python experiments/evaluate_unified_stream.py

# Run Ablation Study
python experiments/run_ablation.py --mode all

# Run Audit Script
python scripts/audit_thesis_numbers.py
```

---

## 📄 License & Academic Attribution

Distributed under the **MIT License** — see [`LICENSE`](LICENSE).

- **Author:** Nguyễn Đức Bình (MSSV: `MSE13183`)
- **Institution:** Master of Software Engineering (MSE) — FSB Institute of Management & Technology, FPT University.
- **Scientific Advisors:** Dr. Bùi Văn Hiệu & Dr. Đặng Văn Hiếu.
