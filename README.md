# 🛡️ SENTINEL: Cognitive Two-Tier SOC Architecture for Automated Threat Detection & Contextual Response

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Docker: Ready](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)
[![CI Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml)
[![Tests: 582](https://img.shields.io/badge/pytest-582%20collected-brightgreen.svg)](tests/)
[![Thesis: 40pp EN+VI](https://img.shields.io/badge/Thesis-40pp%20EN%20%2B%20VI-purple.svg)](docs/Thesis/latex/)
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
| **1. Efficiency & Latency** | Offload Rate · Median Latency · ML Throughput | **97.5% · 0.88 ms · 3,452 eps** | Offloads 97.5% of traffic at sub-millisecond median latency, measured on a 99,717-event stream at a **9.8% attack base rate** (the same system offloads 90.6% at a 31.56% base rate — offload is a property of the mix, not a constant). LightGBM ML Gate achieves **100.0% Auto-BLOCK Precision** (962/962, 0 FP). |
| **2. AI Security & Integrity** | Prompt Inj. Defense · ML Evasion · HMAC Tamper | **100.0% · 98.75% · 100.0%** | Delimited Nonce Encapsulation blocks 678 hard adversarial samples; HMAC-SHA256 detects 100% log edits, insertions, or deletions. |
| **3. ATT&CK Attribution & RAG** | Attribution (retrieval-only · full pipeline) · Code Hallucination | **80.0% · 68.0% · 0 / 1,421 unanchored** | Dual-RAG (FAISS + BM25 RRF $k=60$) over 433 STIX ATT&CK entries. Attribution is **worse with the reasoning tier than without it** — reported as a limitation, not a win. Grounding guardrail fired on 9.26% of batches and blocked **76 ungroundable `BLOCK_IP` actions**. |
| **4. SOC Triage & HITL Queue** | Analyst Load Reduction · Threat Coverage | **-84.24% Load · 95.0% Threat Coverage** | SOC Analysts only need to inspect the Deferred (`AWAIT_HITL`) queue to catch 95.0% of real attacks, cutting 84.24% of manual review burden (6.03× enrichment into 15.76% of volume). |
| **5. Reasoning & Judge Quality** | Mean · best axis · worst axis | **3.78 / 5.0 · Relevancy 4.52 · Ctx-Precision 2.54** | Cross-family LLM-as-judge (`Meta-Llama-3-8B-Instruct` judging `Foundation-Sec-8B-Instruct`), n = 1,052 batches. Only **11.2%** of justifications cite a checkable log value — the weakest link in the system. |

---

## 📐 Architecture Overview

```text
   CSE-CIC-IDS2018 · CSIC 2010 · DAPT2020 · Demo Stream (496,885 events)
                          │
                   [ Redis Streams ]
                          │
   ┌──────────────────────┴──────────────────────┐
   │ TIER 1 — Streaming Rule Engine (O(1)/log)   │
   │ Whitelist (10.0.0.99) → WAF Signatures →    │
   │ Welford Z-score (>3.5σ) → Port Set O(1) →   │
   │ Bounded Cache rep_cache (RAM Protection)    │
   └──────────────────────┬──────────────────────┘
                          │ Offload (97.5% @ 9.8% base rate)
      ┌────────┬──────────┼──────────┬────────┬──────────┐
    DROP      LOG     BLOCK_IP   AWAIT_HITL  ALERT   ESCALATE
      │                                                 │
   (noise)                        ┌──────────────────────┴──────────┐
                                  │ ML GATEWAY — LightGBM, 76 feats │
                                  │ 949,535 rows · 3,452 eps · 0 FP │
                                  └──────────────────┬──────────────┘
                                                     │ ESCALATE band (0.65-0.85)
                                  ┌──────────────────┴──────────────┐
                                  │ TIER 1.75 — ExactMatch Cache    │
                                  │ SHA-256 (Payload + Headers)     │
                                  │ 81.3% Hit Rate · 8.9x Speedup   │
                                  └──────────────────┬──────────────┘
                                                     │ Cache miss → 2.5% of stream
                                  ┌──────────────────┴──────────────┐
                                  │ GUARDRAILS & NONCE ENCAPSULATION│
                                  │ Delimited Nonce <<<DATA_HASH>>> │
                                  │ 100% Prompt Injection Defense   │
                                  └──────────────────┬──────────────┘
                                                     │
   ┌─────────────────────────────────────────────────┴──────────┐
   │ TIER 2 — LangGraph Cognitive Agent (6 Nodes, 1 GPU 16GB)   │
   │   Foundation-Sec-8B-Instruct Q4_K_M via llama.cpp CUDA     │
   │   Dual-RAG (FAISS + BM25 RRF k=60 · 433 ATT&CK entries)    │
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
| 2 | **ML Gateway** | Tier 1 | LightGBM (`ml_gateway.py`) | Trained on 949,535 NetFlow rows; **76 features**; 4-band policy; **3,452 eps**; **100.0% Auto-BLOCK Precision**. |
| 3 | **ExactMatch Cache** | Tier 1.75 | SHA-256 + Python Dict | Bypasses LLM for duplicate attacks (**81.3% hit rate**, **8.9x speedup** 9.8ms vs 87.7ms). |
| 4 | **Guardrails & Nonce** | Security | Delimited Nonce + Regex | Encloses untrusted logs in random nonce tags; **100.0% Prompt Injection defense**. |
| 5 | **Dual-RAG** | Tier 2 | FAISS + BM25 + RRF | Hybrid retrieval over 433 STIX MITRE ATT&CK entries (**Recall@3 = 0.930 ceiling · 0.385 on the full slice**). |
| 6 | **Cognitive Agent** | Tier 2 | LangGraph + `Foundation-Sec-8B-Instruct` | 6-node conditional DAG (`guardrails → rag_context → llm_triage → attack_mapper → action_executor / human_in_the_loop`); 4.6GB weights, **7–8GB VRAM** loaded. |
| 7 | **Grounding Guardrail** | Tier 2 | Regex + MITRE Validator | Intercepts hallucinated actions; enforces **0.0% code hallucination rate** (`bad = 0 / 1,421`). |
| 8 | **Threat Memory** | Storage | SQLite (`synchronous=NORMAL`) | Maintains host history & APT links (**No WAL mode** for Docker cross-UID stability). |
| 9 | **HMAC Audit Chain** | Integrity | HMAC-SHA256 | Cryptographic hash chaining ($H_i = \text{HMAC}(D_i \parallel H_{i-1}, K)$); **100% tamper detection**. |
| 10 | **Backpressure Manager** | Infrastructure | Redis Consumer Group | Manages stream ingestion by consumer group **`lag`** via `XREADGROUP` & `XACK`. |
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
python -m src.rag.embedder
```

### 2. Build the Demo Stream, Then Launch

`data/demo.json` is ~830 MB and is **not tracked in git**. Build it first — order matters,
because `build_demo.py` reads `data/csic.json`; reversing the two silently produces a stream
with **zero CSIC records** and no application-layer evidence at all.

```bash
python scripts/build_csic_dataset.py --limit 36000   # ~1 min
python scripts/build_demo.py                         # ~4 min, ~4 GB RAM
./scripts/run_demo.sh --fresh
```

Access the Streamlit SOC Dashboard at: **`http://localhost:8501`** (login `manager`).
Use `--small` for a ~10,000-event stratified subset if you want the UI populated in minutes.

**Demo stream composition** — 496,885 events, 100% real records, 5.24% attack / 94.76% benign,
24 distinct attack classes, 9 multi-day APT chains:

| Source | Events | Attacks | Role |
| :--- | ---: | ---: | :--- |
| CSE-CIC-IDS2018 NetFlow (10 days) | 456,849 | 6,304 | Benign-heavy volume base, resolved at Tier 1 |
| CSIC 2010 HTTP payloads | 36,000 | 18,000 | Application-layer evidence — the only source that can score attribution |
| DAPT2020 (volume + real chains) | 1,902 | 669 | Multi-day kill-chain correlation |
| `ground_truth` slice | 1,250 | 1,170 | Covers all 15 labelled CICIDS classes |
| Prompt injection + jailbreak | 730 | 730 | deepset + jackhhao public corpora (AML.T0051) |
| Zero-day probes + OWASP | 154 | 154 | Signature-less, caught by Welford |

Both application-layer sources are at their **hard ceiling**: CSIC 2010 has 36,000 normal /
25,065 anomalous requests left, and the injection corpora hold exactly 730 unique samples
which `_build_adv_llm` does not repeat. Full details in
[`RUN_PROJECT.md`](docs/Codebase/guides/RUN_PROJECT.md).

### 3. Run Deterministic E2E & Offline Benchmarks

```bash
# Unit + integration suite (582 tests).
# SENTINEL_FREEZE_DYNAMIC_RULES=1 is REQUIRED: without it the run writes ~1,400
# learned rules into config/system_settings.yaml and dirties your working tree.
SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest

# E2E validation harness (functional pass/fail checks, not metrics)
python experiments/e2e_test_runner.py --offline

# Unified Stream Benchmark
python experiments/evaluate_unified_stream.py

# Ablation Study (action-based scoring; the binary metric saturates at an
# 86.9% attack base rate and cannot separate configurations)
python experiments/run_ablation.py --mode all
```

Integration tests that need `data/csic.json` **skip** rather than fail when the dataset
has not been built — the source corpora are too large to track in git. Build it first if
you want them to run: `python scripts/build_csic_dataset.py --limit 36000`.

### 4. Verify Every Number Before Trusting It

Three audits keep the thesis and the code from drifting apart. All three must be green:

```bash
python scripts/audit_thesis_numbers.py       # 134 phép đối chiếu ⇄ tệp kết quả, gương EN↔VI
python scripts/audit_thesis_refs.py          # 41 mục tài liệu, thứ tự IEEE, nguồn dữ liệu
python scripts/audit_metric_denominators.py  # mẫu số & chỉ số bão hoà (4 cờ có chủ đích)
```

---

## 📄 License & Academic Attribution

Distributed under the **MIT License** — see [`LICENSE`](LICENSE).

- **Author:** Nguyễn Đức Bình (MSSV: `MSE13183`)
- **Institution:** Master of Software Engineering (MSE) — FSB Institute of Management & Technology, FPT University.
- **Scientific Advisors:** Dr. Bùi Văn Hiệu & Dr. Đặng Văn Hiếu.
