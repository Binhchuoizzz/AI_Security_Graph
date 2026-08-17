# 🛡️ SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Docker: Ready](https://img.shields.io/badge/Docker-Compose-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](docker-compose.yml)
[![CI Pipeline](https://img.shields.io/badge/CI-Passing-success.svg?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Security Audit](https://img.shields.io/badge/Security-Audit%20Passed-059669.svg?style=flat-square&logo=shield&logoColor=white)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml)
[![Tests: 609](https://img.shields.io/badge/pytest-609%20passed-brightgreen.svg?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![Thesis: 40pp EN+VI](https://img.shields.io/badge/Thesis-40pp%20EN%20%2B%20VI-7C3AED.svg?style=flat-square&logo=latex&logoColor=white)](docs/Thesis/latex/)
[![Slides: 20-Slide Deck](https://img.shields.io/badge/Defense-20--Slide%20Deck-EA580C.svg?style=flat-square&logo=revealdotjs&logoColor=white)](docs/Thesis/slides/index.html)

</div>

> [!NOTE]
> **SENTINEL** is a **Cognitive Two-Tier Security Operations Center (SOC) Architecture** designed to resolve the three core bottlenecks of modern automated SOCs:
> 1. **Alert Fatigue & Latency Crisis** (handled by Tier 1 $\mathcal{O}(1)$ stream filtering + LightGBM ML Gateway).
> 2. **SOAR Rigidity & LLM Hallucinations** (handled by Tier 2 LangGraph Multi-Agent + Dual-RAG grounding).
> 3. **Adversarial AI Attacks** (handled by Delimited Nonce Encapsulation, Anti-Evasion Z-score gating, and HMAC-SHA256 audit chaining).
>
> Operating **100% On-Premises** on a single consumer GPU (**NVIDIA RTX 4060 Ti 16GB VRAM**), SENTINEL integrates an $\mathcal{O}(1)$ streaming filter (Tier 1), a LightGBM ML Gateway, an ExactMatch Semantic Cache (Tier 1.75), a LangGraph Cognitive Agent (Tier 2), Dual-RAG (FAISS + BM25 RRF), and cryptographic HMAC audit chaining.

---

## 📑 Table of Contents

- [📑 Master's Thesis & Defense Presentation](#-masters-thesis--defense-presentation)
- [📊 Audited 5D Benchmark Results](#-audited-5d-benchmark-results)
- [📐 Architecture Overview](#-architecture-overview)
- [🛠️ Core Modules & Stack](#️-core-modules--stack)
- [🚀 Quick Start Guide](#-quick-start-guide)
  - [1. Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
  - [2. Build Demo Stream & Launch](#2-build-the-demo-stream-then-launch)
  - [3. Deterministic E2E & Offline Benchmarks](#3-run-deterministic-e2e--offline-benchmarks)
  - [4. Number & Metric Audit Verification](#4-verify-every-number-before-trusting-it)
- [📄 License & Academic Attribution](#-license--academic-attribution)

---

## 📑 Master's Thesis & Defense Presentation

| Artifact | Language / Type | Direct Link | Description |
| :--- | :--- | :--- | :--- |
| **Official Submission PDF** | Vietnamese / English | [`docs/Thesis/MSE23HN_NguyenDucBinh_24MSE13183.pdf`](docs/Thesis/MSE23HN_NguyenDucBinh_24MSE13183.pdf) | Official Master's Thesis submitted to FSB Institute |
| **LaTeX English Source** | English (40pp) | [`docs/Thesis/latex/thesis_latex_en/main.pdf`](docs/Thesis/latex/thesis_latex_en/main.pdf) | Academic Thesis Camera-Ready PDF |
| **LaTeX Vietnamese Source** | Vietnamese (40pp) | [`docs/Thesis/latex/thesis_latex_vi/main.pdf`](docs/Thesis/latex/thesis_latex_vi/main.pdf) | Bản dịch học thuật đối ứng 1:1 có kiểm toán số |
| **Defense Presentation Slides** | Interactive HTML5 Deck | [Live Slide Deck (GitHub Pages)](https://binhchuoizzz.github.io/AI_Security_Graph/docs/Thesis/slides/) | 20-slide projector deck (`N` for notes, `O` for agenda) |
| **Audit Benchmark Reference** | Machine-readable JSON | [`experiments/results/thesis_number_audit.json`](experiments/results/thesis_number_audit.json) | 134 audited claim-to-key verification points |

---

## 📊 Audited 5D Benchmark Results

Below are the **100% verified, audited empirical results** across all 5 evaluation dimensions (RTX 4060 Ti 16GB VRAM, Local `llama.cpp` CUDA server running `Foundation-Sec-8B-Instruct Q4_K_M`):

| Dimension (5D) | Key Metrics | Audited Value | Scientific Context & Benchmark Baseline |
| :--- | :--- | :---: | :--- |
| **1. Efficiency & Latency** | Offload Rate · Median Latency · ML Throughput | **97.5% · 0.88 ms · 3,452 eps** | Offloads 97.5% of traffic at sub-millisecond median latency, measured on a 99,717-event stream at a **9.8% attack base rate** (the same system offloads 90.6% at a 31.56% base rate — offload is a property of the mix, not a constant). LightGBM ML Gate achieves **100.0% Auto-BLOCK Precision** (962/962, 0 FP). |
| **2. AI Security & Integrity** | Prompt Inj. Defense · ML Evasion · HMAC Tamper | **100.0% · 98.75% · 100.0%** | Delimited Nonce Encapsulation blocks 678 hard adversarial samples; HMAC-SHA256 detects 100% log edits, insertions, or deletions. |
| **3. ATT&CK Attribution & RAG** | Attribution (retrieval-only · full pipeline) · Code Hallucination | **80.0% · 68.0% · 0 / 1,421 unanchored** | Dual-RAG (FAISS + BM25 RRF $k=60$) over 433 STIX ATT&CK entries. Attribution is **worse with the reasoning tier than without it** — reported as a limitation, not a win. Grounding guardrail fired on 9.26% of batches and blocked **76 ungroundable `BLOCK_IP` actions**. |
| **4. SOC Triage & HITL Queue** | Analyst Load Reduction · Threat Coverage | **-84.24% Load · 95.0% Threat Coverage** | SOC Analysts only need to inspect the Deferred (`AWAIT_HITL`) queue to catch 95.0% of real attacks, cutting 84.24% of manual review burden (6.03× enrichment into 15.76% of volume). |
| **5. Reasoning & Judge Quality** | Mean · best axis · worst axis | **3.78 / 5.0 · Relevancy 4.52 · Ctx-Precision 2.54** | Cross-family LLM-as-judge (`Meta-Llama-3-8B-Instruct` judging `Foundation-Sec-8B-Instruct`), n = 1,052 batches. Only **11.2%** of justifications cite a checkable log value — the weakest link in the system. |

---

## 📐 Architecture Overview

### Visual Interactive Pipeline (Mermaid)

```mermaid
flowchart TD
    subgraph INGESTION ["📥 High-Throughput Ingestion"]
        RAW["Raw Stream (496,885 Events)<br/>CICIDS2018 · CSIC 2010 · DAPT2020"]
        REDIS[("Redis Streams Queue<br/>Consumer Group Lag")]
        RAW --> REDIS
    end

    subgraph TIER1 ["⚡ Tier 1: Streaming Rule Filter & ML Gateway"]
        RULE["O(1) Streaming Rule Engine<br/>Whitelist · WAF Signatures · Welford Z > 3.5σ"]
        ML["LightGBM ML Gateway (76 Feats)<br/>949k Rows · 3,452 eps · 100% Precision"]
        CACHE["Tier 1.75: ExactMatch Semantic Cache<br/>SHA-256 (Payload+Headers) · 81.3% Hit Rate"]

        REDIS --> RULE
        RULE -->|Offload 97.5%| DROP["DROP / LOG / AUTO-BLOCK"]
        RULE -->|Escalate Band| ML
        ML -->|Confidence >= 0.85| BLOCK["AUTO-BLOCK IP"]
        ML -->|Confidence 0.65-0.85| CACHE
        CACHE -->|Cache Hit (9.8ms)| FAST_DECISION["Cached Fast Action"]
    end

    subgraph TIER2 ["🧠 Tier 2: Cognitive Multi-Agent Reasoning (Air-Gapped GPU)"]
        NONCE["Guardrails & Nonce Encapsulation<br/>Delimited Nonce <<<DATA_HASH>>>"]
        AGENT["LangGraph Cognitive Agent (6 Nodes)<br/>Foundation-Sec-8B-Instruct (llama.cpp)"]
        RAG[("Dual-RAG Knowledge Base<br/>FAISS + BM25 RRF (433 ATT&CK)")]
        MEM[("Threat Memory (SQLite)<br/>IP Reputation & APT Linker")]
        HMAC["Cryptographic HMAC-SHA256 Ledger<br/>Tamper-Proof Audit Chaining"]

        CACHE -->|Cache Miss (2.5% Traffic)| NONCE
        NONCE --> AGENT
        AGENT <--> RAG
        AGENT <--> MEM
        AGENT --> HMAC
    end

    subgraph RESPONSE ["🛡️ Contextual Response & HITL Workflow"]
        HMAC --> ACTION{"Policy Action Dispatcher"}
        ACTION -->|High Conf (>0.85)| EXEC["Action Executor (BLOCK_IP)"]
        ACTION -->|Uncertain (0.4-0.65)| HITL["SOC Analyst Queue (AWAIT_HITL)"]
        ACTION -->|Benign (<0.40)| AUDIT_LOG["Audit Log (DROP)"]
        HITL -->|Analyst Approval| EXEC
        HITL -->|Feedback Loop| MEM
    end

    classDef primary fill:#0284C7,stroke:#0369A1,stroke-width:2px,color:#FFFFFF;
    classDef success fill:#059669,stroke:#047857,stroke-width:2px,color:#FFFFFF;
    classDef warning fill:#D97706,stroke:#B45309,stroke-width:2px,color:#FFFFFF;
    classDef purple fill:#7C3AED,stroke:#6D28D9,stroke-width:2px,color:#FFFFFF;

    class RULE,ML primary;
    class AGENT,RAG,MEM purple;
    class CACHE,NONCE,HMAC success;
    class HITL warning;
```

### Complete Terminal Schematic

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
| :-: | :--- | :---: | :--- | :--- |
| **1** | **Rule Engine** | `Tier 1` | Python + Redis Stream | $\mathcal{O}(1)$ streaming filter + Welford $Z$-score anomaly detection ($Z > 3.5\sigma$). |
| **2** | **ML Gateway** | `Tier 1` | LightGBM (`ml_gateway.py`) | Trained on 949,535 NetFlow rows; **76 features**; 4-band policy; **3,452 eps**; **100.0% Auto-BLOCK Precision**. |
| **3** | **ExactMatch Cache** | `Tier 1.75` | SHA-256 + Python Dict | Bypasses LLM for duplicate attacks (**81.3% hit rate**, **8.9x speedup** 9.8ms vs 87.7ms). |
| **4** | **Guardrails & Nonce** | `Security` | Delimited Nonce + Regex | Encloses untrusted logs in random nonce tags; **100.0% Prompt Injection defense**. |
| **5** | **Dual-RAG** | `Tier 2` | FAISS + BM25 + RRF | Hybrid retrieval over 433 STIX MITRE ATT&CK entries (**Recall@3 = 0.930 ceiling · 0.385 on the full slice**). |
| **6** | **Cognitive Agent** | `Tier 2` | LangGraph + `Foundation-Sec-8B` | 6-node conditional DAG (`guardrails → rag_context → llm_triage → attack_mapper → action_executor / human_in_the_loop`); 4.6GB weights, **7–8GB VRAM** loaded. |
| **7** | **Grounding Guardrail** | `Tier 2` | Regex + MITRE Validator | Intercepts hallucinated actions; enforces **0.0% code hallucination rate** (`bad = 0 / 1,421`). |
| **8** | **Threat Memory** | `Storage` | SQLite (`synchronous=NORMAL`) | Maintains host history & APT links (**No WAL mode** for Docker cross-UID stability). |
| **9** | **HMAC Audit Chain** | `Integrity` | HMAC-SHA256 | Cryptographic hash chaining ($H_i = \text{HMAC}(D_i \parallel H_{i-1}, K)$); **100% tamper detection**. |
| **10** | **Backpressure Manager** | `Infra` | Redis Consumer Group | Manages stream ingestion by consumer group **`lag`** via `XREADGROUP` & `XACK`. |
| **11** | **SOC Dashboard** | `UI` | Streamlit (`src/ui/app.py`) | Real-time funnel visualizer, live log auditor, and **1-Click HITL approval queue**. |

---

## 🚀 Quick Start Guide

Detailed deployment documentation: **[`RUN_PROJECT.md`](docs/Codebase/guides/RUN_PROJECT.md)**.

### 1. Prerequisites & Environment Setup

- **GPU:** NVIDIA RTX 4060 Ti 16GB VRAM (Minimum) / RTX 4090 (Recommended)
- **RAM:** 32 GB System RAM
- **OS:** Linux (Ubuntu 22.04 LTS recommended)
- **Storage:** 50 GB SSD space

```bash
# 1. Clone repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# 2. Set up Python virtual environment
python3.10 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Copy configuration template
cp .env.example .env

# 4. Build RAG indexes (FAISS + BM25)
python -m src.rag.embedder
```

### 2. Build the Demo Stream, Then Launch

> [!IMPORTANT]
> `data/demo.json` is ~830 MB and is **not tracked in git**. Build it first — order matters, because `build_demo.py` reads `data/csic.json`; reversing the two silently produces a stream with **zero CSIC records** and no application-layer evidence at all.

```bash
# Step A: Build CSIC dataset (~1 min)
python scripts/build_csic_dataset.py --limit 36000

# Step B: Build unified demo stream (~4 min, ~4 GB RAM)
python scripts/build_demo.py

# Step C: Launch demo infrastructure & SOC dashboard
./scripts/run_demo.sh --fresh
```

Access the Streamlit SOC Dashboard at: **`http://localhost:8501`** (login: `manager`).
*(Use `--small` for a ~10,000-event stratified subset if you want the UI populated in minutes).*

#### Demo Stream Composition Breakdown

496,885 events, 100% real records, 5.24% attack / 94.76% benign, 22 distinct attack classes, 9 DAPT2020 chain records of which **3 attacker IPs carry attack-phase activity on ≥ 2 days** (3/3 APT chains detected). Every figure below is counted directly from `data/demo.json`:

| Source | Events | Attacks | Role in Evaluation |
| :--- | ---: | ---: | :--- |
| **CSE-CIC-IDS2018 NetFlow (10 days)** | 456,849 | 5,296 | Benign-heavy volume base, resolved at Tier 1 |
| **CSIC 2010 HTTP payloads** | 36,000 | 18,000 | Application-layer evidence — primary attribution scoring source |
| **DAPT2020 (volume + real chains)** | 1,902 | 669 | Multi-day kill-chain correlation |
| **`ground_truth` slice** | 1,250 | 1,170 | Covers all 15 labelled CICIDS classes |
| **Prompt injection + jailbreak** | 730 | 730 | deepset + jackhhao public corpora (AML.T0051) |
| **Zero-day probes + OWASP** | 154 | 154 | Signature-less, caught by Welford $Z$-score |

### 3. Run Deterministic E2E & Offline Benchmarks

```bash
# 1. Full unit + integration suite (609 tests; 4 skip when Redis is not running).
# SENTINEL_FREEZE_DYNAMIC_RULES=1 is REQUIRED to prevent modifying dynamic rule files.
SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest

# 2. E2E validation harness (functional pass/fail checks, 15/15 PASS)
python experiments/e2e_test_runner.py --offline

# 3. Unified Stream Benchmark (5D Empirical Evaluation)
python experiments/evaluate_unified_stream.py

# 4. Action-based Ablation Study
python experiments/run_ablation.py --mode all
```

### 4. Verify Every Number Before Trusting It

Three independent audit scripts maintain strict 1:1 synchronization between code, benchmark files, and thesis text:

```bash
# 1. 134 Claim-to-Key cross-validations (EN ↔ VI 1:1 Mirror check)
python scripts/audit_thesis_numbers.py

# 2. Bibliography and dataset citation audit (41 IEEE entries)
python scripts/audit_thesis_refs.py

# 3. Denominator and saturation metric audit (4 deliberate boundary flags)
python scripts/audit_metric_denominators.py
```

---

## 📄 License & Academic Attribution

Distributed under the **MIT License** — see [`LICENSE`](LICENSE).

- **Author:** Nguyễn Đức Bình (MSHV: `24MSE13183` — Lớp: `MSE23HN`)
- **Degree:** Master of Software Engineering (MSE)
- **Institution:** FSB Institute of Management & Technology — FPT University, Hanoi, Vietnam.
- **Scientific Supervisors:** Dr. Bùi Văn Hiệu & Dr. Đặng Văn Hiếu.

```bibtex
@mastersthesis{nguyen2026sentinel,
  author       = {Nguyen Duc Binh},
  title        = {SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI},
  school       = {FSB Institute of Management & Technology, FPT University},
  year         = {2026},
  type         = {Master's Thesis},
  address      = {Hanoi, Vietnam}
}
```
