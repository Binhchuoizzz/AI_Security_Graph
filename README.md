# SENTINEL: A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

[![CI/CD Pipeline](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml/badge.svg)](https://github.com/Binhchuoizzz/AI_Security_Graph/actions/workflows/security.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

SENTINEL attacks the **SOC Alert Fatigue Paradox** with a two-tier split: a cheap, deterministic **Tier-1** filter runs on every log at wire speed, while an expensive **Tier-2 LangGraph agent** (Gemma-2-9B-IT, running locally) reasons only over what survives. The design bet is that most logs never deserve an LLM — and the measured **−82.97% latency** versus an LLM-on-everything baseline is the payoff.

This is a running system (Python · Redis Streams · LangGraph · llama.cpp · Streamlit · Docker) built for a Master's thesis: **267 pytest · 22/22 E2E**.

---

## 📐 Architecture

```text
   CSE-CIC-IDS2018 · DAPT2020 · Zero-day · Adversarial suite
                          │
                   [ Redis Streams ]
                          │
   ┌──────────────────────┴──────────────────────┐
   │ TIER 1 — Rule Engine (O(1)/log, 7 layers)   │
   │ whitelist → WAF sig → injection sig →       │
   │ Welford Z-score >3.5σ → static rules →      │
   │ dynamic rules → session baseline            │
   └──────────────────────┬──────────────────────┘
                          │  6-action routing
      ┌────────┬──────────┼──────────┬────────┬──────────┐
    DROP      LOG     BLOCK_IP   AWAIT_HITL  ALERT   ESCALATE
      │                                                 │ (only this calls the LLM)
   (noise)                        ┌──────────────────────┴──────────┐
                                  │ GUARDRAILS (5 layers)           │
                                  │ nonce encapsulation · encoding  │
                                  │ neutralizer · jailbreak detect  │
                                  │ Drain3 compress · consensus gate│
                                  └──────────────────┬──────────────┘
                                                     │
   ┌─────────────────────────────────────────────────┴──────────┐
   │ TIER 2 — LangGraph, 6 nodes (conditional DAG, no loops)     │
   │   Dual-RAG (MITRE + NIST · FAISS + BM25 · RRF k=60)         │
   │   Threat Memory (SQLite · APT chain linker · IP reputation) │
   └─────────────────────────────────────────────────┬──────────┘
                                                     │
                                     [ HMAC-SHA256 audit chain ]
                                                     │
                        ┌────────────────────────────┼──────────────┐
                      ALERT                     AWAIT_HITL       BLOCK_IP
                        │                            │               │
                  [ Dashboard ] ←────────── [ HITL queue ] → [ Response Executor ]
                        └────────── approved? ───────┴───────────────┘
                                             │
                          [ Feedback → dynamic rules → Tier 1 ]
```

**The loop that matters:** Tier-2 verdicts and human approvals become Tier-1 dynamic rules and IP reputation, so the cheap tier keeps absorbing what the expensive tier already learned.

### Core modules

| # | Component | Layer | Stack | Role |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Rule Engine** | Tier 1 | Python + Redis | 7-layer O(1) filter + online Welford statistics for signature-less anomalies. |
| 2 | **Guardrails** | Pre/Post | Regex + nonce delimiters | Data encapsulation, encoding neutralizer, jailbreak detection, output sanitizer, Tier-consensus gate. |
| 3 | **Drain3 Miner** | Pre | Drain3 | Compresses log tokens before LLM input (context budget). |
| 4 | **Dual-RAG** | Tier 2 | FAISS + BM25 + RRF | Hybrid retrieval over MITRE ATT&CK + NIST SP 800-61r2. |
| 5 | **LangGraph Agent** | Tier 2 | LangGraph + Gemma-2-9B-IT Q6_K | 6-node reasoning DAG: triage → ATT&CK mapping → response. |
| 6 | **Threat Memory** | Tier 2 | SQLite | Long-term host behavior, multi-day APT correlation, IP reputation. |
| 7 | **HMAC Audit Chain** | Integrity | SQLite + HMAC-SHA256 | Each entry hashes the previous → tamper-evident trail. |
| 8 | **Auth & Live FPR** | UI | SQLite + PBKDF2 | Persistent lockout, real-time false-positive metrics. |
| 9 | **Trivy + Neo4j KB** | Vuln | Neo4j + Trivy | Container scan → interactive vulnerability graph. |
| 10 | **HITL Dashboard** | UI | Streamlit | SOC operator console: live monitor, log auditor, approvals. |

---

## 📊 Measured Results

Offline deterministic run (2026-07-14, RTX 4060 Ti 16GB). **These are the honest numbers — missed targets included.**

| Axis | Target | **Measured** | Verdict |
| :--- | :--- | :--- | :--- |
| **1. Classification** (merged stream) | F1 ≥ 0.90 | **F1 0.61** — P 0.948 / R 0.450 | ❌ **Missed.** High precision, low recall: Tier-1 is tuned not to cry wolf, and pays for it in misses. |
| **2. Operational latency** | ≥ 60% reduction | **−82.97%** (26.9s → 4.6s) · Mann-Whitney p<0.05 | ✅ Met |
| **3. Robustness — static guardrails** | bypass < 10% | **50% bypass** (60/120 blocked) | ❌ **Missed.** Encoding 100% blocked, but semantic 0% and jailbreak 10%. |
| **3b. Robustness — full pipeline** | — | **100% resisted** (4/4) | ⚠️ Indicative only — n=4 is far too small to claim a rate. |
| **4. Context quality** (LLM-as-Judge) | ≥ 0.85 relevance | **3.9/5 overall** — Faithfulness 4.0 · Answer-Rel 4.62 · Ctx-Recall 4.01 · **Ctx-Precision 2.99** | ⚠️ Mixed; retrieval precision is the weak link. |
| **5. Explainability** | 100% audit completeness | **100%** (deterministic schema check) | ✅ Met |

**Tier-2 decision quality** (651 escalated cases): **threat recall 1.00** (594/594 — nothing malicious slipped through) · accuracy 0.912 · but **benign specificity 0.00** (all 57 benign cases were flagged too), with 631/651 routed to `AWAIT_HITL`. Read honestly: Tier-2 is a safety net that never misses and never clears — it removes the miss risk, it does not reduce the human workload.

**Judge methodology:** cross-family (Llama-3-8B judges Gemma-2-9B) to avoid self-enhancement bias, n=188 escalated of 300 samples. Source of truth: `experiments/results/reasoning_eval_results.json`.

> **Foundational capabilities — proof-of-concept, routed to Future Work, *not* headline claims:**
> **Zero-day:** 7/7 caught by Welford where static rules missed all 7 (graded boundary ≈4.0σ, pool n=30). **Emergent APT:** 3/3 recall on DAPT2020, specificity 1.0 against 4 benign multi-day IPs, Wilson 95% CI [0.44, 1.00]. Both run on small n with wide intervals — they show the mechanism works; they do not establish a rate.

Benchmarks come from the **offline deterministic path** (`experiments/evaluate_unified_stream.py`), never from the live demo, which is timing- and LLM-dependent.

---

## 🛡️ Security Controls

**Protecting the AI itself:**

* **Delimited Data Encapsulation** — wraps log payloads in a fresh `secrets.token_hex(8)` nonce **per batch**, isolating instruction from data; nested delimiter tokens in raw input are stripped (anti delimiter-smuggling).
* **Encoding Neutralizer** — decodes and sanitizes Base64, Hex, URL, and Unicode homoglyph payloads before analysis.
* **Jailbreak & DAN detection** — signature + semantic patterns, shared as a single hot-reloadable source of truth with Tier-1's pre-screen, so a match escalates into Guardrails instead of being silently dropped.
* **Tier-1/Tier-2 Consensus Guard** — if the deterministic Tier-1 flagged an attack but the LLM downgrades it to `LOG`/`DROP`, the verdict is overridden to `AWAIT_HITL`. This defends against social-engineering payloads embedded in logs ("already approved by admin"): you can talk an LLM down, you cannot talk a rule engine down.
* **Scoped anti-self-DoS** — `BLOCK_IP` downgrades to `ALERT` only for a narrow `critical_infrastructure_subnets` allowlist (loopback + specific gateway/DNS), not all of RFC1918 — a broad shield would silently neuter every internal block.
* **Output Sanitizer** — strips markdown image exfil (`![](...)`), HTML/JS, and deep Base64/Hex-obfuscated payloads from LLM output before it reaches the UI or the database.

**Infrastructure & audit:**

* **HMAC log chaining** — entries in `config/audit_trail.db` chain by hash, so any tampering breaks the chain and raises an alert. (Distinct from the research store `logs/guardrails_audit.db`.)
* **Persistent lockout** — SQLite-backed brute-force protection that survives session clearing and private windows, auto-resetting after the lockout window.
* **No hardcoded credentials (CWE-798)** — PBKDF2-HMAC-SHA256 (100k iterations), pre-computed hashes only, with a fail-loud warning if the demo HASH/SALT are still in use.
* **Measured noise reduction** — the subscriber counts real raw-vs-dropped logs into `config/pipeline_stats.json`, and the Dashboard reports that measured per-run rate rather than an estimate.
* **RAG checksum auditor** — SHA-256 over MITRE/NIST sources to block document poisoning.
* **Hardened Streamlit** — `enableCORS=false`, `enableXsrfProtection=true`, `frameAncestors=['none']`.

> **Enforcement honesty:** `block_ip()` is a `[FIREWALL MOCK]` — it writes the audit trail, it does **not** call iptables. Real enforcement happens inside SENTINEL: an approved dynamic rule makes Tier-1 score that IP's future traffic at 100. The mock is the integration point; production swaps in a firewall API.
>
> **ATT&CK mapping honesty:** Prompt Injection is not an ATT&CK Enterprise technique — it maps to **MITRE ATLAS `AML.T0051`** with its tactic ID deliberately left blank rather than fabricated. IDOR has no dedicated technique, so it maps to `T1190` with a lowered `mapping_confidence`. Details: [codebase_summary.md](docs/Codebase/learning/codebase_summary.md).

---

## 📂 Datasets

| Dataset | Scale | Use |
| :--- | :--- | :--- |
| **CSE-CIC-IDS2018** | 14 attack classes → **4,267-sample** stratified benchmark (`ground_truth.json`) | Tier-1 classification scoring |
| **DAPT2020** | 5 APT phases → **9 chains / 402 events** (324 malicious) | Emergent multi-day APT correlation |
| **Adversarial suite** | **120 vectors** in 5 categories (encoding 45 · structural 20 · semantic 20 · jailbreak 20 · rag_poisoning 15) | Guardrails robustness. A 6th, `rule_injection`, is designed but **not yet generated**. |
| **MITRE ATT&CK + NIST SP 800-61r2** | 299 techniques + IR playbooks | FAISS + BM25 hybrid retrieval |

---

## 📁 Directory Structure

```text
AI_Security_Graph/
├── main.py                       # CLI entrypoint (--mode server | scan | full)
├── src/
│   ├── streaming/                # Redis Streams publisher/subscriber (Tier-1 read loop)
│   ├── tier1_filter/             # Rule engine (Welford), session monitor, feedback listener
│   ├── guardrails/               # Prompt filter, encoding neutralizer, output sanitizer, validators
│   ├── rag/                      # Embedder, FAISS+BM25 retriever, RRF, semantic cache
│   ├── agent/                    # LangGraph workflow + 6 nodes, LLM client, token monitor
│   ├── response/                 # Action executor, HMAC audit chain, threat memory
│   └── ui/                       # Streamlit HITL dashboard + auth
├── experiments/                  # Evaluation scripts + benchmarks + results
│   ├── unified_dataset.py        # SHARED merged-stream builder (CICIDS + DAPT + zero-day)
│   ├── evaluate_unified_stream.py    # Offline deterministic benchmark (classification + APT + zero-day)
│   ├── stream_unified_online.py  # Online publisher, same stream (--include-adversarial → all 4 sources)
│   ├── run_ablation.py           # Ablation A–F   (--mode af | bcde | balanced | all)
│   ├── evaluate_adversarial.py   # Adversarial    (--mode static | pipeline)
│   ├── evaluate_reasoning.py     # LLM-as-a-Judge (Llama-3 judges Gemma-2)
│   ├── evaluate_tier2_decision.py    # Tier-2 verdict quality on escalated cases
│   ├── run_threshold_sensitivity.py  # Welford σ sweep (rebuts "3.5σ cherry-picked")
│   ├── run_zeroday_graded.py     # Zero-day detection-boundary curve
│   ├── run_apt_negative_control.py   # APT specificity + Wilson 95% CI
│   ├── run_context_stress.py     # Token growth: raw vs Drain-compressed vs n_ctx
│   ├── run_llm_robustness.py     # Determinism (seed) + graceful degradation (LLM down → AWAIT_HITL)
│   ├── measure_latency_baseline.py   # Two-tier vs LLM-only latency
│   ├── statistical_tests.py      # McNemar / Mann-Whitney U
│   ├── e2e_test_runner.py        # E2E suite (22 tests)
│   ├── adversarial/              # 120-sample suite (5 generated categories)
│   ├── ground_truth.json         # 4,267-sample labelled benchmark
│   └── results/                  # All result JSONs + plots/
├── scripts/
│   ├── run_demo.sh               # ONE-COMMAND full demo (infra + subscriber + UI + stream)
│   ├── push_flow.py              # Push the merged flow into Redis
│   ├── switch_model.sh           # Hot-swap the served LLM (gemma ⇄ llama judge)
│   └── build_*.py                # KB / RAG index / DAPT chain / adversarial suite builders
├── demos/                        # Standalone CLI demos (tier1, guardrails, rag)
├── config/                       # system_settings.yaml, ablation/ (A–F), *.db (auto-generated)
├── knowledge_base/               # mitre_attack.json, nist_800_61r2.json, faiss_index/
├── data/                         # raw/cicids2018, raw/dapt2020, knowledge/, processed/
├── reports/                      # test_report_FINAL.md, unified_stream_evaluation_report.md
├── docs/
│   ├── Codebase/guides/          # RUN_PROJECT.md, DEMO_FLOWS.md, COMMITTEE_DEMO.md
│   ├── Codebase/learning/        # codebase_summary.md, 00_DOC_CODE_THEO_LUONG.md
│   └── Thesis/                   # latex/, slides/, literature_review/
├── tests/                        # unit/ + integration/  (267 pytest)
├── requirements.txt
├── Dockerfile
└── docker-compose.yml            # Neo4j, Redis, MLflow, llama.cpp
```

---

## 🚀 Quick Start

Full deployment steps: **[RUN_PROJECT.md](docs/Codebase/guides/RUN_PROJECT.md)**. Per-flow committee demos: [DEMO_FLOWS.md](docs/Codebase/guides/DEMO_FLOWS.md) · [COMMITTEE_DEMO.md](docs/Codebase/guides/COMMITTEE_DEMO.md). Reading the code by runtime flow: [00_DOC_CODE_THEO_LUONG.md](docs/Codebase/learning/00_DOC_CODE_THEO_LUONG.md).

### 1. Setup (once)

```bash
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph
python3.10 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# drain3's metadata pins an old cachetools (4.2.1) but it works with the modern one:
pip install drain3==0.9.11 --no-deps && pip install "jsonpickle>=1.5.1"

cp .env.example .env
python src/rag/embedder.py        # REQUIRED: builds FAISS + BM25 indexes and RAG checksums
```

### 2. Run the whole demo — one command

```bash
./scripts/run_demo.sh             # infra + subscriber + UI + push 4,796 events (4 sources)
./scripts/run_demo.sh --small     # short demo (less LLM waiting)
./scripts/run_demo.sh --no-push   # infra only
```

Then open <http://localhost:8501>. Teardown: `pkill -f "main.py --mode server" ; docker-compose stop`

### 3. Or run it manually

```bash
docker-compose up -d                              # Neo4j, Redis, MLflow, llama.cpp CUDA server
python main.py --mode server                      # streaming subscriber (Tier-1 → Tier-2)
streamlit run src/ui/app.py                       # SOC dashboard
python experiments/e2e_test_runner.py --offline   # E2E suite, no LLM needed
```

### 4. Reproduce the benchmarks

```bash
python experiments/evaluate_unified_stream.py     # classification + APT + zero-day
python experiments/measure_latency_baseline.py    # latency reduction
python experiments/evaluate_adversarial.py --mode static
python experiments/run_ablation.py --mode all
```

### 5. (Optional) Hot-swap the LLM

The agent runs **Gemma-2-9B-IT**; the LLM-as-Judge axis uses **Meta-Llama-3-8B-Instruct** as an independent, cross-family judge.

```bash
./scripts/switch_model.sh llama     # swap to the judge model
./scripts/switch_model.sh gemma     # swap back
```

---

## 💻 Requirements

**GPU** RTX 4060 Ti 16GB VRAM (minimum) / RTX 4090 (recommended) · **RAM** 32 GB · **OS** Ubuntu 22.04 LTS or newer · **Storage** 50 GB SSD.

## 📄 License & Authorship

Distributed under the MIT License — see [LICENSE](LICENSE).

* **Author:** Nguyễn Đức Bình
* **Academic context:** Master's Thesis — AI & Machine Learning specialization.
