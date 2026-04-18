# SENTINEL Framework Architecture

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence,
> **N**eutralization, **E**scalation and **L**og-correlation

Kiến trúc tổng thể của hệ thống AI Security Agent, được thiết kế
theo mô hình Containerized Modular Architecture.

## Sơ đồ luồng xử lý (Data Flow)

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL FRAMEWORK                           │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────────┐ │
│  │ CSV/PCAP │───▶│ Redis    │───▶│ TIER 1: Rule Engine        │ │
│  │ Publisher │    │ 3-Queue  │    │ (Static + Dynamic Rules)   │ │
│  │          │    │ FW/WAF/  │    │ + Session Behavioral       │ │
│  │          │    │ Sysmon   │    │   Baselining (Z-score)     │ │
│  └──────────┘    └──────────┘    └─────────┬──────────────────┘ │
│                                            │                    │
│                          ┌─────────────────┤                    │
│                          │ DROP            │ ESCALATE           │
│                          ▼                 ▼                    │
│                     (Baseline      ┌──────────────────────┐     │
│                      Update)       │ GUARDRAILS LAYER     │     │
│                                    │ ├─ Prompt Injection   │     │
│                                    │ │  Detector (Pattern) │     │
│                                    │ ├─ Encoding           │     │
│                                    │ │  Neutralization     │     │
│                                    │ ├─ Dynamic Randomized │     │
│                                    │ │  Delimiter          │     │
│                                    │ │  Encapsulation      │     │
│                                    │ ├─ Log Template Miner │     │
│                                    │ │  (Drain3 — Token    │     │
│                                    │ │  Budget only)       │     │
│                                    │ ├─ Feature Extractor  │     │
│                                    │ └─ Data Validator     │     │
│                                    └─────────┬────────────┘     │
│                                              │                  │
│                                              ▼                  │
│                                    ┌──────────────────────┐     │
│                                    │ TIER 2: LangGraph    │     │
│                                    │ Agent Core           │     │
│                                    │ ├─ Dual-RAG:         │     │
│                                    │ │  MITRE ATT&CK      │     │
│                                    │ │  + ISO 27001        │     │
│                                    │ │  (FAISS+BM25+RRF)  │     │
│                                    │ ├─ LLM Reasoning     │     │
│                                    │ │  (Gemma 2 9B       │     │
│                                    │ │   Local via         │     │
│                                    │ │   Oobabooga API)    │     │
│                                    │ └─ Decision Router   │     │
│                                    └─────────┬────────────┘     │
│                               ┌──────────────┤                  │
│                               │              │                  │
│                               ▼              ▼                  │
│                 ┌─────────────────┐  ┌───────────────┐          │
│                 │ Feedback Loop   │  │ HITL Dashboard │          │
│                 │ (Dynamic Rule   │  │ (Streamlit)    │          │
│                 │  → Tier 1)      │  │ ├─ RBAC Auth   │          │
│                 │ [HITL Gated]    │  │ │  (SHA-256)   │          │
│                 └─────────────────┘  │ ├─ Approve/    │          │
│                                      │ │  Reject      │          │
│                                      │ └─ Audit Trail │          │
│                                      └───────┬───────┘          │
│                                              │                  │
│                                              ▼                  │
│                                      ┌───────────────┐          │
│                                      │ Response       │          │
│                                      │ Executor       │          │
│                                      │ (Block IP /    │          │
│                                      │  Alert / Log)  │          │
│                                      └───────────────┘          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ MLOps Layer: MLflow Tracking + Docker + SQLite Audit     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Mapping giữa Module và Research Question

| Module | Giải quyết RQ | File chính |
|---|---|---|
| Tier 1 + Redis Multi-Queue Streaming | RQ1 (Latency) | `src/tier1_filter/`, `src/streaming/` |
| Guardrails Layer (3-layer + Dynamic Delimiters) | RQ2 (Defeat Rate) | `src/guardrails/` |
| Dual-RAG (MITRE + ISO, Hybrid FAISS+BM25+RRF) | RQ3 (Context Relevance) | `src/rag/` |
| Feedback Loop + Session Baselining | RQ4 (Zero-day Adaptation) | `src/tier1_filter/rule_engine.py` |
| LangGraph Agent (Structured MemoryObject) | RQ1 + RQ3 | `src/agent/` |
| HITL Dashboard (RBAC, Auto-refresh) | RQ3 | `src/ui/` |
