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
│  │ CSV Data │───▶│ Redis    │───▶│ TIER 1: Rule Engine        │ │
│  │ Publisher │    │ Queue    │    │ (Static + Dynamic Rules)   │ │
│  └──────────┘    └──────────┘    │ + Random Sampling (2%)     │ │
│                                  └─────────┬──────────────────┘ │
│                                            │                    │
│                          ┌─────────────────┤                    │
│                          │ DROP            │ ESCALATE / SAMPLE  │
│                          ▼                 ▼                    │
│                     (Discard)    ┌──────────────────────┐       │
│                                 │ GUARDRAILS LAYER     │       │
│                                 │ ├─ Prompt Injection   │       │
│                                 │ │  Detector           │       │
│                                 │ ├─ Entropy Scorer     │       │
│                                 │ ├─ Log Template Miner │       │
│                                 │ │  (Drain3)           │       │
│                                 │ ├─ Token Budget Mgr   │       │
│                                 │ ├─ Feature Extractor  │       │
│                                 │ ├─ Data Validator     │       │
│                                 │ └─ Context Overflow   │       │
│                                 │    Guard              │       │
│                                 └─────────┬────────────┘       │
│                                           │                    │
│                                           ▼                    │
│                                 ┌──────────────────────┐       │
│                                 │ TIER 2: LangGraph    │       │
│                                 │ Agent Core           │       │
│                                 │ ├─ Correlation Node  │       │
│                                 │ │  [IP+5min Window]  │       │
│                                 │ ├─ RAG: MITRE ATT&CK │       │
│                                 │ ├─ RAG: ISO 27001    │       │
│                                 │ ├─ LLM Reasoning     │       │
│                                 │ │  (Gemma 26B Local) │       │
│                                 │ └─ Decision Router   │       │
│                                 └─────────┬────────────┘       │
│                            ┌──────────────┤                    │
│                            │              │                    │
│                            ▼              ▼                    │
│              ┌─────────────────┐  ┌───────────────┐            │
│              │ Feedback Loop   │  │ HITL Dashboard │            │
│              │ (Dynamic Rule   │  │ (Streamlit)    │            │
│              │  → Tier 1)      │  │ ├─ RBAC Auth   │            │
│              └─────────────────┘  │ ├─ Approve/    │            │
│                                   │ │  Reject      │            │
│                                   │ └─ Audit Trail │            │
│                                   └───────┬───────┘            │
│                                           │                    │
│                                           ▼                    │
│                                   ┌───────────────┐            │
│                                   │ Response       │            │
│                                   │ Executor       │            │
│                                   │ (Block IP /    │            │
│                                   │  Alert / Log)  │            │
│                                   └───────────────┘            │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ MLOps Layer: MLflow Tracking + Docker + SQLite Audit     │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Mapping giữa Module và Research Question

| Module | Giải quyết RQ | File chính |
|---|---|---|
| Tier 1 + Redis Streaming | RQ1 (Latency) | `src/tier1_filter/`, `src/streaming/` |
| Guardrails Layer | RQ2 (Defeat Rate) | `src/guardrails/` |
| Dual-RAG (MITRE + ISO) | RQ3 (Context Relevance) | `src/rag/` |
| Feedback Loop + Sampling | RQ4 (Zero-day Adaptation) | `src/tier1_filter/rule_engine.py` |
| LangGraph Agent | RQ1 + RQ3 | `src/agent/` |
| HITL Dashboard | RQ3 | `src/ui/` |
