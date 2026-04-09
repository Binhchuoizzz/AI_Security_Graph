# Autonomous AI Security Agent for Multi-source Log Correlation and Intrusion Response

This Master's Thesis project implements an Autonomous AI Security Agent utilizing LangGraph, Retrieval-Augmented Generation (RAG), a Human-in-the-Loop (HITL) architecture, and strict Adversarial Guardrails. The system leverages a local Gemma 26B model hosted via the Oobabooga API.

## Architecture

The agentic SOC workflow follows a sophisticated pipeline:
1. **Data Ingestion & Correlation:** High-throughput log ingestion and event correlation utilizing time-window algorithms.
2. **Adversarial Guardrails:** Ensures LLM interactions and system boundaries are protected using advanced Prompt Filtering and Data Validation mechanisms (preventing context overflow & injection).
3. **Knowledge Retrieval (RAG):** Contextual intelligence retrieval from structured mappings (MITRE ATT&CK, ISO 27001).
4. **LangGraph Agent:** The cognitive engine, orchestrating incident assessment and response logic via state-based graphs.
5. **HITL UI:** A Streamlit interface allowing Security Analysts (L1/L3) to supervise, validate, and simulate mitigation commands governed by distinct Role-Based Access Control (RBAC).

## Quick Start

Ensure Docker and Docker Compose are installed on your system. 

To build and launch the environment (AI Agent UI + MLflow Tracking Server):

```bash
docker-compose up --build -d
```

### Accessing the Web Interfaces

- **Agent Dashboard (Streamlit):** [http://localhost:8501](http://localhost:8501)
- **MLflow Tracking Server:** [http://localhost:5001](http://localhost:5001)
