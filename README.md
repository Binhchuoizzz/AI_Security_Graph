# Autonomous AI Security Agent for Multi-source Log Correlation 🛡️

*A Master's Thesis Project: Leveraging LangGraph, RAG, and Human-in-the-Loop for Next-Generation SOC Automation*

![Python 3.10](https://img.shields.io/badge/Python-3.10-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)
![MLflow](https://img.shields.io/badge/Tracking-MLflow-0194E2.svg)

## 📖 Overview

Modern Security Operations Centers (SOCs) are plagued by alert fatigue and isolated log analysis. Security analysts are overwhelmed by high volumes of false positives, struggling to correlate complex multi-stage attacks across disjointed defense systems. 

This Master's Thesis project introduces an **Autonomous AI Security Agent** designed to automate the initial triage, correlation, and response recommendation phases of a SOC. By utilizing an Agentic Workflow equipped with stateful reasoning (LangGraph), the system intelligently correlates multi-source logs, retrieves contextual threat intelligence, and bridges the gap between machine speed reasoning and human oversight with explainable, actionable insights.

## ⚙️ Core Architecture

Data flows through a comprehensive, production-grade pipeline:

1. **Ingestion:** Parses and normalizes diverse log sources (Web, Auth, Firewall).
2. **Correlation:** Groups discrete events using a sliding 5-minute time-window per IP address.
3. **Adversarial Guardrails:** Sanitizes inputs and monitors state to block Prompt Injections and context overflow.
4. **RAG Retrieval:** Queries a FAISS vector database to fetch relevant MITRE ATT&CK tactics and ISO 27001 compliance controls.
5. **LLM Reasoning:** A local Gemma 26B model uses LangGraph to evaluate threat severity, map attack vectors, and formulate a response plan.
6. **HITL (Streamlit):** Presents the correlated attack narrative to a Human Analyst (L1/L3) for approval.
7. **Response:** Simulates mitigation executions (e.g., firewall block rules) based on analyst authorization.

## ✨ Key Features

- **Human-in-the-Loop (HITL):** Enforces Role-Based Access Control (RBAC), ensuring that critical mitigation commands are governed by human analysts before execution.
- **Dual-RAG Intelligence:** Simultaneously grounds LLM reasoning in technical threat frameworks (MITRE ATT&CK) and governance standards (ISO 27001).
- **Adversarial Guardrails:** Custom AI safety layers explicitly engineered to defend the agent against prompt poisoning and malicious log injections.
- **MLflow Tracking:** Logs experiment parameters, ablation studies (performance with/without RAG), and accuracy metrics for rigorous academic evaluation.

## 🛠 Prerequisites

To run this project, ensure you have the following installed and configured:
- **Python 3.10.x** (Strictly recommended for local execution to avoid dependency conflicts)
- **Docker & Docker Compose**
- **Git LFS** (for fetching large SQLite and CSV files)
- **Local LLM Backend:** Ensure `text-generation-webui` (Oobabooga) is running locally on port 5000, serving the Gemma 26B model with the API extension enabled.

## 🚀 Quick Start / Installation

**1. Clone the repository:**
```bash
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph
```

**2. Configure Environment Variables:**
Create a `.env` file in the root directory (or modify the existing one):
```env
OLLAMA_BASE_URL=http://host.docker.internal:5000/v1
MODEL_NAME=gemma-26b
MLFLOW_TRACKING_URI=http://mlflow:5000
```

**3. Build and launch with Docker Compose:**
```bash
docker-compose up --build -d
```

## 💻 Usage / Demo Scenario

Once the containers are running, access the agentic environments:
- **Streamlit SOC Dashboard:** Navigate to `http://localhost:8501`. Log in using your assigned RBAC credentials.
- **Analyst Workflow:** View the real-time incident queue. Select a correlated incident to view the AI's gathered evidence, MITRE mappings, and proposed mitigation. Click **Approve** to execute the simulated firewall block or **Reject** to dismiss false positives.
- **MLflow Tracking:** Navigate to `http://localhost:5001` to view benchmarking metrics and ablation study results.

## 📂 Project Structure

```text
ai_security_agent/
├── config/           # RBAC policies and system settings
├── data/             # Raw CSV datasets and processed logs
├── experiments/      # MLflow ablation studies and metric calculations
├── knowledge_base/   # MITRE & ISO structured JSON and FAISS indices
├── logs/             # Audit trails and debug outputs
├── src/
│   ├── ingestion/    # Data parsing and formatting pipeline
│   ├── correlation/  # Time-window clustering logic
│   ├── rag/          # Vector embedding and retrieval
│   ├── guardrails/   # Prompt filters and context overflow protection
│   ├── agent/        # LangGraph state definitions and nodal workflow
│   ├── response/     # Simulated mitigation executor
│   └── ui/           # Streamlit app and components
└── tests/            # Pytest suites for correlation and adversarial defenses
```

## ⚠️ Disclaimer

This software is an academic prototype developed for a Master's Thesis. While it implements security best practices regarding LLM guardrails, it is **not intended for deployment in a production network environment** without significant code review, hardening, and sandbox integration.
