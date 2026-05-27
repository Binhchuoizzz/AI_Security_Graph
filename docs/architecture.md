# Kiến Trúc Hệ Thống (System Architecture)

Hệ thống SENTINEL được thiết kế theo kiến trúc **2-Tier (2 Tầng)** kết hợp luồng dữ liệu thời gian thực (Streaming) và Tác tử suy luận AI (LLM Agent).

## 1. Biểu Đồ Kiến Trúc Luồng Dữ Liệu

```mermaid
graph TD
    subgraph Data Ingestion
        A[Nguồn Log Mạng / DAPT2020 / CICIDS2018] -->|Streaming| B(Redis Pub/Sub)
    end

    subgraph Tier 1: Lọc Sơ Cấp (Rule Engine)
        B --> C[Subscriber]
        C --> D{Rule Engine & Session Baseline}
        D -->|Benign| E[(Drop/Bỏ qua)]
        D -->|Bất Thường (Escalate)| F[Guardrails: Template Miner + Encapsulator]
    end

    subgraph Khối Tri Thức & Trạng Thái (Storage Layer)
        G[(MITRE FAISS Index)]
        H[(NIST FAISS Index)]
        I[(Threat Memory SQLite)]
        J[(MLflow DB & Artifacts)]
        K[(Audit Trail DB)]
    end

    subgraph Tier 2: LLM Agent (LangGraph)
        F --> L[Triage Node]
        L --> M[RAG Retrieval Node]
        M --> O[Reasoning Node (Gemma-2-9B-IT)]
        O --> P[Action/Routing Node]
    end

    M -.-> G
    M -.-> H
    L -.-> I
    O -.-> J
    P -.-> K

    P -->|Phản hồi/Quyết định| Q[Firewall / HITL Dashboard]
    Q -.->|Phê duyệt Rule| R[Feedback Loop (Cập nhật Tier 1)]
    R -.-> D
```

## 2. Các Thành Phần Chính (Components)

1. **Streaming Layer (`src/streaming/`)**: Xử lý dữ liệu đầu vào tốc độ cao. Gồm Publisher đẩy log lên Redis và Subscriber lấy log xuống.
2. **Tier 1 Filter (`src/tier1_filter/`)**: Rule Engine kiểm tra các điều kiện cơ bản (Session Baseline) và chặn nhanh (IP Blacklist, Port rules). Giúp giảm tải cho Tier 2.
3. **Guardrails (`src/guardrails/`)**: Màng bọc an ninh. Đóng gói dữ liệu đầu vào (Delimited Data Encapsulation) chống Prompt Injection và Nén luồng (Drain3 Template Miner) trước khi đưa cho LLM.
4. **LangGraph Agent (`src/agent/`)**: Trái tim của hệ thống. Nhận log bất thường, truy xuất lịch sử APT (Threat Memory), gọi RAG và ra quyết định. LLM sử dụng là `Gemma-2-9B-IT`.
5. **RAG Module (`src/rag/`)**: Chịu trách nhiệm nhúng (Embedder) và tìm kiếm lai (Dual-RAG Hybrid: FAISS + BM25) các kịch bản ứng phó từ MITRE ATT&CK và NIST SP 800-61r2.

## 3. Lớp Lưu Trữ (Storage Layer)

- **`config/`**: Chứa SQLite DB của Hệ thống: `threat_memory.db` (lưu vết APT), `audit_trail.db` (lưu quyết định).
- **`mlruns/`**: Chứa Artifacts và SQLite DB của MLflow. Lưu trữ metrics (F1, Latency, Defeat Rate) để đảm bảo tính tái tạo.
- **`knowledge_base/`**: 
  - Lưu trữ các tệp tri thức gốc dạng JSON (`mitre_attack.json`, `nist_800_61r2.json`).
  - Thư mục `faiss_index/` chứa các tệp nhúng và chỉ mục BM25.
- **`data/`**: Chứa tập dữ liệu đầu vào chuẩn hóa cho luận văn: CSE-CIC-IDS2018 (CSV) và DAPT2020.
