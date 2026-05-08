# Kiến Trúc Hệ Thống (System Architecture)

Hệ thống SENTINEL được thiết kế theo kiến trúc **2-Tier (2 Tầng)** kết hợp luồng dữ liệu thời gian thực (Streaming) và Tác tử suy luận AI (LLM Agent).

## 1. Biểu Đồ Kiến Trúc Luồng Dữ Liệu

```mermaid
graph TD
    subgraph Data Ingestion
        A[Nguồn Log Mạng / Cảm biến] -->|Streaming| B(Redis Pub/Sub)
    end

    subgraph Tier 1: Lọc Sơ Cấp (Rule Engine)
        B --> C[Subscriber]
        C --> D{Rule Engine Filter}
        D -->|Log Hợp Lệ| E[(Elasticsearch / Cold Storage)]
        D -->|Bất Thường (Escalate)| F[Guardrails Encapsulator]
    end

    subgraph Khối Tri Thức & Trạng Thái (Storage Layer)
        G[(MITRE FAISS Index)]
        H[(NIST FAISS Index)]
        I[(Neo4j: Vuln Graph)]
        J[(Redis: Session Memory)]
        K[(MLflow DB & Artifacts)]
    end

    subgraph Tier 2: LLM Agent (LangGraph)
        F --> L[Triage Node]
        L --> M[RAG Retrieval Node]
        L --> N[Vuln Assessment Node]
        M --> O[Reasoning Node (Local LLM)]
        N --> O
        O --> P[Action Node]
    end

    M -.-> G
    M -.-> H
    N -.-> I
    L -.-> J
    O -.-> K

    P -->|Phản hồi| Q[Firewall / HITL Dashboard]
```

## 2. Các Thành Phần Chính (Components)

1. **Streaming Layer (`src/streaming/`)**: Xử lý dữ liệu đầu vào tốc độ cao. Gồm Publisher đẩy log lên Redis và Subscriber lấy log xuống.
2. **Tier 1 Filter (`src/tier1_filter/`)**: Một Rule Engine kiểm tra các điều kiện cơ bản (DDoS, quét port diện rộng). Giúp giảm tải cho Tier 2.
3. **Guardrails (`src/guardrails/`)**: Màng bọc an ninh. Đóng gói dữ liệu đầu vào để chống Prompt Injection trước khi đưa cho LLM.
4. **LangGraph Agent (`src/agent/`)**: Trái tim của hệ thống. Nhận log bất thường, lên kế hoạch suy luận, gọi tool (RAG, Graph) và ra quyết định.
5. **RAG Module (`src/rag/`)**: Chịu trách nhiệm nhúng (Embedder) và tìm kiếm (Retriever) các kịch bản ứng phó từ MITRE và NIST.

## 3. Lớp Lưu Trữ (Storage Layer)

- **`logs/`**: Chứa raw logs (văn bản) sinh ra trong quá trình hệ thống chạy. Phục vụ debug và kiểm toán (Auditing).
- **`mlruns/`**: Chứa Artifacts và SQLite DB của MLflow. Lưu trữ metrics (F1, Latency), tham số thí nghiệm, và model metadata để đảm bảo tính tái tạo (Reproducibility).
- **`knowledge_base/`**: 
  - Lưu trữ các tệp tri thức gốc dạng JSON (`mitre_attack.json`, `nist_800_61r2.json`).
  - Lưu trữ thư mục `faiss_index/` chứa các tệp nhúng `.index` (Vector DB tĩnh).
- **`data/`**: Chứa dữ liệu đầu vào (e.g., CSE-CIC-IDS2018 CSV/PCAP) hoặc file kết quả quét lỗ hổng (như `trivy-results.json`).
