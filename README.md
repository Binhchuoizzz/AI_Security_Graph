# SENTINEL: Hệ Sinh Thái AI Security Graph

**SENTINEL** là một hệ thống Trí tuệ Nhân tạo hỗ trợ An ninh mạng (AI Security) toàn diện, tập trung vào việc tự động phát hiện các chiến dịch tấn công có chủ đích (APT) và đánh giá lỗ hổng mã nguồn mở. Hệ thống áp dụng kiến trúc Hybrid 2-Tier: màng lọc Rule-based ở Tier 1 và Tác tử AI (LLM Agent) trang bị cơ chế RAG (NIST & MITRE) ở Tier 2 để phân tích chuyên sâu. Bằng việc kết hợp hệ sinh thái Knowledge Graph và Machine Learning, SENTINEL giúp giảm thiểu báo động giả (False Positives) và tự động hóa toàn bộ vòng đời ứng phó sự cố mạng.

## Kiến Trúc Hệ Thống (Architecture)

```mermaid
graph TD
    A[Mạng / Cảm biến (Data Ingestion)] -->|Traffic/Logs| B(Tier 1: Rule Engine Filter)
    B -->|Logs bình thường| C[(Elasticsearch / Cold Storage)]
    B -->|Logs bất thường (Escalate)| D{Tier 2: LangGraph LLM Agent}
    
    subgraph Kiến Thức & Trạng Thái
        E[(RAG: FAISS Index\nMITRE & NIST)]
        F[(Short-term Memory\nRedis)]
        G[(Vulnerability Graph\nNeo4j)]
    end
    
    D --- E
    D --- F
    D --- G
    
    D -->|Phân tích & Phán đoán| H[Hành động: BLOCK_IP, ALERT, HITL]
    H --> I[Dashboard & MLflow Tracking]
```

## Khởi Chạy Nhanh (Quick Start)

### 1. Chuẩn bị môi trường
```bash
git clone <repository_url>
cd AI_Security_Graph
cp .env.example .env
```
*(Hãy cấu hình lại các biến trong `.env` cho phù hợp, đặc biệt là `LLM_API_BASE` và `NEO4J_URI`).*

### 2. Khởi chạy với Docker Compose (Khuyên dùng)
Hệ thống được đóng gói sẵn với Docker Compose để quản lý các services phụ trợ (Redis, MLflow) và giao diện:
```bash
docker-compose up -d --build
```
Kiểm tra Dashboard tại: `http://localhost:8501`
Kiểm tra MLflow Metrics tại: `http://localhost:5001`

### 3. Khởi chạy Core Pipeline (CLI)
Bạn có thể chạy trực tiếp pipeline bằng Python (cần cấu hình virtual environment):
```bash
python main.py --mode full --log-level INFO
```

## Tài Liệu Tham Khảo Nhanh
- 🚀 **[Hướng dẫn chạy dự án chi tiết (RUN_PROJECT.md)](RUN_PROJECT.md)**
- 📐 **[Kiến trúc Hệ thống (architecture.md)](docs/architecture.md)**
- 🛡️ **[Thiết kế APT & Vulnerability (apt_vulnerability_design.md)](docs/apt_vulnerability_design.md)**
- 🔒 **[Chính sách Bảo mật (SECURITY.md)](SECURITY.md)**
- 🤝 **[Hướng dẫn Đóng góp (CONTRIBUTING.md)](CONTRIBUTING.md)**
