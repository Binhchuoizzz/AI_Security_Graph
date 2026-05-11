# Hướng Dẫn Khởi Chạy Dự Án SENTINEL (V2 Architecture)

Tài liệu này cung cấp các bước chi tiết để khởi chạy toàn bộ hệ thống SENTINEL (bao gồm cả AI Agent, Knowledge Graph, Vulnerability Scanner và Dashboard).

---

## 1. Môi trường Yêu cầu (Prerequisites)

- **Hệ điều hành:** Linux (Ubuntu 22.04+) hoặc WSL2 trên Windows.
- **Phần cứng:** NVIDIA GPU (RTX 4060 Ti 16GB VRAM) để chạy cục bộ LLM Llama-3-8B. Cần 32GB RAM cho xử lý Graph và Caching.
- **Phần mềm:** Docker, Docker Compose, Python 3.10+, Trivy (cài đặt qua docker-compose hoặc script).

---

## 2. Khởi chạy Tự động bằng Script (Khuyên dùng cho Demo)

Dự án đã được đóng gói kèm một kịch bản demo chạy toàn bộ Pipeline End-to-End từ việc quét lỗ hổng cơ sở hạ tầng, xây dựng Knowledge Graph, đến việc AI Agent phân tích lưu lượng APT.

```bash
# 1. Cấp quyền thực thi cho file script
chmod +x demo_script.sh

# 2. Chạy Demo
./demo_script.sh
```

**Quá trình này sẽ thực hiện 4 bước tự động:**
1. Khởi chạy Vulnerability Scanner (Trivy) & Knowledge Graph Build (Neo4j).
2. Chạy luồng Ingestion Data và phân tích APT (Tích hợp Dual-RAG: MITRE + NIST).
3. Đẩy log và các metric F1-Score lên hệ thống MLflow (Tracking Server).
4. Đóng gói kết quả (Vulnerability Reports, APT Alerts) vào thư mục `demo_outputs/`.

---

## 3. Khởi chạy Thủ công (Từng Thành phần)

Nếu bạn muốn debug hoặc kiểm soát từng quá trình (SIEM UI, Agent, Scanner), hãy làm theo các bước sau:

### Bước 1: Khởi tạo Dịch vụ Phụ trợ (Docker)
Cần có Redis (để Caching/Pub-Sub), Neo4j (cho Vulnerability Graph), và MLflow.
```bash
cp .env.example .env
docker-compose up -d --build
```
*Lưu ý: Mở `.env` và thiết lập `LLM_API_BASE`, `SENTINEL_MANAGER_HASH` và thông tin cấu hình Neo4j.*

### Bước 2: Thiết lập Virtual Environment (Python)
```bash
python3.10 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Bước 3: Chạy SENTINEL Core Backend
File `main.py` hỗ trợ các chế độ (`--mode`) chuyên biệt:

- **Quét Hệ thống & Xây dựng Knowledge Graph (Tier 1 & Graph Build):**
  ```bash
  python main.py --mode scan --log-level INFO
  ```

- **Chạy AI Agent lắng nghe Traffic (Tier 2):**
  ```bash
  python main.py --mode server --log-level INFO
  ```

- **Chạy ĐỒNG THỜI cả Scan và Server:**
  ```bash
  python main.py --mode full --log-level INFO
  ```

### Bước 4: Khởi chạy Dashboard (SOC SIEM)
Giao diện Giám sát và Điều hành An ninh (Human-in-the-loop):
```bash
streamlit run src/ui/app.py
```

---

## 4. Bảng Dịch Vụ và Cổng (Ports Map)

Sau khi hệ thống khởi động thành công, bạn có thể truy cập các thành phần sau:

| Tên Dịch Vụ | Công Cụ | Truy Cập (URL) |
| --- | --- | --- |
| **SENTINEL Dashboard** | Streamlit UI | `http://localhost:8501` |
| **Threat Graph DB** | Neo4j Browser | `http://localhost:7474` (Bolt: 7687) |
| **Model Tracking** | MLflow Server | `http://localhost:5001` |
| **Cache & Pub/Sub** | Redis | `localhost:6379` |
| **AI Inference** | Llama.cpp / Oobabooga | `http://localhost:5000` |

---

## 5. Cấu trúc Thư mục Kết quả (Output)
Khi chạy chế độ phân tích hoặc demo, kết quả sẽ nằm trong `demo_outputs/`:
- `vulnerability_report.md`: Báo cáo từ Trivy đã được Agent dịch/phân tích.
- `knowledge_graph.json`: Cấu trúc Node/Edge của Graph hệ thống.
- `pipeline_summary.md`: Tóm tắt luồng đánh giá RAG và các luật (Rules) được tự động sinh.
- `apt_alerts.json`: Các thông báo và phân tích hành vi của APT Agent.
