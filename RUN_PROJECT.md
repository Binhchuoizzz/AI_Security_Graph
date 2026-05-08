# Hướng Dẫn Khởi Chạy Dự Án (RUN_PROJECT)

Tài liệu này cung cấp các bước chi tiết để khởi chạy hệ thống SENTINEL trên môi trường cục bộ (Local) hoặc thông qua Docker.

## 1. Khởi chạy Local (Virtual Environment)

Phương pháp này dành cho quá trình phát triển (Development) và debug trực tiếp mã nguồn.

### Bước 1: Khởi tạo và kích hoạt Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # Trên Linux/macOS
# .venv\Scripts\activate   # Trên Windows
```

### Bước 2: Cài đặt Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Bước 3: Cấu hình Môi trường
Sao chép template và cấu hình file `.env`:
```bash
cp .env.example .env
```
*(Tham khảo bảng cấu hình biến môi trường ở phần dưới).*

### Bước 4: Chạy các dịch vụ phụ trợ
Bạn cần có Redis và MLflow đang chạy. Cách nhanh nhất là dùng Docker cho chúng:
```bash
docker-compose up -d redis mlflow
```

### Bước 5: Chạy Pipeline Core
Sử dụng cờ `--mode` để chọn chế độ hoạt động:
```bash
python main.py --mode server --log-level INFO
```

---

## 2. Khởi chạy bằng Docker (Production / Evaluation)

Sử dụng Docker Compose để khởi chạy toàn bộ hệ thống (UI, Backend, Redis, MLflow) chỉ bằng một lệnh duy nhất.

### Bước 1: Build và Up
```bash
cp .env.example .env
docker-compose up --build -d
```

### Bước 2: Kiểm tra trạng thái
```bash
docker-compose ps
docker-compose logs -f agent_ui
```

### Bước 3: Truy cập Dịch vụ
- **Sentinel Dashboard (Streamlit):** `http://localhost:8501`
- **MLflow Tracking Server:** `http://localhost:5001`

---

## 3. Danh sách Biến Môi trường (Environment Variables)

| Biến (Variable) | Mô tả (Description) | Giá trị mặc định |
| :--- | :--- | :--- |
| `REDIS_URL` | Chuỗi kết nối tới Redis (dùng cho Pub/Sub và Short-term Memory). | `redis://:SentinelSecurePass2026!@localhost:6379/0` |
| `MLFLOW_TRACKING_URI` | URL của MLflow Tracking Server. | `http://localhost:5001` |
| `LLM_API_BASE` | Endpoint API tương thích OpenAI (Oobabooga/llama.cpp). | `http://127.0.0.1:5000/v1` |
| `LLM_API_KEY` | Khóa API (thường chỉ là placeholder cho Local LLM). | `sk-placeholder-local-only` |
| `MOCK_LLM` | Đặt là `1` để giả lập phản hồi của LLM khi không có GPU. | `0` |
| `NEO4J_URI` | Chuỗi kết nối tới Neo4j Graph Database (Kiến trúc V2). | `bolt://localhost:7687` |

---

## 4. Xử lý Sự cố (Troubleshooting Top 5 Lỗi)

1. **Lỗi `Connection refused` khi chạy LLM Agent**
   - *Nguyên nhân:* Oobabooga/llama.cpp server chưa được bật hoặc sai cổng.
   - *Khắc phục:* Đảm bảo `LLM_API_BASE` trỏ đúng port. Nếu bạn không có GPU, hãy set `MOCK_LLM=1` trong `.env`.

2. **Lỗi `ModuleNotFoundError: No module named 'langgraph'`**
   - *Nguyên nhân:* Quên kích hoạt môi trường ảo.
   - *Khắc phục:* Chạy `source .venv/bin/activate` trước khi chạy lệnh.

3. **Lỗi `Redis ConnectionError`**
   - *Nguyên nhân:* Redis chưa chạy hoặc sai mật khẩu.
   - *Khắc phục:* Chạy `docker-compose up -d redis`. Kiểm tra lại `REDIS_URL`.

4. **Lỗi phân quyền khi ghi log/mlruns trong Docker**
   - *Nguyên nhân:* Người dùng Docker không có quyền ghi vào thư mục được mount.
   - *Khắc phục:* Chạy `chmod -R 777 mlruns/ logs/ data/ knowledge_base/` hoặc `chown` lại thư mục.

5. **Lỗi `IndexError: list index out of range` khi query FAISS**
   - *Nguyên nhân:* FAISS index chưa được tạo.
   - *Khắc phục:* Chạy `python src/rag/embedder.py` để nhúng lại toàn bộ tri thức.
