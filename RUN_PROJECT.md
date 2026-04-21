# Hướng Dẫn Vận Hành Hệ Thống SENTINEL v2 (Turn-key Guide)

Tài liệu này cung cấp hướng dẫn từng bước để khởi chạy và kiểm thử toàn bộ hệ thống SENTINEL v2. Phục vụ trực tiếp cho việc chứng minh tính khả thi của luận văn trước hội đồng.

## 1. Yêu cầu Hệ thống (Prerequisites)
- Docker & Docker Compose
- Python 3.10+
- **Oobabooga Text Generation WebUI** đang chạy Local LLM (Gemma 2 9B) ở `http://localhost:5000`

## 2. Khởi động Hạ tầng Core (Redis & MLflow)

Hệ thống sử dụng Redis làm Message Broker cho kiến trúc Streaming và MLflow để track các Metrics thực nghiệm.

```bash
# 1. Khởi động các services ngầm bằng Docker
docker-compose up -d redis mlflow

# 2. Kiểm tra trạng thái
docker-compose ps
# (Bạn sẽ thấy 2 container đang chạy ở cổng 6379 và 5001)
```

## 3. Khởi chạy Pipeline Thời Gian Thực (End-to-End Mode)

Trong chế độ này, chúng ta sẽ chạy bộ lọc Tier 1 (RuleEngine) và Tier 2 (LangGraph Agent) liên tục.

**Terminal 1 (Chạy Core System):**
```bash
source .venv/bin/activate
python main.py
```
*(Lúc này Subscriber sẽ bắt đầu listen trên Redis Queue chờ log)*

**Terminal 2 (Giả lập Traffic):**
```bash
source .venv/bin/activate
# Bắn dữ liệu log giả lập (CICIDS2017) vào Redis
python src/streaming/publisher.py
```

## 4. Bật Dashboard dành cho Chuyên gia SOC (HITL)

Dashboard cho phép Chuyên gia An ninh mạng (Level 1 Analyst & Level 3 Manager) xem các alert, approve các luật mới và tương tác với AI.

**Terminal 3 (Chạy Dashboard):**
```bash
source .venv/bin/activate
streamlit run src/ui/app.py
```

> **Tài khoản đăng nhập mặc định:**
> - Username: `manager`
> - Password: `sentinel_manager_2026`

## 5. Chạy Đánh giá Tự Động (Ablation Study) & Sinh Số Liệu

Để trả lời Câu hỏi Nghiên cứu (RQ1, RQ2), bạn chỉ cần chạy bộ đánh giá tự động. Bộ đánh giá này sẽ tự test các file log và bắn số liệu thẳng lên MLflow.

```bash
# Đảm bảo bạn đang trong môi trường ảo
source .venv/bin/activate

# 1. Chạy đánh giá F1, Latency
python experiments/run_ablation_study.py

# 2. Tính p-value thống kê (McNemar, Mann-Whitney U)
python experiments/statistical_tests.py

# 3. Tạo biểu đồ minh họa
python experiments/plot_results.py
```

## 6. Xem Báo Cáo Trên MLflow

Sau khi chạy xong bước 5, bạn có thể xem các bảng biểu, so sánh chỉ số của **Config A (Rule-only)** và **Config F (Full)** trên giao diện web.

- Truy cập: `http://localhost:5001`
- Chọn Experiment: **Sentinel_Ablation_Study**

## 7. Dọn dẹp sau khi Demo

```bash
docker-compose down
```
*(Nếu muốn xóa sạch DB của MLflow để làm lại từ đầu: `rm -rf mlruns/`)*
