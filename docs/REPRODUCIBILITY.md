# Hướng Dẫn Tái Tạo Thí Nghiệm (Reproducibility)

Tài liệu này cung cấp các hướng dẫn để các nhà nghiên cứu độc lập có thể tái tạo lại chính xác các kết quả thử nghiệm trong dự án SENTINEL.

## 1. Môi trường Thực thi
- **Phần cứng:** Thí nghiệm được thực thi trên máy ảo giả lập (hoặc Local PC) có tối thiểu 8GB RAM, không yêu cầu GPU (sử dụng cờ `MOCK_LLM=1` cho chế độ offline fallback).
- **Hệ điều hành:** Linux (Ubuntu 20.04/22.04 LTS).
- **Python:** Phiên bản `3.10.x`.
- **Hạt giống ngẫu nhiên (Seed):** Mọi hàm random trong FAISS và Numpy đều được cố định bằng Seed `42`.

## 2. Dataset & Tiền xử lý
- **Nguồn Dữ liệu:** Sử dụng bộ dữ liệu gốc **CSE-CIC-IDS2018** lưu tại AWS Registry of Open Data.
- **Tiền xử lý:** 
  - Tập dữ liệu thô (PCAP/CSV) rất lớn (~450GB). Script tải dữ liệu nằm tại `scripts/download_cicids2018.sh`.
  - Để phục vụ bài Test End-to-End, chúng tôi đã trích xuất thủ công 101 luồng mạng đặc trưng (đại diện cho Brute Force, Web Attacks, DoS) lưu tại `experiments/ground_truth.json`.
  - Mọi thực nghiệm mặc định sẽ chạy trên tệp `.json` này để đảm bảo cùng một tập Input đầu vào cho mọi cấu hình.

## 3. Quản lý Thí nghiệm (MLflow Tracking)
Hệ thống sử dụng **MLflow** để tự động log và phiên bản hóa mọi thông số:
- **Experiment:** `Sentinel_Ablation_Study`
- **Chỉ số lưu trữ (Metrics):** F1-Score, Precision, Recall, Độ trễ (MTTD/MTTR), Tỷ lệ tự động hóa (HITL Ratio).
- **Tham số (Params):** Ngưỡng FAISS (Threshold), Số lượng Batch Size, Model Temperature (`0.1`).
- Các kết quả được MLflow quản lý tại thư mục `mlruns/` (Local SQLite) và có thể xem biểu đồ tương tác tại `http://localhost:5001`.

## 4. Các bước Reproduce Kết quả E2E
1. Sao chép `.env.example` thành `.env` và bật cờ giả lập: `MOCK_LLM=1`.
2. Chạy `docker-compose up -d mlflow redis`
3. Nhúng dữ liệu tri thức: `python src/rag/embedder.py` (tạo ra 256 vector).
4. Chạy thực nghiệm chính: `python experiments/run_ablation_study.py`.
5. Đọc kết quả log F1, Prec, Rec tại màn hình Terminal hoặc giao diện MLflow.

---
*Lưu ý: Nếu bạn có phần cứng GPU mạnh mẽ, hãy đổi `MOCK_LLM=0` và nhập URL thực của Oobabooga LLM vào `LLM_API_BASE` để chạy toàn phần (Full Inference).*
