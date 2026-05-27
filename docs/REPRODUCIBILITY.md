# Hướng Dẫn Tái Tạo Thí Nghiệm (Reproducibility)

Tài liệu này cung cấp các hướng dẫn để các nhà nghiên cứu độc lập có thể tái tạo lại chính xác các kết quả thử nghiệm trong khung đánh giá **5D Evaluation Framework** của dự án SENTINEL.

## 1. Môi trường Thực thi
- **Phần cứng:** Cần có tối thiểu NVIDIA RTX 4060 Ti 16GB VRAM để chạy cục bộ LLM `Gemma-2-9B-IT` (Q4_K_M) thông qua `llama.cpp`. Có thể sử dụng API ngoài nếu cấu hình endpoint OpenAI-compatible trong file `.env`.
- **Hệ điều hành:** Linux (Ubuntu 20.04/22.04 LTS).
- **Python:** Phiên bản `3.10.x`.
- **Hạt giống ngẫu nhiên (Seed):** Mọi hàm random trong FAISS, Numpy và Data Splitting đều được cố định bằng Seed `42`.

## 2. Dataset & Tiền xử lý
- **Nguồn Dữ liệu:** Sử dụng bộ dữ liệu gốc **CSE-CIC-IDS2018** (cho Network Anomaly) và **DAPT2020** (cho APT Chains).
- **Ground Truth:** Để đánh giá chính xác, hệ thống sử dụng tập `experiments/ground_truth.json` gồm 750 samples (15 classes, 50 samples mỗi class).
- **Adversarial Samples:** Tập `experiments/adversarial_samples.json` gồm 45 mẫu chia làm 3 loại (Encoding Bypass, Structural Attacks, Semantic Confusion) để đo lường Defeat Rate.

## 3. Khung Đánh giá 5D (5D Evaluation Framework)

Toàn bộ 20 bài Test thành phần có thể được xác thực qua script E2E:
```bash
python experiments/e2e_test_runner.py --offline
```

Đối với các thực nghiệm chuyên sâu đo lường tham số học thuật:

**1. Phân loại (Classification):**
- Đo F1-Score, Precision, Recall, và McNemar's Test so sánh 6 cấu hình (Ablation).
- Lệnh: `python experiments/run_ablation_study.py`

**2. Vận hành (Operational):**
- Đo lường mức giảm độ trễ (Latency Reduction target ≥ 60%) và kiểm định Mann-Whitney U.
- Lệnh: `python experiments/measure_latency_baseline.py`

**3. Kháng cự (Robustness):**
- Đo lường Defeat Rate (mục tiêu < 10%).
- Lệnh: `python experiments/evaluate_robustness.py`

**4. Chất lượng Ngữ cảnh (Context Quality):**
- Chấm điểm reasoning bằng phương pháp cross-family LLM-as-Judge (dùng Llama 3 chấm điểm Gemma 2).
- Lệnh: `python experiments/evaluate_reasoning.py`

**5. Giải thích (Explainability):**
- Tính toàn vẹn của Audit Trail DB. Tích hợp trong `evaluate_reasoning.py` và `e2e_test_runner.py`.

## 4. Quản lý Thí nghiệm (MLflow Tracking)
Hệ thống sử dụng **MLflow** để tự động log và phiên bản hóa mọi thông số:
- Các kết quả được MLflow quản lý tại thư mục `mlruns/` (Local SQLite) và xem biểu đồ tại `http://localhost:5001`.
- Log bao gồm Hyperparameters (Temperature=0.1) và Metrics của từng luồng.
