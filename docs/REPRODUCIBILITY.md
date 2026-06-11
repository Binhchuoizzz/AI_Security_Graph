# Hướng Dẫn Tái Tạo Thí Nghiệm (Reproducibility)

Tài liệu này cung cấp các hướng dẫn để các nhà nghiên cứu độc lập có thể tái tạo lại chính xác các kết quả thử nghiệm trong khung đánh giá **5D Evaluation Framework** của dự án SENTINEL.

## 1. Môi trường Thực thi

- **Phần cứng:** Cần có tối thiểu NVIDIA RTX 4060 Ti 16GB VRAM để chạy cục bộ LLM `Gemma-2-9B-IT` (Q4_K_M) thông qua `llama.cpp`. Có thể sử dụng API ngoài nếu cấu hình endpoint OpenAI-compatible trong file `.env`.
- **Hệ điều hành:** Linux (Ubuntu 20.04/22.04 LTS).
- **Python:** Phiên bản `3.10.x`.
- **Hạt giống ngẫu nhiên (Seed):** Mọi hàm random trong FAISS, Numpy và Data Splitting đều được cố định bằng Seed `42`.

## 2. Dataset & Tiền xử lý

- **Nguồn Dữ liệu:** Sử dụng bộ dữ liệu gốc **CSE-CIC-IDS2018** (cho Network Anomaly) và **DAPT2020** (cho APT Chains).
- **Ground Truth:** Để đánh giá chính xác, hệ thống sử dụng tập `experiments/ground_truth.json` gồm **4,267 samples** (14 lớp tấn công + Benign + 50 mẫu adversarial), stratified sampling với `random_state=42`.
- **Adversarial Samples:** Bộ `experiments/adversarial/` gồm **120 mẫu** chia làm **5 loại đã sinh mẫu** (`encoding_bypass` 45, `structural_attacks` 20, `semantic_confusion` 20, `jailbreak` 20, `rag_poisoning` 15) để đo lường tỉ lệ kháng (block rate) / tỉ lệ lọt (bypass rate); loại thứ 6 `rule_injection` mới ở dạng skeleton, chưa sinh mẫu. Ngoài ra `adversarial_samples.json` (50 mẫu: 25 structural + 25 semantic) phục vụ test tích hợp.

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

- Đo lường **tỉ lệ kháng / block rate** ở tầng static guardrails (mục tiêu bypass rate < 10%) trên 120 mẫu adversarial; bổ sung `evaluate_adversarial_pipeline.py` đo độ kháng của FULL pipeline (LLM + Tier-Consensus Guard).
- Lệnh: `python experiments/evaluate_robustness.py`

**4. Chất lượng Ngữ cảnh (Context Quality):**

- Chấm điểm reasoning bằng phương pháp cross-family LLM-as-Judge (dùng Llama 3 8B chấm điểm Gemma 2).
- Các bước thực hiện:
  1. Chạy `./scripts/switch_model.sh llama` để switch mô hình sang Llama 3.
  2. Lệnh: `python experiments/evaluate_reasoning.py`
  3. Chạy `./scripts/switch_model.sh gemma` để khôi phục lại Agent mặc định.

**5. Đánh giá Luồng Gộp Thống Nhất (Unified Streaming — Phân loại + APT + Zero-day):**

- **Thay thế** phương pháp 3 luồng tách rời cũ. Gộp CICIDS + DAPT2020 + Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ thống thật (Tier-1 + Welford + Threat Memory) với bộ nhớ **khởi tạo sạch** — phát hiện APT là **emergent** (không nạp sẵn đáp án, xóa bỏ tính circular), và zero-day signature-less bị Welford bắt khi rule tĩnh bỏ sót.
- Lệnh: `python experiments/evaluate_unified_stream.py`
- Kết quả và phân tích chi tiết được lưu tại `reports/unified_stream_evaluation_report.md`.

**6. Giải thích (Explainability):**

- Tính toàn vẹn của Audit Trail DB. Tích hợp trong `evaluate_reasoning.py` and `e2e_test_runner.py`.

## 4. Quản lý Thí nghiệm (MLflow Tracking)

Hệ thống sử dụng **MLflow** để tự động log và phiên bản hóa mọi thông số:

- Các kết quả được MLflow quản lý tại thư mục `mlruns/` (Local SQLite) và xem biểu đồ tại `http://localhost:5001`.
- Log bao gồm Hyperparameters (Temperature=0.1) và Metrics của từng luồng thử nghiệm (F1, Latency, Block/Bypass Rate, reasoning quality scores).
