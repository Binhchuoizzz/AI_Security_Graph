# Reproducibility Package

> **Trạng thái:** SKELETON
> **Mục đích:** Document yêu cầu về khả năng tái lập thí nghiệm dùng trong Contribution 3.

Nghiên cứu khoa học về AI Security bắt buộc hệ thống thử nghiệm có khả năng tái lập (Reproducibility) cao. Gói Reproducibility Package của luận văn SENTINEL cung cấp mọi công cụ để các nhà nghiên cứu độc lập hoặc hội đồng đánh giá có thể chạy lại các experiment và xác minh metric.

## Các thành phần của Reproducibility Package

1. **Environment Sandbox (`docker-compose.yml` & `.env.example`)**
   - Đảm bảo môi trường chạy Agent, Redis, và thư viện (Drain3, FAISS, LangGraph) hoàn toàn độc lập, thống nhất version.

2. **Ablation Configurations (`config/ablation/`)**
   - Chứa 6 file `.yaml` cấu hình sẵn các phiên bản của SENTINEL (A - F) theo đúng bài báo/luận văn. Người đánh giá chỉ cần bật cờ tham số cấu hình mà không phải sửa code.

3. **Ground Truth & Adversarial Datasets (`experiments/`)**
   - `ground_truth.json` (200 mẫu thử Context Quality)
   - `reasoning_ground_truth.json` (30 mẫu thử Reasoning, loại bỏ bias của LLM-as-a-Judge)
   - `adversarial/semantic_confusion/`, `adversarial/structural_attacks/`, `adversarial/encoding_bypass/` (1000+ payload được gán nhãn).

4. **Experiment Tracking Database (`mlruns/` hoặc `logs/`)**
   - MLflow SQLite database lưu toàn bộ nhật ký (metrics, loss, latency, rule execution) của tất cả ablation runs trong quá trình nghiên cứu, cho phép query tham khảo lại kết quả.

5. **Hardware Requirements & Setup Instructions**
   - Yêu cầu cấu hình tối thiểu: GPU NVIDIA RTX 4060 Ti 16GB, RAM 32GB, Storage SSD 100GB.
   - Script chạy thí nghiệm:
     ```bash
     pytest tests/integration/test_end_to_end.py
     python experiments/evaluate_accuracy.py --config F
     ```

Toàn bộ package sẽ được open-source hoặc cung cấp nguyên bản trong quá trình bảo vệ luận văn, minh bạch hóa methodology mà SENTINEL xây dựng.
