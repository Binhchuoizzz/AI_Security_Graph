# Hướng Dẫn Tái Tạo Thí Nghiệm (Reproducibility)

Tài liệu này cung cấp các hướng dẫn để các nhà nghiên cứu độc lập có thể tái tạo lại chính xác các kết quả thử nghiệm trong khung đánh giá **5D Evaluation Framework** của dự án SENTINEL.

## 1. Môi trường Thực thi

- **Phần cứng:** Cần có tối thiểu NVIDIA RTX 4060 Ti 16GB VRAM để chạy cục bộ LLM `Gemma-2-9B-IT` (Q6_K, file `gemma-2-9b-it-Q6_K.gguf`) thông qua `llama.cpp`. Có thể sử dụng API ngoài nếu cấu hình endpoint OpenAI-compatible trong file `.env`.
- **Hệ điều hành:** Linux (Ubuntu 20.04/22.04 LTS).
- **Python:** Phiên bản `3.10.x`.
- **Hạt giống ngẫu nhiên (Seed):** Mọi hàm random trong FAISS, Numpy và Data Splitting đều được cố định bằng Seed `42`. **Suy luận LLM cũng tất định:** `temperature=0.1` + `seed=42` (config `llm.seed`) → cùng prompt cho cùng phán quyết (kiểm chứng bằng `experiments/run_llm_robustness.py`). *(Lưu ý: GPU batching có thể khiến văn bản thô đôi khi khác vài ký tự nhưng `action` sau parse luôn ổn định.)*

## 2. Dataset & Tiền xử lý

- **Nguồn Dữ liệu:** Sử dụng bộ dữ liệu gốc **CSE-CIC-IDS2018** (cho Network Anomaly) và **DAPT2020** (cho APT Chains).
- **Ground Truth:** Để đánh giá chính xác, hệ thống sử dụng tập `experiments/ground_truth.json` gồm **4,267 samples** (14 lớp tấn công + Benign + 50 mẫu adversarial), stratified sampling với `random_state=42`.
- **Adversarial Samples:** Bộ `experiments/adversarial/` gồm **120 mẫu** chia làm **5 loại đã sinh mẫu** (`encoding_bypass` 45, `structural_attacks` 20, `semantic_confusion` 20, `jailbreak` 20, `rag_poisoning` 15) để đo lường tỉ lệ kháng (block rate) / tỉ lệ lọt (bypass rate); loại thứ 6 `rule_injection` mới ở dạng skeleton, chưa sinh mẫu. Ngoài ra `adversarial_samples.json` (50 mẫu: 25 structural + 25 semantic) phục vụ test tích hợp.

## 3. Khung Đánh giá 5D (5D Evaluation Framework)

Toàn bộ 22 bài Test thành phần có thể được xác thực qua script E2E:

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
- **Biến thể ONLINE (demo end-to-end, không dùng làm benchmark):** `python experiments/stream_unified_online.py` phát CÙNG luồng gộp lên Redis qua toàn pipeline (Tier-1 → APT emergent ở subscriber → LLM Agent → Dashboard); cần Redis + `main.py --mode server`. Số liệu tái lập (deterministic) lấy từ bản offline ở trên.

**6. Giải thích (Explainability):**

- Tính toàn vẹn của Audit Trail DB. Tích hợp trong `evaluate_reasoning.py` and `e2e_test_runner.py`.

## 3b. Thực nghiệm Rigor, Robustness & Observability (bổ sung)

Các thực nghiệm tăng độ chặt chẽ (rebut hội đồng) + độ bền LLM + quan sát ngữ cảnh. Tất định khi không cần LLM; chỉ Ablation B–E/cân bằng và determinism cần LLM server.

- **Độ nhạy ngưỡng Welford** (bác bỏ "3.5σ cherry-pick"): `python experiments/run_threshold_sensitivity.py` → `results/threshold_sensitivity_results.json`.
- **Zero-day phân cấp** (đường cong ranh giới k·σ): `python experiments/run_zeroday_graded.py` → `results/zeroday_graded_results.json`.
- **Đối chứng âm APT + Wilson 95% CI** (specificity trên IP benign đa-ngày): `python experiments/run_apt_negative_control.py` → `results/apt_negative_control_results.json`.
- **Ablation B–E** (pure-LLM / Welford-gate / dense-RAG / hybrid-RAG, 300 mẫu): `python experiments/run_ablation_bcde.py` → `results/ablation_bcde_results.json`.
- **Ablation cân bằng 150/150** (A–F so được, warmup benign thật): `python experiments/run_ablation_balanced.py` → `results/ablation_balanced_results.json`.
- **Stress ngữ cảnh** (RAW vs Drain-compressed vs `n_ctx`): `python experiments/run_context_stress.py` → `results/context_stress_results.json` + `results/plots/context_stress.png`.
- **Độ bền LLM** (determinism seed + suy biến an toàn → AWAIT_HITL): `python experiments/run_llm_robustness.py` → `results/llm_robustness_results.json`.
- **Quan sát ngữ cảnh runtime:** `src/agent/token_monitor.py` ghi `config/llm_token_stats.json` (mean/p95/max/utilization% token) trong mọi lần chạy có gọi LLM; Dashboard hiển thị KPI "Context Utilization". Biểu đồ độ nhạy/zero-day vẽ bằng `python experiments/plot_results.py`.

## 4. Quản lý Thí nghiệm (MLflow Tracking)

Hệ thống sử dụng **MLflow** để tự động log và phiên bản hóa mọi thông số:

- Các kết quả được MLflow quản lý tại thư mục `mlruns/` (Local SQLite) và xem biểu đồ tại `http://localhost:5001`.
- Log bao gồm Hyperparameters (Temperature=0.1, Seed=42) và Metrics của từng luồng thử nghiệm (F1, Latency, Block/Bypass Rate, reasoning quality scores).
