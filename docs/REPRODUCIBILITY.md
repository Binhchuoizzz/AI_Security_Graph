# SENTINEL — Reproducibility Package

> **Trạng thái:** HOÀN THIỆN (v4 — 5D Framework v2_5D — Cập nhật 22/04/2026)
> **Mục đích:** Document đầy đủ yêu cầu để tái lập toàn bộ experiments của luận văn.

---

## 1. Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU | NVIDIA RTX 4060 Ti 16GB VRAM | RTX 4090 24GB VRAM |
| RAM | 32GB DDR4 | 64GB DDR5 |
| Storage | 100GB SSD | 256GB NVMe SSD |
| OS | Ubuntu 22.04+ LTS | Ubuntu 24.04 LTS |
| Docker | Docker Engine 24.0+ | Docker Engine 27.0+ |

**Lưu ý về Hệ sinh thái 3 Models:** Để tái lập hoàn toàn nghiên cứu này, cần 3 models độc lập:
1. `all-MiniLM-L6-v2` (Tự động tải về khi chạy code Python).
2. `Gemma 2 9B Q6_K` (Model Triage chính, yêu cầu ~12GB VRAM, chạy trên Oobabooga).
3. `Llama 3 8B Instruct` (Chỉ dùng lúc Evaluate RAGAS, chạy trên Oobabooga).
*Trong môi trường Production thực tế, hệ thống chỉ cần Model 1 và 2.*

---

## 2. Software Dependencies

```bash
# 1. Clone repository
git clone https://github.com/Binhchuoizzz/AI_Security_Graph.git
cd AI_Security_Graph

# 2. Tạo môi trường ảo
python3.10 -m venv .venv
source .venv/bin/activate

# 3. Cài đặt dependencies
pip install -r requirements.txt

# 4. Copy file cấu hình
cp .env.example .env
# Chỉnh sửa .env nếu cần (Redis password, MLflow URI, LLM API)

# 5. Khởi động infrastructure
docker-compose up -d redis mlflow
```

---

## 3. LLM Setup (Oobabooga Text Generation WebUI)

```bash
# Cài đặt Oobabooga
git clone https://github.com/oobabooga/text-generation-webui.git
cd text-generation-webui
./start_linux.sh

# Tải model Gemma 2 9B IT (Q6_K quantization)
# Trong WebUI → Model → Download: google/gemma-2-9b-it-GGUF

# Bật API extension:
# Session → Extensions → Check "openai" → Apply and Restart
# API sẽ chạy tại http://localhost:5000/v1
```

**Lưu ý về 3 Model trong hệ thống:**

| Model | Vai trò | Cách chạy |
|---|---|---|
| Rule Engine & Session Baseline | Tier 1 — Heuristic filter | Tự động (Python thuần, không cần GPU) |
| `all-MiniLM-L6-v2` | Embedding cho RAG (FAISS) | Tự động (chạy ngầm qua `sentence-transformers`) |
| `Gemma 2 9B Q6_K` | LLM Reasoning (Tier 2 Agent) | **Cần bật Oobabooga** trước khi chạy `main.py` |

---

## 4. Dataset Preparation

### CICIDS2017 (CSV từ HuggingFace)

```bash
# Tải tự động qua script
source .venv/bin/activate
python scripts/fetch_and_build_dataset.py

# Hoặc file Demo đã được trích xuất sẵn:
# data/raw/Demo-Attack.csv (50 BENIGN + 500 DDoS — demo nhanh)
```

### Ground Truth Dataset
- **Có sẵn:** `experiments/ground_truth.json` (101 mẫu — 81 attack + 20 benign)
- **Adversarial samples:** `experiments/adversarial/` (45 mẫu pre-built — 3 loại)

---

## 5. Chạy Experiments

### 5.1 Live Demo — Streaming Pipeline (Sát thực tế)

```bash
# Terminal 1: Infrastructure
docker-compose up -d redis mlflow

# Terminal 2: Bật Oobabooga + Load Gemma 9B

# Terminal 3: SENTINEL Core — xem trực tiếp các Node hoạt động
source .venv/bin/activate && python main.py

# Terminal 4: Dashboard SOC
source .venv/bin/activate && streamlit run src/ui/app.py
# → Truy cập http://localhost:8501 (manager / sentinel_manager_2026)

# Terminal 5: Bắn dữ liệu tấn công
source .venv/bin/activate && python src/streaming/publisher.py
```

### 5.2 Ablation Study — 5D Metrics (Gemma 9B loaded)

```bash
source .venv/bin/activate

# 1. Chạy 101 mẫu: F1, FPR, MTTD_Proxy, MTTR_Proxy, HITL Rate, Cache Hit Rate
python experiments/run_ablation_study.py

# 2. Tính p-value thống kê (McNemar + Mann-Whitney U)
python experiments/statistical_tests.py
```

### 5.3 Adversarial Robustness (Không cần LLM)

```bash
# 3. Chạy 45 adversarial samples qua Guardrails
python experiments/evaluate_robustness.py
```

### 5.4 RAGAS-inspired LLM-as-Judge (Llama 3 8B loaded)

```bash
# 4. Unload Gemma 9B → Load Llama 3 8B Instruct trên Oobabooga
# 5. Chạy Cross-Family LLM-as-Judge + Audit Completeness
python experiments/evaluate_reasoning.py
```

> **⚠️ DISCLAIMER:** Evaluation metrics được gắn tag `methodology="RAGAS-inspired proxy metrics"` trong MLflow. Đây KHÔNG phải thư viện `ragas` gốc (NLI decomposition).

### 5.3 Unit & Integration Tests

```bash
# Chạy toàn bộ 79 bài test
pytest tests/ -v --tb=short
# Kết quả kỳ vọng: 79 passed in 0.17s
```

---

## 6. Truy cập kết quả

| Service | URL | Nội dung |
|---------|-----|----------|
| Dashboard | http://localhost:8501 | SOC Analyst Interface (HITL) |
| MLflow | http://localhost:5001 | Experiment Metrics & Charts |
| LLM WebUI | http://localhost:7860 | Model Management (Oobabooga) |

---

## 7. Phương pháp Đánh giá (5D Framework v2_5D)

SENTINEL sử dụng **Dual Evaluation Methodology**: Thống kê + Cross-family LLM-as-Judge.

| Chiều | Metric | Phương pháp | Ngưỡng |
|---|---|---|---|
| Classification | F1, Precision, Recall, FPR | McNemar's Test | p < 0.05 |
| Operational | MTTD/MTTR Proxy*, HITL Rate, Cache Hit | Mann-Whitney U Test | p < 0.05 |
| Robustness | Guardrail Defeat Rate | 45 curated adversarial samples | 3 loại tấn công |
| Context Quality | Context Precision, Faithfulness, Relevancy, Recall | RAGAS-inspired LLM-as-Judge (Llama 3 → Gemma 9B) | Thang 1-5 |
| Explainability | Audit Trail Completeness Rate | Deterministic field check | % |

> *Processing Latency proxy — không bao gồm ingestion/human review time thực tế.

---

## 8. Cách xác minh kết quả

1. **MLflow Dashboard** tại `http://localhost:5001` — Xem biểu đồ F1, Latency cho mỗi ablation run.
2. **experiments/ablation_results.json** — Kết quả chi tiết y_true, y_pred, latencies.
3. **tests/ (79/79 PASS)** — Chạy `pytest tests/` để xác minh toàn bộ logic hệ thống.

---

## 9. Known Limitations

- **Iptables conflict trên Ubuntu 24.04:** Nếu Docker báo lỗi `DOCKER-ISOLATION-STAGE-2`, chạy: `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy && sudo systemctl restart docker`
- **VRAM constraint:** Gemma 2 9B Q6_K cần ~12GB VRAM. Không khuyến khích chạy song song 2 models.
- **HuggingFace warning:** Embedding model `all-MiniLM-L6-v2` sẽ hiện warning nếu chưa set `HF_TOKEN`. Bỏ qua được.
- **LLM Latency:** Gemma 9B mất ~10-15s/lần suy luận. Đây là hành vi thiết kế — LLM đóng vai trò "Chuyên gia phân tích", không phải Firewall chặn gói tin.
