# SENTINEL — Reproducibility Package

> **Trạng thái:** HOÀN THIỆN
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

**Lưu ý:** Gemma 2 9B Q6_K yêu cầu ~12GB VRAM. Nếu dùng Gemma 2 26B Q4_K_M làm Oracle Judge, cần tổng ~20GB VRAM.

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

---

## 4. Dataset Preparation

### CICIDS2017 (Kịch bản PCAP)
```bash
# Tải Thursday-WorkingHours.pcap (~8GB) từ UNB
# https://www.unb.ca/cic/datasets/ids-2017.html
# Đặt vào: data/raw/Thursday-WorkingHours.pcap
```

### Ground Truth Dataset
- **Có sẵn:** `experiments/ground_truth.json` (101 mẫu)
- **Reasoning cases:** `experiments/reasoning_ground_truth.json` (30 mẫu)
- **Adversarial samples:** `experiments/adversarial/` (45+ mẫu pre-built)

---

## 5. Chạy Experiments

### 5.1 Ablation Study (6 configs)
```bash
source .venv/bin/activate

# Chạy từng config ablation
python experiments/evaluate_accuracy.py --config config/ablation/config_a_rule_only.yaml
python experiments/evaluate_accuracy.py --config config/ablation/config_b_llm_only.yaml
python experiments/evaluate_accuracy.py --config config/ablation/config_c_no_encapsulation.yaml
python experiments/evaluate_accuracy.py --config config/ablation/config_d_mitre_only.yaml
python experiments/evaluate_accuracy.py --config config/ablation/config_e_iso_only.yaml
python experiments/evaluate_accuracy.py --config config/ablation/config_f_full.yaml
```

### 5.2 Adversarial Robustness Test
```bash
python experiments/evaluate_robustness.py
# Output: experiments/robustness_results.json
```

### 5.3 Unit & Integration Tests
```bash
# Unit tests
pytest tests/test_tier1_filter.py -v
pytest tests/test_adversarial.py -v

# Integration tests (requires Redis running)
pytest tests/integration/test_streaming_pipeline.py -v

# Full suite
pytest tests/ -v --tb=short
```

### 5.4 Full System E2E Demo
```bash
# Terminal 1: Infrastructure
docker-compose up -d redis mlflow

# Terminal 2: LLM (Oobabooga with Gemma 2 9B loaded)

# Terminal 3: SENTINEL Engine
source .venv/bin/activate && python main.py

# Terminal 4: Dashboard
source .venv/bin/activate && streamlit run src/ui/app.py

# Terminal 5: Traffic Simulation
source .venv/bin/activate && python scripts/simulate_traffic.py
```

---

## 6. Truy cập kết quả

| Service | URL | Nội dung |
|---------|-----|----------|
| Dashboard | http://localhost:8501 | SOC Analyst Interface |
| MLflow | http://localhost:5001 | Experiment Metrics & Charts |
| LLM WebUI | http://localhost:7860 | Model Management |

---

## 7. Cấu trúc Ablation Configs

Mỗi file YAML trong `config/ablation/` toggle on/off từng component:

| Config | Tier 1 | LLM | Guardrails | MITRE RAG | ISO RAG | Mục đích |
|--------|--------|-----|------------|-----------|---------|----------|
| A | ✅ | ❌ | ❌ | ❌ | ❌ | Rule-only baseline |
| B | ❌ | ✅ | ✅ | ✅ | ✅ | LLM-only (no pre-filter) |
| C | ✅ | ✅ | ❌ | ✅ | ✅ | No Guardrails delimiter |
| D | ✅ | ✅ | ✅ | ✅ | ❌ | MITRE-only RAG |
| E | ✅ | ✅ | ✅ | ❌ | ✅ | ISO-only RAG |
| F | ✅ | ✅ | ✅ | ✅ | ✅ | Full system |

---

## 8. Cách xác minh kết quả

1. **MLflow Dashboard** tại `http://localhost:5001` — Xem biểu đồ Latency, Confidence Score, Action Distribution cho mỗi ablation run.
2. **experiments/robustness_results.json** — Kết quả adversarial robustness test, Defeat Rate per category.
3. **config/audit_trail.db** — SQLite database chứa toàn bộ lịch sử quyết định của Agent.

---

## 9. Known Limitations

- **Iptables conflict trên Ubuntu 24.04:** Nếu Docker báo lỗi `DOCKER-ISOLATION-STAGE-2`, chạy: `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy && sudo systemctl restart docker`
- **VRAM constraint:** Gemma 2 9B Q6_K cần ~12GB VRAM. Không khuyến khích chạy song song 2 models.
- **HuggingFace warning:** Embedding model `all-MiniLM-L6-v2` sẽ hiện warning nếu chưa set `HF_TOKEN`. Bỏ qua được.
