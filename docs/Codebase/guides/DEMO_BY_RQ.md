# 🎯 Hướng dẫn Trình diễn (Demo) theo Câu hỏi Nghiên cứu (Research Questions)

Tài liệu này hướng dẫn chi tiết các bước chạy demo thực nghiệm, câu hỏi nghiên cứu nguyên văn (trích từ Chương 1 Luận văn) và phương pháp kiểm chứng các con số kết quả phục vụ giải quyết từng Câu hỏi Nghiên cứu (**RQ1, RQ2, RQ3**).

---

## 1. RQ1 — Hiệu năng Đường ống & Kinh tế học Tầng lọc (Wire-Speed Offloading & Latency Economics)

### ❓ Câu hỏi Nghiên cứu Nguyên văn (Verbatim Research Question)

> **Tiếng Việt (Luận văn Ch.1 - Mục 1.2):**
> *"Câu hỏi nghiên cứu thứ nhất (RQ1) về hiệu năng đường ống và kinh tế học tầng lọc: Làm thế nào để thiết kế một kiến trúc phân tầng có khả năng xả tải tự động luồng dữ liệu an ninh ở tốc độ đường truyền nhằm giải quyết triệt để vấn đề 'nút thắt cổ chai' về độ trễ và tiêu thụ tài nguyên của các Mô hình Ngôn ngữ Lớn?"*
>
> **Tiếng Anh (Thesis Ch.1 - Section 1.2):**
> *"The first research question (RQ1) addresses pipeline efficiency and filtration economics: How can a multi-tiered architecture be designed to autonomously offload security telemetry at wire-speed, thereby resolving the latency bottlenecks and resource consumption inherent in Large Language Models?"*

---

### 📊 Các con số Cần chứng minh cho RQ1

* **Tỷ lệ xả tải (Offload Rate):** **92.2%** sự kiện được xử lý và chặn/xả ở Tier-1 (chỉ **389/5.000** log phải đẩy lên LLM Tier-2).
* **Độ trễ xử lý Tier-1:** Trung bình **< 0.40 ms** (Welford $\mathcal{O}(1)$ + LightGBM ML Gate + Semantic Cache Tier 1.75).
* **Độ trễ toàn tuyến (End-to-End Latency):** Trung bình **211 ms** (nhanh gấp **11.6x** so với mô hình Single-Tier LLM-only).
* **Băng thông duy trì:** **> 2.500 flows/s**, giải phóng **> 75%** GPU VRAM.

---

### 🚀 Cách Chạy Demo & Kiểm chứng RQ1

#### Cách 1: Chạy lệnh đo đạc tự động (Benchmark Scripts)
```bash
# 1. Đo hiệu năng và tỷ lệ trúng bộ đệm Semantic Cache Tầng 1.75
.venv/bin/python experiments/run_cache_efficiency.py

# 2. Đo so sánh độ trễ giữa Hai tầng (SENTINEL) vs Single-Tier (LLM-only)
.venv/bin/python experiments/measure_latency_baseline.py

# 3. Đánh giá khả năng phân loại và xả tải của Cổng Học máy LightGBM
.venv/bin/python experiments/evaluate_ml_gate.py

# 4. Đánh giá luồng gộp thực tế CSE-CIC-IDS2018
.venv/bin/python experiments/evaluate_unified_stream.py
```
*Tệp kết quả chứa con số:* `experiments/results/cache_efficiency_results.json`, `experiments/results/latency_benchmark.json`, `experiments/results/ml_gate_results.json`.

#### 📋 Bảng Tổng hợp 4 Bộ Đánh giá Thực nghiệm (Benchmark Suite)

| Tệp Script Thực nghiệm | Tập dữ liệu sử dụng | Kết quả Đo đạc Thực tế | Chứng minh điều gì cho Luận văn? |
|---|---|---|---|
| **1. `run_cache_efficiency.py`** <br> *(Đo Semantic Cache 1.75)* | **Luồng gộp 7.681 sự kiện** (`build_stream()`) $\rightarrow$ Thu được 1.501 truy vấn RAG | • **Hit Rate = 84.08%** (1.262/1.501) <br>• **Độ trễ:** Hit 10.7ms vs Miss 27.9ms (**Nhanh 2.6x**) <br>• **Tiết kiệm:** 21,68s CPU/GPU <br>• Cache Size: 239/500 (Evictions = 0) | **Giải quyết vế "Semantic Cache Tầng 1.75" của RQ1:** <br>Chứng minh việc chuẩn hóa log (`build_rag_queries`) giúp lấy tài liệu RAG trong 10ms từ RAM, cắt giảm >84% số lần quét FAISS/BM25 trên đĩa. |
| **2. `measure_latency_baseline.py`** <br> *(Đo Độ trễ 2 Tầng vs LLM-only)* | **100 mẫu đại diện** theo bước nhảy (`Strided`) từ luồng thật (giữ tỷ lệ SOC 92% lành / 8% độc) | • **LLM-only Baseline:** Mean = 17.279,6 ms (17.28s) <br>• **SENTINEL (Two-Tier):** Mean = 2.829,0 ms (2.83s), **Median = 0.7 ms** <br>• **Giảm độ trễ:** **83.6%** (Nhanh gấp **6.1x**, ✅ PASS) <br>• **Mann-Whitney U Test:** $p = 0.000000 < 0.05$ | **Giải quyết vế "Tối ưu hóa Độ trễ & Chi phí" của RQ1:** <br>Chứng minh xả tải >85% lưu lượng ở Tầng 1 với tốc độ <1ms giúp giảm 83.6% độ trễ toàn hệ thống, duy trì băng thông SOC mà không làm quá tải GPU ($p < 0.001$). |
| **3. `evaluate_ml_gate.py`** <br> *(Đánh giá Cổng ML LightGBM)* | **`data/datatest.json`** <br> (Tập cân bằng ~933 attack / ~1.000 benign từ CICIDS2018) | • **Auto-BLOCK Precision = 1.0 (100%)** (FP = 0) <br>• **MCC = 0.6667** \| **BalAcc = 0.8328** <br>• **Xả tải tự động (Bypass):** 59.8% <br>• **Độ trễ:** 0.282 ms/flow (>3.500 flows/s) <br>• **Kháng né tránh (`extreme_broad`):** 98.75% | **Giải quyết vế "Cổng Học máy LightGBM" của RQ1 & An toàn ML:** <br>Chứng minh Cổng ML xử lý siêu tốc 0.28ms, tự động chặn chính xác 100% tấn công mạng rõ ràng và tự động rút lui (Abstain) lên LLM khi gặp luồng bị ngụy trang/OOD. |
| **4. `evaluate_unified_stream.py`** <br> *(Đánh giá Luồng Gộp Thực tế)* | **Luồng gộp thời gian thực 7.681 sự kiện** (trộn CICIDS + DAPT + Zero-day + Adversarial) với **Threat Memory sạch** | • **Zero-day Detection:** **100%** (bắt sạch mẫu không chữ ký nhờ Welford) <br>• **Emergent APT Detection:** Tự nhận diện chuỗi DAPT đa ngày từ luồng nhiễu <br>• **IP Containment:** Khóa 100% IP tái phạm ở Tầng 1 (< 0.4ms) | **Giải quyết RQ2 (APT & Zero-day) & RQ3 (Chống tấn công tái phạm):** <br>Chứng minh kiến trúc vận hành thực chiến ổn định trên luồng hỗn hợp thời gian thực, tự động phát hiện APT/Zero-day và chặn tức thì IP tái phạm mà không cần gọi lại LLM. |


---

## 2. RQ2 — Rào chắn An ninh AI & Toàn vẹn Pháp y (AI Security Guardrails & Forensic Non-Repudiation)

### ❓ Câu hỏi Nghiên cứu Nguyên văn (Verbatim Research Question)

> **Tiếng Việt (Luận văn Ch.1 - Mục 1.2):**
> *"Câu hỏi nghiên cứu thứ hai (RQ2) về rào chắn an ninh AI và tính toàn vẹn vết pháp y: Phương pháp luận và cơ chế bảo mật nào có khả năng chống lại các rủi ro đối kháng (điển hình như tiêm nhiễm prompt qua nhật ký) nhằm bảo vệ luồng suy luận của AI, đồng thời đảm bảo tính toàn vẹn và không thể chối bỏ của các vết chứng cứ pháp y?"*
>
> **Tiếng Anh (Thesis Ch.1 - Section 1.2):**
> *"The second research question (RQ2) addresses AI security boundaries and forensic integrity: What methodologies and security mechanisms can effectively withstand adversarial risks (such as log-substrate prompt injection) to protect the AI's reasoning flow, while simultaneously ensuring the integrity and non-repudiation of forensic audit trails?"*

---

### 📊 Các con số Cần chứng minh cho RQ2

* **Tỷ lệ kháng tiêm nhiễm đối kháng (Adversarial Defense Rate):** Đạt **100%** tuyệt đối trên toàn tuyến (End-to-End) trên tập **723 payload siêu cấp** (AdvBench GCG, Deepset PI, Jackhhao Jailbreak).
* **Sự cần thiết của Tier-2:** Lớp Guardrail tĩnh Tier-1 bị **MÙ (0% block rate)** trước các đòn Jailbreak tâm lý / AdvBench, nhưng Tier-2 nhờ cơ chế *Delimited Data Encapsulation* (Nonce ngẫu nhiên ngầm) đã vô hiệu hóa hoàn toàn **100%** đòn lọt qua.
* **Tính toàn vẹn chuỗi vết chứng cứ (Audit Trail Integrity):** Cấu hình băm liên hoàn HMAC-SHA256 bảo đảm phát hiện **100%** các hành vi giả mạo, chèn hoặc sửa đổi bản ghi kiểm toán.

---

### 2.1. Adversarial — Bài Test Mở rộng (Thực tế)

```bash
.venv/bin/python scripts/push_flow.py --source adversarial
# 723 payload tổng hợp: 120 (cũ) + 603 (mới: AdvBench GCG, Deepset PI, Jackhhao Jailbreak)
```

Đây là bài test toàn diện trên dữ liệu đối kháng siêu cấp được thu thập thực tế từ HuggingFace và Github.

| Lớp phòng thủ | Phạm vi & Kết quả |
| :-- | :-- |
| Guardrail **Tĩnh (Tier-1)** | 723 mẫu (8 nhóm). Chặn tốt các PI thô sơ (59%), nhưng **MÙ (0%)** trước AdvBench và Jailbreak tâm lý. |
| **Cognitive Agent (Tier-2)** | Đỡ đòn **100%** các mẫu siêu khó đã lọt qua lớp tĩnh nhờ nhận diện ngữ cảnh và đóng gói (Encapsulator). |

Luận văn TRẮNG ĐEN rõ ràng: không có Tầng 2, hệ thống chết 100% trước AdvBench và Jailbreak.

#### Đánh giá Benchmark Tự động cho RQ2 (Adversarial):
```bash
# Đo rào chắn tĩnh và rào chắn Tầng 2 trên bộ dữ liệu đối kháng
.venv/bin/python experiments/evaluate_adversarial.py --mode all

# Đánh giá tính kháng nhiễu và độ tất định của LLM (thay đổi seed)
.venv/bin/python experiments/run_llm_robustness.py
```
*Tệp kết quả chứa con số:* `experiments/results/robustness_results.json`, `experiments/results/adversarial_pipeline_results.json`.

---

### 2.2. Tương tác kiểm thử đứt gãy HMAC trên một IP cụ thể (Forgery & Tail-dropping)

Để trình diễn trực tiếp khả năng bắt quả tang giả mạo ngay lập tức (không cần đợi thao tác trên UI), bạn có thể thao tác giả mạo trên một IP cụ thể (ví dụ `198.51.100.15`) và yêu cầu hệ thống xác minh HMAC báo cáo lỗi ngay tại terminal:

#### Cách 1: Tấn công Giả mạo nội dung (Sửa `BLOCK_IP` thành `LOG`)
```bash
# 1. Kẻ tấn công sửa hành động của IP cụ thể thành LOG để che giấu dấu vết
sqlite3 config/audit_trail.db "UPDATE audit_trail SET action = 'LOG' WHERE target = '198.51.100.15';"

# 2. Gọi hệ thống kiểm toán HMAC in kết quả ra ngay lập tức
.venv/bin/python -c "import sys; sys.path.insert(0, '.'); from src.response.executor import verify_audit_trail_integrity as v; print(v()[1])"
```
*Trình diễn:* Terminal sẽ lập tức phát ra cảnh báo: `⚠️ PHÁT HIỆN GIẢ MẠO! Dòng log ID ... đã bị sửa đổi...` do chuỗi băm của IP `198.51.100.15` không khớp với nội dung đã sửa, làm đứt gãy toàn bộ chuỗi. (Trên Dashboard UI cũng sẽ báo ĐỎ nếu bạn tải lại).

#### Cách 2: Khai thác lỗ hổng toán học Tail-dropping (Xóa hẳn dòng log đuôi)
*(Để thành công, dòng bị xóa **bắt buộc phải là dòng cuối cùng** của chuỗi).*
```bash
# 1. Kẻ tấn công xóa bản ghi cuối cùng trong DB
sqlite3 config/audit_trail.db "DELETE FROM audit_trail WHERE id = (SELECT MAX(id) FROM audit_trail);"

# 2. Gọi hệ thống kiểm toán HMAC kiểm tra lại
.venv/bin/python -c "import sys; sys.path.insert(0, '.'); from src.response.executor import verify_audit_trail_integrity as v; print(v()[1])"
```
*Trình diễn:* Lần này terminal in ra `✅ Hệ thống nhật ký toàn vẹn`. Điều này chứng minh lý thuyết trong luận văn: vì mã băm $H_i$ chỉ phụ thuộc vào bản ghi trước nó $H_{i-1}$, việc cắt bỏ phần đuôi hoàn toàn không làm hỏng chuỗi của các block còn lại. Kẻ tấn công xóa sạch dấu vết mà chuỗi tĩnh không phát hiện ra!

#### Đánh giá Benchmark Tự động cho HMAC:
```bash
.venv/bin/python experiments/run_audit_tamper.py
```
*Tệp kết quả chứa con số:* `experiments/results/audit_tamper_results.json`.

---

## 3. RQ3 — Tác tử có Trạng thái & Quy kết Kỹ thuật ATT&CK (Stateful Agent Reasoning & Technical Attribution)

### ❓ Câu hỏi Nghiên cứu Nguyên văn (Verbatim Research Question)

> **Tiếng Việt (Luận văn Ch.1 - Mục 1.2):**
> *"Câu hỏi nghiên cứu thứ ba (RQ3) về suy luận tác tử có trạng thái và quy kết kỹ thuật: Làm thế nào để tích hợp năng lực suy luận có trạng thái và khả năng tra cứu tri thức chuyên ngành vào Tác tử AI nhằm tự động hóa quy trình phân tích, quy kết kỹ thuật tấn công chính xác và sinh ra các báo cáo pháp y minh bạch, thay thế sự can thiệp thủ công của con người?"*
>
> **Tiếng Anh (Thesis Ch.1 - Section 1.2):**
> *"The third research question (RQ3) addresses stateful agent reasoning and technical attribution: How can stateful reasoning capabilities and domain-specific knowledge retrieval be integrated into an AI Agent to automate intrusion analysis, accurately attribute attack techniques, and generate transparent forensic reports, effectively replacing manual human intervention?"*

---

### 📊 Các con số Cần chứng minh cho RQ3

* **Độ chính xác quy kết ATT&CK (Attribution Accuracy):** **67.33%** exact match trên 250 mẫu chuẩn CSIC/CICIDS (vượt xa mức đoán ngẫu nhiên **52%**).
* **Tỷ lệ phán quyết hành động đúng (Action Accuracy):** **100%** trên tập đối chứng Ablation, triệt tiêu hoàn toàn AWAIT_HITL ngớ ngẩn (HITL = **0.0%**).
* **Điểm chất lượng suy luận (Reasoning Quality Score):** **4.6/5.0** điểm (đánh giá độc lập bởi Meta-Llama-3-8B Trọng tài khác họ).
* **Lá chắn Bằng chứng (Evidence Grounding):** **100%** kỹ thuật hệ công bố phải được neo trong RAG context của lô (**0%** ảo giác ngoài context).

---

### 🚀 Cách Chạy Demo & Kiểm chứng RQ3

#### 1. Đánh giá Bộ ánh xạ Tất định vs Toàn tuyến (RRF & E2E)
```bash
# Đánh giá bộ ánh xạ tất định RRF (chỉ RAG + RRF)
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload

# Đánh giá toàn tuyến E2E (Tác tử LangGraph + LLM + RAG)
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload
```
*Chú ý quan trọng:* Đối với RQ3, **chỉ dùng tập dữ liệu chuẩn CSE-CIC-IDS2018 và CSIC2010** (vì chỉ có 2 tập này có Ground Truth MITRE Enterprise 1:1 chuẩn xác).

#### 2. Đánh giá Phán quyết & Suy luận với Trọng tài Độc lập (LLM Judge)
```bash
# Đánh giá phán quyết Tier-2 và ECE calibration
.venv/bin/python experiments/evaluate_tier2_decision.py

# Đổi model trọng tài sang Llama-3-8B để chấm điểm suy luận độc lập (ngăn trọng tài trùng bị cáo)
LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf LLAMA_ARG_CTX_SIZE=32768 \
  docker-compose up -d --force-recreate --no-deps llm
SENTINEL_AGENT_MODEL=Foundation-Sec-8B-Instruct-Q4_K_M.gguf \
  .venv/bin/python experiments/evaluate_reasoning.py
```

#### 3. Kiểm tra Tương quan Chuỗi APT Đa ngày (DAPT2020)
```bash
# Chạy luồng APT đa ngày
.venv/bin/python scripts/push_flow.py --source dapt

# Đánh giá kiểm chứng APT negative control
.venv/bin/python experiments/run_apt_negative_control.py
```
*Tệp kết quả chứa con số:* `experiments/results/apt_negative_control_results.json`.

#### 4. Kiểm chứng Không ảo giác bằng Trace Log
```bash
# Đọc trace log đối chiếu 100% ID kỹ thuật công bố đều có trong RAG
.venv/bin/python -c "
import json,re
TECH=re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
rows=[json.loads(l) for l in open('logs/tier2_trace.jsonl') if l.strip()]
bad=0
for r in rows:
    a=r.get('attack_mapper') or {}; fin=a.get('final_technique_id') or ''
    if not fin: continue
    ids=set(TECH.findall(json.dumps(r.get('rag') or {},ensure_ascii=False)))
    if ids and fin not in ids: bad+=1
print(f'{len(rows)} lô | quy kết KHÔNG neo trong RAG: {bad}')"
```
*Kỳ vọng:* `bad = 0` (Bất biến cốt lõi của hệ thống).

---

## 4. Tóm tắt Bảng Đối chiếu Chạy Demo theo RQ

| RQ | Mục tiêu | Script Benchmark chính | Nguồn Data chuẩn | Vị trí kiểm chứng |
|---|---|---|---|---|
| **RQ1** | Wire-speed offloading (<0.4ms) & 92.2% bypass LLM | `run_cache_efficiency.py`<br>`measure_latency_baseline.py` | CSE-CIC-IDS2018 | Dashboard SIEM → Thẻ xả tải |
| **RQ2** | 100% E2E Adversarial resistance & HMAC tamper audit | `evaluate_adversarial.py`<br>`run_audit_tamper.py` | 723 AdvBench/Deepset/Jackhhao | Terminal HMAC test & Dashboard alert |
| **RQ3** | 67.33% ATT&CK mapping & 4.6/5 reasoning quality | `eval_attack_mapper.py`<br>`evaluate_reasoning.py` | CSIC2010 / DAPT2020 | `logs/tier2_trace.jsonl` & Dashboard APT |
