# CAPSTONE PROJECT PROPOSAL

**Project Title:** SENTINEL — Autonomous AI Security Agent for Multi-source Log Correlation and Intrusion Response using LangGraph, Dual-RAG, and Adversarial Guardrails.

*(SENTINEL: Hệ thống phát hiện và phản ứng an ninh tự động dựa trên AI Agent đa nguồn kết hợp LangGraph, Dual-RAG và cơ chế phòng thủ Guardrails).*

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

---

## 1. Introduction and Background

### 1.1. Problem Description

Các Trung tâm Điều hành An ninh (SOC) hiện đại đang đối mặt với "Nghịch lý Dữ liệu lớn": Khối lượng sự kiện trên giây (EPS) khổng lồ dẫn đến tình trạng "quá tải cảnh báo" (alert fatigue). Theo báo cáo Ponemon Institute, trung bình một SOC analyst xử lý hơn 11,000 cảnh báo mỗi ngày, trong đó hơn 45% là dương tính giả. Các hệ thống IDS/SIEM truyền thống phân tích các nguồn dữ liệu (Web, Firewall, Auth) một cách rời rạc, làm giảm khả năng phát hiện chuỗi tấn công tinh vi (Multi-stage/APT attacks).

Việc ứng dụng LLM trực tiếp vào phân tích log sinh ra hai lỗ hổng chí mạng: (1) Độ trễ suy luận (Reasoning Latency) quá cao không đáp ứng được luồng dữ liệu thời gian thực, và (2) Rủi ro AI bị thao túng bởi Prompt Injection ẩn bên trong log — kẻ tấn công chèn chỉ thị độc vào các trường dynamic (User-Agent, Referer, Payload) mà LLM sẽ xử lý (OWASP Top 10 for LLM Applications, 2025). Đặc biệt, nghịch lý giữa việc cần giữ variables chứa payload để phân tích nhưng không để chúng kích hoạt Injection trong Context Window — là bài toán chưa ai giải quyết triệt để trong bối cảnh SOC tự động hóa.

### 1.2. Research Objectives

Nghiên cứu này xây dựng và đánh giá nguyên mẫu AI Security Agent có khả năng liên kết log đa nguồn theo thời gian thực, tự bảo vệ trước adversarial attacks, và hỗ trợ ra quyết định qua HITL. Các câu hỏi nghiên cứu:

- **RQ1:** Kiến trúc 2-Tier (Rule-based + LLM Agent) với Session-Aware Behavioral Baselining tối ưu Reasoning Latency như thế nào so với 1-Tier (LLM-only)?
- **RQ2:** Cơ chế Delimited Data Encapsulation (tách biệt log data khỏi LLM instruction space) có tác động ra sao đến Defeat Rate trước các đòn tấn công Prompt Injection qua log?
- **RQ3:** Dual-RAG (MITRE ATT&CK + ISO 27001) cải thiện Context Relevance và hỗ trợ quyết định HITL như thế nào?
- **RQ4:** Feedback Loop (Agent sinh Dynamic Rules cho Tier 1) giúp hệ thống thích ứng với Zero-day attacks hiệu quả ra sao?

### 1.3. Scope of the Project

- **In-scope:** Data Streaming Pipeline (Redis); Tier-1 Rule Engine với Session Baselining và Feedback Loop; LangGraph Agent với Dual-RAG cục bộ; Guardrails đa tầng gồm Volume Compression (Drain3 Template Mining) tách biệt với Injection Defense (Delimited Data Encapsulation); Streamlit HITL Dashboard với RBAC; MLOps (Docker, MLflow, SQLite Audit Trail).
- **Out-of-scope:** Fine-tuning Foundation Model; Apache Kafka vật lý; DDoS Layer 3/4 mitigation.

---

## 2. Proposed Solution

### 2.1. Solution Description

Kiến trúc **SENTINEL** được thiết kế theo nguyên tắc **Separation of Concerns** nghiêm ngặt — mỗi module giải quyết ĐÚNG MỘT bài toán, không lẫn lộn chức năng:

**A. Tier 1 — Speed Layer (Session-Aware Behavioral Baselining)**

> **LƯU Ý THIẾT KẾ:** Phiên bản đầu dùng Random Sampling (1-3% clean traffic) — đã bị loại bỏ vì phá hủy kill-chain APT. Random sampling ném bỏ 97-99% dữ liệu = bẻ gãy chuỗi bằng chứng tấn công low-and-slow.

Giải pháp thay thế: **Session Baselining** — Tier 1 duy trì behavioral profile cho mỗi Source IP:
- Ghi nhận 100% traffic vào baseline (request_count, unique_ports, avg_packet_size)
- Escalate lên Tier 2 khi phát hiện Statistical Deviation so với baseline (port scanning, high-frequency bursts, volumetric anomaly)
- Mọi quyết định dựa trên LOGIC, không có random — đảm bảo toàn bộ APT evidence chain được bảo toàn
- **Sliding Window TTL:** IP sessions inactive quá 10 phút tự động evict — chống RAM/Redis OOM khi chạy CICIDS2017 (~2.8M records)

**B. Guardrails Layer — Hai module TÁCH BIỆT**

> **LƯU Ý THIẾT KẾ:** Drain3 CHỈ nén volume, KHÔNG phòng thủ Prompt Injection. Đây là hai bài toán khác nhau cần giải pháp khác nhau.

**B1. Volume Compression (template_miner.py — Drain3):**
- Mục đích DUY NHẤT: Giảm 10,000 dòng log → N Templates để vừa Context Window
- Variables (phần động: IP, user, payload) được GIỮ NGUYÊN trong Samples gốc
- LLM cần thấy variables để phân tích — kể cả khi chúng chứa attack payload
- Output: Template summaries + raw samples → chuyển sang module Injection Defense

**B2. Injection Defense (prompt_filter.py — Delimited Data Encapsulation):**

Giải quyết nghịch lý cốt lõi: *"Làm sao giữ variables chứa payload cho phân tích mà không để chúng kích hoạt Prompt Injection?"*

Cơ chế 3 tầng (tương tự **Parameterized Query** trong SQL):
1. **Pattern Detection:** Quét và ĐÁNH DẤU (flag) chuỗi injection đã biết. Quan trọng: KHÔNG xóa/REDACT nội dung — vì đó CÓ THỂ là evidence cần phân tích.
2. **Encoding Neutralization:** Vô hiệu hóa encoding tricks (Base64, Hex, Unicode homoglyphs) mà kẻ tấn công dùng để bypass detection.
3. **Delimited Data Encapsulation** với **Dynamic Randomized Delimiters**: Mỗi request sinh delimiter MỚI bằng cryptographic hash (ví dụ: `<<<DATA_BEGIN_a7f3c9e2>>>`). Kẻ tấn công không thể đoán trước hash → không thể Delimiter Smuggling. Bước sanitize bổ sung: strip mọi chuỗi có dạng `<<<...>>>` trong raw data trước khi encapsulate.

Triết lý: Log data trở thành DATA trong prompt, không phải INSTRUCTION — tương tự cách Parameterized Query ngăn SQL Injection bằng việc tách data khỏi command.

**C. Tier 2 — Intelligence Layer (LangGraph Agent + Dual-RAG)**

- Gom nhóm sự kiện theo [IP + 5-phút window], sử dụng Dual-RAG ánh xạ vào MITRE ATT&CK và ISO 27001
- **Structured MemoryObject (chống Semantic Drift):** State của LangGraph chia làm 2 phần tách biệt:
  1. `narrative_summary`: Bối cảnh chung dạng text (LLM được phép tóm tắt)
  2. `extracted_iocs`: Mảng JSON cứng lưu IOCs — IP, Port, Hash (LLM CHỈ được APPEND, KHÔNG được tóm tắt đè lên)

  Lý do: Summary Memory thuần túy sẽ dẫn đến Semantic Drift — các IOCs chi tiết dần bị làm mờ qua mỗi vòng tóm tắt.

**D. Feedback Loop (Data Flow cụ thể)**

```
LangGraph Agent xác nhận mẫu tấn công mới
        │
        ▼
feedback_listener.py nhận rule (field, pattern, score)
        │
        ▼
Persist vào config/system_settings.yaml → tier1.dynamic_rules[]
        │
        ▼
RuleEngine.reload_dynamic_rules() (hot-reload)
        │
        ▼
Rule mới áp dụng ngay trong evaluate() tiếp theo
```

**E. Human-in-the-Loop (HITL)**

- Dashboard Streamlit, RBAC (L1 view-only, L3 approve/block), SQLite Audit Trail

### 2.2. Software Architecture

Kiến trúc Containerized Modular Architecture (Docker). ***Primary LLM: Gemma 2 9B Q6_K*** (~7GB VRAM) qua Oobabooga API trên RTX 4060 Ti 16GB VRAM, 32GB RAM. Chọn 9B thay vì 26B vì:
- Gemma 26B Q4_K_M chiếm ~15GB VRAM → chỉ còn 0.5-1.5GB cho KV Cache → CUDA OOM khi load System Prompt + RAG + Memory + Logs cùng lúc
- Gemma 2 9B Q6_K chiếm ~7GB VRAM → còn 9GB cho KV Cache → xử lý mượt mà toàn bộ pipeline
- Gemma 26B được giữ lại như optional heavy model cho Ablation Study so sánh chất lượng suy luận

### 2.3. Data Flow Diagram

```
CSV Datasets ──▶ Redis Queue ──▶ Tier 1 (Session Baselining)
                                   │
                          ┌────────┼────────────────────────┐
                          │        │                        │
                          ▼        ▼                        │
                       DROP    ESCALATE                     │
                     (Clean)      │                         │
                                  ▼                         │
                       template_miner.py                    │
                       (Volume Compression ONLY)            │
                                  │                         │
                                  ▼                         │
                       prompt_filter.py                     │
                       (Injection Defense:                  │
                        Detect → Neutralize → Encapsulate)  │
                                  │                         │
                                  ▼                         │
                       LangGraph Agent                      │
                       (Dual-RAG + Reasoning)               │
                                  │                         │
                          ┌───────┴───────┐                 │
                          ▼               ▼                 │
                    HITL Dashboard   Feedback Loop ──────────┘
                    (Approve/Reject)  (Dynamic Rule → Tier 1)
```

---

## 3. Implementation Plan

### 3.1. Methodology & Datasets

Chiến lược **Lab Experiment** + **Adversarial Testing**. Datasets:

1. **CICIDS2017:** Baseline benchmark (DoS, Brute Force). Phổ biến nhất trong literature, cho phép so sánh trực tiếp với nghiên cứu trước.
2. **UNSW-NB15:** Tấn công đa hình, phân tán.
3. **MAWILab:** Log Correlation đa nguồn.

**Synthetic Adversarial Generation:** Dùng Gemma 26B sinh 1,000+ kịch bản Log Injection gồm 4 loại: Direct Injection, Indirect Injection, Encoding Bypass, Context Manipulation.

### 3.2. Ablation Study Design

| Cấu hình | Tier 1 | Guardrails | LLM Agent | Mục đích |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline A: Rule-Only** | ✅ | ❌ | ❌ | Chứng minh LLM có giá trị thực sự |
| **Baseline B: LLM-Only** | ❌ | ❌ | ✅ | Chứng minh 2-Tier tối ưu Latency |
| **Baseline C: No Encapsulation** | ✅ | Drain3 only | ✅ | Chứng minh Encapsulation chống Injection |
| **SENTINEL (Full)** | ✅ | ✅ Full | ✅ | Hệ thống hoàn chỉnh |

### 3.3. Schedule (8-Week Realistic Plan)

- **Week 1-2 (Foundation):** Literature Review, hạ tầng Docker/MLflow/Oobabooga. Viết Chương 1-2 song song.
- **Week 3-4 (Core):** Redis Streaming + Tier-1 Session Baselining + Feedback Loop. LangGraph Agent + FAISS Dual-RAG. Viết Chương 3.
- **Week 5-6 (Guardrails & UI):** Template Miner + Prompt Filter (Delimited Encapsulation). Streamlit Dashboard (RBAC, HITL).
- **Week 7-8 (Evaluation):** Ablation Study + 1,000+ Adversarial Testing + MLflow metrics. Viết Chương 4-5.

### 3.4. Feasibility Assessment

**Phân tích VRAM Budget:**

| Thành phần | Gemma 26B Q4 | Gemma 2 9B Q6 |
| :--- | :--- | :--- |
| Model Weights | ~15GB | ~7GB |
| KV Cache còn lại | 0.5-1.5GB (❌ OOM) | 9GB (✅ Stable) |
| System Prompt + RAG + Memory | ~2-3GB | ~2-3GB |
| **Kết luận** | **Không đủ cho production** | **Đủ cho Streaming pipeline** |

Redis Docker thay Kafka. Rule-based Filter thay ML training. Docker-compose xử lý dependency conflicts. Lộ trình 8 tuần thực tế cho 1 người.

---

## 4. Expected Results

1. **Mã nguồn SENTINEL:** Codebase MLOps-ready, reproducible bằng `docker-compose up`.
2. **Báo cáo Thực nghiệm:** MLflow logs chứng minh (a) 2-Tier giảm Latency vs 1-Tier, (b) Compression Ratio của Template Mining, (c) Defeat Rate của Delimited Encapsulation vs No Encapsulation.
3. **Đóng góp Tri thức:** Mô hình SENTINEL — giải quyết nghịch lý "giữ variables cho phân tích mà không kích hoạt Injection" bằng Delimited Data Encapsulation, tương tự Parameterized Query trong SQL.

---

## 5. Evaluation Plan

**4D Evaluation Framework:**

1. **Classification Metrics:** Precision, Recall, F1-Score trên 3 datasets. So sánh 4 cấu hình Ablation.
2. **Operational Metrics:** Reasoning Latency (sec/incident), bao gồm cả Embedding Latency. Semantic Cache Hit Rate được đo để chứng minh tối ưu hóa RAG lookup. So sánh 2-Tier vs 1-Tier.
3. **Robustness Metrics:** Guardrail Defeat Rate qua 1,000+ adversarial samples, phân loại 4 vector: Direct Injection, Indirect Injection, Encoding Bypass, Context Manipulation. So sánh Full Encapsulation vs No Encapsulation (Baseline C).
4. **Context Quality Metrics:** Đánh giá bằng phương pháp kép:
   - **RAGAS (200 mẫu Ground Truth tĩnh):** Trích xuất 200 sự cố đại diện từ 3 datasets, gán nhãn thủ công (expected MITRE technique, ISO control, action). Tính Context Precision + Answer Relevancy.
   - **LLM-as-a-Judge (toàn bộ dataset, không cần GT):** Dùng Gemma 9B làm trọng tài độc lập chấm điểm Context Relevance (thang 1-5) theo phương pháp Zheng et al. (2023). Đảm bảo không cần gán nhãn thủ công cho toàn bộ dataset.
   - Compression Ratio của Semantic Pruning.

---

## 6. References

1. Sharafaldin et al. (2018) — CICIDS2017: Intrusion Detection Evaluation Dataset.
2. Moustafa & Slay (2015) — UNSW-NB15: Network IDS Dataset.
3. Fontugne et al. (2010) — MAWILab: Combining Diverse Anomaly Detectors.
4. He et al. (2017) — Drain: An Online Log Parsing Approach with Fixed Depth Tree.
5. OWASP Foundation (2025) — OWASP Top 10 for LLM Applications.
6. MITRE Corporation — MITRE ATT&CK Framework & MITRE ATLAS.
7. LangGraph Documentation — State Management for LLM Workflows.
8. Agent Security Bench (ASB) (2024) — Benchmarking Attacks and Defenses for LLM-based Agents.
9. Zheng et al. (2023) — Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena.
