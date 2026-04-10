# CAPSTONE PROJECT PROPOSAL

**Project Title:** SENTINEL — Autonomous AI Security Agent for Multi-source Log Correlation and Intrusion Response using LangGraph, Dual-RAG, and Adversarial Guardrails.

*(SENTINEL: Hệ thống phát hiện và phản ứng an ninh tự động dựa trên AI Agent đa nguồn kết hợp LangGraph, Dual-RAG và cơ chế phòng thủ Guardrails).*

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

---

## 1. Introduction and Background

### 1.1. Problem Description

Các Trung tâm Điều hành An ninh (SOC) hiện đại đang đối mặt với "Nghịch lý Dữ liệu lớn": Khối lượng sự kiện trên giây (EPS) khổng lồ dẫn đến tình trạng "quá tải cảnh báo" (alert fatigue). Theo báo cáo của Ponemon Institute (2023), trung bình một SOC analyst xử lý hơn 11,000 cảnh báo mỗi ngày, trong đó hơn 45% là dương tính giả. Các hệ thống IDS/SIEM truyền thống phân tích các nguồn dữ liệu (Web, Firewall, Auth) một cách rời rạc, làm giảm khả năng phát hiện chuỗi tấn công tinh vi (Multi-stage/APT attacks).

Việc ứng dụng LLM trực tiếp vào phân tích log sinh ra hai lỗ hổng chí mạng: (1) Độ trễ suy luận (Reasoning Latency) quá cao không đáp ứng được luồng dữ liệu thời gian thực, và (2) Rủi ro AI bị thao túng bởi Prompt Injection ẩn bên trong log — kẻ tấn công chèn chỉ thị độc vào các trường dynamic (User-Agent, Referer, Payload) mà LLM sẽ xử lý (OWASP Top 10 for LLM Applications, 2025). Đặc biệt, nghịch lý giữa việc cần giữ variables chứa payload để phân tích nhưng không để chúng kích hoạt Injection trong Context Window — là bài toán chưa ai giải quyết triệt để trong bối cảnh SOC tự động hóa.

### 1.2. Literature Review (Tổng quan nghiên cứu)

Mặc dù việc sử dụng Generative AI trong Cyber Security đang phát triển mạnh, các nghiên cứu vẫn tồn tại khoảng trống lớn khi triển khai thực tế:
- **LLM Agent cho SOC Automation:** Các nghiên cứu gần đây (ví dụ: Oniagbi et al., 2024; Audit-LLM) chủ yếu gọi API đám mây (GPT-4), vi phạm chính sách Data Privacy của tổ chức. Chưa có nghiên cứu nào tích hợp Local LLM với cơ chế tự phòng thủ (Adversarial Defense) ngay tại rìa.
- **RAG trong Security:** Các hệ thống như RAG-ATT&CK đã ứng dụng Knowledge Graph. Tuy nhiên, việc kết hợp **Chuẩn chiến thuật (MITRE)** và **Chuẩn phòng thủ (ISO 27001)** trong cùng một Pipeline (Dual-RAG) vẫn là một điểm mới.
- **Xử lý Log cho LLM:** Thuật toán Drain3 (He et al., 2017) được dùng rộng rãi để tiền xử lý log. SENTINEL nâng cấp việc này: ghép nối Drain3 vào Guardrails Layer như một cơ chế **Token Budgeting**, nhường chỗ cho các variables quan trọng.
- **Prompt Injection Response:** Dù Agent Security Bench (ASB, 2024) đã cảnh báo về rủi ro này, các framework hiện tại chưa đề xuất cơ chế đóng gói dữ liệu (Delimited Data Encapsulation) chống được đòn Delimiter Smuggling thông qua Cryptographic Hash.

Tính mới (Novelty) của SENTINEL không nằm ở việc tạo ra thuật toán đơn lẻ mới, mà nằm ở **Tư duy Kiến trúc Hệ thống (System Architecture Design)**: Ghép nối các công nghệ trên thành một **Dual-Tier Containerized Monolith** hoạt động khép kín với Feedback Loop thời gian thực.

### 1.3. Research Objectives

Nghiên cứu này xây dựng và đánh giá nguyên mẫu AI Security Agent có khả năng liên kết log đa nguồn theo thời gian thực, tự bảo vệ trước adversarial attacks, và hỗ trợ ra quyết định qua HITL. Các câu hỏi nghiên cứu:

- **RQ1:** Kiến trúc 2-Tier (Rule-based + LLM Agent) với Session-Aware Behavioral Baselining + Semantic Cache tối ưu Reasoning Latency như thế nào so với 1-Tier (LLM-only)?
- **RQ2:** Cơ chế Delimited Data Encapsulation (Dynamic Randomized Delimiters) có tác động ra sao đến Defeat Rate trước các đòn tấn công cấu trúc (Delimiter Smuggling & Encoding Bypass), và ngưỡng cơ sở (baseline) an toàn trước đòn tấn công bằng ngôn từ (Semantic Confusion) là gì?
- **RQ3:** Dual-RAG (MITRE ATT&CK + ISO 27001) cải thiện Context Relevance và hỗ trợ quyết định HITL như thế nào?
- **RQ4:** Tích hợp HITL Quarantine vào Feedback Loop có ngăn chặn được rủi ro Adversarial Rule Injection để đảm bảo Agents thích ứng an toàn với Zero-day attacks hay không?

### 1.4. Scope of the Project

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
- **Semantic Cache (Redis):** Cache vector query results trước FAISS để bypass embedding/query lại các payload trùng lặp. Key = template pattern hash từ LogTemplateMiner. Dự kiến cache hit rate: >90% DDoS, >80% Brute Force.
- **Structured MemoryObject (chống Semantic Drift):** State của LangGraph chia làm 2 phần tách biệt:
  1. `narrative_summary`: Bối cảnh chung dạng text (LLM được phép tóm tắt)
  2. `extracted_iocs`: Mảng JSON cứng lưu IOCs — IP, Port, Hash (LLM CHỈ được APPEND, KHÔNG được tóm tắt đè lên)

  Lý do: Summary Memory thuần túy sẽ dẫn đến Semantic Drift — các IOCs chi tiết dần bị làm mờ qua mỗi vòng tóm tắt.

**D. Feedback Loop (Data Flow với HITL Quarantine chống Adversarial Rule Injection)**

Nếu Agent bị tấn công Prompt Injection thành công và sinh ra một luật độc hại (ví dụ: `Block Admin IP`), việc load thẳng vào Tier 1 sẽ triệt hạ hệ thống. Giải pháp:

```
LangGraph Agent xác nhận mẫu tấn công mới
        │
        ▼
feedback_listener.py nhận rule (field, pattern, score)
        │
        ▼
Tạo Database Record với trạng thái: PENDING_APPROVAL (Quarantine)
        │
        ▼
HITL Dashboard (L3 Manager) phê duyệt (Approve) rule mới
        │
        ▼
Persist vào config/system_settings.yaml → tier1.dynamic_rules[]
        │
        ▼
RuleEngine.reload_dynamic_rules() (hot-reload cho Tier 1)
```

**E. Human-in-the-Loop (HITL)**

- Dashboard Streamlit, RBAC (L1 view-only, L3 approve/block), SQLite Audit Trail

### 2.2. Software Architecture

Kiến trúc Containerized Modular Architecture (Docker).

- **Primary Agent LLM:** Gemma 2 9B Q6_K (~7GB VRAM) — xử lý suy luận và phân tích log.
- **Oracle Judge LLM:** Gemma 26B Q4_K_M (~15GB VRAM) — chấm điểm Context Quality (LLM-as-a-Judge). **Không** dùng cùng model với Agent để tránh Confirmation Bias.
- **Ablation:** 26B cũng dùng để so sánh chất lượng suy luận (batch_size=1, short context).

VRAM Budget: RTX 4060 Ti 16GB. Chạy 9B (primary) + 26B (judge) tuần tự, không song song. Config trung tâm: `system_settings.yaml`. MLflow tracking tự động.

### 2.3. Data Flow Diagram

```text
CSV Datasets ──▶ Redis Queue ──▶ Tier 1 (Session Baselining + TTL Eviction)
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
                       (Dynamic Delimiters +                │
                        Detect → Neutralize → Encapsulate)  │
                                  │                         │
                                  ▼                         │
                       Semantic Cache (Redis)               │
                       (Bypass embedding cho                │
                        payload trùng lặp)                   │
                                  │                         │
                                  ▼                         │
                       Dual-RAG (FAISS)                     │
                       (MITRE ATT&CK + ISO 27001)           │
                                  │                         │
                                  ▼                         │
                       LangGraph Agent (9B)                 │
                       (Structured MemoryObject)            │
                                  │                         │
                           ┌───────┴───────┐                 │
                           ▼               ▼                 │
                     HITL Dashboard   Feedback Loop ─────────┤
                    (Approve/Reject)  (Quarantine Pending)   │
                           │               │                 │
                           └───────────────┴─────────────────┘
                                     (Manager Approval)
```

---

## 3. Implementation Plan

### 3.1. Methodology & Datasets

Chiến lược **Lab Experiment** + **Adversarial Testing**. Datasets:

1. **CICIDS2017:** Baseline benchmark (DoS, Brute Force, Web Attack). Tuy đã ra mắt nhiều năm, dataset này vẫn được chọn làm trọng tâm vì là chuẩn mực phổ biến nhất trong literature SOC. Để chứng minh khả năng **liên kết log đa nguồn (Multi-source Correlation)**, các luồng traffic khác nhau trong CICIDS2017 sẽ được giả lập và tách thành các file log riêng biệt ở quá trình tiền xử lý (ví dụ: tách HTTP traffic thành Apache Web Logs, và các kết nối khác thành Firewall/Zeek Logs).
2. **UNSW-NB15:** Thử nghiệm tấn công đa hình, phân tán.

**Synthetic Adversarial Generation:** Dùng Gemma 26B sinh 1,000+ kịch bản Log Injection gồm 4 loại: Direct Injection, Indirect Injection, Encoding Bypass, và **Semantic Confusion**.

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
3. **Robustness Metrics:** Guardrail Defeat Rate qua 1,000+ adversarial samples. Trọng tâm là đánh giá mức độ triệt tiêu hoàn toàn **Structural Bypasses** (Smuggling/Encoding) nhờ Encapsulation, và xác định đường cơ sở phòng thủ (Baseline vulnerability) trước các đòn **Semantic Confusion** (thao túng bằng rào cản ngôn từ). So sánh Full Encapsulation vs No Encapsulation (Baseline C).
4. **Context Quality Metrics & Eval Scoping:**
   - **Tối ưu VRAM Eval (Stratified Sampling):** Chạy code Python của Tier 1 trên toàn bộ ~2.8 triệu bản ghi CICIDS2017 để đánh giá Routing/Latencies. Tuy nhiên, tầng đánh giá LLM-as-a-Judge bằng Oracle 26B sẽ chỉ chạy trên một **mẫu phân tầng (Stratified Sample) gồm 5,000 sự kiện đại diện** (chứa tỷ lệ chuẩn mực cho cả 14 họ tấn công) thay vì toàn bộ dataset để khả thi về thời gian chạy trên tài nguyên RTX 4060 Ti 16GB.
   - **RAGAS (200 mẫu Ground Truth tĩnh):** Tính Context Precision + Answer Relevancy.
   - **LLM-as-a-Judge (Oracle Evaluation):** Dùng **Gemma 26B làm Oracle Model** (trọng tài độc lập) chấm điểm Context Relevance (thang 1-5) theo phương pháp Zheng et al. (2023) trên 5,000 log phân tầng. Mọi phân tích bằng 26B tách rời khỏi model Agent chính (9B) để tránh Self-Evaluation Bias.
   - Compression Ratio của Semantic Pruning.

---

## 6. References

1. Sharafaldin et al. (2018) — CICIDS2017: Intrusion Detection Evaluation Dataset.
2. Moustafa & Slay (2015) — UNSW-NB15: Network IDS Dataset.
4. He et al. (2017) — Drain: An Online Log Parsing Approach with Fixed Depth Tree.
5. OWASP Foundation (2025) — OWASP Top 10 for LLM Applications.
6. MITRE Corporation — MITRE ATT&CK Framework & MITRE ATLAS.
7. LangGraph Documentation — State Management for LLM Workflows.
8. Agent Security Bench (ASB) (2024) — Benchmarking Attacks and Defenses for LLM-based Agents.
9. Zheng et al. (2023) — Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena.
10. Ponemon Institute (2023) — The State of Security Operations and the Role of AI.
11. Oniagbi et al. (2024) — Generative AI in Cybersecurity: A Comprehensive Review.
