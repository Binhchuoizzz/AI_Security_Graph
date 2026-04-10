# CAPSTONE PROJECT PROPOSAL

**Project Title:** SENTINEL — Autonomous AI Security Agent for Multi-source Log Correlation and Intrusion Response using LangGraph, Dual-RAG, and Adversarial Guardrails.

*(SENTINEL: Hệ thống phát hiện và phản ứng an ninh tự động dựa trên AI Agent đa nguồn kết hợp LangGraph, Dual-RAG và cơ chế phòng thủ Guardrails).*

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

---

## 1. Introduction and Background

### 1.1. Problem Description

Các Trung tâm Điều hành An ninh (SOC) hiện đại đang đối mặt với "Nghịch lý Dữ liệu lớn": Khối lượng sự kiện trên giây (EPS - Events Per Second) khổng lồ dẫn đến tình trạng "quá tải cảnh báo" (alert fatigue) cho các chuyên gia phân tích. Theo báo cáo của Ponemon Institute, trung bình một SOC analyst xử lý hơn 11,000 cảnh báo mỗi ngày, trong đó hơn 45% là dương tính giả (false positive). Các hệ thống phát hiện xâm nhập (IDS) và quản lý log (SIEM) truyền thống thường phân tích các nguồn dữ liệu (Web, Firewall, Auth) một cách rời rạc, làm giảm khả năng phát hiện các chuỗi tấn công tinh vi (Multi-stage/APT attacks).

Bên cạnh đó, việc ứng dụng Mô hình Ngôn ngữ Lớn (LLM) trực tiếp vào phân tích log an ninh sinh ra hai lỗ hổng chí mạng: (1) Độ trễ suy luận (Reasoning Latency) quá cao không đáp ứng được luồng dữ liệu thời gian thực (Streaming Data) và (2) Rủi ro AI bị thao túng bởi các đòn tấn công chèn mã độc (Prompt Injection) ẩn bên trong log của kẻ tấn công (OWASP Top 10 for LLM Applications, 2025).

### 1.2. Research Objectives

Nghiên cứu này hướng tới việc xây dựng và đánh giá một nguyên mẫu (prototype) AI Security Agent có khả năng liên kết log đa nguồn theo thời gian thực, có khả năng tự bảo vệ, và hỗ trợ ra quyết định thông qua cơ chế Human-in-the-Loop (HITL). Các câu hỏi nghiên cứu (Research Questions - RQ) bao gồm:

- **RQ1:** Kiến trúc xử lý luồng 2 tầng (2-Tier Architecture: Rule-based + LLM Agent) tối ưu hóa độ trễ suy luận (Reasoning Latency) như thế nào so với việc sử dụng LLM đơn thuần trên tập dữ liệu tốc độ cao?
- **RQ2:** Cơ chế Adversarial Guardrails (Semantic Pruning, Prompt Filtering & State Management) có tác động ra sao đến tỷ lệ phòng ngự thành công (Defeat Rate) trước các đòn tấn công tiêm nhiễm log?
- **RQ3:** Việc kết hợp Dual-RAG (MITRE ATT&CK và ISO 27001) trong đồ thị LangGraph cải thiện khả năng giải thích (Context Relevance) và hỗ trợ quyết định cho HITL như thế nào?
- **RQ4:** Cơ chế Feedback Loop (Dynamic Rules) và Random Sampling giúp hệ thống thích ứng với các cuộc tấn công Zero-day và Application Layer DDoS hiệu quả ra sao?

### 1.3. Scope of the Project

- **In-scope:** Xây dựng Data Streaming Pipeline bằng Redis; Phát triển Tier-1 Rule-based Filter với cơ chế Feedback Loop (Dynamic Rule Update) và Random Sampling; Cài đặt LangGraph Agent với cấu hình Dual-RAG cục bộ; Triển khai lớp Guardrails đa tầng (Prompt Injection Detection, Log Template Mining via Drain3, Entropy-based Importance Scoring, Token Budgeting, DDoS Feature Extraction); Phát triển giao diện Streamlit (HITL) với RBAC. Hệ thống được đóng gói theo chuẩn MLOps (Docker, MLflow) và có Audit Trail (SQLite).
- **Out-of-scope:** Tinh chỉnh (Fine-tuning) kiến trúc lõi của Foundation Model (Gemma 26B); Triển khai cụm Apache Kafka vật lý (sử dụng Redis để giả lập streaming); Ngăn chặn tấn công DDoS ở tầng hạ tầng mạng (Layer 3/4).

---

## 2. Proposed Solution

### 2.1. Solution Description

Dự án áp dụng phương pháp luận nghiên cứu khoa học thiết kế (**Design Science Research - DSR**). Giải pháp đề xuất là kiến trúc **SENTINEL** — một Agentic Workflow bảo mật cao hoạt động theo cơ chế Phễu lọc chịu lỗi (Fault-tolerant Funneling Mechanism):

**A. Tier 1 — Speed Layer (Rule Engine + Feedback Loop)**

- Luồng log thô được đẩy liên tục qua Message Queue (Redis). Engine Rule-based (Tier 1) thực hiện tiền xử lý tốc độ cao (mili-giây), tự động drop traffic sạch và chỉ định tuyến log bất thường (Anomalies) vào Tier 2.
- **Random Sampling (1-3%):** Tier-1 đẩy ngẫu nhiên 1-3% traffic sạch vào Tier-2 để Agent "kiểm tra sức khỏe" xác suất, phát hiện APT ẩn nấp.
- **Dynamic Rule Update:** Khi Tier-2 (LLM) phát hiện mẫu tấn công mới (Zero-day), nó tự động sinh Signature/Regex mới. Chỉ thị được đẩy ngược về Tier-1 qua `feedback_listener.py` để cập nhật luật chặn ngay lập tức tại cửa ngõ.

**B. Guardrails Layer — AI Self-Defense (Semantic Pruning)**

Trước khi dữ liệu đến LLM, lớp Guardrails thực hiện Chiến lược Cắt tỉa Ngữ nghĩa (Semantic Pruning) 3 bước:

- **Bước 1 — Log Template Mining (Drain3):** Nén hàng nghìn dòng log trùng lặp thành Template đại diện kèm frequency và time range. Ví dụ: 5,000 dòng `GET /login.php?user=admin...` → 1 Template `GET /login.php?user=<VAR> (Count: 5000, Time: 0.1s-299s)`. Giảm tải dữ liệu từ hàng MB xuống vài trăm bytes.
- **Bước 2 — Entropy-based Importance Scoring:** Log có Shannon Entropy cao (chứa ký tự đặc biệt SQLi, XSS, Payload lạ) được giữ nguyên bản raw. Log cấu trúc thông thường bị nén thành Template. Source Diversity scoring ưu tiên giữ lại log đại diện từ nhiều IP/User-Agent khác nhau.
- **Bước 3 — Token Budgeting & Top-K Sampling:** Ngân sách token cố định 4,000 tokens cho dữ liệu log. Chiến lược ưu tiên: (1) Giữ nguyên log entropy cao (khả năng chứa payload), (2) Top-K Templates theo frequency. Nếu vượt ngân sách, hệ thống tự động truncate kèm cảnh báo.
- **Feature Extraction cho DDoS:** Thay vì đưa 10,000 dòng log thô, Guardrails tóm tắt thành vector hành vi: `"Behavior: High-frequency; Rate: 500 req/sec; Unique IPs: 1; Pattern: Constant."` — chỉ tiêu tốn ~50 tokens.
- **Prompt Injection Detection:** Regex + heuristic scanning toàn bộ value trong log JSON, tự động sanitize nội dung độc hại trước khi đưa vào LLM.
- **Context Overflow Guard + Loop Detector:** Giám sát VRAM budget và phát hiện LangGraph bị mắc vòng lặp vô hạn.

**C. Tier 2 — Intelligence Layer (LangGraph Agent + Dual-RAG)**

- LangGraph gom nhóm sự kiện theo [IP + Khung 5 phút], sử dụng Dual-RAG để ánh xạ hành vi tấn công vào ma trận MITRE ATT&CK và đối chiếu với tiêu chuẩn ISO 27001.
- **Summary Memory:** Agent lưu trữ tóm tắt ngữ cảnh phiên phân tích trước đó để giữ tính liên tục mà không tốn token.
- **Decision Router:** Phân loại hành động đầu ra: AUTO (tự động chặn), HITL (cần phê duyệt), LOG (chỉ ghi nhận).

**D. Human-in-the-Loop (HITL)**

- Hệ thống bảo lưu trạng thái (State) và tạm dừng đồ thị, yêu cầu SOC Analyst phê duyệt lệnh thông qua Dashboard Streamlit.
- RBAC: L1 Analyst (view-only) vs L3 Manager (can approve/block IP).
- SQLite Audit Trail ghi lại toàn bộ quyết định của Agent phục vụ truy vết (Forensics).

### 2.2. Software Architecture

Kiến trúc phần mềm tuân thủ nguyên tắc module hóa đóng gói (Containerized Modular Architecture) và được container hóa (Docker). Môi trường vận hành sử dụng mô hình LLM cục bộ (Gemma 26B Q4_K_M qua Oobabooga API) trên phần cứng RTX 4060 Ti 16GB VRAM, 32GB RAM, nhằm đảm bảo nguyên tắc Data Privacy (không đưa log nhạy cảm lên Cloud). Toàn bộ tham số hệ thống được quản lý tập trung qua `config/system_settings.yaml` và chỉ số thực nghiệm được tracking tự động bởi MLflow.

### 2.3. Data Flow Diagram

```
CSV Datasets ──▶ Redis Queue ──▶ Tier 1 Rule Engine ──▶ Guardrails ──▶ LangGraph Agent ──▶ HITL Dashboard
                                   │          ▲          (Semantic      (Dual-RAG +         │
                                   │          │           Pruning)       Reasoning)          │
                                   │          └───── Feedback Loop (Dynamic Rules) ◀─────────┘
                                   ▼
                              DROP (Clean)
```

---

## 3. Implementation Plan

### 3.1. Methodology & Datasets

Nghiên cứu sử dụng chiến lược **Lab Experiment** kết hợp với **Adversarial Testing**. Dữ liệu thực nghiệm:

1. **CICIDS2017:** Đo lường hiệu năng Baseline (DoS, Brute Force). Được sử dụng làm benchmark phổ biến nhất trong literature, cho phép so sánh trực tiếp với các nghiên cứu trước.
2. **UNSW-NB15:** Đánh giá khả năng phát hiện tấn công đa hình, phân tán.
3. **MAWILab:** Phục vụ kiểm thử năng lực liên kết log đa nguồn (Log Correlation).

Ngoài ra, hệ thống sử dụng **Synthetic Adversarial Generation**: dùng chính Gemma 26B (với prompt độc lập) để sinh ra **1,000+ kịch bản "Log Injection"** đa dạng nhắm vào các điểm yếu của RAG và Guardrails, bao gồm: Direct Injection, Indirect Injection, Encoding Bypass, và Context Manipulation. Cỡ mẫu >1,000 đảm bảo tính đại diện thống kê cho phần đánh giá Robustness.

Toàn bộ log tĩnh từ dataset sẽ được mô phỏng thành luồng dữ liệu thời gian thực (Real-time stream) thông qua Data Publisher script và Redis Queue.

### 3.2. Ablation Study Design

Để chứng minh đóng góp của từng thành phần, hệ thống được so sánh qua 3 cấu hình:

| Cấu hình | Tier 1 | Guardrails | LLM Agent | Mục đích |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline A: Rule-Only** | ✅ | ❌ | ❌ | Chứng minh LLM có giá trị thực sự |
| **Baseline B: LLM-Only** | ❌ | ❌ | ✅ | Chứng minh 2-Tier tối ưu Latency |
| **SENTINEL (Full)** | ✅ | ✅ | ✅ | Hệ thống hoàn chỉnh |

### 3.3. Schedule (Gantt Chart for 1-Month Intensive Plan)

- **Week 1 (Foundation):** Xác định mục tiêu, hoàn thành Literature Review (Chương 1 & 2); Thiết lập hạ tầng Docker, MLflow và Oobabooga API. Viết song song Chương 3 (Thiết kế hệ thống) vào Markdown.
- **Week 2 (Core Development):** Xây dựng Redis Streaming Pipeline và Tier-1 Filter (bao gồm Feedback Loop). Lập trình luồng LangGraph Agent (`workflow.py`, `nodes.py`, `state.py`), tích hợp FAISS Vector DB (Dual-RAG: `embedder.py`, `retriever.py`).
- **Week 3 (Guardrails & UI):** Lập trình module Adversarial Guardrails gồm Template Mining (`template_miner.py`), Token Budgeting và Feature Extraction. Hoàn thiện giao diện điều hành Streamlit (`app.py`, `auth.py`, `components.py`) tích hợp RBAC cho cơ chế HITL.
- **Week 4 (Evaluation & Reporting):** Chạy Benchmark tự động (Ablation Study) bằng MLflow. Thực hiện tấn công Lab (Red Teaming) với 1,000+ kịch bản Synthetic Adversarial (`evaluate_robustness.py`). Hoàn thiện báo cáo luận văn (Chương 4, 5).

### 3.4. Feasibility Assessment & MVP Strategy

Dự án có tính khả thi cao nhờ việc giới hạn phạm vi mô phỏng Streaming bằng Redis thay vì Kafka, và sử dụng Rule-based Filter thay vì huấn luyện mới mô hình Deep Learning cho Tier 1. Tài nguyên phần cứng (RTX 4060 Ti 16GB VRAM, 32GB RAM) đáp ứng được mô hình Gemma 26B quantized (Q4_K_M, ~15GB VRAM). Các rủi ro về xung đột thư viện được triệt tiêu hoàn toàn nhờ cấu trúc Docker-compose đồng nhất.

Chiến lược **MVP (Minimum Viable Product)** được áp dụng để đảm bảo tiến độ:

| Hạng mục | Ưu tiên | Cách tối ưu hóa thời gian |
| :--- | :--- | :--- |
| **Hạ tầng** | Trung bình | Dùng Docker Compose có sẵn để bỏ qua bước cài đặt thủ công. |
| **Tier-1** | Cao | Dùng Pandas xử lý lọc log nhanh trên RAM thay vì dựng engine phức tạp. |
| **LangGraph Core** | Rất cao | Tập trung vào logic "Liên kết" (Correlation) hơn là số lượng Node. |
| **Guardrails** | Rất cao | Dùng thư viện Drain3 cho Log Template Mining, không tự triển khai parser. |
| **Viết luận văn** | Cao | Viết song song vào Markdown ngay từ Week 1, copy-paste vào Word/LaTeX. |

---

## 4. Expected Results

1. **Mã nguồn & Artifact:** Hệ thống SENTINEL hoàn chỉnh (Codebase) tuân thủ kiến trúc MLOps, có khả năng tái lập (reproducible) bằng 1 lệnh `docker-compose up`.
2. **Báo cáo Thực nghiệm:** Hồ sơ log từ MLflow chứng minh: (a) Sự tối ưu về Reasoning Latency của cấu trúc 2-Tier so với hệ thống 1-Tier; (b) Hiệu quả của Semantic Pruning trong việc giảm Context Overflow (Compression Ratio); (c) Defeat Rate của Guardrails với 1,000+ adversarial samples.
3. **Đóng góp Tri thức:** Mô hình lý thuyết SENTINEL Framework — áp dụng Adversarial Guardrails (Semantic Pruning + Token Budgeting + Feedback Loop) để bảo vệ LLM Agent trong môi trường an toàn thông tin khép kín. Đóng góp vào knowledge gap về việc triển khai LLM Agent an toàn cho SOC tự động hóa.

---

## 5. Evaluation Plan

Khác với các hệ thống phân loại truyền thống chỉ dựa vào độ chính xác, hệ thống SENTINEL Agent sẽ được đánh giá qua bộ tiêu chí **4 chiều (4D Evaluation Framework)**:

1. **Classification Metrics:** Đo lường Precision, Recall, F1-Score trên 3 tập dataset. So sánh với 2 Baseline (Rule-Only vs LLM-Only) để chứng minh lợi thế của kiến trúc hybrid.
2. **Operational Metrics:** Đo lường **Reasoning Latency** (Độ trễ suy luận tính bằng giây/sự cố) để chứng minh khả năng xử lý Streaming. So sánh Latency giữa 3 cấu hình Ablation Study.
3. **Robustness Metrics (Tính bền bỉ):** Tính toán **Guardrail Effectiveness (Defeat Rate)** thông qua bài kiểm tra "tiêm mã độc" vào **1,000+ dòng log giả lập** (Synthetic Adversarial Generation), phân loại theo 4 vector tấn công: Direct Injection, Indirect Injection, Encoding Bypass, Context Manipulation.
4. **Context Quality Metrics:** Đánh giá **Context Relevance** của kết quả RAG (MITRE/ISO) và hiệu quả nén dữ liệu của **Semantic Pruning** (Compression Ratio: số dòng log gốc / số Template sau nén). Context Relevance được đo bằng framework RAGAS hoặc đánh giá thủ công với rubric chấm điểm 5 mức.

---

## 6. References (Trích dẫn chính)

1. Sharafaldin et al. (2018) — CICIDS2017: Intrusion Detection Evaluation Dataset.
2. Moustafa & Slay (2015) — UNSW-NB15: A Comprehensive Data set for Network IDS.
3. Fontugne et al. (2010) — MAWILab: Combining Diverse Anomaly Detectors.
4. He et al. (2017) — Drain: An Online Log Parsing Approach with Fixed Depth Tree.
5. OWASP Foundation (2025) — OWASP Top 10 for LLM Applications.
6. MITRE Corporation — MITRE ATT&CK Framework & MITRE ATLAS.
7. LangGraph Documentation — State Management for LLM Workflows.
8. Agent Security Bench (ASB) (2024) — Benchmarking Attacks and Defenses for LLM-based Agents.
