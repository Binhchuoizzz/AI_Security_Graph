# CAPSTONE PROJECT PROPOSAL

**Project Title:** SENTINEL — Autonomous AI Security Agent for Multi-source Log Correlation and Intrusion Response using LangGraph, Dual-RAG, and Adversarial Guardrails.
*(SENTINEL: Hệ thống phát hiện và phản ứng an ninh tự động dựa trên AI Agent đa nguồn kết hợp LangGraph, Dual-RAG và cơ chế phòng thủ Guardrails).*

> **SENTINEL** = **S**treaming **E**vents **N**etwork for **T**hreat **I**ntelligence, **N**eutralization, **E**scalation and **L**og-correlation

## 1. Introduction and Background

**1.1. Problem Description**
Các Trung tâm Điều hành An ninh (SOC) hiện đại đang đối mặt với "Nghịch lý Dữ liệu lớn": Khối lượng sự kiện trên giây (EPS - Events Per Second) khổng lồ dẫn đến tình trạng "quá tải cảnh báo" (alert fatigue) cho các chuyên gia phân tích (Analyst). Các hệ thống phát hiện xâm nhập (IDS) và quản lý log (SIEM) truyền thống thường phân tích các nguồn dữ liệu (Web, Firewall, Auth) một cách rời rạc, làm giảm khả năng phát hiện các chuỗi tấn công tinh vi (Multi-stage/APT attacks). 

Bên cạnh đó, việc ứng dụng Mô hình Ngôn ngữ Lớn (LLM) trực tiếp vào phân tích log an ninh sinh ra hai lỗ hổng chí mạng: (1) Độ trễ suy luận (Reasoning Latency) quá cao không đáp ứng được luồng dữ liệu thời gian thực (Streaming Data) và (2) Rủi ro AI bị thao túng bởi các đòn tấn công chèn mã độc (Prompt Injection) ẩn bên trong log của kẻ tấn công. 

**1.2. Research Objectives**
Nghiên cứu này hướng tới việc xây dựng và đánh giá một nguyên mẫu (prototype) AI Security Agent có khả năng liên kết log đa nguồn theo thời gian thực, có khả năng tự bảo vệ, và hỗ trợ ra quyết định thông qua cơ chế Human-in-the-Loop (HITL). Các câu hỏi nghiên cứu (Research Questions - RQ) bao gồm:
* **RQ1:** Kiến trúc xử lý luồng 2 tầng (2-Tier Architecture: Rule-based + LLM Agent) tối ưu hóa độ trễ suy luận (Reasoning Latency) như thế nào so với việc sử dụng LLM đơn thuần trên tập dữ liệu tốc độ cao?
* **RQ2:** Cơ chế Adversarial Guardrails (Lọc Prompt & Quản lý State) có tác động ra sao đến tỷ lệ phòng ngự thành công (Defeat Rate) trước các đòn tấn công tiêm nhiễm log?
* **RQ3:** Việc kết hợp Dual-RAG (MITRE ATT&CK và ISO 27001) trong đồ thị LangGraph cải thiện khả năng giải thích (Context Relevance) và hỗ trợ quyết định cho HITL như thế nào?
* **RQ4:** Cơ chế Semantic Pruning và Feedback Loop (Dynamic Rules) giúp hệ thống thích ứng với các cuộc tấn công Zero-day và Application Layer DDoS hiệu quả ra sao?

**1.3. Scope of the Project**
* **In-scope:** Xây dựng Data Streaming Pipeline bằng Redis; Phát triển Tier-1 Rule-based Filter với cơ chế Feedback Loop (Dynamic Rule Update); Cài đặt LangGraph Agent với cấu hình RAG cục bộ; Triển khai hệ thống Guardrails tích hợp Semantic Pruning (Log Template Mining, Token Budgeting) và giao diện Streamlit (HITL). Hệ thống được đóng gói theo chuẩn MLOps (Docker, MLflow).
* **Out-of-scope:** Tinh chỉnh (Fine-tuning) kiến trúc lõi của Foundation Model (Gemma 26B); Triển khai cụm Apache Kafka vật lý (sử dụng Redis để giả lập streaming); Ngăn chặn tấn công DDoS ở tầng hạ tầng mạng (Layer 3/4).

## 2. Proposed Solution

**2.1. Solution Description**
Dự án áp dụng phương pháp luận nghiên cứu khoa học thiết kế (**Design Science Research - DSR**). Giải pháp đề xuất là một kiến trúc Agentic Workflow bảo mật cao, hoạt động theo cơ chế Phễu lọc (Funneling Mechanism):
* **Cơ chế Streaming & Tier-1 Filter:** Luồng log thô được đẩy liên tục qua Message Queue (Redis). Một engine Rule-based (Tier 1) sẽ đóng vai trò tiền xử lý tốc độ cao (mili-giây), tự động drop các traffic sạch và chỉ định tuyến các IP có dấu hiệu bất thường (Anomalies) vào Tier 2. Tier-1 đồng thời thực hiện **Random Sampling (1-5% clean traffic)** để Agent định kỳ "khám sức khỏe" luồng dữ liệu, phát hiện Zero-day.
* **Tier-2 LangGraph & Guardrails:** Trước khi dữ liệu đến LLM, lớp Guardrails sẽ thực hiện:
    * **Semantic Pruning (Log Template Mining):** Sử dụng thuật toán Drain3 để nén hàng nghìn dòng log trùng lặp thành các Template đại diện kèm tần suất (frequency), giảm thiểu tải cho Context Window.
    * **Importance Scoring:** Tính điểm ưu tiên bằng Entropy Score (ký tự lạ = SQLi/XSS) và Source Diversity (ưu tiên nhiều IP khác nhau).
    * **Token Budgeting & Top-K Sampling:** Thiết lập ngân sách token cố định (4,000 tokens). Nếu vượt quá, chỉ lấy K mẫu quan trọng nhất từ mỗi Template. Điều này đảm bảo LLM nhìn thấy "bản chất" cuộc tấn công mà không bị tràn VRAM.
    * **Feature Extraction cho DDoS:** Thay vì đưa 10,000 dòng log thô, Guardrails tóm tắt thành vector hành vi: `"Behavior: High-frequency; Rate: 500 req/sec; Unique IPs: 1; Pattern: Constant."` — chỉ tiêu tốn ~50 tokens.
    * LangGraph sẽ gom nhóm các sự kiện theo [IP + Khung 5 phút], sau đó sử dụng Dual-RAG để ánh xạ hành vi tấn công vào ma trận MITRE ATT&CK và đối chiếu với tiêu chuẩn ISO 27001.
* **Feedback Loop (Dynamic Rule Update):** Khi LangGraph xác nhận một mẫu tấn công mới (APT/Zero-day), Node cuối cùng của Graph sẽ tự động sinh ra luật (Rule) mới và đẩy ngược lại vào cấu hình Tier-1 (`config/system_settings.yaml`) để chặn ngay tại cửa ngõ trong lần sau.
* **Human-in-the-Loop (HITL):** Thay vì tự động chặn hoàn toàn, hệ thống sẽ bảo lưu trạng thái (State) và tạm dừng đồ thị, yêu cầu SOC Analyst phê duyệt lệnh thông qua Dashboard.

**2.2. Software Architecture**
Kiến trúc phần mềm tuân thủ nguyên tắc module hóa đóng gói (Containerized Modular Architecture) và được container hóa (Docker). Môi trường vận hành sử dụng mô hình LLM cục bộ (Gemma 26B qua Oobabooga API) nhằm đảm bảo nguyên tắc Data Privacy (Không đưa log nhạy cảm lên Cloud). Toàn bộ tham số hệ thống và chỉ số thực nghiệm được tracking tự động bởi MLflow.

## 3. Implementation Plan

**3.1. Methodology & Datasets**
Nghiên cứu sử dụng chiến lược **Lab Experiment** kết hợp với **Adversarial Testing**. Để đảm bảo tính tổng quát và thực tế, dữ liệu thực nghiệm được hợp nhất từ 3 bộ dataset chuẩn mực quốc tế:
1.  **CICIDS2017:** Đo lường hiệu năng Baseline (DoS, Brute Force).
2.  **UNSW-NB15:** Đánh giá khả năng phát hiện tấn công đa hình, phân tán.
3.  **MAWILab:** Phục vụ kiểm thử năng lực liên kết log đa nguồn (Log Correlation).

Ngoài ra, hệ thống sử dụng **Synthetic Adversarial Generation**: dùng chính Gemma 26B (với prompt độc lập) để sinh ra **1,000+ kịch bản "Log Injection"** khác nhau nhắm vào các điểm yếu của RAG và Guardrails nhằm tăng tính đại diện thống kê cho phần đánh giá Robustness.

Toàn bộ log tĩnh từ dataset sẽ được mô phỏng thành luồng dữ liệu thời gian thực (Real-time stream) thông qua Data Publisher script và Redis Queue.

**3.2. Schedule (Gantt Chart for 1-Month Intensive Plan)**
* **Week 1 (Foundation):** Xác định mục tiêu, hoàn thành Literature Review (Chương 1 & 2); Thiết lập hạ tầng Docker, MLflow và Oobabooga API.
* **Week 2 (Core Development):** Xây dựng Redis Streaming Pipeline và Tier-1 Filter (bao gồm Feedback Loop stub). Lập trình luồng LangGraph Agent, tích hợp FAISS Vector DB (Dual-RAG).
* **Week 3 (Guardrails & UI):** Lập trình module Adversarial Guardrails gồm Semantic Pruning (Drain3), Token Budgeting và Feature Extraction. Hoàn thiện giao diện điều hành Streamlit (Dashboard) tích hợp RBAC cho cơ chế HITL.
* **Week 4 (Evaluation & Reporting):** Chạy Benchmark tự động (Ablation Study) bằng MLflow. Thực hiện tấn công Lab (Red Teaming) với 1,000+ kịch bản Synthetic Adversarial để đo đạc Defeat Rate. Hoàn thiện báo cáo luận văn (Chương 3, 4, 5).

**3.3. Feasibility Assessment & MVP Strategy**
Dự án có tính khả thi cao nhờ việc giới hạn phạm vi mô phỏng Streaming bằng Redis thay vì Kafka, và sử dụng Rule-based Filter thay vì huấn luyện mới mô hình Deep Learning cho Tier 1. Tài nguyên phần cứng (RTX 4060 Ti 16GB VRAM, 32GB RAM) đáp ứng được mô hình Gemma 26B quantized (Q4_K_M). Các rủi ro về xung đột thư viện được triệt tiêu hoàn toàn nhờ cấu trúc Docker-compose đồng nhất.

Chiến lược **MVP (Minimum Viable Product)** được áp dụng để đảm bảo tiến độ:

| Hạng mục | Ưu tiên | Cách tối ưu hóa thời gian |
| :--- | :--- | :--- |
| **Hạ tầng** | Trung bình | Dùng Docker Compose có sẵn để bỏ qua bước cài đặt thủ công. |
| **Tier-1** | Cao | Dùng Pandas xử lý lọc log nhanh trên RAM thay vì dựng engine phức tạp. |
| **LangGraph Core** | Rất cao | Tập trung vào logic "Liên kết" (Correlation) hơn là số lượng Node. |
| **Guardrails** | Rất cao | Dùng thư viện Drain3 cho Log Template Mining, không tự triển khai parser. |
| **Viết luận văn** | Cao | Ghi chú vào Markdown song song để sau chỉ cần copy-paste vào Word. |

## 4. Expected Results
1.  **Mã nguồn & Artifact:** Một hệ thống SOC Agent hoàn chỉnh (Codebase) tuân thủ kiến trúc MLOps, có khả năng tái lập (reproducible) bằng 1 lệnh khởi chạy duy nhất.
2.  **Báo cáo Thực nghiệm:** Hồ sơ log từ MLflow chứng minh sự tối ưu về Reasoning Latency của cấu trúc 2-Tier so với hệ thống 1-Tier, và hiệu quả của Semantic Pruning trong việc giảm Context Overflow.
3.  **Đóng góp Tri thức:** Mô hình lý thuyết về việc áp dụng Guardrails (Semantic Pruning + Token Budgeting + Feedback Loop) để bảo vệ LLM Agent trong môi trường an toàn thông tin khép kín.

## 5. Evaluation Plan
Khác với các hệ thống phân loại truyền thống chỉ dựa vào độ chính xác, hệ thống Agent sẽ được đánh giá qua bộ tiêu chí **4 chiều (4D Evaluation Framework)**:
1.  **Classification Metrics:** Đo lường Precision, Recall, F1-Score trên 3 tập dataset (So sánh với Baseline).
2.  **Operational Metrics:** Đo lường **Reasoning Latency** (Độ trễ suy luận tính bằng giây/sự cố) để chứng minh khả năng xử lý Streaming. So sánh Latency giữa cấu trúc 2-Tier vs 1-Tier (LLM-only).
3.  **Robustness Metrics (Tính bền bỉ):** Tính toán **Guardrail Effectiveness (Defeat Rate)** thông qua bài kiểm tra "tiêm mã độc" vào **1,000+ dòng log giả lập** (Synthetic Adversarial Generation), đo lường số lần LLM bị thao túng thành công (Bypass) so với số lần bị chặn (Blocked).
4.  **Context Quality Metrics:** Đánh giá **Context Relevance** của kết quả RAG (MITRE/ISO) và hiệu quả nén dữ liệu của **Semantic Pruning** (Compression Ratio: số dòng log gốc / số Template sau nén).
