# ĐỀ CƯƠNG DỰ ÁN TỐT NGHIỆP (CAPSTONE PROJECT PROPOSAL)

**Tên đề tài:** Xây dựng hệ thống phát hiện và tự động hóa phản ứng an ninh (IDS/SOAR) dựa trên AI Agent đa nguồn kết hợp LangGraph, RAG và cơ chế bảo vệ Guardrails.

## 1. GIỚI THIỆU VÀ BỐI CẢNH (Introduction and Background)

### 1.1. Mô tả vấn đề (Problem Description)
Các Trung tâm Điều hành An ninh (SOC) hiện đại đang đối mặt với ba thách thức lớn:
1.  **Quá tải cảnh báo (Alert Fatigue):** Hệ thống IDS truyền thống tạo ra quá nhiều báo động giả, làm giảm khả năng tập trung vào các mối đe dọa thực sự.
2.  **Phân tích rời rạc:** Việc thiếu sự liên kết giữa các nguồn log (Web, Auth, Network) dẫn đến việc bỏ sót các cuộc tấn công chuỗi (multi-stage attacks).
3.  **An toàn cho chính AI (Securing the AI):** Các hệ thống dựa trên LLM dễ bị tấn công bởi Prompt Injection thông qua dữ liệu log độc hại, gây ra rủi ro sai lệch quyết định của Agent.

### 1.2. Mục tiêu nghiên cứu (Research Objectives - SMART)
Xây dựng một hệ thống AI Security Agent có khả năng tự động liên kết log đa nguồn, giải thích mối đe dọa theo chuẩn quốc tế và tự bảo vệ trước các tấn công nội tại (adversarial attacks) trong vòng 6 tháng.
* **RQ1:** Làm thế nào để thiết kế một Log Correlation Engine hiệu quả nhằm gom nhóm dữ liệu đa nguồn phục vụ cho việc suy luận của AI? (Trả lời tại Chương 2).
* **RQ2:** Kiến trúc LangGraph tích hợp RAG (MITRE ATT&CK & ISO 27001) và lớp bảo vệ Guardrails được thiết kế như thế nào để đảm bảo tính giải thích và an toàn? (Trả lời tại Chương 3).
* **RQ3:** Hiệu năng của hệ thống so với các phương pháp truyền thống và giá trị của cơ chế Human-in-the-Loop (HITL) được định lượng ra sao? (Trả lời tại Chương 4).

### 1.3. Phạm vi dự án (Scope)
* **Bao gồm:** Xây dựng Agentic Workflow (LangGraph); Module RAG đa nguồn; Lớp bảo vệ Guardrails (chống Prompt Injection); Giao diện HITL (Streamlit) tích hợp MLflow tracking.
* **Dữ liệu:** Sử dụng 3 bộ dataset chuẩn (CICIDS2017, UNSW-NB15, MAWILab) được giả lập luồng log đa nguồn.
* **Mô hình LLM:** Gemma 26B/27B chạy cục bộ qua Oobabooga API nhằm đảm bảo tính bảo mật dữ liệu.

## 2. GIẢI PHÁP ĐỀ XUẤT (Proposed Solution)

### 2.1. Mô tả giải pháp
Dự án áp dụng phương pháp luận **Design Science Research (DSR)** để xây dựng một "Artifact" phần mềm thông minh. Hệ thống không chỉ phát hiện tấn công mà còn đóng vai trò một chuyên gia tư vấn (Analyst) thông qua:
* **Log Correlation Engine:** Gom nhóm log theo [IP + Time-window 5 phút] để tạo ngữ cảnh đầy đủ.
* **Adversarial Guardrails:** Lọc dữ liệu log trước khi đưa vào LLM để ngăn chặn tiêm mã lệnh (Prompt Injection).
* **Dual-RAG:** Ánh xạ hành vi tấn công vào kỹ thuật MITRE ATT&CK và đối chiếu với chính sách ISO 27001 để đề xuất phản ứng phù hợp.

### 2.2. Kiến trúc Hệ thống (Architecture)
Hệ thống được thiết kế theo mô hình Container hóa (Docker) bao gồm:
1.  **Data Ingestion Layer:** Phân tách và định dạng log đa nguồn.
2.  **AI Safety Layer (Guardrails):** Kiểm soát tính toàn vẹn của dữ liệu và prompt.
3.  **Reasoning Core (LangGraph):** Điều phối các Node phân tích, truy xuất tri thức và định tuyến quyết định.
4.  **HITL Dashboard:** Giao diện phê duyệt tích hợp phân quyền (RBAC) cho SOC Analyst và Manager.

## 3. KẾ HOẠCH TRIỂN KHAI (Implementation Plan)

### 3.1. Phương pháp thực nghiệm (Methodology & Datasets)
Dựa trên **ABC Framework**, dự án ưu tiên Độ chính xác (Precision) và Tính thực tế (Realism) thông qua Lab Experiment trên 3 tập dữ liệu:
* **CICIDS2017:** Thiết lập baseline cho các tấn công phổ biến.
* **UNSW-NB15:** Kiểm thử với các kỹ thuật tấn công hiện đại và đa dạng hơn.
* **MAWILab:** Đánh giá năng lực liên kết luồng dữ liệu (Flow correlation) chuyên sâu.

### 3.2. Lộ trình thực hiện (Schedule)
* **Giai đoạn 1 (Tuần 1-2):** Thiết lập môi trường MLOps (Docker, MLflow, Oobabooga) và tiền xử lý dữ liệu.
* **Giai đoạn 2 (Tuần 3-6):** Xây dựng lõi LangGraph, Module RAG và lớp bảo vệ Guardrails.
* **Giai đoạn 3 (Tuần 7-8):** Phát triển Dashboard HITL và tích hợp Logic phản ứng (Response).
* **Giai đoạn 4 (Tuần 9-10):** Chạy thực nghiệm (Ablation Study), thu thập metrics và hoàn thiện luận văn.

## 4. KẾT QUẢ MONG ĐỢI (Expected Results)
1.  **Hệ thống phần mềm:** Prototype AI Security Agent đạt chuẩn Production-ready với đầy đủ tính năng giám sát và phản ứng.
2.  **Báo cáo thực nghiệm:** Chứng minh sự sụt giảm đáng kể tỷ lệ báo động giả (False Positives) khi có sự can thiệp của RAG và HITL.
3.  **Đóng góp học thuật:** Đề xuất một quy trình vận hành Agentic SOC an toàn, có khả năng tự bảo vệ trước các tấn công nhắm vào AI.

## 5. KẾ HOẠCH ĐÁNH GIÁ (Evaluation Plan)
* **Định lượng:** Đo lường Precision, Recall, F1-Score, FPR trên 3 tập dataset.
* **Đánh giá an toàn:** Thực hiện "Adversarial Testing" nhét mã độc vào log để kiểm chứng hiệu quả của lớp Guardrails.
* **Nghiên cứu cắt lớp (Ablation Study):** So sánh hiệu quả của hệ thống khi có và không có RAG/Guardrails/HITL để khẳng định giá trị của từng thành phần thiết kế.
