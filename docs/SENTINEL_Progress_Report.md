# BÁO CÁO TIẾN ĐỘ LUẬN VĂN THẠC SĨ (SENTINEL PROGRESS REPORT)

<div align="center">

**HỌC VIỆN CÔNG NGHỆ FSB — ĐẠI HỌC FPT**

**CHƯƠNG TRÌNH ĐÀO TẠO THẠC SĨ AI & MACHINE LEARNING**

---

**Đề tài (Tiếng Việt):**
### Kiến Trúc Nhận Thức Hai Tầng Cho Phát Hiện Mối Đe Dọa Tự Động và Phản Ứng Theo Ngữ Cảnh Sử Dụng AI Tác Tử

**Đề tài (Tiếng Anh):**
### SENTINEL — A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI

</div>

---

| Thông tin | Chi tiết |
| :--- | :--- |
| **Học viên** | Nguyễn Đức Bình |
| **Giảng viên hướng dẫn** | **ThS. Bùi Văn Hiệu** |
| **Liên hệ GVHD** | hieubv10@fe.edu.vn |
| **Thời gian thực hiện** | 15/05/2026 – 15/08/2026 (Kế hoạch 3 tháng) |
| **Repository** | [github.com/Binhchuoizzz/AI_Security_Graph](https://github.com/Binhchuoizzz/AI_Security_Graph) |

---

## 1. Tóm Tắt Đề Tài & Mục Tiêu Nghiên Cứu

Hệ thống **SENTINEL** giải quyết triệt để bài toán **"SOC Alert Fatigue"** (Quá tải cảnh báo an ninh mạng) bằng kiến trúc nhận thức hai tầng (**Two-Tier Cognitive Architecture**):
- **Tier 1 (Heuristic & Statistical Filter):** Bộ lọc biên tốc độ cao kết hợp Rule Engine (Stateless) và Session-Aware Behavioral Baselining (Stateful). Sử dụng thuật toán trực tuyến **Welford Running Statistics** tính toán động Z-Score trên 11 đặc trưng lưu lượng mạng, lọc nhiễu $\ge 99\%$ trước khi chuyển tiếp.
- **Tier 2 (Cognitive Reasoning):** Tác tử AI tự chủ (Agentic AI) dựa trên **LangGraph State Machine** và mô hình cục bộ **Gemma-2-9B-IT** (chạy qua llama.cpp CUDA). Tác tử phân tích sâu nhờ cơ chế **Dual-RAG** (MITRE ATT&CK Enterprise + NIST SP 800-61r2) kết hợp với **Threat Memory** (SQLite liên kết chuỗi APT đa ngày) để đưa ra hành động phản ứng tự động theo ngữ cảnh (BLOCK_IP, ESCALATE, AWAIT_HITL, LOG, DROP).

---

## 2. Kế Hoạch Thực Hiện 3 Tháng (15/05/2026 – 15/08/2026)

Lộ trình thực hiện được chia cấu trúc chính xác theo 3 tháng tập trung vào các cột mốc thực thi thực tế:

| Giai đoạn / Nhiệm vụ | Tháng 1 (15/05 - 15/06) | Tháng 2 (16/06 - 15/07) | Tháng 3 (16/07 - 15/08) | Trạng thái |
| :--- | :---: | :---: | :---: | :---: |
| **Nghiên cứu tài liệu & Thiết kế** | ▓▓▓▓▓▓▓▓▓▓ | | | ✅ Hoàn thành |
| **Thu thập & Xử lý dữ liệu (CICIDS/DAPT)** | ▓▓▓▓▓▓▓▓▓▓ | | | ✅ Hoàn thành |
| **Phát triển Tier 1 (Rule Engine / Welford)** | ▓▓▓▓▓▓▓▓▓▓ | | | 🔄 Đang hoàn thiện |
| **Phát triển Guardrails Layer** | | ▓▓▓▓▓▓▓▓▓▓ | | ⏳ Dự kiến |
| **Xây dựng Dual-RAG & Semantic Cache** | | ▓▓▓▓▓▓▓▓▓▓ | | ⏳ Dự kiến |
| **Phát triển Tier 2 LangGraph Agent** | | ▓▓▓▓▓▓▓▓▓▓ | | ⏳ Dự kiến |
| **Streamlit Dashboard (HITL + Graph)** | | | ▓▓▓▓▓▓▓▓▓▓ | ⏳ Dự kiến |
| **Đánh giá thực nghiệm (5D-EF, Ablation)** | | | ▓▓▓▓▓▓▓▓▓▓ | ⏳ Dự kiến |
| **Viết Luận văn & Chuẩn bị Bảo vệ** | | | ▓▓▓▓▓▓▓▓▓▓ | ⏳ Dự kiến |

---

### THÁNG 1: Khảo Sát, Thiết Kế & Xây Dựng Bộ Lọc Biên Tier 1 (15/05 – 15/06)
*Tập trung thiết kế kiến trúc hệ thống, chuẩn hóa dữ liệu an ninh mạng và phát triển bộ lọc nhiễu tốc độ cao.*

| Mã | Nhiệm vụ cụ thể | Thời gian | Sản phẩm / Kết quả đầu ra | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **1.1** | **Khảo sát tài liệu & Đặt vấn đề**<br>- Khảo sát các nghiên cứu về SOC Alert Fatigue, Agentic AI, và LLM trong An ninh mạng.<br>- Xác định kiến trúc Threat Model & ranh giới bảo mật. | 15/05 – 22/05 | - Đề cương nghiên cứu chi tiết.<br>- Sơ đồ Threat Model & Tác nhân đe dọa. | ✅ |
| **1.2** | **Thu thập & Chuẩn hóa Dữ liệu**<br>- Tải và xử lý tập dữ liệu **CSE-CIC-IDS2018** (16M flows, làm sạch NaN/Inf, chuẩn hóa nhãn).<br>- Phân tích cấu trúc chuỗi tấn công nâng cao **DAPT2020**. | 20/05 – 30/05 | - Bộ dữ liệu CSV chuẩn hóa lưu trữ cục bộ.<br>- Báo cáo đặc trưng dữ liệu ([cicids2018_data_report](../data/raw/cicids2018/cicids2018_data_report.md)). | ✅ |
| **1.3** | **Xây dựng Tri thức An ninh (Knowledge Base)**<br>- Trích xuất và lập chỉ mục cấu trúc kỹ thuật chiến thuật của **MITRE ATT&CK Enterprise**.<br>- Chuẩn hóa tài liệu playbook **NIST SP 800-61r2**. | 25/05 – 01/06 | - File JSON tri thức có cấu trúc.<br>- Mã nguồn phân tích tài liệu tự động. | ✅ |
| **1.4** | **Phát triển Tier 1 Rule Engine**<br>- Triển khai các luật tĩnh (stateless) lọc cổng nhạy cảm, IP độc hại.<br>- Tích hợp cơ chế **Hot-reload YAML configuration** không làm gián đoạn streaming. | 28/05 – 08/06 | - Module `rule_engine.py` hoàn chỉnh.<br>- Cơ chế reload an toàn tránh tranh chấp ghi (Race Condition). | ✅ |
| **1.5** | **Triển khai Stateful Session Baseline**<br>- Áp dụng thuật toán trực tuyến **Welford Running Statistics** tính toán mean/stdev thời gian thực với độ phức tạp bộ nhớ $O(1)$.<br>- Kích hoạt tính toán Z-Score phát hiện Port Scan & Volumetric DoS. | 02/06 – 15/06 | - Module baselining tích hợp trong `rule_engine.py`.<br>- Kết quả Unit test kiểm thử Z-score. | 🔄 |

---

### THÁNG 2: Phát Triển Tác Tử Trí Tuệ Nhân Tạo & Lớp Phòng Thủ Guardrails (16/06 – 15/07)
*Phát triển nhân tố nhận thức sâu sử dụng Local LLM, cơ chế Dual-RAG và bảo mật chống tấn công Adversarial AI.*

| Mã | Nhiệm vụ cụ thể | Thời gian | Sản phẩm / Kết quả đầu ra | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **2.1** | **Xây dựng Lớp Guardrails Bảo mật**<br>- Triển khai Delimited Data Encapsulation (nonce động) chống Prompt Injection.<br>- Giải mã đa tầng Encoding Neutralizer (Base64, Hex, URL, Base32, ROT13, leetspeak, homoglyph NFKC, HTML entity).<br>- Tích hợp bộ lọc Jailbreak, Drain3 log template miner, Output Sanitizer và Tier-Consensus Decision Guard. | 16/06 – 25/06 | - Tầng `src/guardrails/` (11 file) với phòng thủ nhiều lớp.<br>- Bộ 120 mẫu adversarial kiểm thử bypass guardrails. | ⏳ |
| **2.2** | **Xây dựng Hệ thống Dual-RAG**<br>- Tạo vector embeddings bằng `all-MiniLM-L6-v2`.<br>- Triển khai Hybrid Search (FAISS vector + BM25 lexical) tích hợp thuật toán gom cụm Reciprocal Rank Fusion (RRF).<br>- Tích hợp Semantic Cache để giảm thiểu truy vấn trùng lặp. | 22/06 – 02/07 | - Cấu trúc dữ liệu vector index cục bộ.<br>- Module `embedder.py` và `retriever.py`. | ⏳ |
| **2.3** | **Xây dựng Tier 2 LangGraph Agent**<br>- Thiết kế Agentic workflow sử dụng LangGraph (Triage → RAG → Reasoning → Router).<br>- Kết nối API với Local LLM Gemma-2-9B-IT tối ưu hóa qua llama.cpp CUDA. | 28/06 – 08/07 | - Module LangGraph nodes (`nodes.py` và `state.py`).<br>- Docker container chạy llama.cpp server. | ⏳ |
| **2.4** | **Phát triển Threat Memory & Stream Linker**<br>- Thiết lập SQLite Threat Memory lưu vết lịch sử phiên giao dịch mạng.<br>- Phát hiện hành vi APT đa ngày bằng liên kết chuỗi sự kiện. | 05/07 – 15/07 | - Database schema SQLite.<br>- Trình phân tích chuỗi APT tích hợp. | ⏳ |

---

### THÁNG 3: Dashboard Giám Sát, Đánh Giá Thực Nghiệm & Viết Luận Văn (16/07 – 15/08)
*Xây dựng giao diện tương tác, chạy thực nghiệm chứng minh độ hiệu quả khoa học, viết báo cáo luận văn và chuẩn bị bảo vệ.*

| Mã | Nhiệm vụ cụ thể | Thời gian | Sản phẩm / Kết quả đầu ra | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **3.1** | **Xây dựng Dashboard SOC (Human-in-the-loop)**<br>- Phát triển giao diện Streamlit (Glassmorphism CSS) quản lý hàng đợi cảnh báo, phê duyệt hành động (HITL).<br>- Quản lý cấu hình Whitelist/Blocklist trực tiếp trên UI.<br>- Tích hợp đồ thị lỗ hổng Neo4j. | 16/07 – 25/07 | - Dashboard Streamlit hoạt động trên cổng `8501`.<br>- Cơ chế HMAC bảo vệ tính toàn vẹn của audit trail logs. | ⏳ |
| **3.2** | **Đánh giá Thực nghiệm Đa chiều (5D-EF)**<br>- Chạy Ablation Study (so sánh 6 cấu hình A-F) trên 4,267 mẫu GT.<br>- Đánh giá tính chịu lỗi trước 120 mẫu Adversarial (5 loại đã sinh).<br>- Đo đạc độ trễ (Latency baseline), kiểm định Mann-Whitney U.<br>- Chạy kiểm định LLM-as-Judge chéo họ mô hình. | 22/07 – 02/08 | - Báo cáo thực nghiệm tự động ghi nhận trên **MLflow**.<br>- Biểu đồ phân tích độ trễ và F1-Score cho luận văn. | ⏳ |
| **3.3** | **Viết Bản thảo Luận văn Thạc sĩ**<br>- Chương 1: Giới thiệu & Đặt vấn đề (SOC Alert Fatigue).<br>- Chương 2: Cơ sở lý thuyết (LLM, RAG, LangGraph, MITRE).<br>- Chương 3: Phương pháp nghiên cứu & Thiết kế kiến trúc.<br>- Chương 4: Triển khai, Thực nghiệm & Đánh giá (5D-EF).<br>- Chương 5: Kết luận & Hướng đi tương lai. | 25/07 – 10/08 | - Bản thảo hoàn chỉnh luận văn (PDF/DOCX) định dạng chuẩn FSB.<br>- Báo cáo kiểm trùng đạo văn. | ⏳ |
| **3.4** | **Chuẩn bị Slide & Kịch bản Bảo vệ**<br>- Thiết kế slide báo cáo kết quả thực nghiệm cô đọng.<br>- Chuẩn bị kịch bản demo hệ thống live (Docker Compose stack). | 05/08 – 13/08 | - Slide trình chiếu PowerPoint.<br>- Dockerized stack sẵn sàng chạy demo offline. | ⏳ |
| **3.5** | **Bảo vệ Luận văn**<br>- Báo cáo tiến độ và trình bày công trình trước Hội đồng. | **15/08/2026** | - **Hoàn thành bảo vệ Luận văn Thạc sĩ.** | ⏳ |

---

## 3. Kiến Trúc SENTINEL & Phân Chia Module

Hạ tầng microservices của SENTINEL được đóng gói hoàn toàn trong Docker Compose để đảm bảo khả năng mở rộng và tính độc lập:

```
[Network Traffic Stream]
         │
         ▼
 ┌──────────────┐      Benign Flows
 │    TIER 1    ├─────────────────────────► [ DROP / LOG ]
 │ Rule Engine  │
 └──────┬───────┘
        │ Escalated / Anomalous
        ▼
 ┌──────────────┐
 │  GUARDRAILS  │ (Delimited Encapsulation, Decoders, Jailbreak Filters)
 └──────┬───────┘
        │ Sanitized Data
        ▼
 ┌──────────────┐      Retrieve Context     ┌────────────────────────┐
 │    TIER 2    ├──────────────────────────►│      DUAL-RAG KB       │
 │  LangGraph   │◄──────────────────────────┤ (MITRE ATT&CK + NIST)  │
 │  AI Agent    │   Augmented Reasoning     └────────────────────────┘
 └──────┬───────┘
        │ Action Decided
        ▼
 ┌────────────────────────────────────────────────────────┐
 │                  RESPONSE EXECUTOR                     │
 │  - BLOCK_IP (Add to Redis Blacklist)                   │
 │  - AWAIT_HITL (Send to Streamlit Queue for Approval)   │
 │  - ESCALATE (Forward to Tier-2 Security Analyst)        │
 └────────────────────────────────────────────────────────┘
```

---

## 4. Kiểm Định Khoa Học (5-Dimensional Evaluation Framework)

Để luận văn đạt tính thuyết phục học thuật cao trước hội đồng FSB, hệ thống sử dụng khung đánh giá 5 chiều nghiêm ngặt:

1. **Classification Quality (Chất lượng Phân loại):** Đo F1-Score, Precision, Recall trên tập Ground Truth **4,267 mẫu** đại diện cho **14 lớp tấn công** (cộng Benign + adversarial). Mục tiêu đạt $F_1 \ge 0.90$.
2. **Operational Efficiency (Hiệu năng Vận hành):** Đo tỷ lệ giảm nhiễu (Noise Reduction Ratio) của Tier 1 và so sánh độ trễ (Latency) qua kiểm định thống kê phi tham số **Mann-Whitney U** ($p < 0.05$).
3. **Adversarial Robustness (Độ bền vững):** Đánh giá khả năng chống chịu trước **120 mẫu** tấn công nghịch đảo LLM (5 loại đã sinh: encoding bypass, structural, semantic confusion, jailbreak, RAG poisoning; rule injection để skeleton). Báo cáo cả block rate ở tầng static guardrails lẫn độ kháng của full pipeline (LLM + Tier-Consensus Guard).
4. **Context Quality (Chất lượng Ngữ cảnh RAG):** Đánh giá mức độ liên quan (Context Relevance) của tri thức MITRE/NIST được lấy ra bằng kỹ thuật LLM-as-Judge chéo họ (Llama-3.1-8B đánh giá Gemma-2-9B).
5. **Explainability & Auditing (Khả năng Giải thích & Kiểm toán):** Kiểm tra tính đầy đủ của biên bản ghi nhận hành vi (Audit Trail DB) với cơ chế bảo vệ HMAC log chaining chống sửa đổi bất hợp pháp.

---

*Hà Nội, ngày 04 tháng 06 năm 2026*

| Giảng viên hướng dẫn | Học viên thực hiện |
| :---: | :---: |
| | |
| **ThS. Bùi Văn Hiệu** | **Nguyễn Đức Bình** |
