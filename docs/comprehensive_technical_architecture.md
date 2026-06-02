# Tài liệu Kiến trúc Kỹ thuật Toàn diện (35 Bước - SENTINEL V5)

Tài liệu này đặc tả chi tiết 35 bước xử lý kỹ thuật trong toàn bộ luồng hoạt động của hệ thống SENTINEL (Cognitive Two-Tier Architecture), phân bổ xuyên suốt qua 6 phân hệ cốt lõi từ tầng Dataset đầu vào cho đến tầng Đánh giá (Evaluation).

---

# **PHẦN 1: DATASET LAYER**

### **1. CSE-CIC-IDS2018 Data Ingestion & Transformation**
1. **STEP NAME:** CSE-CIC-IDS2018 Data Ingestion & Transformation.
2. **LAYER:** Dataset Input Layer.
3. **MỤC ĐÍCH:** Biến đổi tập dữ liệu mạng tĩnh (CSV) thành dòng dữ liệu streaming thực tế mô phỏng môi trường mạng doanh nghiệp (Network Traffic Simulation), cung cấp đầu vào liên tục cho hệ thống.
4. **CÔNG NGHỆ SỬ DỤNG:** `pandas` (ETL), Generator Python (`yield`), Sleep/Delay mechanics.
5. **CƠ CHẾ HOẠT ĐỘNG:** Đọc tệp CSV khổng lồ theo từng chunk (`chunksize`). Chuyển đổi các cột dữ liệu (Timestamp, Flow Duration, Bwd Packet Length Max...) thành JSON payload. Tạo độ trễ ngẫu nhiên (`time.sleep`) để mô phỏng Real-time Traffic/Wire speed.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `scripts/fetch_and_build_dataset.py` & `src/streaming/publisher.py`.
   - Function: `stream_logs()`, `fetch_dataset()`.
   - Logic snippet:
     ```python
     for chunk in pd.read_csv("dataset.csv", chunksize=1000):
         for _, row in chunk.iterrows():
             payload = row.to_json()
             publish_to_redis(payload)
             time.sleep(random.uniform(0.01, 0.05))
     ```
   - Input: Raw CSV/Parquet file → Output: JSON strings.
7. **LUỒNG DỮ LIỆU:** CSV trên đĩa → Chunking Memory → JSON Formatting → Redis Pub/Sub channel.
8. **VAI TRÒ BẢO MẬT:** N/A — performance/efficiency role only (Mô phỏng dữ liệu).

### **2. DAPT2020 Multi-stage APT Chain Loading**
1. **STEP NAME:** Multi-Stage APT Pattern Injection.
2. **LAYER:** Dataset Input Layer.
3. **MỤC ĐÍCH:** Đảm bảo hệ thống có khả năng kiểm thử các chiến dịch Low-and-Slow APT kéo dài nhiều giai đoạn (Reconnaissance → Initial Access → Lateral Movement → Exfiltration), không chỉ các mã độc (malware) cục bộ.
4. **CÔNG NGHỆ SỬ DỤNG:** JSON Serialization, HuggingFace Datasets, SQLite.
5. **CƠ CHẾ HOẠT ĐỘNG:** Load tập dữ liệu DAPT2020 đã gán nhãn chuỗi tấn công (Kill-Chain). Các log được gán Session ID và giữ nguyên thứ tự thời gian tuyến tính để kích hoạt logic Long-Term Memory của Tier 2 sau này thông qua liên kết lịch sử.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `scripts/fetch_dapt2020.py` & `scripts/build_dapt_chains.py`.
   - Function: `process_dapt2020()`, `build_chains()`.
   - Input: DAPT2020 JSON → Output: Mapped Normalized JSON.
7. **LUỒNG DỮ LIỆU:** Raw DAPT2020 logs → Data Normalizer (Đồng nhất schema với CIC-IDS) → Redis Channel.
8. **VAI TRÒ BẢO MẬT:** N/A — performance/efficiency role only (Hỗ trợ đánh giá Contextual Correlation).

### **3. Redis Stream Ingestion and Stateful Session Tracking**
1. **STEP NAME:** Redis Pub/Sub & Stateful Session Tracker.
2. **LAYER:** Dataset Input Layer / Middleware.
3. **MỤC ĐÍCH:** Hoạt động như một Message Broker tốc độ cao (In-memory) giữa Data Publisher và Tier 1 Rule Engine, đồng thời duy trì trạng thái (State) của các phiên kết nối mạng mà không cần Database lưu trữ vĩnh viễn.
4. **CÔNG NGHỆ SỬ DỤNG:** `redis-py`, Redis Pub/Sub, Redis EXPIRE (TTL) / Local sliding memory.
5. **CƠ CHẾ HOẠT ĐỘNG:** Khi Publisher gửi log dạng JSON lên Redis Channel `sentinel_logs`, Subscriber lắng nghe. Với mỗi IP Nguồn mới, hệ thống tạo/cập nhật Session Profile trong `SessionBaseline`. Các log được liên kết phiên theo Source IP. Hệ thống thiết lập cơ chế tự dọn dẹp (eviction) các profile đã lâu không có traffic hoạt động vượt quá `ttl_seconds` để tránh cạn kiệt bộ nhớ.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/streaming/subscriber.py` & `src/tier1_filter/rule_engine.py`.
   - Class: `RedisSubscriber`, `SessionBaseline`.
   - Logic snippet:
     ```python
     def _evict_stale_profiles(self):
         now = time.time()
         stale_ips = [ip for ip, profile in self.profiles.items() 
                      if profile["last_seen"] and (now - profile["last_seen"]) > self.ttl_seconds]
         for ip in stale_ips:
             del self.profiles[ip]
     ```
   - Input: JSON từ Pub/Sub → Output: In-memory Stateful IP Profiles.
7. **LUỒNG DỮ LIỆU:** Network Stream → Redis Message Broker → Tier 1 Event Listener → Stateful Memory Update.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công từ chối dịch vụ (DoS) cạn kiệt tài nguyên bộ nhớ thông qua cơ chế tự động hủy Session rác (TTL/Eviction).

---

# **PHẦN 2: TIER 1 — RULE ENGINE**

### **4. Session-Aware Behavioral Baseline Computation (Welford Outlier)**
1. **STEP NAME:** Unsupervised Outlier Detection using Welford's Algorithm.
2. **LAYER:** Tier 1 Rule Engine.
3. **MỤC ĐÍCH:** Xây dựng đường cơ sở (Baseline) hành vi mạng chuẩn cho từng IP theo thời gian thực và phát hiện zero-day attack dưới dạng các dị biệt thống kê phi giám sát mà không tốn tài nguyên bộ nhớ.
4. **CÔNG NGHỆ SỬ DỤNG:** Thuật toán trực tuyến Welford (O(1) time, O(1) memory), Z-Score.
5. **CƠ CHẾ HOẠT ĐỘNG:** Duy trì các giá trị Trung bình (Mean) và Độ lệch chuẩn (Std Dev) chạy trực tuyến của các đặc trưng lưu lượng mạng chính. Khi có log mới, tính toán Z-Score: nếu |Z| > 3.5, đánh dấu là Outlier Anomaly và leo thang lên Tier 2 để điều tra.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/tier1_filter/rule_engine.py`.
   - Class: `RunningStats`, `RuleEngine`.
   - Logic snippet:
     ```python
     def push(self, x: float):
         self.n += 1
         if self.n == 1:
             self.old_m = self.new_m = x
             self.old_s = 0.0
         else:
             self.new_m = self.old_m + (x - self.old_m) / self.n
             self.new_s = self.old_s + (x - self.old_m) * (x - self.new_m)
             self.old_m = self.new_m
             self.old_s = self.new_s
     ```
   - Input: Flow statistics variables → Output: Z-Score / Escalation flag.
7. **LUỒNG DỮ LIỆU:** Raw Flow variables → Welford calculations → Z-Score evaluation → Outlier Trigger.
8. **VAI TRÒ BẢO MẬT:** Phát hiện zero-day attack vượt qua các rule tĩnh truyền thống bằng cách kiểm soát độ lệch phân bố thống kê.

### **5. IP Blacklist Lookup Mechanism**
1. **STEP NAME:** Static Threat Intelligence Lookup.
2. **LAYER:** Tier 1 Rule Engine.
3. **MỤC ĐÍCH:** Drop tức thì (Wire-speed drop) các IP độc hại đã biết mà không cần phân tích tốn kém ở LLM.
4. **CÔNG NGHỆ SỬ DỤNG:** O(1) Hash Map (Python `set` hoặc Redis lookup).
5. **CƠ CHẾ HOẠT ĐỘNG:** Truy vấn IP nguồn (`src_ip`) vào một bảng Hash Table chứa danh sách IP xấu từ Threat Intel. Quá trình tra cứu mất chưa tới O(1) thời gian. Nếu khớp, tăng điểm rủi ro và chặn lập tức.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/tier1_filter/rule_engine.py`.
   - Function: `_check_blacklist(ip)`.
   - Logic: `if ip in self.blacklist_set: return ThreatLevel.CRITICAL`
   - Input: IP String → Output: Boolean (Matched/Unmatched).
7. **LUỒNG DỮ LIỆU:** Extracted IP → Hash Table Memory Lookup → Drop Trigger.
8. **VAI TRÒ BẢO MẬT:** Chống lại Known Botnets, Mass Scanners, DDoS.

### **6. Rate Threshold Evaluation**
1. **STEP NAME:** Heuristic Rate Limiting.
2. **LAYER:** Tier 1 Rule Engine.
3. **MỤC ĐÍCH:** Chặn đứng các hành vi Brute-force, Syn Flood truyền thống bằng các rule cứng (Hard Rules).
4. **CÔNG NGHỆ SỬ DỤNG:** Token Bucket / Leaky Bucket Heuristics (Python Variables).
5. **CƠ CHẾ HOẠT ĐỘNG:** Đếm số lượng request/packet vào các Port nhạy cảm (22 SSH, 3389 RDP) trong cửa sổ 1 giây hoặc 1 phút. Nếu vượt ngưỡng cho phép → Tính điểm rủi ro.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/tier1_filter/rule_engine.py`.
   - Function: `_evaluate_rate_limits()`.
   - Input: Flow Record → Output: Penalty Score.
7. **LUỒNG DỮ LIỆU:** Port/Protocol extraction → Counter check → Scoring.
8. **VAI TRÒ BẢO MẬT:** Chống lại Brute-force Authentication, Port Scanning, DDoS.

### **7. Benign Traffic Drop Decision**
1. **STEP NAME:** Wire-speed Clean Traffic Dropping.
2. **LAYER:** Tier 1 Rule Engine.
3. **MỤC ĐÍCH:** Đây là màng lọc quan trọng nhất giúp Tier 2 (LLM Agent) không bị nghẽn (Bottleneck) thông qua việc triệt tiêu hơn 99% lượng log an toàn (Noise).
4. **CÔNG NGHỆ SỬ DỤNG:** If-else Heuristic Logic (Python).
5. **CƠ CHẾ HOẠT ĐỘNG:** Nếu tổng điểm rủi ro (Risk Score) của một Session từ Baseline + Rate Limit + Blacklist nhỏ hơn một `THRESHOLD_BENIGN` (ví dụ: < 30 điểm), trả về hành động `DROP`. Log biến mất khỏi luồng xử lý và không được gửi đi.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/tier1_filter/rule_engine.py`.
   - Function: `evaluate()`.
   - Logic: `if total_score < self.risk_threshold: return {"tier1_action": "DROP", ...}`
   - Input: Total Score → Output: Void / Drop Action.
7. **LUỒNG DỮ LIỆU:** Scored Session → Garbage Collector (Hủy).
8. **VAI TRÒ BẢO MẬT:** Triệt tiêu cảnh báo giả và giảm tải tối đa cho mô hình ngôn ngữ lớn (Alert Fatigue Prevention).

### **8. Anomalous Traffic Escalation Trigger**
1. **STEP NAME:** Threat Escalation (Escalate to Tier 2).
2. **LAYER:** Tier 1 Rule Engine.
3. **MỤC ĐÍCH:** Đẩy các luồng mạng bất thường hoặc có biểu hiện outlier vượt ngưỡng (|Z| > 3.5) lên AI Agent để phân tích chuyên sâu.
4. **CÔNG NGHỆ SỬ DỤNG:** Redis Queue, Message broker.
5. **CƠ CHẾ HOẠT ĐỘNG:** Khi `total_score >= THRESHOLD_ESCALATE` hoặc phát hiện dị biệt thống kê bởi Welford, Tier 1 đánh dấu hành động là `ESCALATE` và đẩy log vào bộ đệm của subscriber để gom thành batch gửi đến Tier 2.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/tier1_filter/rule_engine.py` & `src/streaming/subscriber.py`.
   - Function: `evaluate()`, `start_listening()`.
   - Input: Raw network log → Output: Escalate flag + Session history payload.
7. **LUỒNG DỮ LIỆU:** Tier 1 evaluation → Escalate Flag → Subscriber batch buffer → LangGraph workflow input.
8. **VAI TRÒ BẢO MẬT:** Đưa các lưu lượng nghi ngờ, mập mờ vào luồng phân tích nhận thức sâu để phát hiện xâm nhập tinh vi.

---

# **PHẦN 3: GUARDRAIL LAYER**

### **9. Drain3 Log Template Mining**
1. **STEP NAME:** Log Parsing & Template Abstraction.
2. **LAYER:** Guardrail Layer (Pre-processing).
3. **MỤC ĐÍCH:** Giải quyết bài toán giới hạn token của LLM, tránh việc đưa hàng nghìn dòng log giống hệt nhau làm tràn cửa sổ ngữ cảnh (Context Overflow).
4. **CÔNG NGHỆ SỬ DỤNG:** `drain3` library (Thuật toán Fixed Depth Tree).
5. **CƠ CHẾ HOẠT ĐỘNG:** Duyệt qua log mạng và tách các trường động (IP, Port, Timestamp) thành thẻ `<*>`. Xây dựng cây parse tree để gom nhóm các log có cùng cấu trúc tĩnh vào một Template ID và đếm tần suất xuất hiện của chúng.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/guardrails/template_miner.py`.
   - Class: `LogTemplateMiner`.
   - Function: `add_log_dict()`.
   - Input: Array of raw logs → Output: Dictionary of templates & occurrences.
7. **LUỒNG DỮ LIỆU:** Raw JSON/string → Drain3 Tree Parser → Abstracted Template.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công làm cạn kiệt tài nguyên ngữ cảnh LLM (Context Exhaustion / DoS).

### **10. Token Compression Output**
1. **STEP NAME:** Summarized Token Budgeting.
2. **LAYER:** Guardrail Layer.
3. **MỤC ĐÍCH:** Đảm bảo dữ liệu gửi vào prompt luôn nằm trong giới hạn tối đa cho phép của mô hình (ví dụ 4000 tokens) nhưng vẫn giữ lại đầy đủ chỉ báo xâm nhập.
4. **CÔNG NGHỆ SỬ DỤNG:** Tiktoken / LLM Tokenizer heuristics.
5. **CƠ CHẾ HOẠT ĐỘNG:** Đếm tổng số token của các template. Định dạng đầu ra dưới dạng Markdown cô đọng: `[1000x] Template: Connection from IP <*>`. Nếu vượt quá giới hạn token, hệ thống tự động cắt bỏ (truncate) các log ít quan trọng hơn.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/guardrails/template_miner.py`.
   - Class: `TokenBudgetManager`.
   - Function: `fit_to_budget()`.
   - Input: Abstracted Templates → Output: Compressed Markdown String.
7. **LUỒNG DỮ LIỆU:** Template Dictionary → Length Evaluation → Truncated String.
8. **VAI TRÒ BẢO MẬT:** Tối ưu hóa hiệu năng và giảm chi phí suy luận (Inference cost).

### **11. Delimited Data Encapsulation**
1. **STEP NAME:** Dynamic Prompt Encapsulation.
2. **LAYER:** Guardrail Layer.
3. **MỤC ĐÍCH:** Phân tách rạch ròi giữa chỉ thị hệ thống (System Prompt) và dữ liệu log đầu vào không đáng tin cậy. Ngăn LLM nhầm lẫn dữ liệu log là câu lệnh điều khiển.
4. **CÔNG NGHỆ SỬ DỤNG:** Python `secrets.token_hex()` (Cryptographically Secure Pseudo-Random Number Generator).
5. **CƠ CHẾ HOẠT ĐỘNG:** Sinh ngẫu nhiên một chuỗi Delimiter có cấu trúc bảo mật (ví dụ: `===SENTINEL_DATA_a1b2c3d4===`) cho mỗi phiên. Hướng dẫn LLM chỉ được xử lý dữ liệu nằm giữa dấu phân cách này và bọc toàn bộ log vào bên trong.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/guardrails/prompt_filter.py`.
   - Class: `DelimitedDataEncapsulator`.
   - Logic snippet:
     ```python
     delimiter = f"===SENTINEL_DATA_{secrets.token_hex(8)}==="
     return f"{delimiter}\n{raw_data}\n{delimiter}"
     ```
   - Input: Compressed String → Output: Encapsulated String.
7. **LUỒNG DỮ LIỆU:** Compressed Log → Hex Generator → Wrapped Payload.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công chèn mã lệnh trực tiếp (Direct Prompt Injection).

### **12. Delimiter Smuggling Prevention**
1. **STEP NAME:** Smuggling Escapement & Stripping.
2. **LAYER:** Guardrail Layer.
3. **MỤC ĐÍCH:** Ngăn chặn kẻ tấn công tự sinh chuỗi phân cách giả mạo (ví dụ chèn `===SENTINEL_DATA_` trong User-Agent payload) để đóng ngoặc sớm và chèn lệnh điều khiển bên ngoài vùng đóng gói.
4. **CÔNG NGHỆ SỬ DỤNG:** Regex Pattern Matching.
5. **CƠ CHẾ HOẠT ĐỘNG:** Quét qua dữ liệu log thô bằng Regex trước khi đóng gói. Nếu phát hiện bất kỳ chuỗi nào trùng khớp với định dạng Delimiter, hệ thống lập tức loại bỏ (`[DELIMITER_STRIPPED]`) để vô hiệu hóa nỗ lực smuggling.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/guardrails/prompt_filter.py`.
   - Class: `DelimitedDataEncapsulator`.
   - Function: `_strip_smuggling_attempts()`.
   - Input: Raw data string, Delimiter Pattern → Output: Cleaned data string.
7. **LUỒNG DỮ LIỆU:** Raw string → Regex Stripper → Safe String.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công Delimiter Smuggling / Escape Injection.

### **13. Structural Sanitization**
1. **STEP NAME:** Encoding Neutralization & Character Normalization.
2. **LAYER:** Guardrail Layer (Output/Input Sanitizer).
3. **MỤC ĐÍCH:** Bảo vệ công cụ RAG khỏi nhiễu ngữ nghĩa (Semantic Confusion), giải mã các obfuscation của hacker, và cấm XSS/Markdown Exfiltration khi trả kết quả về UI.
4. **CÔNG NGHỆ SỬ DỤNG:** Unicode Normalization (NFKC), Base64/Hex decoding, HTML/Markdown Sanitization.
5. **CƠ CHẾ HOẠT ĐỘNG:** Giải mã các payload Hex/Base64 độc hại. Loại bỏ ký tự zero-width, control characters. Quét và loại bỏ các thẻ HTML nguy hiểm và cú pháp hình ảnh Markdown (`!alt`) để cấm LLM đẩy dữ liệu nhạy cảm ra ngoài qua render HTML.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/guardrails/output_sanitizer.py`.
   - Class: `OutputSanitizer`.
   - Function: `sanitize()`, `_decode_base64()`.
   - Input: LLM Output / Log Input → Output: Sanitized String.
7. **LUỒNG DỮ LIỆU:** Raw text → Normalization → Decoding → Sanitized Output.
8. **VAI TRÒ BẢO MẬT:** Phòng chống RAG Poisoning, XSS, và rò rỉ dữ liệu qua giao diện quản trị (Data Exfiltration).

---

# **PHẦN 4: TIER 2 — LANGGRAPH AGENT**

### **14. LangGraph StateGraph Node Definitions & Edges**
1. **STEP NAME:** Cognitive Workflow Orchestration.
2. **LAYER:** Tier 2 LangGraph Agent.
3. **MỤC ĐÍCH:** Xây dựng cỗ máy trạng thái hữu hạn (FSM) luân chuyển dữ liệu qua các node xử lý một cách an toàn, duy trì trạng thái của phiên điều tra mà không làm mất thông tin.
4. **CÔNG NGHỆ SỬ DỤNG:** `langgraph.graph.StateGraph`, `TypedDict` (State Schema).
5. **CƠ CHẾ HOẠT ĐỘNG:** Định nghĩa cấu trúc `SentinelState` mang thông tin phiên điều tra. Đăng ký các nút xử lý: `rag_context` → `llm_triage` → `execute_action`. Tại `llm_triage`, kết quả phân loại từ LLM sẽ kích hoạt Conditional Edges để điều hướng hành động tiếp theo.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/agent/workflow.py` & `src/agent/nodes.py`.
   - Class/Function: `SentinelState`, `create_agent_workflow()`, `route_triage_decision()`.
   - Logic snippet:
     ```python
     workflow.add_node("rag_context", node_rag_context)
     workflow.add_node("llm_triage", node_llm_triage)
     workflow.add_edge("rag_context", "llm_triage")
     workflow.add_conditional_edges("llm_triage", route_triage_decision)
     ```
   - Input: State Object → Output: Compiled Graph App.
7. **LUỒNG DỮ LIỆU:** Raw Incident → Guardrails Node → RAG Node → LLM Node → Action/HITL Node.
8. **VAI TRÒ BẢO MẬT:** Ràng buộc quy trình logic bảo mật (Logic Enforcer), cấm tác tử tự động thực thi phản hồi mạng mà không qua các trạm thẩm định.

### **15 & 16. FAISS Index 1 & 2 (MITRE ATT&CK & NIST SP 800-61r2)**
1. **STEP NAME:** Dual-Knowledge Dense Vector Retrieval.
2. **LAYER:** Tier 2 LangGraph Agent (RAG Sub-module).
3. **MỤC ĐÍCH:** Cung cấp tri thức chuyên sâu về kỹ thuật tấn công (MITRE ATT&CK) và quy trình ứng phó (NIST) dựa trên ngữ nghĩa của log mạng, ngăn chặn ảo giác (Hallucination) của LLM.
4. **CÔNG NGHỆ SỬ DỤNG:** `faiss-cpu`, mô hình embedding `all-MiniLM-L6-v2` (384 chiều).
5. **CƠ CHẾ HOẠT ĐỘNG:** Tài liệu MITRE và NIST được lưu trữ dưới dạng vector 384 chiều trong 2 chỉ mục FAISS. Khi có truy vấn từ log, hệ thống mã hóa nó thành vector và tìm kiếm top-K văn bản có khoảng cách Euclidean nhỏ nhất.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/rag/embedder.py` & `src/rag/retriever.py`.
   - Class: `DualRetriever`.
   - Function: `_retrieve_dense(query, index)`.
   - Input: Query String → Output: List of Top-K Document Dicts.
7. **LUỒNG DỮ LIỆU:** Query String → Embedding Model → Vector → FAISS L2 Search → Ranked Chunks.
8. **VAI TRÒ BẢO MẬT:** Đảm bảo LLM lập luận bảo mật dựa trên các khung tiêu chuẩn chính thống, giảm dương tính giả.

### **17. BM25Okapi Sparse Keyword Matching**
1. **STEP NAME:** Lexical/Sparse Retrieval Matching.
2. **LAYER:** Tier 2 LangGraph Agent (RAG Sub-module).
3. **MỤC ĐÍCH:** Khắc phục điểm yếu của dense vector search trong việc tìm kiếm các từ khóa chính xác như CVE ID, địa chỉ IP hoặc port đặc thù.
4. **CÔNG NGHỆ SỬ DỤNG:** `rank_bm25.BM25Okapi`.
5. **CƠ CHẾ HOẠT ĐỘNG:** Kho tài liệu được tokenize và lập chỉ mục ngược. Điểm số tương đồng từ khóa được tính toán bằng thuật toán BM25Okapi để lọc ra các văn bản chứa chính xác định danh bảo mật cần tìm.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/rag/retriever.py`.
   - Class: `DualRetriever`.
   - Function: `_retrieve_sparse(query_tokens)`.
   - Input: Query Tokens → Output: List of Sparse Scores.
7. **LUỒNG DỮ LIỆU:** Query Tokens → BM25 calculation → Ranked Sparse Chunks.
8. **VAI TRÒ BẢO MẬT:** N/A — Cải thiện độ chính xác tìm kiếm RAG đối với các chỉ báo xâm nhập cụ thể.

### **18. Reciprocal Rank Fusion (RRF, k=60) Score Merging**
1. **STEP NAME:** Hybrid Search Score Aggregation.
2. **LAYER:** Tier 2 LangGraph Agent (RAG Sub-module).
3. **MỤC ĐÍCH:** Hợp nhất kết quả xếp hạng từ FAISS (Dense) và BM25 (Sparse) một cách công bằng mà không cần chuẩn hóa điểm số khác biệt về thang đo của 2 thuật toán.
4. **CÔNG NGHỆ SỬ DỤNG:** Thuật toán Reciprocal Rank Fusion (RRF) với hằng số k = 60.
5. **CƠ CHẾ HOẠT ĐỘNG:** Chạy Dense và Sparse song song. Lấy vị trí thứ hạng (rank) của từng tài liệu trong 2 list và cộng điểm RRF: RRF_Score = tổng_của( 1 / (k + rank) ). Sắp xếp lại danh sách theo điểm số này.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/rag/retriever.py`.
   - Function: `_rrf_merge(dense_results, sparse_results, k=60)`.
   - Logic:
     ```python
     rrf_scores[doc_id] += 1.0 / (k + rank)
     ```
   - Input: 2 Ranked Lists → Output: 1 Final Sorted Top-K List.
7. **LUỒNG DỮ LIỆU:** Dense Ranks + Sparse Ranks → RRF merging → Final Sorted Context.
8. **VAI TRÒ BẢO MẬT:** N/A — Đảm bảo ngữ cảnh đưa vào LLM là tối ưu nhất.

### **19. Context Merge and LLM Prompt Construction (Few-shot Active Learning)**
1. **STEP NAME:** Prompt Structuring & Context Injection.
2. **LAYER:** Tier 2 LangGraph Agent.
3. **MỤC ĐÍCH:** Tạo lập prompt hoàn chỉnh chứa logs mạng, tri thức RAG và bổ sung thêm các ví dụ thực tiễn từ vòng lặp Few-shot Active Learning để LLM tự học quyết định sửa sai của con người.
4. **CÔNG NGHỆ SỬ DỤNG:** Jinja2 / Prompt formatting.
5. **CƠ CHẾ HOẠT ĐỘNG:** Đọc các quyết định Approve/Reject trước đây của analyst trong cấu hình hệ thống, sinh các ví dụ few-shot đưa trực tiếp vào cuối System Prompt để định hình lập luận bảo mật cho LLM.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/agent/prompts.py` & `src/agent/nodes.py`.
   - Function: `build_triage_prompt(log_data, rag_context)`.
   - Input: Logs + Context → Output: Message Array `[{"role": "system", ...}, {"role": "user", ...}]`.
7. **LUỒNG DỮ LIỆU:** Sub-components + Active Learning examples → Prompt Builder → LLM Input.
8. **VAI TRÒ BẢO MẬT:** Giúp tác tử tự sửa sai và cải thiện độ chính xác phân loại theo thời gian dựa trên tương tác con người.

### **20. Gemma-2-9B-IT Inference via llama.cpp**
1. **STEP NAME:** Agentic Cognitive Inference.
2. **LAYER:** Tier 2 LangGraph Agent.
3. **MỤC ĐÍCH:** "Bộ não" chính của toàn hệ thống, chịu trách nhiệm đọc ngữ cảnh, suy luận logic an ninh mạng và đưa ra phán quyết.
4. **CÔNG NGHỆ SỬ DỤNG:** Server `llama.cpp`, mô hình cục bộ `Gemma-2-9B-IT` định dạng GGUF lượng tử hóa 4-bit (`Q4_K_M`).
5. **CƠ CHẾ HOẠT ĐỘNG:** Phục vụ mô hình hoàn toàn offline trên GPU (RTX 4060 Ti). Gửi HTTP POST request tới API tương thích OpenAI của server llama.cpp. Cấu hình `temperature=0.1` để đảm bảo câu trả lời mang tính xác định cao nhất và tuân thủ định dạng JSON.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/agent/llm_client.py`.
   - Class: `OpenAILLMClient`.
   - Function: `invoke(messages, temperature)`.
   - Input: Message Array → Output: JSON String.
7. **LUỒNG DỮ LIỆU:** Node Triage → HTTP POST Request → GPU Compute → JSON Response.
8. **VAI TRÒ BẢO MẬT:** Thực hiện phân tích nhận thức sâu để phát hiện các mẫu tấn công tinh vi.

### **21. Decision Output: BLOCK / QUARANTINE / ALERT**
1. **STEP NAME:** Action Routing & Execution.
2. **LAYER:** Tier 2 LangGraph Agent.
3. **MỤC ĐÍCH:** Biến kết quả phán quyết JSON của LLM thành các hành động tác động vật lý lên tường lửa hoặc đưa vào quarantine.
4. **CÔNG NGHỆ SỬ DỤNG:** Python API Callbacks, OS Firewall command scripting.
5. **CƠ CHẾ HOẠT ĐỘNG:** Đọc trường `action` từ JSON:
   - `BLOCK_IP`: Gọi hàm chặn IP ở mức mạng và ghi nhận quy tắc vào hàng đợi cách ly chờ phê duyệt.
   - `ALERT`: Ghi cảnh báo đỏ lên DB mà không cấm.
   - `AWAIT_HITL` (QUARANTINE): Phán quyết mập mờ, chuyển thẳng vào hàng đợi chờ analyst duyệt.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/agent/nodes.py` & `src/response/executor.py`.
   - Function: `node_action_executor()`, `block_ip()`.
   - Input: Parsed JSON Dictionary → Output: Action Executions.
7. **LUỒNG DỮ LIỆU:** LLM Output JSON → Callback Router → Execution / Database write.
8. **VAI TRÒ BẢO MẬT:** Cô lập tấn công, phản ứng ngăn chặn kịp thời (Threat Neutralization).

### **22 & 23. Long-Term Threat Memory & APT Chain Tracking Logic**
1. **STEP NAME:** Stateful Threat Memory & APT Correlation.
2. **LAYER:** Tier 2 LangGraph Agent (Memory).
3. **MỤC ĐÍCH:** Lưu trữ uy tín (Reputation) dài hạn của các IP vi phạm và kết nối các hành vi đơn lẻ qua nhiều ngày để phát hiện các chiến dịch APT low-and-slow.
4. **CÔNG NGHỆ SỬ DỤNG:** Cơ sở dữ liệu SQLite, IP Reputation Scoring.
5. **CƠ CHẾ HOẠT ĐỘNG:** Lưu vết mọi incident vi phạm vào SQLite. Khi có IP mới bị leo thang, hệ thống tra cứu SQLite xem IP này đã thực hiện các kỹ thuật gì. Nếu IP vi phạm liên quan đến >= 3 giai đoạn khác nhau trong ma trận MITRE ATT&CK theo thời gian → Đánh dấu cảnh báo APT nguy cấp và nâng mức cảnh báo của IP lên critical.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/agent/threat_memory.py`.
   - Class: `ThreatMemoryManager`.
   - Function: `record_incident()`, `check_apt_pattern()`.
   - Input: IP, Action, MITRE ID → Output: SQLite Insert/Update, APT Candidate Flag (Boolean).
7. **LUỒNG DỮ LIỆU:** Action Node → SQLite Write → (Chu kỳ sau) SQLite Read → System Prompt.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công APT có kỹ năng ẩn mình và đổi chiến thuật qua thời gian dài để bypass Signature.

---

# **PHẦN 5: HITL DASHBOARD**

### **24. Streamlit UI Layout and State Management**
1. **STEP NAME:** SOC SIEM Dashboard Initialization.
2. **LAYER:** HITL Dashboard Layer.
3. **MỤC ĐÍCH:** Giao diện trực quan thời gian thực (Real-time GUI) cho phép chuyên gia an ninh mạng theo dõi hệ thống, điều tra sự cố và phê duyệt quy tắc mà không cần xem terminal.
4. **CÔNG NGHỆ SỬ DỤNG:** `streamlit`, `streamlit-autorefresh`, `st.session_state`.
5. **CƠ CHẾ HOẠT ĐỘNG:** Tổ chức giao diện dưới dạng Tabs (SIEM Monitor, Tường lửa, Quét lỗ hổng...). Sử dụng autorefresh định kỳ mỗi 3 giây để đồng bộ dữ liệu mới nhất từ cơ sở dữ liệu.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/ui/app.py`.
   - Function: `main_dashboard()`.
   - Input: User interactions → Output: Rendered HTML/CSS.
7. **LUỒNG DỮ LIỆU:** SQLite Reads / Feedback Listener Reads → Streamlit App → Browser.
8. **VAI TRÒ BẢO MẬT:** N/A — Tăng khả năng giám sát trực quan cho SOC.

### **25. Quarantine Rule Review & SOC Manager Workflow**
1. **STEP NAME:** Role-Based Access Control (RBAC) & Human-In-The-Loop Workflow.
2. **LAYER:** HITL Dashboard Layer.
3. **MỤC ĐÍCH:** Ngăn chặn LLM tự động đưa ra các quyết định cấm nhầm IP quan trọng hoặc gateway bằng cách bắt buộc phải có sự xác nhận của quản trị viên (L3 Manager).
4. **CÔNG NGHỆ SỬ DỤNG:** RBAC Session, Streamlit Buttons.
5. **CƠ CHẾ HOẠT ĐỘNG:** Các quy tắc chặn do AI đề xuất sẽ ở trạng thái `PENDING` và đưa vào hàng đợi cách ly. Giao diện chỉ cho phép tài khoản có vai trò `manager` (L3) click duyệt (**Approve**) hoặc từ chối (**Reject**).
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/ui/app.py` & `src/tier1_filter/feedback_listener.py`.
   - Function: `approve_rule()`, `get_active_dynamic_rules()`.
   - Input: Manager Click Event → Output: Rule status change (PENDING → ACTIVE/REJECTED).
7. **LUỒNG DỮ LIỆU:** UI Click → State change → Ghi file cấu hình `system_settings.yaml`.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công Adversarial Rule Injection.

### **26. Live Production False Positive Rate (FPR) Tracker**
1. **STEP NAME:** Live Production FPR Metric Display.
2. **LAYER:** HITL Dashboard Layer.
3. **MỤC ĐÍCH:** Trực quan hóa tỷ lệ cảnh báo sai thực tế của mô hình LLM tại môi trường vận hành thời gian thực để chuyên gia SOC đánh giá hiệu năng AI.
4. **CÔNG NGHỆ SỬ DỤNG:** Streamlit Metric Cards, Python calculations.
5. **CƠ CHẾ HOẠT ĐỘNG:** Hệ thống tính toán tỷ lệ cảnh báo sai dựa trên phản hồi bác bỏ của analyst: Live FPR = (Rejected Rules) / (Approved + Rejected) * 100%. Thẻ KPI hiển thị màu sắc Neon để chỉ thị cảnh báo tương ứng (Xanh lá < 10%, Đỏ > 25%).
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/ui/app.py` & `src/ui/components.py`.
   - Function: `render_metrics_header()`.
   - Input: Configuration count lists → Output: Live FPR Score (Float).
7. **LUỒNG DỮ LIỆU:** Rule counters → FPR Formula → Rendered Dashboard Metric Card.
8. **VAI TRÒ BẢO MẬT:** Đánh giá tính kháng nhiễu và độ tin cậy thực tế của bộ óc AI trong môi trường sản xuất.

### **27. Docker Model Switcher Orchestration**
1. **STEP NAME:** LLM Model Switcher.
2. **LAYER:** HITL Dashboard Layer.
3. **MỤC ĐÍCH:** Cho phép quản trị viên chuyển đổi nhanh cấu hình hoặc hoán đổi mô hình LLM đang chạy (ví dụ giữa Gemma và Llama) trực tiếp từ giao diện mà không gây gián đoạn luồng xử lý chính.
4. **CÔNG NGHỆ SỬ DỤNG:** Bash scripting, Docker-compose env hot-reload.
5. **CƠ CHẾ HOẠT ĐỘNG:** Khi admin chọn model trên UI và bấm áp dụng, hệ thống gọi script chạy ngầm cập nhật biến môi trường `LLM_MODEL_FILE` trong file `.env` và restart container `sentinel_llm` tự động.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `scripts/switch_model.sh` & `src/ui/app.py`.
   - Input: Model name string → Output: Environment hot-reload.
7. **LUỒNG DỮ LIỆU:** UI Select → Script execution → Docker Container Restart → Port 5000 API reconnect.
8. **VAI TRÒ BẢO MẬT:** Hỗ trợ tính linh hoạt và dự phòng lỗi (Failover) của bộ óc AI.

### **28. HMAC Cryptographic Log Chaining**
1. **STEP NAME:** Immutable Audit Logging with Cryptographic Chaining.
2. **LAYER:** HITL Dashboard Layer / Response.
3. **MỤC ĐÍCH:** Chống giả mạo nhật ký sự kiện trong DB SQLite bằng cách tạo ra một chuỗi liên kết băm mật mã học (HMAC Log Chaining) tương tự cấu trúc Blockchain.
4. **CÔNG NGHỆ SỬ DỤNG:** `hmac` (SHA-256), `sqlite3`.
5. **CƠ CHẾ HOẠT ĐỘNG:** Khi ghi một dòng log mới vào bảng `audit_trail`, giá trị băm HMAC được tính toán dựa trên nội dung log và hash của dòng log trước đó. Nút kiểm tra tính toàn vẹn logs quét qua DB, tính toán lại hash và báo đỏ nếu phát hiện bất kỳ sự thay đổi dữ liệu trái phép nào.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `src/response/executor.py` & `src/ui/app.py`.
   - Function: `_log_to_db()`, `verify_log_chain()`.
   - Input: Log record data → Output: Cryptographic Hash string.
7. **LUỒNG DỮ LIỆU:** Log data → HMAC calculation → SQLite Write → Integrity Check.
8. **VAI TRÒ BẢO MẬT:** Phòng chống tấn công xâm nhập DB sửa xóa dấu vết log (Non-repudiation / Forensics Protection).

### **29 & 30. Cross-family Judge Invocation & RAGAS Metric Computation**
1. **STEP NAME:** Cross-family LLM-as-a-Judge RAGAS Context Evaluation.
2. **LAYER:** Evaluation Framework / HITL Context.
3. **MỤC ĐÍCH:** Chấm điểm tự động và độc lập chất lượng ngữ cảnh truy xuất RAG của Gemma-2-9B-IT mà không bị ảnh hưởng bởi thiên kiến tự đề cao.
4. **CÔNG NGHỆ SỬ DỤNG:** Mô hình `Llama-3.1-8B-Instruct` (trọng tài), RAGAS-inspired Prompting Rubrics.
5. **CƠ CHẾ HOẠT ĐỘNG:** Sử dụng mô hình `Llama-3.1` (khác họ với Gemma) làm trọng tài chấm điểm câu trả lời từ 0.0 đến 1.0 cho 4 khía cạnh: Context Precision, Answer Relevancy, Faithfulness, Context Recall dựa trên các tiêu chí RAGAS.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `experiments/evaluate_reasoning.py`.
   - Function: `evaluate_with_llama_judge()`.
   - Input: Gemma Output + Context → Output: 4 Metric Scores (JSON).
7. **LUỒNG DỮ LIỆU:** RAG Output + Gemma Response → Llama-3.1 Prompt → Metric Scores.
8. **VAI TRÒ BẢO MẬT:** Đánh giá chất lượng và độ trung thực của RAG, chống ngộ độc tri thức (RAG Poisoning).

---

# **PHẦN 6: EVALUATION FRAMEWORK (5D)**

### **31. Ablation Study Setup**
1. **STEP NAME:** 5-Dimensional Ablation Configuration.
2. **LAYER:** Evaluation Framework.
3. **MỤC ĐÍCH:** Chứng minh hiệu năng của kiến trúc 2-Tier thông qua thử nghiệm loại bỏ (Ablation Study) bằng cách so sánh 6 cấu hình từ A đến F.
4. **CÔNG NGHỆ SỬ DỤNG:** YAML configs, MLflow Experiment Tracking.
5. **CƠ CHẾ HOẠT ĐỘNG:** Bật/tắt các cấu phần hệ thống thông qua các file YAML. Chạy thử nghiệm tự động trên tập dữ liệu ground truth và ghi nhật ký chỉ số lên MLflow để phân tích trực quan.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `config/ablation/*.yaml` & `experiments/run_ablation_study.py`.
   - Input: YAML Config → Output: MLflow logs.
7. **LUỒNG DỮ LIỆU:** Config YAML → Ablation script run → Metric results → MLflow dashboard.
8. **VAI TRÒ BẢO MẬT:** N/A — Phương pháp luận thực nghiệm nghiên cứu khoa học.

### **32. Classification Metrics & McNemar's Test**
1. **STEP NAME:** Statistical Classification Benchmark.
2. **LAYER:** Evaluation Framework.
3. **MỤC ĐÍCH:** Đo lường khả năng phân loại và kiểm định ý nghĩa thống kê của việc cải thiện độ chính xác (Precision, Recall, F1, FPR).
4. **CÔNG NGHỆ SỬ DỤNG:** `scikit-learn`, `statsmodels` (McNemar's Test).
5. **CƠ CHẾ HOẠT ĐỘNG:** So sánh nhãn dự đoán và ground truth trên 750 mẫu. Chạy kiểm định McNemar trên ma trận nhầm lẫn để tính toán p-value: nếu p < 0.05, chứng minh cải tiến có ý nghĩa thống kê thực tế.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `experiments/statistical_tests.py` & `run_ablation_study.py`.
   - Function: `compute_classification_metrics()`, `mcnemar_test()`.
   - Input: Prediction arrays → Output: Quality scores & p-value.
7. **LUỒNG DỮ LIỆU:** Result arrays → Sklearn formulas → P-value.
8. **VAI TRÒ BẢO MẬT:** N/A — Đánh giá tính chính xác tổng thể trong phát hiện xâm nhập.

### **33. Operational Metrics & Mann-Whitney U Test**
1. **STEP NAME:** Processing Latency & System Operations Tracking.
2. **LAYER:** Evaluation Framework.
3. **MỤC ĐÍCH:** Đo lường độ trễ xử lý (MTTR/MTTD proxy), tỷ lệ leo thang và cache hit rate để chứng minh tính khả thi triển khai trong thực tế.
4. **CÔNG NGHỆ SỬ DỤNG:** Python `time`, `scipy.stats` (Mann-Whitney U Test).
5. **CƠ CHẾ HOẠT ĐỘNG:** Ghi nhận thời gian suy luận. So sánh độ trễ giữa hệ thống 1-tier và 2-tier bằng kiểm định phi tham số Mann-Whitney U để xác minh việc giảm 99.8% độ trễ xử lý của Tier 1 có ý nghĩa thống kê.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `experiments/statistical_tests.py`.
   - Function: `mann_whitney_u_test(latency_A, latency_F)`.
   - Input: Latency arrays → Output: U-test p-value.
7. **LUỒNG DỮ LIỆU:** Time Deltas → U-test math → p-value.
8. **VAI TRÒ BẢO MẬT:** Xác thực hiệu năng của màng lọc Tier 1 trong việc chống nghẽn LLM.

### **34. Robustness against Adversarial Attacks**
1. **STEP NAME:** Adversarial Guardrail Defeat Rate Measurement.
2. **LAYER:** Evaluation Framework.
3. **MỤC ĐÍCH:** Đánh giá độ bền bỉ và khả năng phòng thủ của hệ thống trước 45 mẫu tấn công nghịch đảo tinh vi.
4. **CÔNG NGHỆ SỬ DỤNG:** JSON adversarial dataset (45 mẫu).
5. **CƠ CHẾ HOẠT ĐỘNG:** Nhồi các log chứa chuỗi prompt injection và encoding bypass đặc chế. Tính toán tỷ lệ phần trăm payload có thể bypass được guardrail để thao túng LLM.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `experiments/evaluate_robustness.py`.
   - Function: `run_robustness_eval()`.
   - Input: Adversarial JSON List → Output: Defeat Rate Percentage.
7. **LUỒNG DỮ LIỆU:** Adversarial logs → Guardrails pipeline → Block/Pass decisions.
8. **VAI TRÒ BẢO MẬT:** Đo lường khả năng chống đỡ trước mã độc chèn prompt injection ẩn giấu trong log.

### **35. Explainability (Audit Trail Completeness Rate)**
1. **STEP NAME:** Deterministic Audit Completeness Check.
2. **LAYER:** Evaluation Framework.
3. **MỤC ĐÍCH:** Đo lường tính giải thích được (Explainability) của mô hình một cách xác định thông qua kiểm tra cấu trúc dữ liệu bắt buộc.
4. **CÔNG NGHỆ SỬ DỤNG:** Python Key/Field Validation Logic.
5. **CƠ CHẾ HOẠT ĐỘNG:** Quét các câu trả lời JSON của LLM và kiểm tra sự hiện diện đầy đủ của 5 trường dữ liệu quan trọng: `action`, `confidence`, `reasoning`, `target`, và `mitre_technique`. Tính toán tỷ lệ phần trăm hoàn thành.
6. **CẤU TRÚC MÃ NGUỒN:**
   - File: `experiments/evaluate_reasoning.py`.
   - Function: `check_audit_completeness()`.
   - Logic: `valid = all(k in response for k in REQUIRED_FIELDS)`
   - Input: LLM JSON response → Output: Completeness percentage.
7. **LUỒNG DỮ LIỆU:** Output JSON → Key validator → Completeness metric.
8. **VAI TRÒ BẢO MẬT:** Đảm bảo hệ thống đạt chuẩn Explainable AI (XAI) cho ứng cứu sự cố SOC, tránh hiện tượng hộp đen AI.
