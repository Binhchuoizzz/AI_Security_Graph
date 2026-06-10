# Tài liệu Tổng kết Cấu trúc Mã nguồn & Lộ trình Học tập (SENTINEL V5)

Tài liệu này tổng hợp toàn bộ **50 tệp tin mã nguồn** trong hệ thống SENTINEL, được phân bổ theo **Luồng dữ liệu (Dataflow)** và xếp theo **Thứ tự lộ trình học tập 5 ngày** của học viên. Mỗi file đều được phân tích rõ: Mục đích, Tác dụng, và Mối quan hệ tương tác với các cấu phần khác.

---

## **NGÀY 1: TẦNG DỮ LIỆU ĐẦU VÀO & BỘ LỌC TỐC ĐỘ CAO TIER 1**

### 1. `scripts/fetch_and_build_dataset.py`
*   **Mục đích:** Tự động tải và định dạng hóa bộ dữ liệu an ninh mạng chuẩn CSE-CIC-IDS2018 phục vụ nghiên cứu.
*   **Tác dụng:** Tải tệp dữ liệu tĩnh CSV của bộ dữ liệu CSE-CIC-IDS2018 từ nguồn công khai, thực hiện ETL ban đầu để làm sạch dữ liệu.
*   **Mối quan hệ:** Đầu ra ghi vào thư mục `data/raw/cicids2018/`. Được gọi thủ công khi cài đặt môi trường.

### 2. `scripts/fetch_dapt2020.py`
*   **Mục đích:** Tải bộ dữ liệu tấn công chuỗi dài ngày DAPT2020 phục vụ nghiên cứu kịch bản tấn công APT.
*   **Tác dụng:** Tải các tệp dữ liệu thô DAPT2020, làm sạch ban đầu, xử lý các ngày hoạt động (Day 1 - Day 5) để phân cấp các sự kiện.
*   **Mối quan hệ:** Lưu trữ dữ liệu thô vào `data/raw/dapt2020/`.

### 3. `scripts/dapt2020_config.py`
*   **Mục đích:** Lưu trữ cấu hình ánh xạ nhãn, các hằng số và chuẩn hóa cột cho dữ liệu DAPT2020.
*   **Tác dụng:** Định nghĩa bảng ánh xạ các nhãn tấn công sang mã kỹ thuật MITRE ATT&CK (`DAPT_LABEL_TO_MITRE`) và các giai đoạn APT (`APT_PHASES`).
*   **Mối quan hệ:** Được import và sử dụng chung bởi `scripts/fetch_dapt2020.py` và `scripts/build_dapt_chains.py`.

### 4. `scripts/build_dapt_chains.py`
*   **Mục đích:** Xử lý và cấu trúc dữ liệu DAPT2020 thành các chuỗi tấn công (Kill-chain) theo thời gian của từng địa chỉ IP.
*   **Tác dụng:** Đọc dữ liệu DAPT2020 đã được xử lý sơ bộ, thực hiện gom nhóm theo IP nguồn (`src_ip`), sắp xếp sự kiện theo trình tự thời gian chính xác, ưu tiên giữ NHIỀU sự kiện tấn công (tối đa 50 attack + 10 benign mỗi chuỗi) để có càng nhiều log tấn công APT càng tốt, đóng gói thành `dapt2020_chains.jsonl`.
*   **Mối quan hệ:** Phụ thuộc vào dữ liệu từ `scripts/fetch_dapt2020.py`. Đầu ra dùng cho các kịch bản kiểm thử APT của Tier-2.

### 5. `src/streaming/publisher.py`
*   **Mục đích:** Mô phỏng dòng lưu lượng mạng doanh nghiệp thời gian thực.
*   **Tác dụng:** Đọc cấu hình kết nối Redis trực tiếp từ file cấu hình trung tâm `config/system_settings.yaml` (loại bỏ các khóa cấu hình tĩnh dư thừa); đọc tập dữ liệu đã chuẩn hóa, chuyển đổi từng dòng log (flow) thành JSON và đẩy liên tục lên Redis Pub/Sub channel ở tốc độ tùy chỉnh (mô phỏng wire-speed).
*   **Mối quan hệ:** Đẩy dữ liệu lên Redis. Được import và gọi bởi `scripts/simulate_traffic.py`.

### 6. `scripts/simulate_traffic.py`
*   **Mục đích:** Script thực thi dòng lưu lượng mạng mô phỏng.
*   **Tác dụng:** Điểm khởi chạy (entrypoint) để bắt đầu tiến trình stream dữ liệu logs mạng. Hỗ trợ ánh xạ 17 trường mạng từ tập dữ liệu thô sang các trường chuẩn hóa của Rule Engine thông qua alias khóa (`_KEY_ALIASES` và `_RAW_TO_CANONICAL`).
*   **Mối quan hệ:** Khởi tạo instance và gọi hàm từ `src/streaming/publisher.py`.

### 7. `src/streaming/subscriber.py`
*   **Mục đích:** Lắng nghe và gom batch dữ liệu logs từ Redis.
*   **Tác dụng:** Đăng ký lắng nghe kênh Redis (cấu hình đọc động từ `system_settings.yaml`), nhận JSON log mạng, tích lũy logs theo từng cửa sổ trượt thời gian (time window) và đẩy sang Rule Engine của Tier 1 để đánh giá.
*   **Mối quan hệ:** Nhận logs từ Redis Pub/Sub, chuyển tiếp dữ liệu đến `src/tier1_filter/rule_engine.py` và gọi tác tử LangGraph ở `src/agent/workflow.py` nếu có escalate.

### 8. `src/tier1_filter/rule_engine.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Màng lọc thô heuristics và phát hiện dị biệt thống kê phi giám sát trực tuyến.
*   **Tác dụng:** 
    *   Class `RunningStats`: Cài đặt thuật toán Welford trực tuyến cập nhật Mean/StdDev với độ phức tạp $O(1)$ RAM/CPU.
    *   Class `SessionBaseline`: Quản lý IP profiles, theo dõi hành vi quét cổng (Port scan) và cơ chế tự dọn dẹp (eviction) IP rác quá TTL để chống OOM.
    *   Đo lường Z-Score và so sánh với blacklist/rate-limit để tính tổng điểm rủi ro. Quyết định DROP, LOG, ALERT, hoặc ESCALATE.
    *   Đồng bộ hóa 100% với cấu hình cổng nhạy cảm `sensitive_ports` (loại bỏ các cổng Web chuẩn như 80/443 để tránh chặn nhầm các cuộc tấn công tầng ứng dụng SQLi/XSS cần LLM phân tích) và loại bỏ hoàn toàn IP `0.0.0.0` khỏi whitelist để tránh bypass.
*   **Mối quan hệ:** Nhận logs đầu vào từ `subscriber.py`, đọc cấu hình từ `system_settings.yaml` (thông qua `feedback_listener.py`), trả quyết định chặn về cho hệ thống.

### 9. `src/tier1_filter/feedback_listener.py`
*   **Mục đích:** Cầu nối phản hồi thời gian thực giúp đồng bộ cấu hình hệ thống.
*   **Tác dụng:** Lắng nghe các thay đổi trong cấu hình rules từ UI và cập nhật nạp nóng (hot-reload) vào class `RuleEngine` mà không cần restart. Sử dụng cơ chế ghi đè an toàn (atomic write) kết hợp `FileLock` trên file YAML cấu hình rules động, đồng thời đảm bảo điểm số rủi ro (risk score) luôn được giới hạn (clamp) trong khoảng `[0, 100]`.
*   **Mối quan hệ:** Được gọi bởi Web UI ở `src/ui/app.py` để đồng bộ xuống `src/tier1_filter/rule_engine.py`.

### 10. `src/tier1_filter/scanner.py`
*   **Mục đích:** Phân hệ quét lỗ hổng bảo mật tĩnh phụ thuộc (SCA - Software Composition Analysis).
*   **Tác dụng:** Tích hợp công cụ Trivy để quét mã nguồn và dependencies của chính hệ thống nhằm phát hiện CVE tĩnh, phục vụ kiểm thử tính tự an toàn (Self-Securing) của hệ thống.
*   **Mối quan hệ:** Chạy độc lập dưới dạng tác vụ DevSecOps của hệ thống; kết quả quét được lưu xuống ổ đĩa dạng JSON và đồng bộ hóa làm tri thức RAG/Knowledge Graph.

### 11. `demo_tier1.py`
*   **Mục đích:** Demo chạy riêng phân hệ Tier 1.
*   **Tác dụng:** Cung cấp script tương tác dòng lệnh để kiểm tra thuật toán Welford và Z-Score. Khắc phục lỗi Case 4 bằng cách tích hợp xử lý đúng trạng thái phê duyệt của rule động (`ACTIVE` và `PENDING_APPROVAL`), đảm bảo kịch bản leo thang (ESCALATE) chạy chuẩn xác.
*   **Mối quan hệ:** Gọi trực tiếp `src/tier1_filter/rule_engine.py`.

---

## **NGÀY 2: TẦNG AN TOÀN VÀ NÉN DỮ LIỆU (GUARDRAILS)**

### 12. `src/guardrails/constants.py`
*   **Mục đích:** Quản lý tập trung ánh xạ tên trường logs mạng giữa các tầng.
*   **Tác dụng:** Định nghĩa dictionary `KEY_ALIASES` dùng chung nhằm chuyển đổi đồng bộ các trường dữ liệu Redis (như `src_ip`, `dst_port`) thành định dạng chuẩn hóa (như `Source IP`, `Destination Port`) trên toàn bộ hệ thống guardrails, ngăn chặn sai lệch cấu trúc dữ liệu.
*   **Mối quan hệ:** Được import và sử dụng trực tiếp bởi `data_validator.py`, `feedback_validator.py` và các module phân tích logs mạng.

### 13. `src/guardrails/template_miner.py`
*   **Mục đích:** Khử trùng lặp logs và quản lý token đầu vào LLM.
*   **Tác dụng:** Sử dụng thư viện `drain3` để phân tích logs thô, trích xuất cấu trúc tĩnh (Template) và gom nhóm logs cùng loại kèm tần suất; ước lượng token budget bằng heuristic (`len(text)//4` ký tự ≈ 1 token), cắt tỉa logs nếu vượt ngưỡng. Đảm bảo ép kiểu an toàn cho các tham số cấu hình từ file YAML.
*   **Mối quan hệ:** Nhận logs bị leo thang từ Tier 1, nén lại và chuyển tiếp sang `src/guardrails/prompt_filter.py`.

### 14. `src/guardrails/prompt_filter.py`
*   **Mục đích:** Vô hiệu hóa đòn tấn công chèn lệnh trực tiếp (Direct Prompt Injection).
*   **Tác dụng:** Sinh khóa Delimiter ngẫu nhiên bảo mật bằng `secrets.token_hex(8)` để bọc payload log mạng gửi sang LLM; thực hiện quét Regex phát hiện và loại bỏ các nỗ lực smuggling (delimiter giả mạo trong logs).
*   **Mối quan hệ:** Nhận log đã nén từ `template_miner.py`, thực hiện đóng gói bảo mật trước khi nạp vào hệ thống Prompt của Agent.

### 15. `src/guardrails/output_sanitizer.py`
*   **Mục đích:** Làm sạch dữ liệu đầu ra và chống XSS/Markdown Exfiltration.
*   **Tác dụng:** Quét nội dung phản hồi của LLM hoặc logs thô, giải mã Base64/Hex để phát hiện payload ẩn, loại bỏ ký tự zero-width điều khiển bypass, và strip sạch các thẻ script/markdown hình ảnh độc hại trước khi hiển thị hoặc lưu trữ.
*   **Mối quan hệ:** Xử lý kết quả đầu ra của Agent trước khi hiển thị tại Web UI `src/ui/app.py` hoặc lưu vào cơ sở dữ liệu.

### 16. `src/guardrails/data_validator.py`
*   **Mục đích:** Xác thực cấu trúc dữ liệu đầu vào chống Schema Abuse.
*   **Tác dụng:** Đảm bảo logs mạng đẩy lên Tier 2 tuân thủ đúng định dạng JSON schema bắt buộc bằng cách ánh xạ thông qua `KEY_ALIASES`. Từ chối và bắt lỗi chi tiết thay vì để lọt dữ liệu invalid vào Agent.
*   **Mối quan hệ:** Chốt chặn kiểm soát định dạng dữ liệu đầu vào cho hệ thống Guardrail Layer.

### 17. `src/guardrails/state_monitor.py`
*   **Mục đích:** Giám sát trạng thái an toàn, ghi log kiểm toán và ngăn chặn vòng lặp vô hạn.
*   **Tác dụng:** Ghi nhận logs kiểm toán vào DB SQLite bằng cơ chế an toàn. Triển khai lớp `LoopDetector` bảo vệ bằng `threading.Lock` để tránh xung đột luồng và hàm `reset()` để xóa sạch counter giữa các chu kỳ chạy đồ thị.
*   **Mối quan hệ:** Ghi nhận sự kiện kiểm toán và giám sát chu kỳ hoạt động của các Nodes trong LangGraph.

### 18. `src/guardrails/rag_sanitizer.py`
*   **Mục đích:** Bảo vệ hệ thống khỏi tấn công RAG Poisoning và Semantic Cache Poisoning.
*   **Tác dụng:** Thực hiện lọc thô ngữ nghĩa (Semantic structural sanitization) trên các tài liệu thu thập (Ingestion) và ngữ cảnh truy vấn (Retrieval). Bổ sung phương thức `sanitize_cache_entry()` để trung hòa mã độc khi đọc từ Semantic Cache (Cache Hit path).
*   **Mối quan hệ:** Được import và tích hợp vào module RAG tại `src/rag/retriever.py`.

### 19. `src/guardrails/decision_validator.py`
*   **Mục đích:** Thẩm định và làm sạch quyết định đầu ra của LLM Agent (chống Hallucination & Self-DoS).
*   **Tác dụng:** Ép kiểu JSON đầu ra, downgrade phán quyết `BLOCK_IP` đối với các IP hạ tầng quan trọng xuống mức `ALERT` nhằm tránh tự tấn công từ chối dịch vụ (Self-DoS), làm sạch trường `reasoning` chống Markdown/HTML XSS-SSRF. Bổ sung **`enforce_tier_consensus`** — lá chắn chống social-engineering ngữ nghĩa: nếu Tier-1 (xác định) coi luồng là tấn công nhưng LLM bị thao túng hạ cấp xuống `LOG/DROP`, hệ thống KHÔNG tin LLM mà buộc `AWAIT_HITL`.
*   **Mối quan hệ:** Được gọi bởi `node_llm_triage` ở `src/agent/nodes.py` để kiểm duyệt quyết định trước khi thực thi.

### 20. `src/guardrails/feedback_validator.py`
*   **Mục đích:** Xác thực an toàn cho các quy tắc động (Dynamic rules) và whitelist được đẩy về Tier-1.
*   **Tác dụng:** Áp dụng nguyên lý Zero-Trust, ngăn chặn các rule bypass dạng wildcard rộng (`0.0.0.0/0`, `*`), giới hạn prefix CIDR tối thiểu từ `/8`, và ngăn chặn chặn nhầm IP thiết bị nội bộ quan trọng.
*   **Mối quan hệ:** Tích hợp trực tiếp vào `FeedbackListener` để kiểm duyệt các rule do con người hoặc Agent thiết lập.

### 21. `demo_guardrails.py`
*   **Mục đích:** Demo chạy riêng phân hệ Guardrail tích hợp đầy đủ.
*   **Tác dụng:** Trực quan hóa toàn bộ 8 lớp phòng thủ AI an toàn cao bao gồm phát hiện prompt injection, bọc nonce delimiter, làm sạch RAG poisoning, kiểm định quyết định LLM và xác thực feedback loop.
*   **Mối quan hệ:** Gọi trực tiếp các cấu phần trong thư mục `src/guardrails/`.

---

## **NGÀY 3: TẦNG TRUY XUẤT TRI THỨC KÉP (DUAL-RAG SUBMODULE)**

### 22. `src/rag/embedder.py`
*   **Mục đích:** Xây dựng và quản lý mô hình Vector Embeddings và cập nhật checksum.
*   **Tác dụng:** Tải mô hình `all-MiniLM-L6-v2`, chuyển đổi các tài liệu văn bản MITRE ATT&CK và NIST thành các vector 384 chiều, lưu trữ vào chỉ mục FAISS. Đồng thời, tự động tính toán lại SHA-256 cho toàn bộ tệp KB và index thông qua hàm `update_checksums_file()` để cập nhật vào `checksums.sha256`, tích hợp `verify_document_integrity(exclude_generated=True)` ở đầu tiến trình build index.
*   **Mối quan hệ:** Được gọi bởi `scripts/build_rag_indexes.py` và chạy trên CI Pipeline để khởi tạo chỉ mục.

### 23. `scripts/build_rag_indexes.py`
*   **Mục đích:** Khởi tạo cơ sở dữ liệu tri thức tĩnh ngoại tuyến.
*   **Tác dụng:** Đọc tệp nguồn tài liệu MITRE và NIST, chạy phân mảnh (chunking) và gọi `embedder.py` để ghi đè chỉ mục FAISS lên đĩa cứng.
*   **Mối quan hệ:** Chạy một lần duy nhất lúc cài đặt dự án.

### 24. `src/rag/retriever.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Tìm kiếm tri thức bảo mật lai an toàn (Hybrid Search & Cache Defense).
*   **Tác dụng:** 
    *   Thực hiện tìm kiếm song song: Dense Vector Search (FAISS) và Sparse Lexical Search (BM25Okapi); hợp nhất bằng thuật toán RRF.
    *   Tích hợp `RAGSanitizer.sanitize_cache_entry()` trên luồng cache hit để lọc sạch các payload độc hại trước khi chèn vào prompt, ngăn ngừa Semantic Cache Poisoning.
*   **Mối quan hệ:** Được gọi bởi các nodes của LangGraph tại `src/agent/nodes.py` để lấy ngữ cảnh tri thức an toàn.

### 25. `src/rag/semantic_cache.py`
*   **Mục đích:** Giảm thiểu độ trễ suy luận RAG bằng kỹ thuật cache thông minh.
*   **Tác dụng:** LRU cache (OrderedDict + TTL) lưu kết quả RAG theo khóa băm SHA-256 exact-match của query (đã chuẩn hóa qua template). Nếu query trùng khớp chính xác thì trả kết quả cache ngay, tránh embed + FAISS lại — an toàn (không có false cache hit).
*   **Mối quan hệ:** Được gọi trực tiếp bên trong `src/rag/retriever.py`.

### 26. `src/rag/security.py`
*   **Mục đích:** Kiểm soát tính toàn vẹn của tri thức RAG vật lý.
*   **Tác dụng:** Tính toán và kiểm tra giá trị băm SHA-256 của các tệp tri thức trên đĩa cứng trước khi tạo Vector Index, chống đòn tấn công thay đổi trực tiếp tệp tri thức RAG trên disk. Hỗ trợ tham số `exclude_generated=True` để bỏ qua các file chỉ mục tự sinh trong giai đoạn build ban đầu.
*   **Mối quan hệ:** Gọi bởi `embedder.py` và `retriever.py` để kiểm chứng dữ liệu.

### 27. `src/rag/graph_builder.py`
*   **Mục đích:** Xây dựng đồ thị liên kết tri thức dạng Graph (nếu có mở rộng).
*   **Tác dụng:** Liên kết các thực thể kỹ thuật MITRE với các bước quy trình NIST tương ứng.
*   **Mối quan hệ:** Bổ trợ cấu trúc ngữ cảnh cho RAG.

### 28. `demo_rag.py`
*   **Mục đích:** Demo chạy riêng phân hệ Hybrid RAG.
*   **Tác dụng:** Kiểm tra tính năng tìm kiếm tích hợp FAISS + BM25 bằng CLI.
*   **Mối quan hệ:** Gọi trực tiếp `src/rag/retriever.py`.

---

## **NGÀY 4: CỖ MÁY TRẠNG THÁI LANGGRAPH & PHẢN HỒI AN NINH**

### 29. `src/agent/state.py`
*   **Mục đích:** Định nghĩa Schema bộ nhớ trạng thái của tác tử LangGraph.
*   **Tác dụng:** Khai báo cấu trúc dữ liệu `SentinelState` (một `TypedDict`) chứa các trường: `current_batch_logs`, `rag_mitre_context`, `decisions`, `cycle_count`,...
*   **Mối quan hệ:** Được import bởi tất cả các file trong cấu phần `src/agent/`.

### 30. `src/agent/workflow.py`
*   **Mục đích:** Định nghĩa kiến trúc đồ thị nhận thức của tác tử.
*   **Tác dụng:** Khởi tạo `StateGraph`, đăng ký các Node xử lý, kết nối các Edge và định nghĩa Conditional Edge để định tuyến rẽ nhánh (Block/Quarantine/Alert/HITL/End).
*   **Mối quan hệ:** Compile ra đối tượng ứng dụng Agent chạy chính; import các node từ `src/agent/nodes.py`.

### 31. `src/agent/nodes.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Triển khai chi tiết logic xử lý tại các "Trạm" của đồ thị.
*   **Tác dụng:** 
    *   `node_rag_context`: Gọi RAG để lấy ngữ cảnh hỗ trợ.
    *   `node_llm_triage`: Đóng gói prompt và gọi LLM, tích hợp bộ `DecisionValidator` để làm sạch quyết định và `AuditLogger` để ghi log kiểm toán.
    *   `node_action_executor`: Xử lý phán quyết, tích hợp `LoopDetector` ngăn chặn vô hạn chu kỳ và gọi `FeedbackListener` để đẩy rule về Tier-1.
*   **Mối quan hệ:** Gọi `DualRetriever` từ tầng RAG, gọi `llm_client` để suy luận, gọi `threat_memory` để tương quan logs, và gọi `executor.py` để phản hồi.

### 32. `src/agent/prompts.py`
*   **Mục đích:** Quản lý kho mẫu Prompt (System & User Instruct).
*   **Tác dụng:** Cấu trúc prompt mẫu cho LLM. Tự động đọc lịch sử analyst từ file cấu hình để tiêm các ví dụ Few-shot Active Learning (Analyst Approve/Reject trước đây) vào prompt.
*   **Mối quan hệ:** Được gọi bởi `node_llm_triage` ở file `nodes.py`.

### 33. `src/agent/llm_client.py`
*   **Mục đích:** API Client giao tiếp với mô hình AI cục bộ phục vụ offline.
*   **Tác dụng:** Gửi HTTP POST request theo chuẩn OpenAI API sang cổng dịch vụ của server `llama.cpp` đang chạy Gemma-2-9B-IT; kiểm soát tham số `temperature=0.1` để ép định dạng đầu ra JSON sạch.
*   **Mối quan hệ:** Được gọi bởi `node_llm_triage` tại `nodes.py`.

### 34. `src/agent/threat_memory.py`
*   **Mục đích:** Quản lý uy tín IP dài hạn, chuỗi APT và chống Memory Poisoning.
*   **Tác dụng:** 
    *   Kết nối DB SQLite, ghi nhận các kỹ thuật MITRE mà IP đã thực hiện; tự động cắm cờ APT (`check_apt_chain`) nếu một IP xuất hiện trong sự kiện thuộc $\ge 2$ ngày khác nhau (`COUNT(DISTINCT apt_day) >= 2`), nâng mức CRITICAL khi $\ge 3$ ngày.
    *   Tải cấu trúc DAPT chain sử dụng bộ quản lý ngữ cảnh `with open` đảm bảo an toàn tài nguyên.
    *   Tích hợp `output_sanitizer` để làm sạch trường kỹ thuật MITRE, mô tả thực thể trước khi ghi DB SQLite, chống đòn tấn công Long-term Threat Memory Poisoning.
*   **Mối quan hệ:** Được gọi bởi `node_action_executor` ở `nodes.py` để ghi vết và gọi ở `node_rag_context` để nạp lịch sử.

### 35. `src/response/executor.py`
*   **Mục đích:** Ghi nhận nhật ký kiểm toán không thể chối cãi.
*   **Tác dụng:** Ghi nhận nhật ký audit trail vào SQLite kèm theo tính toán giá trị băm **HMAC SHA-256** móc xích dòng trước-dòng sau để chống giả mạo logs.
*   **Mối quan hệ:** Được gọi bởi Node Action Executor ở `nodes.py` và Web UI để verify logs.


---

## **NGÀY 5: GIAO DIỆN SOC & KHUNG ĐÁNH GIÁ THỰC NGHIỆM**

### 37. `src/ui/app.py`
*   **Mục đích:** File khởi chạy Web Dashboard Streamlit.
*   **Tác dụng:** Tổ chức giao diện Tabs của SOC Dashboard: SIEM Real-time, Quarantine Rules Review, Active Firewall Rules, và RAGAS Evaluation metrics.
*   **Mối quan hệ:** Đọc DB SQLite trực tiếp để hiển thị thông tin; gọi `feedback_listener.py` khi quản trị viên Approve/Reject rules.

### 38. `src/ui/components.py`
*   **Mục đích:** Cấu phần hiển thị và giao diện trực quan hóa.
*   **Tác dụng:** Cung cấp thiết kế cho Neon metric cards, thanh tiến trình, biểu diễn dòng thời gian sự kiện của IP (chronological event timeline) tương tác.
*   **Mối quan hệ:** Được import và render bởi `src/ui/app.py`.

### 39. `src/ui/auth.py`
*   **Mục đích:** Cơ chế xác thực người dùng dựa trên phân quyền (RBAC) và chống Input Injection.
*   **Tác dụng:** Quản lý mật khẩu bằng giải thuật băm NIST PBKDF2-HMAC-SHA256 và so sánh hăm bằng `hmac.compare_digest`. Đồng thời áp dụng regex `^[a-zA-Z0-9_]{1,30}$` thắt chặt dữ liệu đầu vào cho Username nhằm chống HITL Auth Input Injection. Di chuyển các module `re` và `hmac` lên đầu file để tối ưu hóa hiệu năng và tránh reimport.
*   **Mối quan hệ:** Tích hợp kiểm tra quyền truy cập của analyst (L1) và manager (L3) trên Dashboard.

### 40. `src/ui/style.css`
*   **Mục đích:** Thiết lập ngôn ngữ thiết kế thị giác của SOC Dashboard.
*   **Tác dụng:** Định nghĩa các CSS variables, tạo hiệu ứng Glassmorphism, Neon Glow và Dark Mode tùy biến cho Dashboard Streamlit.
*   **Mối quan hệ:** Được load tự động bên trong `src/ui/app.py`.

### 41. `experiments/run_ablation_study.py`
*   **Mục đích:** Tự động hóa chạy thực nghiệm Ablation Study.
*   **Tác dụng:** Nạp cấu hình từ 6 file YAML (A -> F), cho chạy toàn bộ tập dữ liệu Ground Truth qua pipeline tương ứng, đo lường các chỉ số Precision, Recall, FPR, F1, độ trễ và đẩy kết quả lên MLflow.
*   **Mối quan hệ:** Khởi động và chạy toàn bộ hệ thống ở các cấu hình khác nhau.

### 42. `experiments/statistical_tests.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Kiểm định ý nghĩa thống kê của kết quả nghiên cứu.
*   **Tác dụng:** Cài đặt và thực thi thuật toán kiểm định phi tham số **McNemar's Test** cho độ chính xác phân loại và **Mann-Whitney U Test** cho độ trễ hệ thống.
*   **Mối quan hệ:** Được gọi sau khi chạy xong Ablation Study để kiểm chứng độ tin cậy thực tế của số liệu.

### 43. `experiments/evaluate_robustness.py`
*   **Mục đích:** Đánh giá tính kháng nhiễu nghịch đảo của Guardrail.
*   **Tác dụng:** Bơm **120 mẫu adversarial KHÓ** (5 nhóm: encoding đa lớp, structural, semantic social-engineering, jailbreak, RAG poisoning — sinh bởi `scripts/build_adversarial_suite.py`) qua lớp Guardrail TĨNH, tính tỷ lệ chặn (37.5%). Cặp với `evaluate_adversarial_pipeline.py` đẩy mẫu khó qua FULL pipeline (Tier-2 LLM kháng 100% sau khi vá consensus guard).
*   **Mối quan hệ:** Đánh giá độc lập độ bền Guardrail tĩnh; bổ trợ bởi `evaluate_adversarial_pipeline.py` cho lớp LLM.

### 44. `experiments/evaluate_reasoning.py`
*   **Mục đích:** Đánh giá độ tin cậy tri thức của Agent và chất lượng RAG.
*   **Tác dụng:** Triển khai mô hình làm trọng tài (LLM-as-a-Judge) chấm điểm chất lượng RAG (Context Precision, Faithfulness, Relevancy) theo chuẩn RAGAS; kiểm tra tính giải thích được qua việc validate cấu trúc dữ liệu JSON.
*   **Mối quan hệ:** Kết nối server để chấm điểm kết quả từ Gemma-2.

### 45. `experiments/evaluate_zeroday.py`
*   **Mục đích:** Đánh giá năng lực phát hiện mối đe dọa Zero-day chưa có nhãn.
*   **Tác dụng:** Mô phỏng các cuộc tấn công Zero-day để đo lường tính hiệu quả của Welford Outlier so với các rule tĩnh.
*   **Mối quan hệ:** Phụ thuộc vào `rule_engine.py`.

### 46. `experiments/measure_latency_baseline.py`
*   **Mục đích:** Đo lường độ trễ nền tảng làm cơ sở so sánh.
*   **Tác dụng:** Tính toán độ trễ tối thiểu khi suy luận của LLM trần trụi trước khi tích hợp các cơ chế caching và filtering.
*   **Mối quan hệ:** Bổ sung số liệu so sánh cho Mann-Whitney U test.

### 47. `experiments/plot_results.py`
*   **Mục đích:** Trực quan hóa số liệu thực nghiệm.
*   **Tác dụng:** Vẽ các biểu đồ cột so sánh F1-Score, biểu đồ hộp (Boxplot) phân bố độ trễ xử lý logs giữa các cấu hình của Ablation Study để đưa vào bài báo cáo/luận văn.
*   **Mối quan hệ:** Đọc dữ liệu đầu ra từ MLflow/tệp CSV kết quả thực nghiệm.

### 48. `experiments/e2e_test_runner.py` *(Quan trọng cho việc kiểm thử)*
*   **Mục đích:** Chạy kiểm thử tự động tích hợp (E2E Integration Tests) của toàn bộ hệ thống.
*   **Tác dụng:** Chạy 20/20 kịch bản kiểm định chất lượng cho hệ thống bao gồm: Rule Engine, Delimiter Guardrails, Dual-RAG, SQLite Threat Memory, và logic Agent.
*   **Mối quan hệ:** Đóng vai trò là chốt chặn đảm bảo tính toàn vẹn của mã nguồn trước khi đẩy mã nguồn lên Production hoặc chạy thực nghiệm.

---

## **CÁC TỆP KIỂM THỬ ĐƠN VỊ CỦA LỚP PHÒNG THỦ GUARDRAILS MỚI BỔ SUNG**

### 49. `tests/unit/test_rag_sanitizer.py`
*   **Mục đích:** Kiểm thử tính an toàn của module `RAGSanitizer`.
*   **Tác dụng:** Verify khả năng lọc sạch mã độc RAG Poisoning trong cả quá trình Ingestion, Retrieval cũng như trung hòa các mã độc từ Semantic Cache.
*   **Mối quan hệ:** Được thực thi bởi `pytest` trong bộ test của Guardrail.

### 50. `tests/unit/test_decision_validator.py`
*   **Mục đích:** Kiểm thử tính an toàn của module `DecisionValidator`.
*   **Tác dụng:** Đảm bảo downgrade chặn IP hạ tầng quan trọng thành công và strip sạch các thẻ HTML/Markdown chứa mã độc trong reasoning của LLM.
*   **Mối quan hệ:** Được thực thi bởi `pytest` trong bộ test của Guardrail.

### 51. `tests/unit/test_feedback_validator.py`
*   **Mục đích:** Kiểm thử tính an toàn của module `FeedbackValidator`.
*   **Tác dụng:** Đảm bảo từ chối các rule động không an toàn (wildcard `*`, dải IP ngoài mạng tin cậy, rule ảnh hưởng tới IP hạ tầng quan trọng).
*   **Mối quan hệ:** Được thực thi bởi `pytest` trong bộ test của Guardrail.

---

## **FILE TÍCH HỢP HỆ THỐNG GỐC (ROOT)**

### 52. `main.py`
*   **Mục đích:** Điểm khởi chạy tích hợp của toàn dự án.
*   **Tác dụng:** Khởi động đồng thời các tiến trình Redis Subscriber chạy nền và chạy ứng dụng Streamlit Web UI để khởi chạy Sentinel ở môi trường đồ họa, tích hợp reset LoopDetector trước mỗi chu kỳ.
*   **Mối quan hệ:** File tích hợp gọi tất cả các cấu phần chính trong `src/`.
