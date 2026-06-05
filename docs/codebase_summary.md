# Tài liệu Tổng kết Cấu trúc Mã nguồn & Lộ trình Học tập (SENTINEL V5)

Tài liệu này tổng hợp toàn bộ **45 tệp tin mã nguồn** trong hệ thống SENTINEL, được phân bổ theo **Luồng dữ liệu (Dataflow)** và xếp theo **Thứ tự lộ trình học tập 5 ngày** của học viên. Mỗi file đều được phân tích rõ: Mục đích, Tác dụng, và Mối quan hệ tương tác với các cấu phần khác.

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
*   **Tác dụng:** Đọc dữ liệu DAPT2020 đã được xử lý sơ bộ, thực hiện gom nhóm theo IP nguồn (`src_ip`), sắp xếp sự kiện theo trình tự thời gian chính xác, thực hiện lấy mẫu cân bằng (10 sự kiện tấn công + 10 sự kiện benign) để bảo toàn tín hiệu đe dọa, đóng gói thành `dapt2020_chains.jsonl`.
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

### 12. `src/guardrails/template_miner.py`
*   **Mục đích:** Khử trùng lặp logs và quản lý token đầu vào LLM.
*   **Tác dụng:** Sử dụng thư viện `drain3` để phân tích logs thô, trích xuất cấu trúc tĩnh (Template) và gom nhóm logs cùng loại kèm tần suất; sử dụng tiktoken để tính toán token budget, cắt tỉa logs nếu vượt ngưỡng.
*   **Mối quan hệ:** Nhận logs bị leo thang từ Tier 1, nén lại và chuyển tiếp sang `src/guardrails/prompt_filter.py`.

### 13. `src/guardrails/prompt_filter.py`
*   **Mục đích:** Vô hiệu hóa đòn tấn công chèn lệnh trực tiếp (Direct Prompt Injection).
*   **Tác dụng:** Sinh khóa Delimiter ngẫu nhiên bảo mật bằng `secrets.token_hex(8)` để bọc payload log mạng gửi sang LLM; thực hiện quét Regex phát hiện và loại bỏ các nỗ lực smuggling (delimiter giả mạo trong logs).
*   **Mối quan hệ:** Nhận log đã nén từ `template_miner.py`, thực hiện đóng gói bảo mật trước khi nạp vào hệ thống Prompt của Agent.

### 14. `src/guardrails/output_sanitizer.py`
*   **Mục đích:** Làm sạch dữ liệu và chống XSS/Markdown Exfiltration.
*   **Tác dụng:** Quét nội dung phản hồi của LLM hoặc logs thô, giải mã Base64/Hex của hacker, loại bỏ ký tự zero-width điều khiển bypass, và strip sạch các thẻ script/markdown hình ảnh độc hại trước khi hiển thị trên dashboard.
*   **Mối quan hệ:** Xử lý kết quả đầu ra của Agent trước khi hiển thị tại Web UI `src/ui/app.py`.

### 15. `src/guardrails/data_validator.py`
*   **Mục đích:** Xác thực cấu trúc dữ liệu đầu vào.
*   **Tác dụng:** Đảm bảo logs mạng đẩy lên Tier 2 tuân thủ đúng định dạng JSON schema bắt buộc.
*   **Mối quan hệ:** Hỗ trợ kiểm soát lỗi cho tầng tiền xử lý Guardrail.

### 16. `src/guardrails/state_monitor.py`
*   **Mục đích:** Giám sát trạng thái an toàn tổng quát của tiến trình suy luận.
*   **Tác dụng:** Ghi nhận logs kiểm toán về các lần phát hiện vi phạm bảo mật prompt.
*   **Mối quan hệ:** Ghi dữ liệu cảnh báo ra logs hệ thống.

### 17. `demo_guardrails.py`
*   **Mục đích:** Demo chạy riêng phân hệ Guardrail.
*   **Tác dụng:** Kiểm thử khả năng nén log của Drain3 và cơ chế bọc delimiter trực quan.
*   **Mối quan hệ:** Gọi trực tiếp các cấu phần trong thư mục `src/guardrails/`.

---

## **NGÀY 3: TẦNG TRUY XUẤT TRI THỨC KÉP (DUAL-RAG SUBMODULE)**

### 18. `src/rag/embedder.py`
*   **Mục đích:** Xây dựng và quản lý mô hình Vector Embeddings.
*   **Tác dụng:** Tải mô hình `all-MiniLM-L6-v2`, chuyển đổi các tài liệu văn bản MITRE ATT&CK và NIST thành các vector 384 chiều và lưu trữ vào chỉ mục FAISS.
*   **Mối quan hệ:** Được gọi bởi `scripts/build_rag_indexes.py` để khởi tạo chỉ mục.

### 19. `scripts/build_rag_indexes.py`
*   **Mục đích:** Khởi tạo cơ sở dữ liệu tri thức tĩnh ngoại tuyến.
*   **Tác dụng:** Đọc tệp nguồn tài liệu MITRE và NIST, chạy phân mảnh (chunking) và gọi `embedder.py` để ghi đè chỉ mục FAISS lên đĩa cứng.
*   **Mối quan hệ:** Chạy một lần duy nhất lúc cài đặt dự án.

### 20. `src/rag/retriever.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Thực hiện thuật toán tìm kiếm tri thức bảo mật lai (Hybrid Search).
*   **Tác dụng:** Class `DualRetriever` thực thi tìm kiếm song song: Dense Vector Search (khoảng cách FAISS L2) và Sparse Lexical Search (tương đồng BM25Okapi); sau đó hợp nhất kết quả bằng thuật toán RRF với hằng số phạt $k=60$.
*   **Mối quan hệ:** Được import và gọi bởi các nodes của LangGraph tại `src/agent/nodes.py` để lấy ngữ cảnh.

### 21. `src/rag/semantic_cache.py`
*   **Mục đích:** Giảm thiểu độ trễ suy luận RAG bằng kỹ thuật cache thông minh.
*   **Tác dụng:** Lưu trữ các câu hỏi truy vấn trước đó kèm kết quả RAG tương ứng; nếu truy vấn mới có khoảng cách cosine rất nhỏ với truy vấn cũ thì trả kết quả cache ngay lập tức mà không quét lại FAISS.
*   **Mối quan hệ:** Được gọi trực tiếp bên trong `src/rag/retriever.py`.

### 22. `src/rag/security.py`
*   **Mục đích:** Phòng chống RAG Poisoning.
*   **Tác dụng:** Quét các chuỗi truy vấn đầu vào RAG để đảm bảo không chứa mã độc hoặc chuỗi gây nhiễu ngữ nghĩa.
*   **Mối quan hệ:** Bảo vệ đầu vào của class `DualRetriever`.

### 23. `src/rag/graph_builder.py`
*   **Mục đích:** Xây dựng đồ thị liên kết tri thức dạng Graph (nếu có mở rộng).
*   **Tác dụng:** Liên kết các thực thể kỹ thuật MITRE với các bước quy trình NIST tương ứng.
*   **Mối quan hệ:** Bổ trợ cấu trúc ngữ cảnh cho RAG.

### 24. `demo_rag.py`
*   **Mục đích:** Demo chạy riêng phân hệ Hybrid RAG.
*   **Tác dụng:** Kiểm tra tính năng tìm kiếm tích hợp FAISS + BM25 bằng CLI.
*   **Mối quan hệ:** Gọi trực tiếp `src/rag/retriever.py`.

---

## **NGÀY 4: CỖ MÁY TRẠNG THÁI LANGGRAPH & PHẢN HỒI AN NINH**

### 25. `src/agent/state.py`
*   **Mục đích:** Định nghĩa Schema bộ nhớ trạng thái của tác tử LangGraph.
*   **Tác dụng:** Khai báo cấu trúc dữ liệu `SentinelState` (một `TypedDict`) chứa các trường: `current_batch_logs`, `rag_mitre_context`, `decisions`, `cycle_count`,...
*   **Mối quan hệ:** Được import bởi tất cả các file trong cấu phần `src/agent/`.

### 26. `src/agent/workflow.py`
*   **Mục đích:** Định nghĩa kiến trúc đồ thị nhận thức của tác tử.
*   **Tác dụng:** Khởi tạo `StateGraph`, đăng ký các Node xử lý, kết nối các Edge và định nghĩa Conditional Edge để định tuyến rẽ nhánh (Block/Quarantine/Alert/HITL/End).
*   **Mối quan hệ:** Compile ra đối tượng ứng dụng Agent chạy chính; import các node từ `src/agent/nodes.py`.

### 27. `src/agent/nodes.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Triển khai chi tiết logic xử lý tại các "Trạm" của đồ thị.
*   **Tác dụng:** 
    *   `node_rag_context`: Gọi RAG để lấy ngữ cảnh hỗ trợ.
    *   `node_llm_triage`: Đóng gói prompt và gọi LLM thông qua client.
    *   `node_action_executor`: Xử lý phán quyết và lưu lịch sử.
*   **Mối quan hệ:** Gọi `DualRetriever` từ tầng RAG, gọi `llm_client` để suy luận, gọi `threat_memory` để tương quan logs, và gọi `executor.py` để phản hồi.

### 28. `src/agent/prompts.py`
*   **Mục đích:** Quản lý kho mẫu Prompt (System & User Instruct).
*   **Tác dụng:** Cấu trúc prompt mẫu cho LLM. Tự động đọc lịch sử analyst từ file cấu hình để tiêm các ví dụ Few-shot Active Learning (Analyst Approve/Reject trước đây) vào prompt.
*   **Mối quan hệ:** Được gọi bởi `node_llm_triage` ở file `nodes.py`.

### 29. `src/agent/llm_client.py`
*   **Mục đích:** API Client giao tiếp với mô hình AI cục bộ phục vụ offline.
*   **Tác dụng:** Gửi HTTP POST request theo chuẩn OpenAI API sang cổng dịch vụ của server `llama.cpp` đang chạy Gemma-2-9B-IT; kiểm soát tham số `temperature=0.1` để ép định dạng đầu ra JSON sạch.
*   **Mối quan hệ:** Được gọi bởi `node_llm_triage` tại `nodes.py`.

### 30. `src/agent/threat_memory.py`
*   **Mục đích:** Quản lý uy tín IP dài hạn và kết nối chuỗi Kill-chain APT.
*   **Tác dụng:** Kết nối DB SQLite, ghi nhận các kỹ thuật MITRE mà IP đã thực hiện; tự động quét và cắm cờ APT nguy cấp nếu một IP vi phạm liên quan đến $\ge 3$ giai đoạn MITRE khác nhau theo thời gian.
*   **Mối quan hệ:** Được gọi bởi `node_action_executor` ở `nodes.py` để ghi vết và gọi ở `node_rag_context` để nạp lịch sử.

### 31. `src/response/executor.py`
*   **Mục đích:** Thực thi phản hồi mạng và ghi nhận nhật ký kiểm toán không thể chối cãi.
*   **Tác dụng:** Gọi các API chặn mạng hoặc ghi rule cách ly; ghi nhận nhật ký audit trail vào SQLite kèm theo tính toán giá trị băm **HMAC SHA-256** móc xích dòng trước-dòng sau để chống giả mạo logs.
*   **Mối quan hệ:** Được gọi bởi Node Action Executor ở `nodes.py` và Web UI để verify logs.

### 32. `demo_apt.py`
*   **Mục đích:** Demo luồng tấn công Kill-chain APT dài ngày.
*   **Tác dụng:** Chạy liên tục chuỗi logs DAPT2020 để biểu diễn cơ chế SQLite tương quan liên kết nâng mức cảnh báo của IP lên Critical khi thấy lặp lại nhiều giai đoạn.
*   **Mối quan hệ:** Gọi trực tiếp `src/agent/workflow.py` và `src/agent/threat_memory.py`.

---

## **NGÀY 5: GIAO DIỆN SOC & KHUNG ĐÁNH GIÁ THỰC NGHIỆM**

### 33. `src/ui/app.py`
*   **Mục đích:** File khởi chạy Web Dashboard Streamlit.
*   **Tác dụng:** Tổ chức giao diện Tabs của SOC Dashboard: SIEM Real-time, Quarantine Rules Review, Active Firewall Rules, và RAGAS Evaluation metrics.
*   **Mối quan hệ:** Đọc DB SQLite trực tiếp để hiển thị thông tin; gọi `feedback_listener.py` when quản trị viên Approve/Reject rules.

### 34. `src/ui/components.py`
*   **Mục đích:** Cấu phần hiển thị và giao diện trực quan hóa.
*   **Tác dụng:** Cung cấp thiết kế cho Neon metric cards, thanh tiến trình, biểu diễn dòng thời gian sự kiện của IP (chronological event timeline) tương tác.
*   **Mối quan hệ:** Được import và render bởi `src/ui/app.py`.

### 35. `src/ui/auth.py`
*   **Mục đích:** Cơ chế xác thực người dùng dựa trên phân quyền (RBAC).
*   **Tác dụng:** Quản lý mật khẩu bằng giải thuật băm NIST PBKDF2-HMAC-SHA256 và so sánh hăm bằng `hmac.compare_digest` để chống tấn công phân tích thời gian.
*   **Mối quan hệ:** Tích hợp kiểm tra quyền truy cập của analyst (L1) và manager (L3) trên Dashboard.

### 36. `src/ui/style.css`
*   **Mục đích:** Thiết lập ngôn ngữ thiết kế thị giác của SOC Dashboard.
*   **Tác dụng:** Định nghĩa các CSS variables, tạo hiệu ứng Glassmorphism, Neon Glow và Dark Mode tùy biến cho Dashboard Streamlit.
*   **Mối quan hệ:** Được load tự động bên trong `src/ui/app.py`.

### 37. `experiments/run_ablation_study.py`
*   **Mục đích:** Tự động hóa chạy thực nghiệm Ablation Study.
*   **Tác dụng:** Nạp cấu hình từ 6 file YAML (A -> F), cho chạy toàn bộ tập dữ liệu Ground Truth qua pipeline tương ứng, đo lường các chỉ số Precision, Recall, FPR, F1, độ trễ và đẩy kết quả lên MLflow.
*   **Mối quan hệ:** Khởi động và chạy toàn bộ hệ thống ở các cấu hình khác nhau.

### 38. `experiments/statistical_tests.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Kiểm định ý nghĩa thống kê của kết quả nghiên cứu.
*   **Tác dụng:** Cài đặt và thực thi thuật toán kiểm định phi tham số **McNemar's Test** cho độ chính xác phân loại và **Mann-Whitney U Test** cho độ trễ hệ thống.
*   **Mối quan hệ:** Được gọi sau khi chạy xong Ablation Study để kiểm chứng độ tin cậy thực tế của số liệu.

### 39. `experiments/evaluate_robustness.py`
*   **Mục đích:** Đánh giá tính kháng nhiễu nghịch đảo của Guardrail.
*   **Tác dụng:** Bơm 45 payload prompt injection/obfuscation phức tạp qua hệ thống, tính toán tỷ lệ bypass thành công để chứng minh độ cứng cáp của Tầng Guardrail.
*   **Mối quan hệ:** Đánh giá độc lập tính an sau prompt.

### 40. `experiments/evaluate_reasoning.py`
*   **Mục đích:** Đánh giá độ tin cậy tri thức của Agent và chất lượng RAG.
*   **Tác dụng:** Triển khai **Llama-3.1-8B-Instruct** đóng vai trò trọng tài (LLM-as-a-Judge) chấm điểm chất lượng RAG (Context Precision, Faithfulness, Relevancy) theo chuẩn RAGAS; kiểm tra tính giải thích được qua việc validate cấu trúc dữ liệu JSON.
*   **Mối quan hệ:** Kết nối llama.cpp server của Llama-3.1 để chấm điểm kết quả từ Gemma-2.

### 41. `experiments/evaluate_zeroday.py`
*   **Mục đích:** Đánh giá năng lực phát hiện mối đe dọa Zero-day chưa có nhãn.
*   **Tác dụng:** Mô phỏng các cuộc tấn công Zero-day để đo lường tính hiệu quả của Welford Outlier so với các rule tĩnh.
*   **Mối quan hệ:** Phụ thuộc vào `rule_engine.py`.

### 42. `experiments/measure_latency_baseline.py`
*   **Mục đích:** Đo lường độ trễ nền tảng làm cơ sở so sánh.
*   **Tác dụng:** Tính toán độ trễ tối thiểu khi suy luận của LLM trần trụi trước khi tích hợp các cơ chế caching và filtering.
*   **Mối quan hệ:** Bổ sung số liệu so sánh cho Mann-Whitney U test.

### 43. `experiments/plot_results.py`
*   **Mục đích:** Trực quan hóa số liệu thực nghiệm.
*   **Tác dụng:** Vẽ các biểu đồ cột so sánh F1-Score, biểu đồ hộp (Boxplot) phân bố độ trễ xử lý logs giữa các cấu hình của Ablation Study để đưa vào bài báo cáo/luận văn.
*   **Mối quan hệ:** Đọc dữ liệu đầu ra từ MLflow/tệp CSV kết quả thực nghiệm.

### 44. `experiments/e2e_test_runner.py` *(Quan trọng cho việc kiểm thử)*
*   **Mục đích:** Chạy kiểm thử tự động tích hợp (E2E Integration Tests) của toàn bộ hệ thống.
*   **Tác dụng:** Chạy 20/20 kịch bản kiểm định chất lượng cho hệ thống bao gồm: Rule Engine, Delimiter Guardrails, Dual-RAG, SQLite Threat Memory, và logic Agent.
*   **Mối quan hệ:** Đóng vai trò là chốt chặn đảm bảo tính toàn vẹn của mã nguồn trước khi đẩy mã nguồn lên Production hoặc chạy thực nghiệm.

### 45. `main.py`
*   **Mục đích:** Điểm khởi chạy tích hợp của toàn dự án.
*   **Tác dụng:** Khởi động đồng thời các tiến trình Redis Subscriber chạy nền và chạy ứng dụng Streamlit Web UI để khởi chạy Sentinel ở môi trường đồ họa.
*   **Mối quan hệ:** File tích hợp gọi tất cả các cấu phần chính trong `src/`.
