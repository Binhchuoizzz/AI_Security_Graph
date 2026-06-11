# Tài liệu Tổng kết Cấu trúc Mã nguồn & Lộ trình Học tập (SENTINEL)

Tài liệu này tổng hợp mã nguồn hệ thống SENTINEL theo **Luồng dữ liệu (Dataflow)** và **Lộ trình học tập theo ngày**. Mỗi file được phân tích: Mục đích, Tác dụng, Mối quan hệ với các cấu phần khác.

> **Tiến độ hiện tại:** Đã đi qua **NGÀY 1** (Tầng dữ liệu đầu vào & Bộ lọc Tier-1),
> **NGÀY 2** (Tầng an toàn Guardrails) và **NGÀY 3** (Tầng truy xuất tri thức kép Dual-RAG) — 28 file,
> được mô tả CHI TIẾT & đối chiếu sát với code hiện tại bên dưới. Các **Ngày 4 → 5** (LangGraph Agent, UI & Thực nghiệm)
> **CHƯA đi qua** — chỉ liệt kê outline ngắn ở cuối để định hướng.

---

## **NGÀY 1: TẦNG DỮ LIỆU ĐẦU VÀO & BỘ LỌC TỐC ĐỘ CAO TIER 1**

### 1. `scripts/fetch_and_build_dataset.py`
*   **Mục đích:** Trích xuất & chuẩn hóa bộ dữ liệu CSE-CIC-IDS2018 thành tập `ground_truth.json` cho thực nghiệm/demo.
*   **Tác dụng:** Đọc các tệp CSV thô CIC-IDS2018, lọc theo `LABEL_MAP` (14 lớp tấn công + Benign), ánh xạ mỗi lớp sang MITRE + hành động kỳ vọng, tiền xử lý (ép kiểu số, xử lý inf/NaN, dedup), lấy mẫu phân tầng `n_per_label` (mặc định 300) ghi ra `experiments/ground_truth.json`. **Đã bổ sung lớp thứ 14 `DDoS attacks-LOIC-HTTP`** bằng cách đọc CHUNKED (200k dòng/chunk) file Tuesday-20-02 (3.8GB) để tránh OOM. Sinh kèm 50 mẫu adversarial cho kiểm thử Guardrails.
*   **Mối quan hệ:** Đọc từ `data/raw/cicids2018/`. Đầu ra `ground_truth.json` dùng cho Ablation Study, dashboard seed và các script đánh giá.

### 2. `scripts/fetch_dapt2020.py`
*   **Mục đích:** Tải/chuẩn bị bộ dữ liệu tấn công chuỗi dài ngày DAPT2020 (kịch bản APT).
*   **Tác dụng:** Tải các tệp thô DAPT2020, làm sạch ban đầu, phân cấp sự kiện theo ngày hoạt động (Day 1 → Day 5).
*   **Mối quan hệ:** Lưu dữ liệu thô vào `data/raw/dapt2020/`.

### 3. `scripts/dapt2020_config.py`
*   **Mục đích:** Cấu hình ánh xạ nhãn, hằng số và chuẩn hóa cột cho DAPT2020.
*   **Tác dụng:** Định nghĩa `DAPT_LABEL_TO_MITRE` (nhãn tấn công → mã MITRE ATT&CK) và `APT_PHASES` (giai đoạn kill-chain theo ngày).
*   **Mối quan hệ:** Được import bởi `scripts/fetch_dapt2020.py` và `scripts/build_dapt_chains.py`.

### 4. `scripts/build_dapt_chains.py`
*   **Mục đích:** Cấu trúc DAPT2020 thành các chuỗi tấn công APT (kill-chain) theo thời gian của từng IP.
*   **Tác dụng:** Đọc 5 ngày DAPT2020, gom nhóm theo `src_ip`, sắp xếp theo thời gian, chỉ giữ chuỗi đa-ngày (≥2 ngày) có ít nhất 1 sự kiện tấn công. **Ưu tiên giữ NHIỀU sự kiện tấn công (tối đa 50 attack + 10 benign mỗi chuỗi)** để tối đa hóa log tấn công APT; đóng gói ra `data/processed/dapt2020_chains.jsonl` (giữ nhãn chi tiết + `mitre_ttp`).
*   **Mối quan hệ:** Đầu ra dùng cho `threat_memory.ingest_dapt_chains()` và các kịch bản kiểm thử APT của Tier-2.

### 5. `src/streaming/publisher.py`
*   **Mục đích:** Mô phỏng dòng lưu lượng mạng doanh nghiệp thời gian thực.
*   **Tác dụng:** Đọc `REDIS_URL` từ `.env`/`system_settings.yaml`, đọc CSV (Demo-Attack/CICIDS), chuẩn hóa & sinh IP xác định (`_inject_ips`), đẩy từng flow JSON vào **Redis Stream** bằng `xadd` (maxlen giới hạn chống OOM) với độ trễ tùy chỉnh (wire-speed). *(Lưu ý: dùng Redis Streams — KHÔNG phải Pub/Sub.)*
*   **Mối quan hệ:** Đẩy vào Stream `queue_waf`; subscriber tiêu thụ qua consumer group.

### 6. `scripts/simulate_traffic.py`
*   **Mục đích:** Entrypoint chạy mô phỏng dòng lưu lượng mạng.
*   **Tác dụng:** Khởi chạy tiến trình stream logs; hỗ trợ ánh xạ các trường mạng thô → chuẩn hóa của Rule Engine qua alias khóa.
*   **Mối quan hệ:** Gọi hàm từ `src/streaming/publisher.py`.

### 7. `src/streaming/subscriber.py`
*   **Mục đích:** Lắng nghe & gom batch logs từ Redis để chuyển cho Tier-1/Tier-2; ghi chuỗi APT emergent từ luồng.
*   **Tác dụng:** Tạo/tham gia **consumer group `sentinel_group`** trên các **Redis Stream** (`queue_firewall`, `queue_waf`) qua `xreadgroup`; với mỗi log gọi `RuleEngine.evaluate`, rồi định tuyến theo `tier1_action`: `ESCALATE` → gom batch gọi LangGraph Agent; `BLOCK_IP` → blacklist Redis; `AWAIT_HITL` → đẩy queue HITL; `ALERT/LOG` → ghi `queue_decisions`. Trigger Agent theo batch_size hoặc timeout. **APT EMERGENT (online):** message mang metadata DAPT (`apt_phase`/`apt_day`/`apt_is_attack` — từ `stream_unified_online.py`) được ghi dần vào Threat Memory (`record_apt_event`); khi `check_apt_chain` BẬT (đủ đa-ngày) → ép `ESCALATE` chuỗi APT lên Agent. Traffic thường (không metadata) đi đường cũ, không đổi.
*   **Mối quan hệ:** Nhận từ Redis Streams, gọi `rule_engine.py` (Tier-1), `agent/threat_memory.py` (APT) và `agent/workflow.py` (Tier-2) khi escalate.

### 8. `src/tier1_filter/rule_engine.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Màng lọc heuristics tốc độ cao + phát hiện dị biệt thống kê phi giám sát trực tuyến.
*   **Tác dụng:**
    *   Class `RunningStats`: thuật toán **Welford** cập nhật Mean/StdDev trực tuyến, $O(1)$ RAM/CPU.
    *   Class `SessionBaseline`: quản lý IP profiles, phát hiện **port scan** (>10 cổng non-HTTP), tần suất cao, dung lượng bất thường; cơ chế **eviction TTL** chống OOM.
    *   `evaluate()` xử lý theo tầng: Whitelist → **WAF signature** (`_check_waf_signatures`: SQLi/XSS/Path-Traversal/Cmd-Inj) → **Prompt-Injection/Jailbreak signature** (`_check_injection_signatures`) → **Z-Score anomaly** (warmup 100 mẫu sạch, lệch >3.5σ → phạt zero-day) → Static rules (cổng nhạy cảm, volumetric) → **Dynamic rules (chỉ status `ACTIVE`)** → Session baseline → phân luồng action (DROP/LOG/ALERT/BLOCK_IP/AWAIT_HITL/ESCALATE).
    *   **Chống Baseline Poisoning:** chỉ nạp flow được coi là benign (DROP/LOG) vào `global_stats`. **Hot-reload** config mỗi 5s khi YAML đổi.
    *   Đồng bộ `sensitive_ports` (loại 80/443 để tấn công tầng ứng dụng SQLi/XSS được ESCALATE lên LLM) và loại `0.0.0.0` khỏi whitelist.
*   **Mối quan hệ:** Nhận logs từ `subscriber.py`, đọc/hot-reload config từ `system_settings.yaml`, trả quyết định Tier-1.

### 9. `src/tier1_filter/feedback_listener.py`
*   **Mục đích:** Vòng phản hồi (Feedback Loop) đồng bộ cấu hình rule động giữa UI/Agent ↔ Tier-1.
*   **Tác dụng:** Nhận rule mới (qua `FeedbackValidator`), persist vào `system_settings.yaml` bằng **atomic write** (`mkstemp` + `chmod 0644` + `os.replace`) kết hợp `FileLock`. Quản lý vòng đời `PENDING_APPROVAL → ACTIVE/REJECTED` (HITL approval), whitelist, và clamp risk score `[0,100]`.
*   **Mối quan hệ:** Gọi bởi `node_action_executor` (Agent) và Web UI; RuleEngine hot-reload các rule `ACTIVE`.

### 10. `src/tier1_filter/scanner.py`
*   **Mục đích:** Phân hệ quét lỗ hổng phụ thuộc (SCA) bằng Trivy.
*   **Tác dụng:** Tích hợp Trivy quét mã nguồn & dependencies của chính hệ thống (Self-Securing/DevSecOps), kết quả JSON dùng nạp vào Knowledge Graph (Neo4j, V2 tùy chọn).
*   **Mối quan hệ:** Chạy độc lập; đầu ra đồng bộ làm tri thức RAG/Graph.

### 11. `demos/demo_tier1.py`
*   **Mục đích:** Demo chạy riêng Tier-1.
*   **Tác dụng:** Script CLI minh họa 6 loại action (DROP/BLOCK_IP/ALERT/ESCALATE/AWAIT_HITL) + Welford Z-Score zero-day; xử lý đúng trạng thái rule động (`ACTIVE`/`PENDING_APPROVAL`).
*   **Mối quan hệ:** Gọi trực tiếp `rule_engine.py`.

---

## **NGÀY 2: TẦNG AN TOÀN VÀ NÉN DỮ LIỆU (GUARDRAILS)**

### 12. `src/guardrails/constants.py`
*   **Mục đích:** Tập trung ánh xạ tên trường log giữa các tầng.
*   **Tác dụng:** `KEY_ALIASES` + `normalize_log_keys()` chuyển các biến thể (`src_ip`, `dst_port`, `user_agent`...) về tên chuẩn (`Source IP`, `Destination Port`, `User-Agent`...), chống sai lệch cấu trúc dữ liệu.
*   **Mối quan hệ:** Dùng bởi `data_validator.py`, `feedback_validator.py`, `template_miner.py`, `prompt_filter.py`.

### 13. `src/guardrails/template_miner.py`
*   **Mục đích:** Nén volume logs + quản lý token đầu vào LLM.
*   **Tác dụng:** `LogTemplateMiner` dùng `drain3` gom logs cùng cấu trúc thành Template + count + mẫu; `EntropyScorer` tính Shannon entropy ưu tiên log bất thường; `TokenBudgetManager` ước lượng token bằng heuristic (`len//4`) và cắt theo ngân sách (đọc `token_budget` từ config). Có guard ép kiểu an toàn cho tham số YAML.
*   **Mối quan hệ:** Nhận logs escalate từ Tier-1, nén & chuyển cho `prompt_filter.py`.

### 14. `src/guardrails/prompt_filter.py`
*   **Mục đích:** 3 tầng phòng thủ Prompt Injection trước khi log vào LLM.
*   **Tác dụng:** `load_config` (nguồn config trung tâm + fallback); `PromptInjectionDetector` & `JailbreakDetector` (regex pattern + `role_play_re`, set isolation `HIGH`/`CRITICAL`); `EncodingNeutralizer` (giải base64/URL/hex, strip zero-width & HTML/script); `DelimitedDataEncapsulator` (sinh **nonce `secrets.token_hex(8)`**, strip delimiter smuggling `<<<...>>>`, chỉ giữ `ALLOWED_FIELDS`); `GuardrailsPipeline` orchestrate cả `process()` và `process_batch()` (kết hợp template miner + entropy + token budget).
*   **Mối quan hệ:** Nhận log đã nén từ `template_miner.py`, đóng gói an toàn trước khi vào prompt Agent.

### 15. `src/guardrails/output_sanitizer.py`
*   **Mục đích:** Làm sạch ĐẦU RA LLM, chống Data Exfiltration / XSS / Markdown.
*   **Tác dụng:** Singleton `output_sanitizer`: strip zero-width & ANSI; thay 11 pattern nguy hiểm (markdown image/link, `<script>/<img>/<iframe>/<svg>`, data URI...) bằng placeholder; quét **base64/hex obfuscation sâu** để bắt payload ẩn.
*   **Mối quan hệ:** Dùng bởi `decision_validator`, `threat_memory`, `nodes` (double-sanitize) trước khi hiển thị UI/ghi DB.

### 16. `src/guardrails/data_validator.py`
*   **Mục đích:** Xác thực schema log đầu vào (chống Schema Abuse).
*   **Tác dụng:** Chuẩn hóa key, ép kiểu an toàn, kiểm IP (`ipaddress`), port `[0,65535]`, protocol `[0,255]`; gắn `_is_valid`/`_validation_errors`; hỗ trợ batch với `filter_invalid`/`raise_on_error`.
*   **Mối quan hệ:** Chốt chặn định dạng đầu vào cho Guardrail Layer.

### 17. `src/guardrails/state_monitor.py`
*   **Mục đích:** Giám sát runtime: audit log, chống vòng lặp vô hạn, kiểm soát context.
*   **Tác dụng:** `AuditLogger` ghi SQLite an toàn (`threading.Lock` + try/finally); `LoopDetector` (đếm visit, `FORCE_STOP` khi vượt, `reset()` giữa các cycle); `ContextOverflowGuard` kiểm tra ngân sách token. Xuất singletons `loop_detector`, `audit_logger`, `context_overflow_guard`.
*   **Mối quan hệ:** Ghi audit & giám sát các Node LangGraph.

### 18. `src/guardrails/rag_sanitizer.py`
*   **Mục đích:** Chống RAG Poisoning & Semantic Cache Poisoning.
*   **Tác dụng:** `sanitize_ingest` (NFKC, strip control/zero-width/HTML/markdown, truncate) lúc nạp tài liệu; `sanitize_retrieve` (strip delimiter, trung hòa injection/jailbreak) lúc truy xuất; `sanitize_cache_entry` làm sạch khi đọc Semantic Cache (cache-hit path).
*   **Mối quan hệ:** Tích hợp vào `src/rag/retriever.py` và `src/rag/security.py`.

### 19. `src/guardrails/decision_validator.py`
*   **Mục đích:** Thẩm định & làm sạch quyết định LLM (chống Hallucination / Self-DoS / Social-Engineering).
*   **Tác dụng:** Ép Action Enum hợp lệ; **Confidence Gate** (BLOCK_IP cần ≥0.5); **Anti-Self-DoS Shield** downgrade BLOCK_IP→ALERT cho IP hạ tầng (parse cả hex/octal/integer chống bypass); sanitize `reasoning`/`mitre`/`nist`. **`enforce_tier_consensus`** — lá chắn chống social-engineering ngữ nghĩa: nếu Tier-1 (xác định) coi luồng là tấn công nhưng LLM bị thao túng hạ xuống `LOG/DROP` thì KHÔNG tin LLM, buộc `AWAIT_HITL`.
*   **Mối quan hệ:** Gọi bởi `node_llm_triage` (`nodes.py`) trước khi thực thi quyết định.

### 20. `src/guardrails/feedback_validator.py`
*   **Mục đích:** Zero-Trust cho rule động & whitelist đẩy về Tier-1.
*   **Tác dụng:** Chặn wildcard (`0.0.0.0/0`, `*`, `any`), giới hạn CIDR ≥ `/8`, cấm chặn IP hạ tầng nội bộ; validate regex cho URI/User-Agent; chỉ cho whitelist IP trong subnet tin cậy.
*   **Mối quan hệ:** Tích hợp vào `FeedbackListener` để kiểm duyệt rule (con người/Agent).

### 21. `demos/demo_guardrails.py`
*   **Mục đích:** Demo tích hợp đầy đủ Guardrails.
*   **Tác dụng:** Trực quan hóa 8 lớp phòng thủ: injection/jailbreak detection, nonce delimiter, encoding neutralize, RAG poison sanitize, decision validate, feedback validate, output sanitize.
*   **Mối quan hệ:** Gọi trực tiếp các module `src/guardrails/`.

---

## **NGÀY 3: TẦNG TRUY XUẤT TRI THỨC KÉP (DUAL-RAG) & ĐỒ THỊ TRI THỨC**

### 22. `src/rag/embedder.py`
*   **Mục đích:** Xây dựng và cập nhật Vector Index (FAISS & BM25) từ cơ sở dữ liệu tri thức thô.
*   **Tác dụng:** Phân tách các kỹ thuật MITRE ATT&CK và quy trình NIST SP 800-61r2 (dạng văn bản thô đầy đủ) thành các chunk có kích thước phù hợp (~256 tokens), làm sạch qua `RAGSanitizer.sanitize_ingest()`, sau đó sử dụng `SentenceTransformer` với mô hình `all-MiniLM-L6-v2` để sinh vector nhúng 384 chiều. Ghi đè chữ ký số SHA-256 của các file index/JSON thô vào tệp `checksums.sha256` để kiểm soát tính toàn vẹn.
*   **Mối quan hệ:** Đọc từ `knowledge_base/` và ghi các file vector/metadata đã được nhúng vào `knowledge_base/faiss_index/`.

### 23. `scripts/build_rag_indexes.py`
*   **Mục đích:** CLI wrapper để chạy tiến trình xây dựng chỉ mục.
*   **Tác dụng:** Cấu hình PYTHONPATH và kích hoạt `build_all_indexes()` của embedder.
*   **Mối quan hệ:** Gọi trực tiếp module `src/rag/embedder.py`.

### 24. `src/rag/security.py`
*   **Mục đích:** Thiết lập lá chắn bảo mật cho tầng RAG nhằm chống lại RAG Poisoning.
*   **Tác dụng:**
    *   `verify_document_integrity()`: Xác thực chữ ký SHA-256 của toàn bộ tệp KB và index trên disk so với chữ ký trong `checksums.sha256` trước khi nạp; nếu có sai khác sẽ lập tức ngắt tiến trình.
    *   `log_tokenizer()`: Tokenizer tối ưu cho log an ninh mạng (giữ nguyên định dạng CVE IDs và địa chỉ IP).
    *   `add_provenance()`: Gắn tag chứng thực nguồn gốc `[SOURCE: ... | VERIFIED: SENTINEL_KB]` vào tri thức để giúp LLM phân biệt dữ liệu tri thức đáng tin cậy với log mạng.
*   **Mối quan hệ:** Cung cấp các kiểm tra bảo mật cho `retriever.py` và `embedder.py`.

### 25. `src/rag/semantic_cache.py`
*   **Mục đích:** Giảm thiểu độ trễ truy xuất bằng bộ đệm ngữ nghĩa.
*   **Tác dụng:** Triển khai bộ nhớ đệm LRU Cache (sử dụng `OrderedDict` của Python) với khóa băm SHA-256 của query text (log template). Hỗ trợ giới hạn số lượng `max_size=500` và thời gian sống `ttl_seconds=1800`.
*   **Mối quan hệ:** Tích hợp trực tiếp vào `retriever.py` giúp bỏ qua embedding/search đối với các log trùng lặp template (như DDoS, Brute Force).

### 26. `src/rag/retriever.py`
*   **Mục đích:** Bộ truy xuất tri thức an toàn kết hợp Dense & Sparse search.
*   **Tác dụng:**
    *   Thực hiện kiểm tra chữ ký số ở khởi tạo. Tra cứu `SemanticCache` để trả kết quả tức thì nếu cache hit.
    *   `_hybrid_search()`: Truy vấn Dense Search (FAISS IndexFlatIP) và Sparse Search (BM25Okapi) đồng thời, dung hòa thứ hạng bằng thuật toán Reciprocal Rank Fusion (RRF, k=60), lọc theo ngưỡng `MIN_SCORE_THRESHOLD=0.15`, đưa qua `RAGSanitizer.sanitize_retrieve()` làm sạch và gắn provenance tag.
*   **Mối quan hệ:** Nhận logs từ Agent Tier-2, truy xuất tri thức và trả về prompt ngữ cảnh RAG tổng hợp (`combined_prompt`).

### 27. `demos/demo_rag.py`
*   **Mục đích:** Demo CLI của RAG layer.
*   **Tác dụng:** Thực thi tìm kiếm lai và trực quan hóa ngữ cảnh thu được từ MITRE và NIST đối với một truy vấn log mẫu.
*   **Mối quan hệ:** Gọi trực tiếp `src/rag/retriever.py`.

### 28. `src/rag/graph_builder.py`
*   **Mục đích:** Quản lý đồ thị tri thức phụ thuộc an toàn thông tin (Knowledge Graph).
*   **Tác dụng:** Sử dụng driver Neo4j (Bolt protocol) đọc kết quả quét Trivy (`data/trivy-results.json`), thiết lập các nút `Component`, `SubComponent` (ví dụ: requirements.txt) và `Vulnerability` (CVE) cùng các quan hệ `CONTAINS`, `HAS_VULNERABILITY`. Tự động xuất mock JSON nếu Neo4j offline.
*   **Mối quan hệ:** Quét lỗ hổng tĩnh và nạp vào Neo4j Graph.

---

## ⏳ **CÁC NGÀY TIẾP THEO (CHƯA ĐI QUA — OUTLINE ĐỊNH HƯỚNG)**

> Các tầng dưới đây **đã có code** và chạy được, nhưng **chưa được học/đối chiếu chi tiết**
> trong lộ trình hiện tại. Phần này chỉ là outline ngắn; sẽ mở rộng chi tiết khi đi tới.

### **NGÀY 4 — Cỗ máy trạng thái LangGraph & phản hồi an ninh**
*   `src/agent/state.py` — schema `SentinelState` (batch logs, RAG context, decisions, IOCs...).
*   `src/agent/workflow.py` — `StateGraph` + node + conditional edge (Block/Alert/HITL/End).
*   `src/agent/nodes.py` *(quan trọng)* — `node_guardrails` / `node_rag_context` (query RAG từ **metadata flow thật**: service/port/tier1 reasons) / `node_llm_triage` (DecisionValidator + **enforce_tier_consensus** + AuditLogger) / `node_action_executor`.
*   `src/agent/prompts.py` — system prompt (có **rule #7 chống social-engineering**) + few-shot Active Learning.
*   `src/agent/llm_client.py` — client OpenAI-compatible → llama.cpp (Gemma-2-9B), `DEFAULT_MODEL` đọc từ env.
*   `src/agent/threat_memory.py` — uy tín IP, chuỗi APT (`check_apt_chain` ≥2 ngày), chống Memory Poisoning.
*   `src/response/executor.py` — audit trail SQLite + **HMAC SHA-256 log-chaining** chống giả mạo.

### **NGÀY 5 — Giao diện SOC & khung đánh giá thực nghiệm**
*   `src/ui/app.py`, `components.py`, `auth.py` (PBKDF2-HMAC-SHA256), `style.css` — Dashboard HITL Streamlit (5 tab: Alerts/Rules/APT/Blocklist/Graph).
*   `experiments/run_ablation_study.py`, `statistical_tests.py` (McNemar + Mann-Whitney U), `evaluate_robustness.py` (**120 mẫu adversarial / 5 nhóm**), `evaluate_adversarial_pipeline.py` (kháng LLM), `evaluate_reasoning.py` (LLM-as-Judge/RAGAS), `evaluate_unified_stream.py` (**luồng gộp CICIDS+DAPT+zero-day, phát hiện APT emergent, thay phương pháp 3 luồng cũ**), `stream_unified_online.py` (**publisher ONLINE phát cùng luồng gộp qua Redis → toàn pipeline, demo realtime**), `measure_latency_baseline.py`, `plot_results.py`, `e2e_test_runner.py` (22/22).
*   `scripts/build_adversarial_suite.py`, `seed_demo_data.py` — sinh bộ adversarial & seed Dashboard từ data thật.
*   `main.py` — entrypoint tích hợp (mode server/scan/full).

---

> **Kiểm thử đơn vị (xuyên suốt):** `tests/unit/` (data_validator, decision_validator + tier-consensus guard, feedback_validator, output_sanitizer, prompt_filter, rag_sanitizer, template_miner, threat_memory) + `tests/integration/` + `tests/test_adversarial.py`. Trạng thái hiện tại: **pytest 165 passed, E2E 22/22**.
