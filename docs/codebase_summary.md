# Tài liệu Tổng kết Cấu trúc Mã nguồn & Lộ trình Học tập (SENTINEL)

Tài liệu này tổng hợp **toàn bộ tệp mã nguồn** của hệ thống SENTINEL, phân bổ theo **Luồng dữ liệu (Dataflow)** và xếp theo **Lộ trình học tập 5 ngày**. Mỗi file phân tích rõ: **Mục đích → Tác dụng → Mối quan hệ** với các cấu phần khác. Đã đối chiếu sát với code ở HEAD (cập nhật 2026-06: luồng gộp online, zero-day real-derived, Anti-Self-DoS shield hẹp, raw-log counter thật, BLOCK_IP brute-force, FIREWALL MOCK).

> **Bản đồ luồng:** Dataset → **Tier-1** (RuleEngine + Welford) → **Guardrails** → **Dual-RAG** → **LangGraph Agent (LLM)** → **Response/Audit** → **Dashboard HITL** → Feedback Loop về Tier-1.
> **Trạng thái kiểm thử:** `pytest 194 passed`, `E2E 22/22 PASSED`.

---

## **NGÀY 1: TẦNG DỮ LIỆU ĐẦU VÀO & BỘ LỌC TỐC ĐỘ CAO TIER-1**

### 1. `scripts/fetch_and_build_dataset.py`
*   **Mục đích:** Trích xuất & chuẩn hóa CSE-CIC-IDS2018 thành `experiments/ground_truth.json`.
*   **Tác dụng:** Đọc CSV thô CIC-IDS2018, lọc theo `LABEL_MAP` (14 lớp tấn công + Benign), ánh xạ mỗi lớp → MITRE + hành động kỳ vọng, tiền xử lý (ép kiểu, xử lý inf/NaN, dedup, clip), lấy mẫu phân tầng `n_per_label` (mặc định 300, `random_state=42`) → **4267 mẫu**. Đọc CHUNKED (200k dòng/chunk) file Tuesday-20-02 (3.8GB) lấy lớp `DDoS attacks-LOIC-HTTP` tránh OOM. Sinh kèm 50 mẫu adversarial.
*   **Mối quan hệ:** Đọc `data/raw/cicids2018/`; output dùng cho Ablation, dashboard seed, unified stream, các script đánh giá.

### 2. `scripts/download_cicids2018.sh`
*   **Mục đích:** Tải bộ CSE-CIC-IDS2018 thô từ AWS S3 (public bucket).
*   **Tác dụng:** `aws s3 sync --no-sign-request` về `data/raw/cicids2018/` (≈8GB), kiểm tra AWS CLI.
*   **Mối quan hệ:** Bước chuẩn bị data cho `fetch_and_build_dataset.py`.

### 3. `scripts/fetch_dapt2020.py`
*   **Mục đích:** Tải/sinh bộ DAPT2020 (kịch bản APT đa-ngày).
*   **Tác dụng:** Tải từ Kaggle (kagglehub); nếu không có → sinh CSV giả lập theo schema 85 cột (5 ngày, chuỗi tấn công đa giai đoạn) để kiểm định Threat Memory.
*   **Mối quan hệ:** Lưu thô vào `data/raw/dapt2020/`.

### 4. `scripts/dapt2020_config.py`
*   **Mục đích:** Cấu hình ánh xạ nhãn/hằng số/chuẩn hóa cột cho DAPT2020.
*   **Tác dụng:** Định nghĩa `APT_PHASES` (giai đoạn kill-chain theo ngày), `DAPT_LABEL_TO_MITRE` (nhãn → MITRE), `BENIGN_LABELS`, `DAPT2020_HEADERS` (85 cột), hàm `normalize_stage/normalize_label`.
*   **Mối quan hệ:** Import bởi `fetch_dapt2020.py` và `build_dapt_chains.py`.

### 5. `scripts/build_dapt_chains.py`
*   **Mục đích:** Cấu trúc DAPT2020 thành chuỗi APT (kill-chain) theo IP.
*   **Tác dụng:** Đọc 5 ngày, gom theo `src_ip`, sắp theo thời gian, chỉ giữ chuỗi đa-ngày (≥2 ngày) có ≥1 sự kiện tấn công. Ưu tiên giữ nhiều log tấn công (tối đa 50 attack + 10 benign/chuỗi) → `data/processed/dapt2020_chains.jsonl` (giữ nhãn + `mitre_ttp`).
*   **Mối quan hệ:** Output dùng cho `threat_memory.ingest_dapt_chains()` và `evaluate_unified_stream.py`.

### 6. `src/streaming/publisher.py`
*   **Mục đích:** Stream CSV THÔ ở quy mô lớn (production load-test).
*   **Tác dụng:** Đọc CSV **CHUNKED** (chunksize=500, file hàng triệu dòng không nạp hết RAM), chuẩn hóa cột + sinh IP xác định (`_inject_ips`), đẩy từng flow JSON vào **Redis Stream** `xadd` (maxlen chống OOM) với backpressure. *(1 trong **BA PUBLISHER**: file này = raw load-test; `simulate_traffic.py` = replay ground_truth; `stream_unified_online.py` = luồng gộp online.)*
*   **Mối quan hệ:** Đẩy vào `queue_waf`; subscriber tiêu thụ qua consumer group.

### 7. `scripts/simulate_traffic.py`
*   **Mục đích:** Replay `ground_truth.json` (4267 mẫu có nhãn) lên Redis cho demo/ablation.
*   **Tác dụng:** Multi-source routing (`determine_queue`: port → queue_firewall/queue_waf), `map_to_cicids` ánh xạ network_layer → schema RuleEngine, kèm metadata ground-truth (`gt_id`...).
*   **Mối quan hệ:** Đọc `ground_truth.json`, đẩy 3 queue; subscriber tiêu thụ.

### 8. `src/streaming/subscriber.py`
*   **Mục đích:** Lắng nghe & gom batch logs từ Redis cho Tier-1/Tier-2; ghi chuỗi APT emergent; đếm số liệu thật.
*   **Tác dụng:** Consumer group `sentinel_group` trên các Redis Stream (`queue_firewall`/`queue_waf`) qua `xreadgroup`; mỗi log → `RuleEngine.evaluate` → định tuyến theo `tier1_action`: `ESCALATE` → batch gọi Agent; `BLOCK_IP` → blacklist; `AWAIT_HITL` → `queue_hitl`; `ALERT/LOG` → `queue_decisions`. **APT EMERGENT (online):** message mang metadata DAPT (`apt_phase`/`apt_day`/`apt_is_attack` từ `stream_unified_online.py`) → `record_apt_event` rồi `check_apt_chain`; bản án bật (đủ đa-ngày) → ép `ESCALATE`. **Số liệu THẬT:** đếm log thô qua Tier-1 + số bị DROP → ghi `config/pipeline_stats.json` (atomic, chia sẻ qua volume) cho Dashboard tính Noise Reduction thật (KHÔNG dùng Redis vì container Dashboard không reach được redis).
*   **Mối quan hệ:** Gọi `rule_engine.py` (Tier-1), `agent/threat_memory.py` (APT), `agent/workflow.py` (Tier-2 khi escalate).

### 9. `src/tier1_filter/rule_engine.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Màng lọc heuristics tốc độ cao + phát hiện dị biệt thống kê phi giám sát trực tuyến.
*   **Tác dụng:**
    *   `RunningStats`: thuật toán **Welford** cập nhật Mean/StdDev trực tuyến, $O(1)$ RAM/CPU.
    *   `SessionBaseline`: IP profiles, phát hiện **port scan** (>10 cổng non-HTTP), tần suất/dung lượng bất thường; eviction TTL chống OOM.
    *   `evaluate()` theo tầng: Whitelist → **WAF signature** (SQLi/XSS/Path/Cmd-Inj) → **Injection/Jailbreak signature** → **Z-Score anomaly** (warmup 100 mẫu sạch, lệch >3.5σ → zero-day) → Static rules (cổng nhạy cảm, volumetric) → **Dynamic rules (status `ACTIVE`)** → Session baseline → action (DROP/LOG/ALERT/BLOCK_IP/AWAIT_HITL/ESCALATE).
    *   **Chống Baseline Poisoning:** chỉ nạp flow benign (DROP/LOG) vào `global_stats`. **Hot-reload** config mỗi 5s.
*   **Mối quan hệ:** Nhận logs từ `subscriber.py`; đọc/hot-reload `system_settings.yaml`; trả quyết định Tier-1. Luật ACTIVE (do HITL duyệt) được enforce ở đây.

### 10. `src/tier1_filter/feedback_listener.py`
*   **Mục đích:** Vòng phản hồi đồng bộ rule động UI/Agent ↔ Tier-1.
*   **Tác dụng:** Nhận rule mới (`receive_new_rule` qua `FeedbackValidator`), persist `system_settings.yaml` bằng **atomic write** (`mkstemp`+`chmod 0644`+`os.replace`) + `FileLock`. Vòng đời `PENDING_APPROVAL → ACTIVE/REJECTED` (HITL); `approve_rule`/`reject_rule`/`get_pending_rules`/`get_active_dynamic_rules`; whitelist; clamp score `[0,100]`.
*   **Mối quan hệ:** Gọi bởi `node_action_executor` (Agent khi BLOCK_IP) và Dashboard (nút Duyệt); RuleEngine hot-reload rule ACTIVE.

### 11. `src/tier1_filter/scanner.py`
*   **Mục đích:** Quét lỗ hổng phụ thuộc (SCA) bằng Trivy (DevSecOps tự-bảo-vệ).
*   **Tác dụng:** `VulnerabilityScanner` chạy `trivy fs` (list-form, không shell), xuất `data/trivy-results.json` nạp vào Knowledge Graph. KHÔNG tương tác runtime pipeline.
*   **Mối quan hệ:** Chạy độc lập (main.py mode scan/full); output cho `graph_builder.py`.

### 12. `demos/demo_tier1.py`
*   **Mục đích:** Demo chạy riêng Tier-1.
*   **Tác dụng:** CLI minh họa các action (DROP/BLOCK_IP/ALERT/ESCALATE/AWAIT_HITL) + Welford Z-Score zero-day; xử lý đúng rule động.
*   **Mối quan hệ:** Gọi trực tiếp `rule_engine.py`.

---

## **NGÀY 2: TẦNG AN TOÀN & NÉN DỮ LIỆU (GUARDRAILS)**

### 13. `src/guardrails/constants.py`
*   **Mục đích:** Tập trung ánh xạ tên trường log giữa các tầng.
*   **Tác dụng:** `KEY_ALIASES` + `normalize_log_keys()` chuyển biến thể (`src_ip`/`dst_port`/`user_agent`...) → chuẩn (`Source IP`/`Destination Port`/`User-Agent`...).
*   **Mối quan hệ:** Dùng bởi `data_validator`, `feedback_validator`, `template_miner`, `prompt_filter`.

### 14. `src/guardrails/template_miner.py`
*   **Mục đích:** Nén volume logs + quản lý token đầu vào LLM.
*   **Tác dụng:** `LogTemplateMiner` (drain3) gom logs cùng cấu trúc thành Template+count; `EntropyScorer` (Shannon entropy) ưu tiên log bất thường; `TokenBudgetManager` ước lượng token (`len//4`) cắt theo `token_budget` config.
*   **Mối quan hệ:** Nhận logs escalate từ Tier-1, nén & chuyển `prompt_filter.py`.

### 15. `src/guardrails/prompt_filter.py`
*   **Mục đích:** Phòng thủ Prompt Injection nhiều lớp trước khi log vào LLM.
*   **Tác dụng:** `PromptInjectionDetector`/`JailbreakDetector` (regex + role-play, isolation `HIGH`/`CRITICAL`); `EncodingNeutralizer` (NFKC + giải base64/base32/ROT13/URL/hex + fold homoglyph/leetspeak + strip zero-width/HTML, có guard chống false-positive); `DelimitedDataEncapsulator` (**nonce `secrets.token_hex(8)`**, strip delimiter smuggling, chỉ giữ `ALLOWED_FIELDS`); `GuardrailsPipeline` orchestrate `process()`/`process_batch()`.
*   **Mối quan hệ:** Nhận log đã nén; đóng gói an toàn trước prompt Agent.

### 16. `src/guardrails/output_sanitizer.py`
*   **Mục đích:** Làm sạch ĐẦU RA LLM (chống Data Exfiltration/XSS/Markdown).
*   **Tác dụng:** Singleton `output_sanitizer`: strip zero-width/ANSI; thay pattern nguy hiểm (markdown image/link, `<script>/<img>/<iframe>/<svg>`, data URI) bằng placeholder; quét **base64/hex obfuscation sâu**.
*   **Mối quan hệ:** Dùng bởi `decision_validator`, `threat_memory`, `nodes` (double-sanitize) trước khi hiển thị/ghi DB.

### 17. `src/guardrails/data_validator.py`
*   **Mục đích:** Xác thực schema log đầu vào (chống Schema Abuse).
*   **Tác dụng:** Chuẩn hóa key, ép kiểu an toàn, kiểm IP (`ipaddress`), port `[0,65535]`, protocol `[0,255]`; gắn `_is_valid`/`_validation_errors`; batch `filter_invalid`/`raise_on_error`.
*   **Mối quan hệ:** Chốt định dạng đầu vào cho Guardrail Layer.

### 18. `src/guardrails/state_monitor.py`
*   **Mục đích:** Giám sát runtime: audit, chống vòng lặp vô hạn, kiểm soát context.
*   **Tác dụng:** `AuditLogger` ghi SQLite an toàn (`threading.Lock`); `LoopDetector` (`FORCE_STOP` khi vượt, `reset()`); `ContextOverflowGuard` (ngân sách token). Singletons `loop_detector`/`audit_logger`/`context_overflow_guard`.
*   **Mối quan hệ:** Ghi audit & giám sát các Node LangGraph.

### 19. `src/guardrails/rag_sanitizer.py`
*   **Mục đích:** Chống RAG Poisoning & Semantic Cache Poisoning.
*   **Tác dụng:** `sanitize_ingest` (NFKC, strip control/zero-width/HTML/markdown, truncate); `sanitize_retrieve` (strip delimiter, trung hòa injection); `sanitize_cache_entry` (làm sạch cache-hit path).
*   **Mối quan hệ:** Tích hợp vào `rag/retriever.py` và `rag/security.py`.

### 20. `src/guardrails/decision_validator.py`
*   **Mục đích:** Thẩm định quyết định LLM (chống Hallucination/Self-DoS/Social-Engineering).
*   **Tác dụng:** Ép Action Enum hợp lệ; **Confidence Gate** (BLOCK_IP cần ≥0.5); **Anti-Self-DoS Shield** hạ BLOCK_IP→ALERT **chỉ** khi target ∈ **`critical_infrastructure_subnets`** (HẸP: loopback + hạ tầng cụ thể, parse hex/octal/integer chống bypass) — **KHÔNG** dùng toàn RFC1918 (nếu rộng → không chặn được attacker nội bộ/lateral, vá 2026-06); sanitize reasoning/mitre/nist. **`enforce_tier_consensus`**: nếu Tier-1 coi là tấn công nhưng LLM hạ xuống LOG/DROP → KHÔNG tin LLM, ép `AWAIT_HITL`.
*   **Mối quan hệ:** Gọi bởi `node_llm_triage` trước khi thực thi quyết định.

### 21. `src/guardrails/feedback_validator.py`
*   **Mục đích:** Zero-Trust cho rule động & whitelist đẩy về Tier-1.
*   **Tác dụng:** Chặn wildcard (`0.0.0.0/0`, `*`, `any`), CIDR ≥ `/8`, cấm chặn IP hạ tầng (`127.0.0.1`/`10.0.0.99`); validate regex URI/User-Agent; chỉ whitelist IP trong subnet tin cậy (`trusted_internal_subnets`).
*   **Mối quan hệ:** Dùng bởi `FeedbackListener` kiểm duyệt rule.

### 22. `scripts/build_adversarial_suite.py`
*   **Mục đích:** Sinh bộ adversarial mở rộng (120 mẫu / 5 nhóm) theo OWASP LLM Top 10.
*   **Tác dụng:** Sinh `encoding_bypass`(45)/`structural_attacks`(20)/`semantic_confusion`(20)/`jailbreak`(20)/`rag_poisoning`(15) ra `experiments/adversarial/{cat}/samples.json`.
*   **Mối quan hệ:** Đầu vào cho `evaluate_robustness.py` và `evaluate_adversarial_pipeline.py`.

### 23. `demos/demo_guardrails.py`
*   **Mục đích:** Demo tích hợp Guardrails.
*   **Tác dụng:** Trực quan hóa các lớp: injection/jailbreak, nonce delimiter, encoding neutralize, RAG sanitize, decision/feedback validate, output sanitize.
*   **Mối quan hệ:** Gọi trực tiếp `src/guardrails/`.

---

## **NGÀY 3: TẦNG TRUY XUẤT TRI THỨC KÉP (DUAL-RAG) & ĐỒ THỊ TRI THỨC**

### 24. `src/rag/embedder.py`
*   **Mục đích:** Xây Vector Index (FAISS & BM25) + cập nhật checksum.
*   **Tác dụng:** Chunk MITRE/NIST (~256 token), `RAGSanitizer.sanitize_ingest()`, `SentenceTransformer('all-MiniLM-L6-v2')` → vector 384 chiều; ghi SHA-256 vào `checksums.sha256`. `verify_document_integrity(exclude_generated=True)` ở đầu build.
*   **Mối quan hệ:** Đọc `knowledge_base/`, ghi `knowledge_base/faiss_index/`.

### 25. `scripts/build_rag_indexes.py`
*   **Mục đích:** CLI wrapper xây chỉ mục RAG.
*   **Tác dụng:** Set PYTHONPATH, gọi `build_all_indexes()`.
*   **Mối quan hệ:** Gọi `src/rag/embedder.py`.

### 26. `scripts/build_knowledge_base.py` (TỰ-CHỨA, single file)
*   **Mục đích:** **Entry point DUY NHẤT** xây dựng/mở rộng tri thức RAG trong MỘT lần.
*   **Tác dụng:** Inline trực tiếp data → append idempotent **67 kỹ thuật MITRE (0 trùng id) + 7 playbook NIST** (phủ đủ 14 tactic) vào `mitre_attack.json`/`nist_800_61r2.json`, RỒI tự rebuild FAISS/BM25 index + checksum (cờ `--no-index` để bỏ qua). Hai file `expand_knowledge_base.py` + `supplement_knowledge_base.py` cũ **đã xóa** — toàn bộ `ALL_MITRE`/`ALL_NIST` nay nằm gọn trong file này (1 source of truth thật sự).
*   **Mối quan hệ:** Đọc data inline → gọi `embedder.build_all_indexes()` + `update_checksums_file()`.

### 27. `src/rag/security.py`
*   **Mục đích:** Lá chắn toàn vẹn tri thức RAG (chống RAG Poisoning vật lý).
*   **Tác dụng:** `verify_document_integrity()` so SHA-256 file KB/index với `checksums.sha256`, sai khác → ngắt (fail-closed); `log_tokenizer()` giữ CVE/IP; `add_provenance()` gắn tag `[VERIFIED: SENTINEL_KB]`.
*   **Mối quan hệ:** Gọi bởi `embedder.py` và `retriever.py` (chạy TRƯỚC `pickle.load` BM25 → chặn CWE-502).

### 28. `src/rag/semantic_cache.py`
*   **Mục đích:** Giảm độ trễ truy xuất bằng bộ đệm ngữ nghĩa.
*   **Tác dụng:** LRU Cache (`OrderedDict`) khóa SHA-256 query template; `max_size=500`, `ttl_seconds=1800`; thống kê hit/miss/eviction cho MLflow.
*   **Mối quan hệ:** Tích hợp trong `retriever.py` (bỏ qua embed/search log trùng template).

### 29. `src/rag/retriever.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Truy xuất tri thức an toàn (Hybrid Search & Cache Defense).
*   **Tác dụng:** Kiểm checksum ở init (raise nếu fail); tra `SemanticCache` (cache hit qua `sanitize_cache_entry`); `_hybrid_search()`: Dense (FAISS IndexFlatIP) + Sparse (BM25Okapi) hợp nhất bằng **RRF (k=60)**, lọc `MIN_SCORE_THRESHOLD=0.15`, `sanitize_retrieve` + provenance.
*   **Mối quan hệ:** Gọi bởi `node_rag_context` (Agent); trả `combined_prompt`.

### 30. `src/rag/graph_builder.py`
*   **Mục đích:** Đồ thị tri thức lỗ hổng (Knowledge Graph, V2 tùy chọn).
*   **Tác dụng:** Driver Neo4j (Bolt) đọc `data/trivy-results.json`, tạo node `Component`/`SubComponent`/`Vulnerability` + quan hệ `CONTAINS`/`HAS_VULNERABILITY`; mock JSON nếu Neo4j offline.
*   **Mối quan hệ:** Nạp kết quả `scanner.py` vào Neo4j; hiển thị tab Graph trên Dashboard.

### 31. `demos/demo_rag.py`
*   **Mục đích:** Demo CLI RAG layer.
*   **Tác dụng:** Tìm kiếm lai + trực quan hóa ngữ cảnh MITRE/NIST cho 1 truy vấn log mẫu.
*   **Mối quan hệ:** Gọi trực tiếp `retriever.py`.

---

## **NGÀY 4: CỖ MÁY TRẠNG THÁI LANGGRAPH & PHẢN HỒI AN NINH**

### 32. `src/agent/state.py`
*   **Mục đích:** Schema bộ nhớ trạng thái của tác tử LangGraph.
*   **Tác dụng:** `SentinelState` (`TypedDict`): `current_batch_logs`, `current_batch_encapsulated`, `rag_mitre_context`/`rag_nist_context`, `decisions`, `narrative_summary`, `cycle_count`, IOCs, `hitl_status`...
*   **Mối quan hệ:** Import bởi toàn bộ `src/agent/`.

### 33. `src/agent/workflow.py`
*   **Mục đích:** Định nghĩa đồ thị nhận thức của tác tử.
*   **Tác dụng:** Khởi tạo `StateGraph`, đăng ký node (guardrails → rag_context → llm_triage → action_executor), nối edge + conditional edge (Block/Alert/HITL/End). Compile `agent_app`.
*   **Mối quan hệ:** Import node từ `nodes.py`; `agent_app` được `subscriber`/`main.py`/eval gọi.

### 34. `src/agent/nodes.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Logic xử lý tại các "Trạm" của đồ thị.
*   **Tác dụng:**
    *   `node_guardrails`: chạy `GuardrailsPipeline` (nén + đóng gói nonce).
    *   `node_rag_context`: query RAG từ metadata flow thật + inject lịch sử Threat Memory (`get_context_for_prompt`, gồm **chuỗi APT đa-ngày**).
    *   `node_llm_triage`: build prompt + gọi LLM; `DecisionValidator.validate_decision` + **`enforce_tier_consensus`** (lá chắn social-engineering) + `AuditLogger`.
    *   `node_action_executor`: thực thi action; **`BLOCK_IP`** → `block_ip()` (audit, MOCK) **VÀ** `FeedbackListener.receive_new_rule()` (sinh luật PENDING cho HITL); ghi `threat_memory.record_incident`; nếu `check_apt_chain` BẬT → ghi indicator `multi_day_chain`. `LoopDetector` chống vô hạn.
*   **Mối quan hệ:** Gọi `DualRetriever`, `llm_client`, `threat_memory`, `executor`, `feedback_listener`.

### 35. `src/agent/prompts.py`
*   **Mục đích:** Kho mẫu Prompt (System & User).
*   **Tác dụng:** System prompt có **rule #7 chống social-engineering** (bỏ qua tuyên bố thẩm quyền/whitelist trong log) + **Decision Matrix** (BLOCK_IP cho brute-force/scan rõ ràng từ IP ngoài whitelist trên cổng nhạy cảm SSH/FTP/RDP/SMB; ALERT cho DoS/DDoS spoofed). Tiêm few-shot Active Learning (rule analyst đã Approve/Reject).
*   **Mối quan hệ:** Gọi bởi `node_llm_triage`.

### 36. `src/agent/llm_client.py`
*   **Mục đích:** API client tới LLM cục bộ (offline).
*   **Tác dụng:** HTTP POST chuẩn OpenAI → `llama.cpp` server (Gemma-2-9B-IT), `temperature=0.1` ép JSON sạch; `parse_llm_response` (bóc JSON an toàn); `DEFAULT_MODEL` từ env (hỗ trợ hot-swap Llama-3 trọng tài).
*   **Mối quan hệ:** Gọi bởi `node_llm_triage` và `evaluate_reasoning.py`.

### 37. `src/agent/threat_memory.py`
*   **Mục đích:** Uy tín IP dài hạn, chuỗi APT, chống Memory Poisoning.
*   **Tác dụng:** SQLite (`config/threat_memory.db`): `record_incident`/`get_ip_reputation`; **`record_apt_event` + `check_apt_chain`** (đánh dấu APT khi IP xuất hiện ở **≥2 NGÀY khác nhau** — không phải "≥3 giai đoạn"); `get_context_for_prompt` (reputation + known-entity + **APT CHAIN đa-ngày** inject vào LLM); `ingest_dapt_chains` (bulk seed dashboard); known entities; `output_sanitizer` cho mọi trường trước khi ghi.
*   **Mối quan hệ:** Gọi bởi `node_action_executor` (ghi) và `node_rag_context` (nạp lịch sử); `subscriber` ghi APT emergent.

### 38. `src/response/executor.py`
*   **Mục đích:** Audit trail không thể chối cãi + hành động ứng phó.
*   **Tác dụng:** Ghi `config/audit_trail.db` với **HMAC SHA-256 móc-xích** (dòng trước→sau, `verify_audit_trail_integrity` phát hiện giả mạo); `block_ip()`/`quarantine_host()`/`raise_alert()` = **`[FIREWALL MOCK]`** (ghi audit, KHÔNG gọi iptables/OS — enforcement thật là luật ACTIVE ở Tier-1); login lockout (`get/increment/reset_login_attempts`, `lock_user`).
*   **Mối quan hệ:** Gọi bởi `node_action_executor` và Dashboard (verify + auth).

---

## **NGÀY 5: GIAO DIỆN SOC & KHUNG ĐÁNH GIÁ THỰC NGHIỆM**

### 39. `src/ui/app.py`
*   **Mục đích:** Web Dashboard Streamlit (SOC HITL).
*   **Tác dụng:** 5 tab (Nhật ký SIEM & Audit / Phê duyệt Luật HITL / Giám sát APT / Blocklist & Whitelist / Lỗ hổng & Graph). KPI header: "Cảnh báo Escalated", "Luật chờ duyệt/đang chặn", "Live FPR" và **"Logs thô"/"Noise Reduction" đọc `config/pipeline_stats.json` (SỐ THẬT** do subscriber ghi — bỏ ước lượng ×35). Nút Duyệt/Bác → `approve_rule`/`reject_rule` persist YAML → Tier-1 enforce. Nút Reset xóa DBs + dynamic_rules + `pipeline_stats.json`.
*   **Mối quan hệ:** Đọc `audit_trail.db`/`threat_memory.db`/`feedback_listener`/`pipeline_stats.json`.

### 40. `src/ui/components.py`
*   **Mục đích:** Component hiển thị tái dùng (Glassmorphism SOC).
*   **Tác dụng:** `render_metrics_header(..., noise_reduction)` (KPI cards, dùng noise_reduction đo thật); `render_alert_card` (card cảnh báo + MITRE/confidence/reasoning + NIST playbook, anti-XSS); `render_threat_intel_tables` (IP nguy cơ + known entities); `render_apt_events_table` (chuỗi APT DAPT2020).
*   **Mối quan hệ:** Import & render bởi `app.py`.

### 41. `src/ui/auth.py`
*   **Mục đích:** Xác thực RBAC + chống Input Injection.
*   **Tác dụng:** **PBKDF2-HMAC-SHA256 (100k vòng), KHÔNG hardcode plaintext** — hash demo tính sẵn + cảnh báo fail-loud khi dùng HASH/SALT demo; `hmac.compare_digest` (constant-time chống timing); regex `^[a-zA-Z0-9_]{1,30}$` cho username; lockout brute-force (5 lần). 2 vai trò L1_Analyst / L3_Manager.
*   **Mối quan hệ:** Bọc Dashboard; dùng `executor` cho lockout.

### 42. `src/ui/style.css`
*   **Mục đích:** Ngôn ngữ thiết kế thị giác SOC Dashboard.
*   **Tác dụng:** CSS variables, Glassmorphism, Neon Glow, severity glow + pulse critical, KPI cards, console box (font Inter).
*   **Mối quan hệ:** Load trong `app.py`.

### 43. `experiments/run_ablation_study.py`
*   **Mục đích:** Ablation Study (đóng góp từng thành phần).
*   **Tác dụng:** So sánh **Config A** (Tier-1 đầy đủ, không LLM) vs **Config F** (full SENTINEL) trên ground_truth; đo Precision/Recall/F1/FPR/latency; sinh `Config_F.reasoning_outputs` (cho trọng tài); đẩy MLflow. *(Config A ở đây = Tier-1 đầy đủ — KHÁC "static-only" trong unified stream.)*
*   **Mối quan hệ:** Output `results/ablation_results.json` dùng cho `statistical_tests` + `evaluate_reasoning`.

### 44. `experiments/statistical_tests.py` *(Quan trọng)*
*   **Mục đích:** Kiểm định ý nghĩa thống kê.
*   **Tác dụng:** **McNemar's Test** (khác biệt phân loại Config A vs F) + **Mann-Whitney U** (khác biệt độ trễ), đọc `ablation_results.json`.
*   **Mối quan hệ:** Chạy sau Ablation.

### 45. `experiments/evaluate_robustness.py`
*   **Mục đích:** Đo kháng adversarial của Guardrails **TĨNH** (120 mẫu / 5 nhóm).
*   **Tác dụng:** Bơm payload qua lớp tĩnh, tính **block rate / bypass rate** (đã sửa naming khỏi "defeat_rate" gây hiểu lầm); ghi `results/robustness_results.json`.
*   **Mối quan hệ:** Đọc `experiments/adversarial/`; output cho `plot_results`.

### 46. `experiments/evaluate_adversarial_pipeline.py`
*   **Mục đích:** Đo kháng của **FULL pipeline (Tier-2 LLM)** với payload KHÓ.
*   **Tác dụng:** Nhúng payload (semantic/jailbreak/rag-poison) vào flow tấn công thật, đẩy qua Tier-1→Guardrails→RAG→LLM; đếm RESISTED vs COMPROMISED (LLM bị ép ra LOG/DROP).
*   **Mối quan hệ:** Chứng minh `enforce_tier_consensus` đóng lỗ hổng social-engineering.

### 47. `experiments/evaluate_reasoning.py`
*   **Mục đích:** Đánh giá chất lượng suy luận (LLM-as-Judge cross-family).
*   **Tác dụng:** Hot-swap sang **Llama-3 8B (Meta)** chấm reasoning của **Gemma-2 (Google)** từ `ablation_results.json` → Context Precision/Answer Relevancy/Faithfulness/Context Recall/Audit Completeness (chuẩn RAGAS); đẩy MLflow.
*   **Mối quan hệ:** Cần `run_ablation_study` chạy trước (sinh reasoning_outputs); dùng `switch_model.sh`.

### 48. `experiments/evaluate_unified_stream.py`
*   **Mục đích:** Đánh giá luồng gộp THỐNG NHẤT (offline, tất định) — thay phương pháp 3 luồng circular cũ.
*   **Tác dụng:** `build_stream()` gộp CICIDS + DAPT2020 + **zero-day REAL-DERIVED (7 mẫu, nền flow benign thật, đẩy 1 feature cực trị, rải ngày 2-5)** vào MỘT luồng sắp theo thời gian (golden-ratio interleave), stream qua Tier-1 + Welford + Threat Memory **bộ nhớ sạch** → đo: phân loại, **APT EMERGENT** (recall + độ trễ), zero-day (Welford bắt khi static bỏ sót).
*   **Mối quan hệ:** Đọc `ground_truth.json` + `dapt2020_chains.jsonl`; output `results/unified_stream_results.json` + `reports/unified_stream_evaluation_report.md`.

### 49. `experiments/stream_unified_online.py`
*   **Mục đích:** Publisher ONLINE phát cùng luồng gộp qua TOÀN BỘ hệ thống (demo realtime).
*   **Tác dụng:** `build_sequence()` + `enrich()` (gắn metadata DAPT/zero-day) → đẩy Redis qua pipeline thật (Tier-1 → APT emergent ở subscriber → LLM Agent → Dashboard); có `--dry-run`. Chỉ event ESCALATE mới gọi LLM (đúng thiết kế SOC). *(Offline #48 = benchmark tất định; online #49 = chứng minh end-to-end.)*
*   **Mối quan hệ:** Dùng chung `build_stream()` với #48; cần Redis + `main.py --mode server`.

### 50. `experiments/measure_latency_baseline.py`
*   **Mục đích:** Đo độ trễ Two-Tier vs LLM-only.
*   **Tác dụng:** Chạy N log qua 2 cấu hình, đo Mean/Median/P95, tính **Latency Reduction** (mục tiêu ≥60%) — Tier-1 lọc ~99% nên không phải gọi LLM cho mọi log.
*   **Mối quan hệ:** Output `results/latency_benchmark.json`; bổ sung cho Mann-Whitney U.

### 51. `experiments/plot_results.py`
*   **Mục đích:** Trực quan hóa số liệu thực nghiệm.
*   **Tác dụng:** Vẽ biểu đồ block-rate theo nhóm + pie accuracy từ `robustness_results.json` → `results/plots/*.png`.
*   **Mối quan hệ:** Đọc result JSON cho luận văn.

### 52. `experiments/e2e_test_runner.py` *(Quan trọng kiểm thử)*
*   **Mục đích:** Bộ kiểm thử tích hợp E2E toàn hệ thống.
*   **Tác dụng:** Chạy **22 kịch bản** (T01-T22): RuleEngine, Guardrails, Dual-RAG, Threat Memory, Agent, Latency (T19, cần LLM), **Unified Stream (T21)** + **Online Publisher (T22)**; `--offline` bỏ qua test cần LLM.
*   **Mối quan hệ:** Chốt chặn toàn vẹn trước khi push/demo.

### 53. `scripts/seed_demo_data.py`
*   **Mục đích:** Seed Dashboard từ data THẬT (không bịa).
*   **Tác dụng:** Chạy pipeline thật (Tier-1 + Agent + LLM) trên mẫu CICIDS 14 lớp → quyết định thật vào audit/threat/pending-rules; `ingest_dapt_chains` 9 chuỗi APT; seed known entities. *(SEED dashboard, KHÔNG phải benchmark APT — benchmark ở #48.)*
*   **Mối quan hệ:** Đọc `ground_truth.json` + `dapt2020_chains.jsonl`; ghi DBs production.

### 54. `scripts/convert_report.py` & `scripts/switch_model.sh` & `scripts/cleanup.sh`
*   **convert_report.py:** Markdown → DOCX (báo cáo tiến độ).
*   **switch_model.sh:** Hot-swap LLM (`gemma`/`llama`), sửa `.env` + restart container `sentinel_llm`, chờ healthy.
*   **cleanup.sh:** Dọn artifact tạm (mlruns, `results/*.json`, plots, eval DB), GIỮ benchmark (ground_truth, adversarial).

---

## **TÍCH HỢP HỆ THỐNG GỐC (ROOT)**

### 55. `main.py`
*   **Mục đích:** Điểm khởi chạy tích hợp (entrypoint).
*   **Tác dụng:** `argparse` mode `server`/`scan`/`full`. Mode server: khởi động **Subscriber loop** (`start_listening(on_batch_ready=handle_escalated_batch)`) — Tier-1 lọc, escalate → LangGraph Agent → LLM → audit. Mode scan/full: chạy Trivy + build Neo4j KG. Reset LoopDetector mỗi cycle. *(KHÔNG tự chạy Streamlit — Dashboard chạy qua Docker `streamlit run src/ui/app.py`.)*
*   **Mối quan hệ:** Gọi `subscriber.start_listening`, `agent.agent_app`, `tier1_filter.scanner`, `rag.graph_builder`.

---

## **KIỂM THỬ (TESTS)**

> Bộ test đảm bảo tính toàn vẹn — `pytest 194 passed`, `E2E 22/22`.

*   **`tests/unit/`** — data_validator, decision_validator (+ Anti-Self-DoS shield + tier-consensus guard), feedback_validator, **feedback_listener** (HITL lifecycle), output_sanitizer, prompt_filter, rag_sanitizer, template_miner, entropy_scorer, threat_memory (+ APT-chain-context), **subscriber** (chống lộ nhãn dataset vào LLM + hợp đồng enrich↔strip), **semantic_cache**, **auth** (PBKDF2/RBAC), **executor** (HMAC chain, đã cô lập DB tạm), agent, rag.
*   **`tests/integration/`** — `test_unified_stream.py` (3 nguồn trộn + APT emergent + **bất biến zero-day real-derived**), `test_streaming_pipeline.py` (routing đa-nguồn), `test_end_to_end.py`.
*   **`tests/test_adversarial.py`** + **`tests/test_tier1_filter.py`** + **`tests/conftest.py`** (sys.path root).
