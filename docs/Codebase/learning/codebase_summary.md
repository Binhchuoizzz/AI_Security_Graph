# Tài liệu Tổng kết Cấu trúc Mã nguồn & Lộ trình Học tập (SENTINEL)

Tài liệu này tổng hợp **toàn bộ tệp mã nguồn** của hệ thống SENTINEL, phân bổ theo **Luồng dữ liệu (Dataflow)** và xếp theo **Lộ trình học tập 5 ngày**. Mỗi file phân tích rõ: **Mục đích → Tác dụng → Mối quan hệ** với các cấu phần khác. Đã đối chiếu sát với code ở HEAD (cập nhật 2026-06: luồng gộp online, zero-day real-derived, Anti-Self-DoS shield hẹp, raw-log counter thật, BLOCK_IP brute-force, FIREWALL MOCK; **bổ sung mới nhất:** quan sát ngữ cảnh `token_monitor` + seed tất định + suy biến an toàn ở Agent, và 7 experiment rigor: ablation B–E/cân bằng, độ nhạy ngưỡng, zero-day phân cấp, đối chứng âm APT, stress ngữ cảnh, độ bền LLM; và **Lớp ánh xạ MITRE ATT&CK có cấu trúc** — node thứ 6 `attack_mapper` sau triage, cổng theo ACTION, eval `scripts/eval_attack_mapper.py`).

> **Bản đồ luồng:** Dataset → **Tier-1** (RuleEngine + Welford) → **Guardrails** → **Dual-RAG** → **LangGraph Agent (LLM + ATT&CK Mapper)** → **Response/Audit** → **Dashboard HITL** → Feedback Loop về Tier-1.
> **Trạng thái kiểm thử:** `pytest 256 passed` (unit+tier1+adversarial; gồm 8 test Reputation-enforcement Tier-1), `E2E 22/22 PASSED`.
> **Hạ tầng & quan sát (deployment/observability):** docker-compose **5 dịch vụ** (llm · redis · mlflow · neo4j · agent_ui) — **tất cả có `healthcheck` + `restart: unless-stopped` + resource limits**; `agent_ui` khởi động chỉ khi redis/mlflow/llm đều `healthy` (`depends_on: service_healthy`). Quan sát: MLflow (metrics thí nghiệm) · `token_monitor`→`llm_token_stats.json` (ngân sách ngữ cảnh) · `subscriber`→`pipeline_stats.json` (Noise Reduction thật) · audit HMAC chain · logging 20 module. Dockerfile multi-stage non-root (`--no-install-recommends`) + Trivy self-scan; **mọi host-port bind `127.0.0.1`** (Zero-Trust — kể cả dashboard). CI/CD 2 workflow: `ci.yml` (ruff-lint + **pyright** type-check pinned + pytest đa-version **có coverage**) và `security.yml` (pip-audit CVE + trufflehog secrets + **hadolint** Dockerfile-lint + **Trivy IaC misconfig**→SARIF lên tab Security). Chi tiết vận hành: [RUN_PROJECT.md](guides/RUN_PROJECT.md).
>
> **📚 Lộ trình học chi tiết theo từng hàm (5 ngày):** [DAY1](learning/DAY1.md) Tier-1 & Streaming · [DAY2](learning/DAY2.md) Guardrails · [DAY3](learning/DAY3.md) Dual-RAG & Knowledge Graph · [DAY4](learning/DAY4.md) LangGraph Agent + Response/Audit · [DAY5](learning/DAY5.md) SOC UI + Khung đánh giá 5D. Mỗi file có "💡 Sơ đồ 1 phút" để hình dung nhanh trước khi đọc sâu.
> **🚀 Lộ trình mở rộng quy mô (Scalability Roadmap):** đã viết vào `docs/latex/thesis_latex{,_vi}/chapters/ch5_conclusion.tex` (mục *Horizontal Scalability Roadmap* / *Lộ trình Mở rộng Quy mô theo Chiều ngang*) — 5 trục: shard Tier-1 bằng **consistent hashing** theo Source IP, **Redis Cluster/Kafka** phân mảnh, **idempotency** cho at-least-once, **cụm worker LLM co giãn**, **KV store nhân bản** (quorum W+R>N) + LB + rate limiter. Đối chiếu trực tiếp với *System Design Interview* (Ch1/4/5/6/10/14).

---

## **LUỒNG XỬ LÝ ĐẦU-CUỐI (END-TO-END FLOW) — đọc trước để nắm "từng quá trình một"**

Phần này mô tả ĐÚNG đường đi của **một bản ghi log** qua hệ thống (online runtime), và đường đi **offline benchmark** — kèm file/hàm chính xác ở mỗi bước. Số trong ngoặc `(#n)` trỏ tới mục chi tiết bên dưới.

### A. LUỒNG ONLINE THỜI GIAN THỰC (production/demo realtime)

1. **Thu nhận (Ingestion):** một nguồn đẩy log JSON vào **Redis Stream** (`xadd`) trên queue `queue_firewall`/`queue_waf`/`queue_sysmon`. Có **4 nguồn**: `publisher.py` (#6, raw CSV load-test), `simulate_traffic.py` (#7, replay ground_truth), `stream_unified_online.py` (#53, luồng gộp online), `live_log_collector.py` (#8, **bắt log THẬT** từ `/var/log/auth.log` + decoy WAF).
2. **Tiêu thụ (Subscriber):** `subscriber.py` (#9) đọc qua consumer group `sentinel_group` (`xreadgroup`), gọi `RuleEngine.evaluate(log)`.
3. **Tier-1 quyết định** (`rule_engine.py` #10): trả `tier1_action` → định tuyến:
   - `DROP`/`LOG` (benign) → đếm vào `pipeline_stats.json`, KHÔNG leo thang.
   - `BLOCK_IP` → blacklist ngay. *(Reputation ≥70 ÉP `BLOCK_IP` dù gói lành — kẻ tái phạm bị chặn không cần LLM.)*
   - `AWAIT_HITL` → `queue_hitl`. *(Reputation 50–69 ÉP `AWAIT_HITL`.)*
   - `ALERT` → `queue_decisions`.
   - `ESCALATE` → gom batch gọi Agent. *(APT emergent: `record_apt_event`+`check_apt_chain` có thể ÉP `ESCALATE`.)*
4. **Agent (LangGraph)** — batch escalate → `agent_app.invoke(SentinelState)` (`workflow.py` #34). Đồ thị **6 node**: `guardrails → rag_context → llm_triage →` (rẽ nhánh `route_after_triage`) `attack_mapper` (nếu là threat verdict) `→ action_executor` / `human_in_the_loop`; hoặc thẳng `END` (benign `LOG`).
5. **node_guardrails** (#35): `GuardrailsPipeline` nén Drain (#15) + đóng gói nonce (#16).
6. **node_rag_context** (#35): `DualRetriever._hybrid_search` (FAISS+BM25+RRF, #30) + `threat_memory.get_context_for_prompt` (lịch sử APT, #39).
7. **node_llm_triage** (#35): `build_triage_prompt` (#36) → `llm_client.invoke` (Gemma, seed=42, `token_monitor` preflight/record #38) → parse → `DecisionValidator.validate_decision` + `enforce_tier_consensus` (#21) → ghi `AuditLogger`. *(LLM chết → suy biến `AWAIT_HITL`.)*
8. **Cổng `route_after_triage`**: nếu action ∈ {`BLOCK_IP`,`ALERT`,`AWAIT_HITL`} → **node_attack_mapper** (`agent/attack_mapper.py`): NEO vào technique-id triage đã gán → cấu trúc hóa thành bản ghi MITRE (tactic/technique/sub-technique/URL/`mapping_confidence`/`recommended_response`); web-attack phổ biến tra `WEB_ATTACK_MAP` (tất định, không LLM), còn lại RRF + LLM-select (graceful). Benign `LOG` → bỏ qua mapper.
9. **Rẽ nhánh** (`route_triage_decision`, sau mapper): `execute_action` → **node_action_executor** (#35): `block_ip()` (FIREWALL MOCK #40) + `FeedbackListener.receive_new_rule()` PENDING (#11) + `threat_memory.record_incident` (#39) + audit HMAC. `await_hitl` → **node_human_in_the_loop** (#35) → hàng đợi analyst. `end_cycle` → kết thúc.
10. **Audit** (`executor.py` #40): ghi `audit_trail.db` chuỗi HMAC-SHA256 (chống giả mạo).
11. **Dashboard** (`app.py` #41): đọc `audit_trail.db`/`threat_memory.db`/`pipeline_stats.json`/`llm_token_stats.json`; analyst Duyệt luật → `approve_rule` persist `system_settings.yaml` → **RuleEngine hot-reload** → Tier-1 enforce IP đó ở lần sau ⇒ **VÒNG PHẢN HỒI khép kín** (#11).

### B. LUỒNG OFFLINE BENCHMARK (đánh giá tất định, không cần Redis)

`evaluate_unified_stream.build_stream()` (#52) gộp **CICIDS + DAPT2020 + zero-day real-derived** thành MỘT luồng sắp theo thời gian → chạy qua `RuleEngine` + Welford + `ThreatMemoryStore` **bộ nhớ SẠCH** → đo phân loại + APT emergent + zero-day. Các script rigor (#54–#57) và ablation (#46–#47) **tái dùng** `build_stream`/`map_cicids`/`_is_threat` để đo trên cùng dữ liệu thật.

> **Tóm tắt 2 trục:** Online (A) = chứng minh end-to-end + demo; Offline (B) = benchmark tất định cho luận văn. Cả hai dùng CHUNG Tier-1/Guardrails/RAG/Memory — chỉ khác nguồn đẩy và việc có gọi LLM hay không.

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
*   **Tác dụng:** Đọc CSV **CHUNKED** (chunksize=500, file hàng triệu dòng không nạp hết RAM), chuẩn hóa cột + sinh IP xác định (`_inject_ips`), đẩy từng flow JSON vào **Redis Stream** `xadd` (maxlen chống OOM) với backpressure. *(1 trong **4 NGUỒN ĐẦU VÀO**: file này = raw load-test; `simulate_traffic.py` (#7) = replay ground_truth; `stream_unified_online.py` (#53) = luồng gộp online; `live_log_collector.py` (#8) = **bắt log THẬT** live từ OS/decoy WAF.)*
*   **Mối quan hệ:** Đẩy vào `queue_waf`; subscriber (#9) tiêu thụ qua consumer group.

### 7. `scripts/simulate_traffic.py`
*   **Mục đích:** Replay `ground_truth.json` (4267 mẫu có nhãn) lên Redis cho demo/ablation.
*   **Tác dụng:** Multi-source routing (`determine_queue`: port → queue_firewall/queue_waf), `map_to_cicids` ánh xạ network_layer → schema RuleEngine, kèm metadata ground-truth (`gt_id`...).
*   **Mối quan hệ:** Đọc `ground_truth.json`, đẩy 3 queue; subscriber tiêu thụ.

### 8. `scripts/live_log_collector.py`
*   **Mục đích:** Bắt log THẬT từ máy chủ (live capture) đẩy vào Redis cho demo pentest trực tiếp (Kali) — nguồn đầu vào THẬT thứ tư (khác 3 publisher benchmark/demo).
*   **Tác dụng:** `follow_file()` tail realtime `/var/log/auth.log`, `parse_ssh_line()` bắt SSH login fail (cả **password** lẫn **publickey**) → `push_to_redis('queue_firewall')`; chạy **decoy WAF HTTP server** (`DecoyWAFHandler`, cổng 8000) bắt request lạ → `push_to_redis('queue_waf')`. `xadd` maxlen=10000.
*   **Mối quan hệ:** Đẩy vào `queue_firewall`/`queue_waf`; subscriber (#9) tiêu thụ như mọi publisher khác. Dùng trong `docs/guides/KALI_PENTEST_DEMO.md`.

### 9. `src/streaming/subscriber.py`
*   **Mục đích:** Lắng nghe & gom batch logs từ Redis cho Tier-1/Tier-2; ghi chuỗi APT emergent; đếm số liệu thật.
*   **Tác dụng:** Consumer group `sentinel_group` trên các Redis Stream (`queue_firewall`/`queue_waf`/`queue_sysmon`) qua `xreadgroup`; mỗi log → `RuleEngine.evaluate` → định tuyến theo `tier1_action`: `ESCALATE` → batch gọi Agent; `BLOCK_IP` → blacklist; `AWAIT_HITL` → `queue_hitl`; `ALERT/LOG` → `queue_decisions`; **`WHITELIST_DROP`** → cho qua + ghi audit `WHITELIST` (qua `_log_to_db`, `ALLOWED_ACTIONS` có `WHITELIST`) cho UI hiện thẻ riêng. **APT EMERGENT (online):** message mang metadata DAPT (`apt_phase`/`apt_day`/`apt_is_attack` từ `stream_unified_online.py`) → `record_apt_event` rồi `check_apt_chain`; bản án bật (đủ đa-ngày) → ép `ESCALATE`. **Số liệu THẬT:** đếm log thô qua Tier-1 + số bị DROP → ghi `config/pipeline_stats.json` (atomic, chia sẻ qua volume) cho Dashboard tính Noise Reduction thật (KHÔNG dùng Redis vì container Dashboard không reach được redis).
*   **Mối quan hệ:** Gọi `rule_engine.py` (Tier-1), `agent/threat_memory.py` (APT), `agent/workflow.py` (Tier-2 khi escalate).

### 10. `src/tier1_filter/rule_engine.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Màng lọc heuristics tốc độ cao + phát hiện dị biệt thống kê phi giám sát trực tuyến.
*   **Tác dụng:**
    *   `RunningStats`: thuật toán **Welford** cập nhật Mean/StdDev trực tuyến, $O(1)$ RAM/CPU.
    *   `SessionBaseline`: IP profiles, phát hiện **port scan** (>10 cổng non-HTTP), tần suất/dung lượng bất thường; eviction TTL chống OOM.
    *   `evaluate()` theo tầng: Whitelist → **WAF signature** (SQLi/XSS/Path/Cmd-Inj) → **Injection/Jailbreak signature** → **Z-Score anomaly** (warmup 100 mẫu sạch, lệch > `z_threshold`σ (tham số, mặc định 3.5) → zero-day) → Static rules (cổng nhạy cảm, volumetric) → **Dynamic rules (status `ACTIVE`)** → Session baseline → **Reputation enforcement (Tầng 3.5)** → action (WHITELIST_DROP/DROP/LOG/ALERT/BLOCK_IP/AWAIT_HITL/ESCALATE).
    *   **Whitelist (Tầng 0):** IP whitelist → action `WHITELIST_DROP` + cờ `is_whitelisted` (thay vì DROP thầm lặng) → vẫn CHO QUA (đếm noise như DROP, KHÔNG feed baseline) nhưng subscriber ghi 1 bản audit `WHITELIST` riêng để UI hiện **thẻ Whitelist xanh** (không MITRE/suy luận tấn công). Whitelist thắng cả reputation ≥70 lẫn payload tấn công.
    *   **Reputation enforcement (`_get_reputation_score`, cache TTL):** tra điểm danh tiếng IP từ Threat Memory; **≥ `reputation_block_threshold`** (mặc định 70) → `BLOCK_IP`; **≥ `reputation_hitl_threshold`** (mặc định 50) → `AWAIT_HITL` — **độc lập điểm gói** (kẻ đã bị chứng minh xấu bị chặn/HITL dù gói hiện tại lành), KHÔNG hạ cấp tín hiệu mạnh hơn, miễn trừ Whitelist, KHÔNG tốn LLM. Tắt/chỉnh qua `tier1.reputation_*` (hot-reload). Cache RAM giữ Tier-1 ở tốc độ cao (tránh SELECT SQLite mỗi log).
    *   **Chống Baseline Poisoning:** chỉ nạp flow benign (DROP/LOG) vào `global_stats`. **Hot-reload** config mỗi 5s.
    *   `z_threshold` được tham số hóa (đọc `tier1.z_threshold`, mặc định 3.5) để `run_threshold_sensitivity.py` quét độ nhạy mà KHÔNG đổi hành vi production.
*   **Mối quan hệ:** Nhận logs từ `subscriber.py`; đọc/hot-reload `system_settings.yaml`; trả quyết định Tier-1. Luật ACTIVE (do HITL duyệt) được enforce ở đây bằng **substring match** `pattern in log[field]` — bao gồm cả luật HÀNH VI (`User-Agent`/`URI`), nên IP MỚI dùng cùng chữ ký kỹ thuật cũng bị CỜ. `_KEY_ALIASES` nay chuẩn hoá cả `user_agent`→`User-Agent`, `uri`→`URI` (đồng bộ Guardrails G1) để luật khớp bất kể log nguồn viết hoa/thường.

### 11. `src/tier1_filter/feedback_listener.py`
*   **Mục đích:** Vòng phản hồi đồng bộ rule động UI/Agent ↔ Tier-1.
*   **Tác dụng:** Nhận rule mới (`receive_new_rule` qua `FeedbackValidator`), persist `system_settings.yaml` bằng **atomic write** (`mkstemp`+`chmod 0666`+`os.replace`) + `FileLock`. **Cross-UID Docker:** Dashboard (container uid 999) VÀ subscriber/reset (host uid 1000) luân phiên GHI chung file mount `config/` → phải `chmod 0666` (nếu 0644 thì chỉ owner ghi được, bên kia Permission denied — từng khiến `reset_all` không xoá nổi luật động). `_ensure_lock_writable()` xoá+tạo lại file `.lock` 0666 nếu bị UID khác chiếm. Rule có thể theo **IP** (`Source IP`) HOẶC theo **HÀNH VI** (`URI`/`User-Agent`). Vòng đời `PENDING_APPROVAL → ACTIVE/REJECTED` (HITL); `approve_rule`/`reject_rule`/`get_pending_rules`/`get_active_dynamic_rules`; `clear_all_dynamic_rules` **trả bool**; whitelist; clamp score `[0,100]`.
*   **Mối quan hệ:** Gọi bởi `node_action_executor` (Agent khi BLOCK_IP) và Dashboard (nút Duyệt); RuleEngine hot-reload rule ACTIVE.

### 12. `src/tier1_filter/scanner.py`
*   **Mục đích:** Quét lỗ hổng phụ thuộc (SCA) bằng Trivy (DevSecOps tự-bảo-vệ).
*   **Tác dụng:** `VulnerabilityScanner` chạy `trivy fs` (list-form, không shell), xuất `data/trivy-results.json` nạp vào Knowledge Graph. KHÔNG tương tác runtime pipeline.
*   **Mối quan hệ:** Chạy độc lập (main.py mode scan/full); output cho `graph_builder.py`.

### 13. `demos/demo_tier1.py`
*   **Mục đích:** Demo chạy riêng Tier-1.
*   **Tác dụng:** CLI minh họa các action (DROP/BLOCK_IP/ALERT/ESCALATE/AWAIT_HITL) + Welford Z-Score zero-day; xử lý đúng rule động.
*   **Mối quan hệ:** Gọi trực tiếp `rule_engine.py`.

---

## **NGÀY 2: TẦNG AN TOÀN & NÉN DỮ LIỆU (GUARDRAILS)**

### 14. `src/guardrails/constants.py`
*   **Mục đích:** Tập trung ánh xạ tên trường log giữa các tầng.
*   **Tác dụng:** `KEY_ALIASES` + `normalize_log_keys()` chuyển biến thể (`src_ip`/`dst_port`/`user_agent`...) → chuẩn (`Source IP`/`Destination Port`/`User-Agent`...).
*   **Mối quan hệ:** Dùng bởi `data_validator`, `feedback_validator`, `template_miner`, `prompt_filter`.

### 15. `src/guardrails/template_miner.py`
*   **Mục đích:** Nén volume logs + quản lý token đầu vào LLM.
*   **Tác dụng:** `LogTemplateMiner` (drain3) gom logs cùng cấu trúc thành Template+count; `EntropyScorer` (Shannon entropy) ưu tiên log bất thường; `TokenBudgetManager` ước lượng token (`len//4`) cắt theo `token_budget` config.
*   **Mối quan hệ:** Nhận logs escalate từ Tier-1, nén & chuyển `prompt_filter.py`. Cũng được `run_context_stress.py` dùng để chứng minh nén ngữ cảnh bão hòa.

### 16. `src/guardrails/prompt_filter.py`
*   **Mục đích:** Phòng thủ Prompt Injection nhiều lớp trước khi log vào LLM.
*   **Tác dụng:** `PromptInjectionDetector`/`JailbreakDetector` (regex + role-play, isolation `HIGH`/`CRITICAL`); `EncodingNeutralizer` (NFKC + giải base64/base32/ROT13/URL/hex + fold homoglyph/leetspeak + strip zero-width/HTML, có guard chống false-positive); `DelimitedDataEncapsulator` (**nonce `secrets.token_hex(8)`**, strip delimiter smuggling, chỉ giữ `ALLOWED_FIELDS`); `GuardrailsPipeline` orchestrate `process()`/`process_batch()`.
*   **Mối quan hệ:** Nhận log đã nén; đóng gói an toàn trước prompt Agent.

### 17. `src/guardrails/output_sanitizer.py`
*   **Mục đích:** Làm sạch ĐẦU RA LLM (chống Data Exfiltration/XSS/Markdown).
*   **Tác dụng:** Singleton `output_sanitizer`: strip zero-width/ANSI; thay pattern nguy hiểm (markdown image/link, `<script>/<img>/<iframe>/<svg>`, data URI) bằng placeholder; quét **base64/hex obfuscation sâu**.
*   **Mối quan hệ:** Dùng bởi `decision_validator`, `threat_memory`, `nodes` (double-sanitize) trước khi hiển thị/ghi DB.

### 18. `src/guardrails/data_validator.py`
*   **Mục đích:** Xác thực schema log đầu vào (chống Schema Abuse).
*   **Tác dụng:** Chuẩn hóa key, ép kiểu an toàn, kiểm IP (`ipaddress`), port `[0,65535]`, protocol `[0,255]`; gắn `_is_valid`/`_validation_errors`; batch `filter_invalid`/`raise_on_error`.
*   **Mối quan hệ:** Chốt định dạng đầu vào cho Guardrail Layer.

### 19. `src/guardrails/state_monitor.py`
*   **Mục đích:** Giám sát runtime: audit, chống vòng lặp vô hạn, kiểm soát context.
*   **Tác dụng:** `AuditLogger` ghi SQLite an toàn (`threading.Lock`); `LoopDetector` (`FORCE_STOP` khi vượt, `reset()`); `ContextOverflowGuard` (ngân sách token). Singletons `loop_detector`/`audit_logger`/`context_overflow_guard`.
*   **Mối quan hệ:** Ghi audit & giám sát các Node LangGraph.

### 20. `src/guardrails/rag_sanitizer.py`
*   **Mục đích:** Chống RAG Poisoning & Semantic Cache Poisoning.
*   **Tác dụng:** `sanitize_ingest` (NFKC, strip control/zero-width/HTML/markdown, truncate); `sanitize_retrieve` (strip delimiter, trung hòa injection); `sanitize_cache_entry` (làm sạch cache-hit path).
*   **Mối quan hệ:** Tích hợp vào `rag/retriever.py` và `rag/security.py`.

### 21. `src/guardrails/decision_validator.py`
*   **Mục đích:** Thẩm định quyết định LLM (chống Hallucination/Self-DoS/Social-Engineering).
*   **Tác dụng:** Ép Action Enum hợp lệ; **Confidence Gate** (BLOCK_IP cần ≥0.5); **Anti-Self-DoS Shield** hạ BLOCK_IP→ALERT **chỉ** khi target ∈ **`critical_infrastructure_subnets`** (HẸP: loopback + hạ tầng cụ thể, parse hex/octal/integer chống bypass) — **KHÔNG** dùng toàn RFC1918 (nếu rộng → không chặn được attacker nội bộ/lateral, vá 2026-06); sanitize reasoning/mitre/nist. **`enforce_tier_consensus`**: nếu Tier-1 coi là tấn công nhưng LLM hạ xuống LOG/DROP → KHÔNG tin LLM, ép `AWAIT_HITL`.
*   **Mối quan hệ:** Gọi bởi `node_llm_triage` trước khi thực thi quyết định.

### 22. `src/guardrails/feedback_validator.py`
*   **Mục đích:** Zero-Trust cho rule động & whitelist đẩy về Tier-1.
*   **Tác dụng:** Chặn wildcard (`0.0.0.0/0`, `*`, `any`), CIDR ≥ `/8`, cấm chặn IP hạ tầng (`127.0.0.1`/`10.0.0.99`); validate regex URI/User-Agent. **`validate_whitelist_ip`**: analyst được whitelist **MỌI HOST cụ thể** (bất kỳ dải — nội bộ, TEST-NET, hay public như DAPT — phục vụ mọi luồng demo/vận hành); CHỈ CẤM wildcard toàn Internet + dải CIDR quá rộng (`< /16`). Trả `(ok, errors)` → UI `app.py` TÔN TRỌNG return (không báo giả; whitelist TRƯỚC, chỉ gỡ block nếu whitelist thành công).
*   **Mối quan hệ:** Dùng bởi `FeedbackListener` kiểm duyệt rule.

### 23. `scripts/build_adversarial_suite.py`
*   **Mục đích:** Sinh bộ adversarial mở rộng (120 mẫu / 5 nhóm) theo OWASP LLM Top 10.
*   **Tác dụng:** Sinh `encoding_bypass`(45)/`structural_attacks`(20)/`semantic_confusion`(20)/`jailbreak`(20)/`rag_poisoning`(15) ra `experiments/adversarial/{cat}/samples.json`.
*   **Mối quan hệ:** Đầu vào cho `evaluate_adversarial.py --mode static` và `--mode pipeline`.

### 24. `demos/demo_guardrails.py`
*   **Mục đích:** Demo tích hợp Guardrails.
*   **Tác dụng:** Trực quan hóa các lớp: injection/jailbreak, nonce delimiter, encoding neutralize, RAG sanitize, decision/feedback validate, output sanitize.
*   **Mối quan hệ:** Gọi trực tiếp `src/guardrails/`.

---

## **NGÀY 3: TẦNG TRUY XUẤT TRI THỨC KÉP (DUAL-RAG) & ĐỒ THỊ TRI THỨC**

### 25. `src/rag/embedder.py`
*   **Mục đích:** Xây Vector Index (FAISS & BM25) + cập nhật checksum.
*   **Tác dụng:** Chunk MITRE/NIST (~256 token), `RAGSanitizer.sanitize_ingest()`, `SentenceTransformer('all-MiniLM-L6-v2')` → vector 384 chiều; ghi SHA-256 vào `checksums.sha256`. `verify_document_integrity(exclude_generated=True)` ở đầu build.
*   **Mối quan hệ:** Đọc `knowledge_base/`, ghi `knowledge_base/faiss_index/`.

### 26. `scripts/build_rag_indexes.py`
*   **Mục đích:** CLI wrapper xây chỉ mục RAG.
*   **Tác dụng:** Set PYTHONPATH, gọi `build_all_indexes()`.
*   **Mối quan hệ:** Gọi `src/rag/embedder.py`.

### 27. `scripts/build_knowledge_base.py` (TỰ-CHỨA, single file)
*   **Mục đích:** **Entry point DUY NHẤT** xây dựng/mở rộng tri thức RAG trong MỘT lần.
*   **Tác dụng:** Inline trực tiếp data → append idempotent **67 kỹ thuật MITRE (0 trùng id) + 7 playbook NIST** (phủ đủ 14 tactic) vào `mitre_attack.json`/`nist_800_61r2.json`, RỒI tự rebuild FAISS/BM25 index + checksum (cờ `--no-index` để bỏ qua). Hai file `expand_knowledge_base.py` + `supplement_knowledge_base.py` cũ **đã xóa** — toàn bộ `ALL_MITRE`/`ALL_NIST` nay nằm gọn trong file này (1 source of truth thật sự).
*   **Mối quan hệ:** Đọc data inline → gọi `embedder.build_all_indexes()` + `update_checksums_file()`.

### 28. `src/rag/security.py`
*   **Mục đích:** Lá chắn toàn vẹn tri thức RAG (chống RAG Poisoning vật lý).
*   **Tác dụng:** `verify_document_integrity()` so SHA-256 file KB/index với `checksums.sha256`, sai khác → ngắt (fail-closed); `log_tokenizer()` giữ CVE/IP; `add_provenance()` gắn tag `[VERIFIED: SENTINEL_KB]`.
*   **Mối quan hệ:** Gọi bởi `embedder.py` và `retriever.py` (chạy TRƯỚC `pickle.load` BM25 → chặn CWE-502).

### 29. `src/rag/semantic_cache.py`
*   **Mục đích:** Giảm độ trễ truy xuất bằng bộ đệm ngữ nghĩa.
*   **Tác dụng:** LRU Cache (`OrderedDict`) khóa SHA-256 query template; `max_size=500`, `ttl_seconds=1800`; thống kê hit/miss/eviction cho MLflow.
*   **Mối quan hệ:** Tích hợp trong `retriever.py` (bỏ qua embed/search log trùng template).

### 30. `src/rag/retriever.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Truy xuất tri thức an toàn (Hybrid Search & Cache Defense).
*   **Tác dụng:** Kiểm checksum ở init (raise nếu fail); tra `SemanticCache` (cache hit qua `sanitize_cache_entry`); `_hybrid_search()`: Dense (FAISS IndexFlatIP) + Sparse (BM25Okapi) hợp nhất bằng **RRF (k=60)**, lọc `MIN_SCORE_THRESHOLD=0.15`, `sanitize_retrieve` + provenance.
*   **Mối quan hệ:** Gọi bởi `node_rag_context` (Agent); trả `combined_prompt`.

### 31. `src/rag/graph_builder.py`
*   **Mục đích:** Đồ thị tri thức lỗ hổng (Knowledge Graph, V2 tùy chọn).
*   **Tác dụng:** Driver Neo4j (Bolt) đọc `data/trivy-results.json`, tạo node `Component`/`SubComponent`/`Vulnerability` + quan hệ `CONTAINS`/`HAS_VULNERABILITY`; mock JSON nếu Neo4j offline.
*   **Mối quan hệ:** Nạp kết quả `scanner.py` vào Neo4j; hiển thị tab Graph trên Dashboard.

### 32. `demos/demo_rag.py`
*   **Mục đích:** Demo CLI RAG layer.
*   **Tác dụng:** Tìm kiếm lai + trực quan hóa ngữ cảnh MITRE/NIST cho 1 truy vấn log mẫu.
*   **Mối quan hệ:** Gọi trực tiếp `retriever.py`.

---

## **NGÀY 4: CỖ MÁY TRẠNG THÁI LANGGRAPH & PHẢN HỒI AN NINH**

### 33. `src/agent/state.py`
*   **Mục đích:** Schema bộ nhớ trạng thái của tác tử LangGraph.
*   **Tác dụng:** `SentinelState` (**`@dataclass`**, không phải TypedDict): `current_batch_logs`, `current_batch_encapsulated`, `rag_mitre_context`/`rag_nist_context`, `decisions`, `narrative_summary`, `cycle_count`, IOCs, `hitl_status`... Kèm 2 dataclass: **`IOCEntry`** (ioc_type/value/severity/source_template — LLM chỉ APPEND, chống Semantic Drift) và **`AgentDecision`** (action/target/confidence/reasoning/mitre_technique/nist_control/hitl_status **+ các trường MITRE có cấu trúc do `node_attack_mapper` bồi đắp:** `mitre_tactic`/`mitre_tactic_id`/`mitre_technique_id`/`mitre_subtechnique(_id)`/`mitre_url`/`mapping_confidence`/`mapping_status`/`recommended_response`; `to_dict()` + `add_decision(**mitre_mapping)` mở rộng tương ứng).
*   **Mối quan hệ:** Import bởi toàn bộ `src/agent/`.

### 34. `src/agent/workflow.py`
*   **Mục đích:** Định nghĩa đồ thị nhận thức của tác tử.
*   **Tác dụng:** Khởi tạo `StateGraph` với **6 node** (`guardrails`/`rag_context`/`llm_triage`/`attack_mapper`/`action_executor`/`human_in_the_loop`); entry=`guardrails`; edge thẳng `guardrails → rag_context → llm_triage`; **conditional edge `route_after_triage`** từ `llm_triage`: nếu action ∈ {`BLOCK_IP`,`ALERT`,`AWAIT_HITL`} → `attack_mapper` (làm giàu MITRE), ngược lại (LOG/benign) định tuyến thẳng theo action; **conditional edge `route_triage_decision`** từ `attack_mapper` → `execute_action`(→action_executor) / `await_hitl`(→human_in_the_loop) / `end_cycle`(→END); `action_executor`→END, `human_in_the_loop`→END. Compile `agent_app` (singleton). *(Cổng theo ACTION, KHÔNG theo confidence — đo thực tế cho thấy triage gán ALERT@0.6-0.7 nên ngưỡng `>0.7` cũ lọc mất gần hết verdict.)*
*   **Mối quan hệ:** Import node từ `nodes.py` (gồm `route_after_triage`); `agent_app` được `subscriber`/`main.py`/eval gọi.

### 35. `src/agent/nodes.py` *(Cực kỳ quan trọng)*
*   **Mục đích:** Logic xử lý tại các "Trạm" của đồ thị.
*   **Tác dụng:**
    *   `node_guardrails`: chạy `GuardrailsPipeline` (nén + đóng gói nonce).
    *   `node_rag_context`: query RAG từ metadata flow thật + inject lịch sử Threat Memory (`get_context_for_prompt`, gồm **chuỗi APT đa-ngày**).
    *   `node_llm_triage`: build prompt + gọi LLM; **suy biến an toàn** (bọc `try/except`: nếu LLM cục bộ chết → log lỗi, đặt response rỗng → đồ thị KHÔNG vỡ, đẩy về `AWAIT_HITL`; Tier-1 vẫn bảo vệ độc lập); `DecisionValidator.validate_decision` + **`enforce_tier_consensus`** (lá chắn social-engineering) + `AuditLogger`. Sau khi validate, **ghi `threat_memory.record_incident`** (reputation + MITRE) cho action ∈ {BLOCK_IP, ALERT, AWAIT_HITL} + `check_apt_pattern`/`check_apt_chain`. *(record_incident nằm ở ĐÂY — node_llm_triage — không phải ở action_executor.)*
    *   **`route_after_triage` (cổng theo ACTION)**: threat verdict (`BLOCK_IP`/`ALERT`/`AWAIT_HITL`) → `node_attack_mapper`; benign `LOG` → route thẳng theo action.
    *   `node_attack_mapper`: NEO vào technique-id mà triage đã gán → cấu trúc hóa bản ghi MITRE qua `map_attack` (web-attack phổ biến tra `WEB_ATTACK_MAP` tất định, không LLM; còn lại RRF top-3 + LLM-select, graceful); bồi đắp `mitre_tactic`/`mitre_technique_id`/`mitre_url`/`mapping_confidence`/`mapping_status`/`recommended_response` vào quyết định. *(Logic chi tiết ở mục 35b.)*
    *   `node_action_executor`: thực thi action; **`BLOCK_IP`** → `block_ip()` (audit HMAC, MOCK) **VÀ** sinh **HAI** luật PENDING cho HITL qua `FeedbackListener.receive_new_rule()`: **(1) luật theo IP** (`Source IP`, score 100 — "nhớ mặt") và **(2) luật HÀNH VI** (`_derive_behavioral_rule` trích chữ ký công cụ trên `User-Agent` (sqlmap/nikto/nmap...) hoặc token tấn công trên `URI`, score 50 — "nhớ NGÓN ĐÒN" để Tier-1 bắt IP MỚI cùng kỹ thuật; suy biến nhẹ: không có chữ ký an toàn → chỉ giữ luật IP). `LoopDetector` chống vô hạn. *(record_incident KHÔNG ở đây — nó ở node_llm_triage.)*
    *   `node_human_in_the_loop`: nhánh `AWAIT_HITL` — đẩy quyết định mập mờ/bị Consensus-Guard ép xuống vào hàng đợi chờ analyst duyệt (không tự thực thi), rồi kết thúc cycle.
*   **Mối quan hệ:** Gọi `DualRetriever`, `llm_client`, `threat_memory`, `executor`, `feedback_listener`.

### 35b. `src/agent/attack_mapper.py` *(MỚI — Lớp ánh xạ MITRE ATT&CK có cấu trúc)*
*   **Mục đích:** Biến `mitre_technique` dạng văn bản tự do của triage thành bản ghi MITRE ATT&CK CÓ CẤU TRÚC, kiểm chứng được (Pydantic) — tactic/technique/sub-technique/URL/`mapping_confidence`/`recommended_response`.
*   **Tác dụng:** Models Pydantic `AttackMapperInput`/`MitreMapping` (schema LUÔN hợp lệ). `map_attack()` 3 đường: (1) **curated** — web-attack phổ biến tra `WEB_ATTACK_MAP` (10 lớp: SQLi→T1190, XSS→T1059.007, cmd-inj→T1059, prompt-inj→ATLAS `AML.T0051`...) tất định, KHÔNG LLM; (2) **anchor** — neo vào technique-id hợp lệ triage đã sinh (`_from_triage_anchor`); (3) **RRF** — `_from_rrf` lấy top-3 từ KB (tái dùng `DualRetriever`, RRF k=60) + `_llm_select` (graceful, fallback top-RRF nếu LLM chết). Fallback "C + cờ": luôn ghi structured + `mapping_status` ∈ {`resolved`,`low_confidence`}. `recommended_response` rule-based theo tactic. `build_mitre_url`/`normalize_tactic` (chuẩn hóa nhãn KB phi-chuẩn "Stealth"→Defense Evasion); keyword match dùng **word-boundary** (tránh dương-tính-giả "rce"⊂"force"). TRUNG THỰC: prompt-injection gắn cờ ATLAS (không Enterprise), IDOR không có technique riêng → T1190 confidence thấp.
*   **Mối quan hệ:** Gọi bởi `node_attack_mapper` (#35, tái dùng `retriever`+`llm_client` singleton); KB = `knowledge_base/mitre_attack.json` (299 kỹ thuật); đo bằng `scripts/eval_attack_mapper.py`; test `tests/unit/test_attack_mapper.py` (35 test, không cần LLM).

### 36. `src/agent/prompts.py`
*   **Mục đích:** Kho mẫu Prompt (System & User).
*   **Tác dụng:** System prompt có **rule #7 chống social-engineering** (bỏ qua tuyên bố thẩm quyền/whitelist trong log) + **Decision Matrix** (BLOCK_IP cho brute-force/scan rõ ràng từ IP ngoài whitelist trên cổng nhạy cảm SSH/FTP/RDP/SMB; ALERT cho DoS/DDoS spoofed). Tiêm few-shot Active Learning (rule analyst đã Approve/Reject).
*   **Mối quan hệ:** Gọi bởi `node_llm_triage`.

### 37. `src/agent/llm_client.py`
*   **Mục đích:** API client tới LLM cục bộ (offline).
*   **Tác dụng:** HTTP POST chuẩn OpenAI → `llama.cpp` server (Gemma-2-9B-IT), `temperature=0.1` ép JSON sạch; `parse_llm_response` (bóc JSON an toàn); `DEFAULT_MODEL` từ env (hỗ trợ hot-swap Llama-3 trọng tài); **seed cố định** (config `llm.seed=42`) → cùng prompt + temp thấp cho output TẤT ĐỊNH (tái lập); retry + exponential backoff. Tích hợp **`token_monitor`**: `preflight_check` (cảnh báo TRƯỚC khi prompt sát trần ngữ cảnh) + `record_usage` (ghi token THẬT server trả về sau mỗi call). `MOCK_LLM=1` trả JSON cố định cho test offline.
*   **Mối quan hệ:** Gọi bởi `node_llm_triage` và `evaluate_reasoning.py`; gọi `token_monitor` mỗi lần invoke.

### 38. `src/agent/token_monitor.py` *(MỚI — Quan sát ngân sách ngữ cảnh)*
*   **Mục đích:** Quan sát token/ngữ cảnh LLM để BIẾT prompt cách trần `n_ctx` bao xa mà tinh chỉnh — trả lời lo ngại "log quá dài/nhiều → tràn ngữ cảnh local LLM, làm sao theo dõi?".
*   **Tác dụng:** `estimate_tokens(messages)` (chars/3.5, bảo thủ); `preflight_check(messages, max_output)` log **WARNING + đếm** khi prompt ước lượng vượt 90% ngân sách input (degrade CÓ quan sát, không âm thầm); `record_usage(usage)` ghi token THẬT (`response.usage` prompt/completion) → mean/p95/max/utilization% bền vững ở `config/llm_token_stats.json`; `get_stats()` cho Dashboard KPI "Context Utilization". Thread-safe; nuốt mọi lỗi ghi file (không bao giờ làm hỏng luồng LLM). `N_CTX=8192` đọc từ `llm.max_context_tokens` (server llama.cpp đặt 16384 → còn headroom).
*   **Mối quan hệ:** Gọi bởi `llm_client.invoke` (preflight TRƯỚC + record SAU); số liệu đọc bởi Dashboard và `run_context_stress.py`.

### 39. `src/agent/threat_memory.py`
*   **Mục đích:** Uy tín IP dài hạn, chuỗi APT, chống Memory Poisoning.
*   **Tác dụng:** SQLite (`config/threat_memory.db`): `record_incident`/`get_ip_reputation`; **`record_apt_event` + `check_apt_chain`** (đánh dấu APT khi IP xuất hiện ở **≥2 NGÀY khác nhau** — không phải "≥3 giai đoạn"); `get_context_for_prompt` (reputation + known-entity + **APT CHAIN đa-ngày** inject vào LLM); `ingest_dapt_chains` (bulk seed dashboard); known entities; `output_sanitizer` cho mọi trường trước khi ghi.
*   **Mối quan hệ:** Gọi bởi `node_action_executor` (ghi) và `node_rag_context` (nạp lịch sử); `subscriber` ghi APT emergent. **`get_ip_reputation` nay còn được `RuleEngine` (Tier-1) ĐỌC** (qua cache) để tự chặn/HITL IP có tiền sử ≥70/≥50 — Threat Memory không chỉ nuôi Tier-2 mà còn khép vòng về Tier-1.

### 40. `src/response/executor.py`
*   **Mục đích:** Audit trail không thể chối cãi + hành động ứng phó.
*   **Tác dụng:** Ghi `config/audit_trail.db` với **HMAC SHA-256 móc-xích** (dòng trước→sau, `verify_audit_trail_integrity` phát hiện giả mạo); `block_ip()`/`quarantine_host()`/`raise_alert()` = **`[FIREWALL MOCK]`** (ghi audit, KHÔNG gọi iptables/OS — enforcement thật là luật ACTIVE ở Tier-1); login lockout (`get/increment/reset_login_attempts`, `lock_user`).
*   **Mối quan hệ:** Gọi bởi `node_action_executor` và Dashboard (verify + auth).

---

## **NGÀY 5: GIAO DIỆN SOC & KHUNG ĐÁNH GIÁ THỰC NGHIỆM**

### 41. `src/ui/app.py`
*   **Mục đích:** Web Dashboard Streamlit (SOC HITL).
*   **Tác dụng:** 5 tab (Nhật ký SIEM & Audit / Phê duyệt Luật HITL / Giám sát APT / Blocklist & Whitelist / Lỗ hổng & Graph). KPI header: "Cảnh báo Escalated", "Luật chờ duyệt/đang chặn", "Live FPR" và **"Logs thô"/"Noise Reduction" đọc `config/pipeline_stats.json` (SỐ THẬT** do subscriber ghi — bỏ ước lượng ×35); KPI "Context Budget" đọc `config/llm_token_stats.json`. Nút Duyệt/Bác → `approve_rule`/`reject_rule` persist YAML → Tier-1 enforce. Nút Reset xóa DBs + dynamic_rules + `pipeline_stats.json` *(CLI tương đương 1 lệnh: `scripts/reset_all.py` — tự dừng/xoá/bật lại đúng 1 subscriber)*. Panel **"Tier-1 đã chặn"** (`_get_tier1_blocks`) khử trùng theo IP nhưng hiện **Số lần** chặn + **Lần cuối** (timestamp) để không che mất việc 1 IP bị chặn nhiều lần. Bộ lọc "Phân loại Hành động" gồm `BLOCK_IP/ALERT/AWAIT_HITL/LOG/QUARANTINE`. Nút Whitelist (mọi chỗ) **kiểm return `add_to_whitelist`** — thất bại thì báo lỗi thật + GIỮ block rule (trước đây báo giả "whitelisted" rồi gỡ block → lần sau bị chặn lại).
*   **Mối quan hệ:** Đọc `audit_trail.db`/`threat_memory.db`/`feedback_listener`/`pipeline_stats.json`/`llm_token_stats.json`.

### 42. `src/ui/components.py`
*   **Mục đích:** Component hiển thị tái dùng (Glassmorphism SOC).
*   **Tác dụng:** `render_metrics_header(..., noise_reduction)` (KPI cards, dùng noise_reduction đo thật); `render_alert_card` (card cảnh báo + MITRE/confidence/reasoning + NIST playbook, anti-XSS); `render_threat_intel_tables` (IP nguy cơ + known entities); `render_apt_events_table` (chuỗi APT DAPT2020). Nhãn "Xem bản ghi Quyết định (Audit Record JSON)" làm rõ đây là ĐẦU RA quyết định, KHÔNG phải input LLM.
*   **Mối quan hệ:** Import & render bởi `app.py`.

### 43. `src/ui/auth.py`
*   **Mục đích:** Xác thực RBAC + chống Input Injection.
*   **Tác dụng:** **PBKDF2-HMAC-SHA256 (100k vòng), KHÔNG hardcode plaintext** — hash demo tính sẵn + cảnh báo fail-loud khi dùng HASH/SALT demo; `hmac.compare_digest` (constant-time chống timing); regex `^[a-zA-Z0-9_]{1,30}$` cho username; lockout brute-force (5 lần). 2 vai trò L1_Analyst / L3_Manager.
*   **Mối quan hệ:** Bọc Dashboard; dùng `executor` cho lockout.

### 44. `src/ui/style.css`
*   **Mục đích:** Ngôn ngữ thiết kế thị giác SOC Dashboard.
*   **Tác dụng:** CSS variables, Glassmorphism, Neon Glow, severity glow + pulse critical, KPI cards (accent bar), tabs/headers/sidebar/buttons, gradient bg, scrollbar, panel `.soc-empty` (empty-state trung tính), console box (font Inter).
*   **Mối quan hệ:** Load trong `app.py`.

> **Ghi chú (gộp file):** 3 file ablation cũ (`run_ablation_study/bcde/balanced.py`) nay HỢP NHẤT vào **`experiments/run_ablation.py`** với `--mode {af,bcde,balanced,all}`. Ba entry dưới mô tả 3 mode của CÙNG một file; tên file kết quả GIỮ NGUYÊN.

### 45. `experiments/run_ablation.py --mode af`
*   **Mục đích:** Ablation A vs F (đóng góp 2 đầu mút).
*   **Tác dụng:** So sánh **Config A** (Tier-1 đầy đủ, không LLM) vs **Config F** (full SENTINEL) trên ground_truth; đo Precision/Recall/F1/FPR/latency; sinh `Config_F.reasoning_outputs` (cho trọng tài); đẩy MLflow. *(Config A ở đây = Tier-1 đầy đủ — KHÁC "static-only" trong unified stream.)*
*   **Mối quan hệ:** Output `results/ablation_results.json` dùng cho `statistical_tests` + `evaluate_reasoning`.

### 46. `experiments/run_ablation.py --mode bcde`
*   **Mục đích:** Ablation **Configs B, C, D, E** — chạy THẬT, không ước tính.
*   **Tác dụng:** Trên CÙNG 300 mẫu phân tầng tất định: **B** Pure LLM (mọi mẫu→LLM, KHÔNG gate/RAG/guardrails), **C** Welford-gate + LLM (không RAG), **D** gate + dense-RAG (FAISS-only), **E** gate + hybrid-RAG (FAISS+BM25+RRF). Gate Welford tính 1 lần/mẫu, dùng chung C/D/E → escalation set giống hệt nên hiệu số D−C, E−D cô lập đúng đóng góp từng tầng RAG. Verdict = action thô LLM (không áp consensus-guard) để đo năng lực phân loại thuần.
*   **Mối quan hệ:** Output `results/ablation_bcde_results.json`; ghép với A/F của `--mode af`.

### 47. `experiments/run_ablation.py --mode balanced`
*   **Mục đích:** Ablation **CÂN BẰNG 150/150** — cả 6 cấu hình A–F trên cùng tập, để phép so cấu phần CÓ ý nghĩa (tập gốc 93% tấn công khiến mọi cấu hình suy biến về dự đoán toàn-dương, F1 ≈ base rate).
*   **Tác dụng:** Dựng 150 benign (expected=LOG, **warmup Welford bằng benign THẬT held-out** `benign[150:300]`) + 150 tấn công (phân tầng đều 10/lớp × 15 lớp). Có benign thật → gate Welford/Tier-1 có cơ hội DROP benign (true negative) nên C/D/E/F không còn buộc trùng nhau; đo P/R/F1/FPR + latency từng cấu hình + McNemar (B-vs-gated).
*   **Mối quan hệ:** Cùng file (dùng chung hàm gate/RAG/LLM nội bộ); cần LLM server; output `results/ablation_balanced_results.json`.

### 48. `experiments/statistical_tests.py` *(Quan trọng)*
*   **Mục đích:** Kiểm định ý nghĩa thống kê.
*   **Tác dụng:** **McNemar's Test** (khác biệt phân loại Config A vs F) + **Mann-Whitney U** (khác biệt độ trễ), đọc `ablation_results.json`.
*   **Mối quan hệ:** Chạy sau Ablation.

### 49. `experiments/evaluate_adversarial.py --mode static`
*   **Mục đích:** Đo kháng adversarial của Guardrails **TĨNH** (120 mẫu / 5 nhóm).
*   **Tác dụng:** Bơm payload qua lớp tĩnh, tính **block rate / bypass rate** (đã sửa naming khỏi "defeat_rate" gây hiểu lầm); ghi `results/robustness_results.json`.
*   **Mối quan hệ:** Đọc `experiments/adversarial/`; output cho `plot_results`.

### 50. `experiments/evaluate_adversarial.py --mode pipeline`
*   **Mục đích:** Đo kháng của **FULL pipeline (Tier-2 LLM)** với payload KHÓ.
*   **Tác dụng:** Nhúng payload (semantic/jailbreak/rag-poison) vào flow tấn công thật, đẩy qua Tier-1→Guardrails→RAG→LLM; đếm RESISTED vs COMPROMISED (LLM bị ép ra LOG/DROP).
*   **Mối quan hệ:** Chứng minh `enforce_tier_consensus` đóng lỗ hổng social-engineering.

### 51. `experiments/evaluate_reasoning.py`
*   **Mục đích:** Đánh giá chất lượng suy luận (LLM-as-Judge cross-family).
*   **Tác dụng:** Hot-swap sang **Llama-3 8B (Meta)** chấm reasoning của **Gemma-2 (Google)** từ `ablation_results.json` → Context Precision/Answer Relevancy/Faithfulness/Context Recall/Audit Completeness (chuẩn RAGAS); đẩy MLflow.
*   **Mối quan hệ:** Cần `run_ablation.py --mode af` chạy trước (sinh reasoning_outputs); dùng `switch_model.sh`.

### 52. `experiments/evaluate_unified_stream.py`
*   **Mục đích:** Đánh giá luồng gộp THỐNG NHẤT (offline, tất định) — thay phương pháp 3 luồng circular cũ.
*   **Tác dụng:** `build_stream()` gộp CICIDS + DAPT2020 + **zero-day REAL-DERIVED (7 mẫu, nền flow benign thật, đẩy 1 feature cực trị, rải ngày 2-5)** vào MỘT luồng sắp theo thời gian (golden-ratio interleave), stream qua Tier-1 + Welford + Threat Memory **bộ nhớ sạch** → đo: phân loại, **APT EMERGENT** (recall + độ trễ), zero-day (Welford bắt khi static bỏ sót).
*   **Mối quan hệ:** Đọc `ground_truth.json` + `dapt2020_chains.jsonl`; output `results/unified_stream_results.json` + `reports/unified_stream_evaluation_report.md`. Hàm `build_stream`/`map_cicids`/`_is_threat` được tái dùng bởi các script rigor #54–#57.

### 53. `experiments/stream_unified_online.py`
*   **Mục đích:** Publisher ONLINE phát cùng luồng gộp qua TOÀN BỘ hệ thống (demo realtime).
*   **Tác dụng:** `build_sequence()` + `enrich()` (gắn metadata DAPT/zero-day/adversarial) → đẩy Redis qua pipeline thật (Tier-1 → APT emergent ở subscriber → LLM Agent → Dashboard); có `--dry-run`. **Cờ `--include-adversarial`: 1 LỆNH đẩy CẢ 4 nguồn** (CICIDS + DAPT + Zero-day + **120 payload adversarial**, tổng 4796 sự kiện) — tái dùng loader `_adversarial_logs()` của `push_flow.py` (lazy import tránh vòng import). Chỉ event ESCALATE mới gọi LLM (đúng thiết kế SOC). *(Offline #52 = benchmark tất định; online #53 = chứng minh end-to-end. Đây là lệnh "chạy FULL" cho demo hội đồng — xem `docs/Codebase/guides/COMMITTEE_DEMO.md`.)*
*   **Mối quan hệ:** Dùng chung `build_stream()` với #52; cần Redis + `main.py --mode server`.

### 54. `experiments/run_threshold_sensitivity.py` *(MỚI — rigor)*
*   **Mục đích:** Phân tích **độ nhạy ngưỡng Welford** (Z-score) — bác bỏ lo ngại "3.5σ chọn may rủi / cherry-pick / tinh chỉnh quá khớp".
*   **Tác dụng:** Quét τ ∈ {2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0} trên ĐÚNG luồng gộp thật của `evaluate_unified_stream` (Tier-1 đầy đủ, KHÔNG LLM, tất định); đo trade-off: tỷ lệ escalation (tải/chi phí LLM), FP-rate benign, P/R/F1 Tier-1, zero-day bắt được /7. Ghi đè `RuleEngine.z_threshold` chỉ khi quét; production giữ 3.5.
*   **Mối quan hệ:** Output `results/threshold_sensitivity_results.json`; vẽ bởi `plot_results.plot_threshold_sensitivity()`.

### 55. `experiments/run_zeroday_graded.py` *(MỚI — rigor)*
*   **Mục đích:** Đường cong phát hiện zero-day **PHÂN CẤP** — thay vì chỉ 7 mẫu cực trị (lệch ≫100σ, bắt 7/7 hiển nhiên), xác định RANH GIỚI phát hiện thật.
*   **Tác dụng:** Quét độ lệch k ∈ {2,3,3.5,4,5,6,8,10,20,50,100}·σ trên nhiều flow benign thật × nhiều feature Welford; đo "noticed" (Welford gắn cờ Z>3.5σ) và "escalated" (điểm Tier-1 ≥ risk_threshold → leo thang Tầng 2). Baseline Welford **đóng băng** (snapshot+restore) trước mỗi probe để z=k chính xác. Tất định, Tier-1 only.
*   **Mối quan hệ:** Output `results/zeroday_graded_results.json`; vẽ bởi `plot_results.plot_zeroday_graded()`.

### 56. `experiments/run_apt_negative_control.py` *(MỚI — rigor)*
*   **Mục đích:** **Đối chứng ÂM tính + khoảng tin cậy** cho phần APT (vốn chỉ báo recall=1.0 trên n nhỏ, thiếu đối chứng âm).
*   **Tác dụng:** (a) báo **Wilson 95% CI** cho recall k/n (phù hợp n nhỏ, p ở biên); (b) đối chứng âm — đếm IP benign hiện diện ≥2 ngày phân biệt trong luồng rồi xác nhận **0 IP** nào kích hoạt `check_apt_chain` (specificity=1.0). Cơ chế phân biệt nằm ở CỔNG GHI: chỉ sự kiện gắn cờ tấn công mới ghi kho APT; cảnh báo bật khi đủ ≥2 NGÀY-TẤN-CÔNG phân biệt. Tier-1 + Memory, tất định, KHÔNG LLM.
*   **Mối quan hệ:** Dùng `ThreatMemoryStore` + `build_stream`; output `results/apt_negative_control_results.json`.

### 57. `experiments/run_context_stress.py` *(MỚI — rigor/observability)*
*   **Mục đích:** **Đường cong stress ngữ cảnh** — chứng minh kiến trúc giữ token đầu vào trong ngân sách bất kể số log (trả lời "log quá nhiều có tràn ngữ cảnh local LLM không, tinh chỉnh thế nào").
*   **Tác dụng:** Đẩy số log N ∈ {1..2000}, đo token vào LLM theo 2 cách: **RAW** (nối thẳng → tăng TUYẾN TÍNH, vượt n_ctx rất nhanh) vs **COMPRESSED** (Drain template mining → BÃO HÒA, chặn bằng thiết kế quanh token_budget=4000/n_ctx=8192). Tất định, KHÔNG LLM; vẽ `results/plots/context_stress.png`.
*   **Mối quan hệ:** Dùng `template_miner` + `token_monitor.N_CTX`; output `results/context_stress_results.json`.

### 58. `experiments/run_llm_robustness.py` *(MỚI — rigor)*
*   **Mục đích:** **Độ bền LLM & quy trình** — (A) tái lập (determinism) và (B) suy biến an toàn (graceful degradation).
*   **Tác dụng:** (A) cùng prompt + **seed=42** gọi N lần → kiểm action GIỐNG HỆT (báo cả raw có tất định không); (B) monkeypatch `llm_client.invoke` ném ConnectionError (giả lập LLM chết) → chạy `agent_app` đầy đủ trên 1 mẫu tấn công, xác nhận hệ KHÔNG vỡ mà suy biến về **AWAIT_HITL** (Tier-1 vẫn bảo vệ độc lập). Kèm thống kê semantic-cache (bonus).
*   **Mối quan hệ:** Cần LLM server cho (A); output `results/llm_robustness_results.json`.

### 59. `experiments/measure_latency_baseline.py`
*   **Mục đích:** Đo độ trễ Two-Tier vs LLM-only.
*   **Tác dụng:** Chạy N log qua 2 cấu hình, đo Mean/Median/P95, tính **Latency Reduction** (mục tiêu ≥60%) — Tier-1 lọc ~99% nên không phải gọi LLM cho mọi log.
*   **Mối quan hệ:** Output `results/latency_benchmark.json`; bổ sung cho Mann-Whitney U.

### 60. `experiments/plot_results.py`
*   **Mục đích:** Trực quan hóa số liệu thực nghiệm.
*   **Tác dụng:** Vẽ biểu đồ block-rate theo nhóm + pie accuracy từ `robustness_results.json`; **`plot_threshold_sensitivity()`** (đường cong độ nhạy ngưỡng) và **`plot_zeroday_graded()`** (đường cong phát hiện phân cấp) → `results/plots/*.png`.
*   **Mối quan hệ:** Đọc result JSON cho luận văn.

### 61. `experiments/e2e_test_runner.py` *(Quan trọng kiểm thử)*
*   **Mục đích:** Bộ kiểm thử tích hợp E2E toàn hệ thống.
*   **Tác dụng:** Chạy **22 kịch bản** (T01-T22): RuleEngine, Guardrails, Dual-RAG, Threat Memory, Agent, Latency (T19, cần LLM), **Unified Stream (T21)** + **Online Publisher (T22)**; `--offline` bỏ qua test cần LLM.
*   **Mối quan hệ:** Chốt chặn toàn vẹn trước khi push/demo.

### 61b. `scripts/eval_attack_mapper.py` *(MỚI — đo chất lượng ATT&CK Mapper)*
*   **Mục đích:** Đo độ chính xác ánh xạ MITRE của node `attack_mapper` (#35b) trên ground truth, sinh số THẬT cho ch4 luận văn.
*   **Tác dụng:** 2 mode — **`rrf`** (offline, tất định, không LLM: dựng query flow như `node_rag_context` → top-RRF; cô lập đóng góp KB) và **`e2e`** (chạy FULL `agent_app`, cần LLM server; **TỰ CÔ LẬP** threat_memory/audit/config sang DB tạm + no-op các hàm ghi → KHÔNG đụng dữ liệu thật). Metrics: technique exact/parent-match, tactic-match, mapper-fired-rate, latency p50/p95, **trần KB-coverage** (báo trung thực giới hạn). Cờ `--ground-truth experiments/ground_truth_webattacks.json` (50 payload web thật, nhãn ATT&CK chuẩn) đo ở MIỀN thiết kế → e2e 64% (vs flow-GT 0% — bài toán flow-only ill-posed).
*   **Mối quan hệ:** Gọi `map_attack`/`agent_app`; output `results/attack_mapper_eval_*.json` (đã commit làm bằng chứng); tổng hợp ở `docs/METRICS_SUMMARY.md`.

### 62. `scripts/seed_demo_data.py`
*   **Mục đích:** Seed Dashboard từ data THẬT (không bịa).
*   **Tác dụng:** Chạy pipeline thật (Tier-1 + Agent + LLM) trên mẫu CICIDS 14 lớp → quyết định thật vào audit/threat/pending-rules; `ingest_dapt_chains` 9 chuỗi APT; seed known entities. *(SEED dashboard, KHÔNG phải benchmark APT — benchmark ở #52.)*
*   **Mối quan hệ:** Đọc `ground_truth.json` + `dapt2020_chains.jsonl`; ghi DBs production.

### 63. `scripts/convert_report.py` & `scripts/switch_model.sh` & `scripts/cleanup.sh`
*   **convert_report.py:** Markdown → DOCX (báo cáo tiến độ).
*   **switch_model.sh:** Hot-swap LLM (`gemma`/`llama`), sửa `.env` + restart container `sentinel_llm`, chờ healthy.
*   **cleanup.sh:** Dọn artifact tạm AN TOÀN — chỉ xóa thứ tái tạo được/gitignored (mlruns, eval DB tạm, faiss index cache, logs, `__pycache__`/caches). **KHÔNG** đụng dữ liệu thực nghiệm. *(Ghi chú chính xác về bằng chứng đã commit: nằm ở **`experiments/results/attack_mapper_eval_*.json`** (4 file eval mapper) + **`reports/unified_stream_evaluation_report.md`** + **`docs/METRICS_SUMMARY.md`**. Thư mục **`results/` top-level** (ablation/latency/plots) là **scratch — regenerate từ script**, KHÔNG commit; con số vẫn tái lập bằng cách chạy lại `run_ablation_*`/`measure_latency_baseline`/`plot_results`.)*

---

## **TÍCH HỢP HỆ THỐNG GỐC (ROOT)**

### 64. `main.py`
*   **Mục đích:** Điểm khởi chạy tích hợp (entrypoint).
*   **Tác dụng:** `argparse` mode `server`/`scan`/`full`. Mode server: khởi động **Subscriber loop** (`start_listening(on_batch_ready=handle_escalated_batch)`) — Tier-1 lọc, escalate → LangGraph Agent → LLM → audit. Mode scan/full: chạy Trivy + build Neo4j KG. Reset LoopDetector mỗi cycle. *(KHÔNG tự chạy Streamlit — Dashboard chạy qua Docker `streamlit run src/ui/app.py`.)*
*   **Mối quan hệ:** Gọi `subscriber.start_listening`, `agent.agent_app`, `tier1_filter.scanner`, `rag.graph_builder`.

---

## **KIỂM THỬ (TESTS)**

> Bộ test đảm bảo tính toàn vẹn — `pytest 248 passed` (unit+tier1+adversarial), `E2E 22/22`.

*   **`tests/unit/`** — data_validator, decision_validator (+ Anti-Self-DoS shield + tier-consensus guard), feedback_validator, **feedback_listener** (HITL lifecycle), output_sanitizer, prompt_filter, rag_sanitizer, template_miner, entropy_scorer, threat_memory (+ APT-chain-context), **subscriber** (chống lộ nhãn dataset vào LLM + hợp đồng enrich↔strip), **semantic_cache**, **auth** (PBKDF2/RBAC), **executor** (HMAC chain, đã cô lập DB tạm), agent, rag, **attack_mapper** (35 test: curated 10 web-attack, anchor, RRF fallback, schema — không cần LLM), **token_monitor**, **behavioral_learning** (14 test: `_derive_behavioral_rule` chữ ký UA/URI + loại benign/curl; alias user_agent/uri; Tier-1 bắt IP MỚI cùng kỹ thuật; không over-block benign).
*   **`tests/integration/`** — `test_unified_stream.py` (3 nguồn trộn + APT emergent + **bất biến zero-day real-derived**), `test_streaming_pipeline.py` (routing đa-nguồn), `test_end_to_end.py`.
*   **`tests/test_adversarial.py`** + **`tests/test_tier1_filter.py`** + **`tests/conftest.py`** (sys.path root).
</content>
</invoke>
