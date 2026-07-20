# 🧭 Bắt đầu từ đâu — Đọc code SENTINEL theo LUỒNG (không bị ngợp)

> Bạn KHÔNG cần đọc hết ~40 file `src/`. Chỉ cần **bám theo hành trình của MỘT bản ghi log** đi qua hệ thống — mỗi điểm dừng học **1 khái niệm + 1 công nghệ + 1 hàm cốt lõi**, rồi chạy 1 lệnh để **thấy tận mắt**. Đọc xong 12 điểm dừng dưới đây là đủ hiểu + giải thích được toàn hệ.
>
> Tài liệu bạn đọc: **file này** (đọc code theo luồng) → [Bản đồ Quyết định 2 Tier](04_DECISION_MAP_TIER1_TIER2.md) (chi tiết điều kiện Block/Alert) → [codebase_summary.md](codebase_summary.md) (bản đồ file→vai trò) → [RUN_PROJECT.md](../guides/RUN_PROJECT.md) (cách chạy).

---

## 0. Mô hình tư duy trong 60 giây (đọc trước khi mở code)

SENTINEL giải **1 bài toán**: SOC bị ngập cảnh báo (alert fatigue), mà đưa MỌI log qua LLM thì quá chậm (4–6s/log) và LLM lại **bị tấn công thao túng được**. Giải pháp = **2 tầng**, có **Cổng ML** làm van giảm tải ở giữa:

- **Tier-1** (tất định, ~0.1ms/log): luật + thống kê **Welford** lọc phần lớn log ở "tốc độ đường truyền". Chỉ phần **mơ hồ** mới leo thang (`ESCALATE`).
- **Cổng ML** (LightGBM, ~0.3ms): ca `ESCALATE` đi qua đây TRƯỚC — chấm xác suất tấn công rồi tự quyết **83.8%** (Chặn/Báo/Thả) mà **KHÔNG cần LLM**; chỉ ca ML "bỏ ngỏ" mới lên Tier-2.
- **Tier-2** (nhận thức, ~vài giây/lô): tác tử **LangGraph** chạy LLM **Gemma-2-9B cục bộ** + **Dual-RAG** (MITRE/NIST) để suy luận có căn cứ, rồi hành động.

Mấu chốt: **tầng LLM nằm NGOÀI đường chặn đồng bộ** → LLM nghẽn thì chỉ chậm phần làm-giàu-ngữ-cảnh, KHÔNG chậm việc bảo vệ. Và **Tier-1 (không thể bị thuyết phục) làm trọng tài kiểm tra Tier-2** — nếu LLM bị lừa hạ cấp tấn công thành lành tính, hệ ép về con người duyệt.

> Giữ đúng 1 hình trong đầu: `log → Tier-1 lọc → Cổng ML → (chỉ ca ML bỏ ngỏ) Tier-2 suy luận → hành động + học ngược về Tier-1`. Mọi file đều rơi vào 1 mắt xích của chuỗi này.

---

## 1. Cách đọc repo này (mẹo chống ngợp)

1. **Mở IDE + file này song song.** Mỗi điểm dừng có link `file.py:dòng` — bấm để nhảy thẳng tới **đúng 1 hàm**, đọc hàm đó thôi, đừng đọc cả file.
2. **Chạy demo trước, đọc code sau.** `./scripts/run_demo.sh --small` rồi mở `http://localhost:8501` — thấy hệ chạy rồi đọc code sẽ "khớp" ngay.
3. **Bỏ qua 3 nhóm file lúc đầu:** `experiments/` (benchmark), `demos/`, `scripts/` build dataset — chúng KHÔNG nằm trong luồng runtime (xem §Bỏ qua cuối bài).
4. **Đọc theo thứ tự 12 điểm dừng dưới** — chính là thứ tự 1 log đi qua hệ thống.

---

## 2. Hành trình 1 bản ghi log — 12 điểm dừng

Mỗi điểm: 🎯 bản chất · 📂 hàm cốt lõi (bấm vào) · ⚙️ công nghệ · 👀 thấy tận mắt · ➡️ đưa cho ai.

### ① Điểm vào hệ thống — `main.py`

- 🎯 **Bản chất:** nơi bật "trái tim". Mode `server` = khởi động vòng lặp subscriber; escalate thì gọi Agent.
- 📂 [main.py:90 `main()`](../../../main.py#L90) → [main.py:132 gọi `start_listening(...)`](../../../main.py#L132) với callback [main.py:58 `handle_escalated_batch`](../../../main.py#L58).
- ⚙️ `argparse` (server/scan/full). Dashboard chạy RIÊNG qua Docker, không ở đây.
- 👀 `.venv/bin/python main.py --mode server --log-level INFO`
- ➡️ Trao quyền cho **subscriber**.

### ② Tiêu thụ log từ hàng đợi — `subscriber.py`

- 🎯 **Bản chất:** đọc log từ Redis theo lô, gọi Tier-1 cho từng log, rồi định tuyến. Cũng đếm số liệu Noise-Reduction thật + phát hiện APT emergent.
- 📂 [subscriber.py:117 `start_listening()`](../../../src/streaming/subscriber.py#L117) — vòng lặp chính ở [subscriber.py:287 `xreadgroup`](../../../src/streaming/subscriber.py#L287).
- ⚙️ **Redis Streams** + consumer-group `sentinel_group` (nhiều consumer chia tải, at-least-once) trên 3 queue `queue_firewall/queue_waf/queue_sysmon`.
- 👀 `docker exec sentinel_redis redis-cli -a '...' XLEN queue_waf`
- ➡️ Mỗi log → `RuleEngine.evaluate(log)`.

### ③ Tier-1 — bộ lọc tốc độ đường truyền · `rule_engine.py` *(TRÁI TIM 1)*

- 🎯 **Bản chất:** 7 lớp tất định O(1) quyết định số phận mỗi log. Điểm hay nhất: **Welford** bắt zero-day KHÔNG cần mẫu tấn công.
- 📂 [rule_engine.py:597 `evaluate()`](../../../src/tier1_filter/rule_engine.py#L597) — đọc **theo thứ tự các lớp** (Whitelist → WAF sig → Injection sig → **Welford Z-score** → static → dynamic → session). Rồi mở lớp Welford: [rule_engine.py:35 `class RunningStats`](../../../src/tier1_filter/rule_engine.py#L35) (cập nhật μ, M2 online) + [rule_engine.py:450 `_seed_golden_baseline`](../../../src/tier1_filter/rule_engine.py#L450) (seed 300 flow benign).
- ⚙️ Thuật toán **Welford** (phương sai online O(1) RAM); regex biên dịch sẵn.
- 🔑 **Ý cốt lõi:** lệch > **3.5σ** → cờ zero-day; tổng điểm ≥ **15** (`risk_threshold`) → `ESCALATE`. Chỉ flow benign (DROP/LOG) mới cập nhật baseline (chống đầu độc).
- 👀 `.venv/bin/python demos/demo_tier1.py`
- ➡️ Trả `tier1_action` cho subscriber định tuyến.

### ④ Định tuyến 6 hành động — (trong `subscriber.py`)

- 🎯 **Bản chất:** `DROP/LOG` (bỏ, không phiền LLM) · `BLOCK_IP` (chặn ngay) · `AWAIT_HITL` (chờ người) · `ALERT` · **`ESCALATE`** (chưa gọi LLM ngay — đưa qua **Cổng ML** ở bước ⑤ trước). Chỉ ca **Cổng ML bỏ ngỏ** mới thực sự tốn LLM — đây là lý do hệ nhanh.
- 📂 Quay lại vòng định tuyến trong [subscriber.py:287+](../../../src/streaming/subscriber.py#L287); nhánh `ESCALATE` ở [subscriber.py:364](../../../src/streaming/subscriber.py#L364).
- ➡️ `ESCALATE` → **Cổng ML** (⑤).

### ⑤ Cổng ML — van giảm tải trước LLM · `ml_gateway.py`

- 🎯 **Bản chất:** ca `ESCALATE` (Tier-1 thấy đáng ngờ nhưng chưa chắc) đi qua **LightGBM**: chấm `P(tấn công)` rồi tự quyết **83.8%** (Chặn/Báo/Thả) mà **KHÔNG gọi LLM**; chỉ ca ML "bỏ ngỏ" (dải `ESCALATE`) mới lên Tier-2. Đây là van cắt ~6× chi phí LLM.
- 📂 subscriber gọi [ml_gateway.py:115 `evaluate()`](../../../src/tier1_filter/ml_gateway.py#L115) tại [subscriber.py:370](../../../src/streaming/subscriber.py#L370); lõi phân dải [decision_policy.py:72 `classify_ml`](../../../src/guardrails/decision_policy.py#L72); mô hình nạp ở [ml_gateway.py:46 `class MLGateway`](../../../src/tier1_filter/ml_gateway.py#L46).
- ⚙️ **LightGBM** (full-feature, `predict_proba`) + **4 dải confidence** (`classify_ml`): `BLOCK_IP` ≥0.85 · `ESCALATE` 0.65–0.85 (→ LLM) · `ALERT` 0.40–0.65 (IP tái phạm → tự BLOCK) · `DROP` <0.40.
- 🔑 **Ý cốt lõi:** giảm tải LLM **83.8%** (761/908 ca), precision trên bypass **98.82%**; kháng né-tránh **99.58%**. ML tự tin chặn → block-on-sight qua reputation.
- 👀 `.venv/bin/python experiments/evaluate_ml_gate.py`
- ➡️ Ca ML bỏ ngỏ → `agent_app.invoke(...)` (bước ⑥). Ca ML tự quyết → `queue_decisions` (không tốn LLM).

### ⑥ Đồ thị tác tử — `workflow.py` *(TRÁI TIM 2)*

- 🎯 **Bản chất:** Tier-2 KHÔNG phải "gọi LLM 1 phát". Nó là **máy trạng thái 6 nút** (DAG, không loop, không tool-calling) — LLM chỉ là 1 nút.
- 📂 [workflow.py:26 `create_agent_workflow()`](../../../src/agent/workflow.py#L26) — đọc thứ tự `add_node` + 2 `add_conditional_edges`. Singleton [workflow.py:88 `agent_app`](../../../src/agent/workflow.py#L88).
- ⚙️ **LangGraph** `StateGraph`; trạng thái = `SentinelState` (dataclass).
- 🔑 Luồng: `guardrails → rag_context → llm_triage →` **rẽ theo ACTION** `→ attack_mapper → action_executor / human_in_the_loop / END`.
- ➡️ Vào từng nút ở `nodes.py`.

### ⑦ Bộ não — `node_llm_triage` · `nodes.py`

- 🎯 **Bản chất:** dựng prompt → gọi LLM → **KHÔNG tin ngay**: kiểm chứng bằng validator + lá chắn đồng thuận, rồi mới ghi. LLM chết → suy biến an toàn về `AWAIT_HITL`.
- 📂 [nodes.py:160 `node_llm_triage`](../../../src/agent/nodes.py#L160). Kèm: [prompts.py:162 `build_triage_prompt`](../../../src/agent/prompts.py#L162) · [llm_client.py:131 `invoke`](../../../src/agent/llm_client.py#L131) + [llm_client.py:88 `DECISION_JSON_SCHEMA`](../../../src/agent/llm_client.py#L88) · [decision_validator.py:151 `enforce_tier_consensus`](../../../src/guardrails/decision_validator.py#L151).
- ⚙️ **Gemma-2-9B-IT Q6_K** qua **llama.cpp** (OpenAI API), temp 0.1 + **seed 42** → tất định. **`response_format=DECISION_JSON_SCHEMA`** (constrained decoding) ép server xuất **JSON HỢP LỆ** → dứt điểm "parse lỗi/prose bị cắt cụt", và reasoning đi thẳng field nên **bám tiếng Việt** đúng chỉ dẫn prompt.
- 🔑 **Confidence LÁI action (`classify_llm`):** conf ≥0.85 → BLOCK · 0.65–0.85 → ALERT · <0.65 → AWAIT_HITL (bỏ kiểu "LLM tự chọn action"). Đồng bộ 1 nguồn với Cổng ML qua `decision_policy.py`.
- 🔑 **Prompt Engineering nâng cao:** LLM bị ép phân tích chuỗi tấn công (Attack Chain) theo trình tự thời gian và đếm số lượng hành vi. Nó bắt buộc viết lý do bằng **ngôn ngữ tự nhiên (storytelling)** của chuyên gia SOC. Nếu gặp Zero-day không có trong RAG, nó được phép **Tự suy luận** kỹ thuật gần nhất, gắn nhãn `[Tự suy luận]`, và cấm ảo tưởng (hallucinate) các bước không có thật.
- 🔑 **`enforce_tier_consensus`** = tinh túy bảo mật: Tier-1 nói tấn công mà LLM hạ xuống LOG/DROP → hệ KHÔNG tin LLM, ép `AWAIT_HITL`.
- ➡️ Threat verdict → `node_attack_mapper`; benign → kết thúc.

### ⑧ Dual-RAG — `retriever.py`

- 🎯 **Bản chất:** để LLM không "bịa" technique/playbook, ta nạp ngữ cảnh THẬT từ MITRE + NIST. Kết hợp tìm-theo-nghĩa và tìm-theo-từ-khóa.
- 📂 [retriever.py:144 `_hybrid_search()`](../../../src/rag/retriever.py#L144) (gọi trong node [nodes.py:84 `node_rag_context`](../../../src/agent/nodes.py#L84)).
- ⚙️ **FAISS** (all-MiniLM-L6-v2, 384 chiều, cosine `IndexFlatIP`) + **BM25Okapi** hợp nhất bằng **RRF k=60**; checksum SHA-256 fail-closed chống KB poisoning.
- 🔑 **Ý RRF:** gộp 2 bảng xếp hạng chỉ theo THỨ HẠNG `R(d)=Σ 1/(k+rank)` → khỏi cân 2 thang điểm khác nhau.
- 👀 `.venv/bin/python demos/demo_rag.py`
- ➡️ Ngữ cảnh ghép vào prompt ở bước ⑦.

### ⑨ Cấu trúc hóa MITRE — `node_attack_mapper` · `attack_mapper.py`

- 🎯 **Bản chất:** biến nhãn tự do "phát hiện SQLi" của LLM → bản ghi ATT&CK kiểm chứng được (tactic/technique/URL/response).
- 📂 [nodes.py:376 `node_attack_mapper`](../../../src/agent/nodes.py#L376) → `map_attack()` trong [attack_mapper.py](../../../src/agent/attack_mapper.py).
- ⚙️ **Pydantic** (schema luôn hợp lệ); 3 đường: curated (tra bảng) / anchor / RRF+LLM-select.
- ➡️ Quyết định đã làm giàu → executor.

### ⑩ Hành động + Audit chống giả mạo — `executor.py`

- 🎯 **Bản chất:** thực thi (chặn IP — MOCK) và ghi nhật ký **không thể sửa lén**.
- 📂 [nodes.py:643 `node_action_executor`](../../../src/agent/nodes.py#L643) → [executor.py:292 `block_ip`](../../../src/response/executor.py#L292); chuỗi HMAC ở [executor.py:224](../../../src/response/executor.py#L224); dò giả mạo [executor.py:421 `verify_audit_trail_integrity`](../../../src/response/executor.py#L421).
- ⚙️ **HMAC-SHA256 móc-xích** `Hᵢ = HMAC(Dᵢ ‖ Hᵢ₋₁, K)` (kiểu blockchain) → sửa/xóa 1 dòng là gãy chuỗi.
- 👀 Bấm 1 thẻ cảnh báo trên Dashboard → xem thẻ *Audit HMAC*.
- ➡️ Ghi `audit_trail.db` + `threat_memory.db`.

### ⑪ Trí nhớ dài hạn + APT — `threat_memory.py`

- 🎯 **Bản chất:** nhớ uy tín IP qua thời gian + ghép tấn công rải rác nhiều ngày thành **chuỗi APT**.
- 📂 [threat_memory.py:447 `check_apt_chain`](../../../src/agent/threat_memory.py#L447) · [threat_memory.py:276 `get_ip_reputation`](../../../src/agent/threat_memory.py#L276).
- ⚙️ **SQLite**; reputation **decay** theo thời gian im lặng; cờ APT khi `COUNT(DISTINCT apt_day) ≥ 2`.
- 🔑 **Khép vòng:** `get_ip_reputation` được **Tier-1 đọc** (bước ③) → IP tiền sử xấu bị chặn ngay, khỏi tốn LLM lần sau.
- ➡️ Nuôi cả Tier-1 lẫn prompt Tier-2.

### ⑫ Vòng phản hồi + Dashboard — `feedback_listener.py` + `ui/app.py`

- 🎯 **Bản chất:** Tier-2 sinh luật → **người duyệt** → Tier-1 nạp nóng → lần sau chặn ở tốc độ cao (hệ "học"). Con người là chốt chặn cuối. Giao diện (UI) hiển thị tường minh mọi suy luận của Agent.
- 📂 [feedback_listener.py:126 `receive_new_rule`](../../../src/tier1_filter/feedback_listener.py#L126) → [feedback_listener.py:272 `approve_rule`](../../../src/tier1_filter/feedback_listener.py#L272); UI ở [ui/app.py](../../../src/ui/app.py) và [components.py](../../../src/ui/components.py) (nơi bóc tách nhãn MITRE tự suy luận).
- ⚙️ Ghi `system_settings.yaml` atomic + FileLock; **Tier-1 hot-reload theo mtime mỗi 5s**; Dashboard **Streamlit** tự động render thẻ badge **🤖 AI Tự Suy Đoán** nếu phát hiện log không khớp RAG.
- 👀 Đăng nhập `manager` → **Approve** 1 rule → thấy nó thành ACTIVE. Xem log cảnh báo để thấy đoạn lập luận ngôn ngữ tự nhiên.
- ➡️ Quay lại ③ (Tier-1) — **vòng khép kín**.

---

## 3. Tra ngược — "bị hỏi X thì mở file nào?"

| Câu hỏi hội đồng | Câu trả lời nằm ở |
| --- | --- |
| Zero-day phát hiện thế nào? | `rule_engine.py` `RunningStats` (Welford) + `evaluate()` lớp Z-score |
| Cổng ML quyết ra sao? | `ml_gateway.py:115` `evaluate()` + `decision_policy.py:72` `classify_ml` (4 dải) |
| Sao không bị prompt-injection? | `prompt_filter.py` (nonce) + `decision_validator.py:151` (`enforce_tier_consensus`) |
| LLM bịa thì sao? | `retriever.py:144` (RAG grounding) + validator |
| Chống sửa nhật ký? | `executor.py:224/421` (HMAC chain) |
| Phát hiện APT đa-ngày? | `threat_memory.py:447` (`check_apt_chain`) |
| Hệ "học" ra sao? | `feedback_listener.py:126` → Tier-1 hot-reload |
| Vì sao nhanh hơn LLM-only? | ④ định tuyến + ⑤ Cổng ML (chỉ ca ML bỏ ngỏ gọi LLM) + `experiments/measure_latency_baseline.py` (−82.97%) |
| LLM chết có sập không? | `nodes.py:240` (try/except → `AWAIT_HITL`) |

---

## 4. Bỏ qua lúc đầu (đọc sau khi đã nắm luồng)

- `experiments/*` — benchmark/rigor sinh số liệu luận văn (KHÔNG chạy runtime). Xem [codebase_summary.md](codebase_summary.md) §"Ngoài luồng".
- `demos/*`, `scripts/fetch_*`, `scripts/build_*` — dựng dữ liệu & minh họa.
- `src/guardrails/*` còn lại (`data_validator`, `state_monitor`, `constants`) — tiện ích bọc quanh, đọc khi cần chi tiết bảo mật.
- Neo4j `graph_builder.py` — Knowledge Graph V2 **tùy chọn**, luồng lõi không phụ thuộc.

## 5. Ba mạch đọc theo mục tiêu

- **Hiểu luồng để giải thích (bạn ở đây):** đọc §0 → 12 điểm dừng ①–⑫.
- **Hiểu tuyến phòng thủ bảo mật:** ⑦ consensus → ⑧ RAG checksum → ⑩ HMAC → `prompt_filter.py`/`output_sanitizer.py` (Phần B [codebase_summary.md](codebase_summary.md)).
- **Hiểu thực nghiệm/số liệu:** [RUN_PROJECT.md §3](../guides/RUN_PROJECT.md) → `evaluate_unified_stream.py` → `run_ablation.py`.

> **Kiểm tra bản thân:** giải thích lại được chuỗi `log → ③ Tier-1 (Welford) → ④ ESCALATE → ⑤ Cổng ML → ⑥ đồ thị → ⑦ LLM+consensus → ⑩ HMAC → ⑪ APT → ⑫ feedback` bằng lời của bạn là **đã hiểu hệ thống**.
