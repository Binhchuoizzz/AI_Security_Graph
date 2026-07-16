# 🧭 Bắt đầu từ đâu — Đọc code SENTINEL theo LUỒNG (không bị ngợp)

> Bạn KHÔNG cần đọc hết 37 file `src/`. Chỉ cần **bám theo hành trình của MỘT bản ghi log** đi qua hệ thống — mỗi điểm dừng học **1 khái niệm + 1 công nghệ + 1 hàm cốt lõi**, rồi chạy 1 lệnh để **thấy tận mắt**. Đọc xong 11 điểm dừng dưới đây là đủ hiểu + giải thích được toàn hệ.
>
> Tài liệu bạn đọc: **file này** (đọc code theo luồng) → [codebase_summary.md](codebase_summary.md) (bản đồ file→vai trò) → [RUN_PROJECT.md](../guides/RUN_PROJECT.md) (cách chạy).

---

## 0. Mô hình tư duy trong 60 giây (đọc trước khi mở code)

SENTINEL giải **1 bài toán**: SOC bị ngập cảnh báo (alert fatigue), mà đưa MỌI log qua LLM thì quá chậm (4–6s/log) và LLM lại **bị tấn công thao túng được**. Giải pháp = **2 tầng**:

- **Tier-1** (tất định, ~0.6ms/log): luật + thống kê **Welford** lọc ~90% log ở "tốc độ đường truyền". Chỉ phần **mơ hồ** mới leo thang.
- **Tier-2** (nhận thức, ~15s/lô): tác tử **LangGraph** chạy LLM **Gemma-2-9B cục bộ** + **Dual-RAG** (MITRE/NIST) để suy luận có căn cứ, rồi hành động.

Mấu chốt: **tầng LLM nằm NGOÀI đường chặn đồng bộ** → LLM nghẽn thì chỉ chậm phần làm-giàu-ngữ-cảnh, KHÔNG chậm việc bảo vệ. Và **Tier-1 (không thể bị thuyết phục) làm trọng tài kiểm tra Tier-2** — nếu LLM bị lừa hạ cấp tấn công thành lành tính, hệ ép về con người duyệt.

> Giữ đúng 1 hình trong đầu: `log → Tier-1 lọc → (chỉ ca khó) Tier-2 suy luận → hành động + học ngược về Tier-1`. Mọi file đều rơi vào 1 mắt xích của chuỗi này.

---

## 1. Cách đọc repo này (mẹo chống ngợp)

1. **Mở IDE + file này song song.** Mỗi điểm dừng có link `file.py:dòng` — bấm để nhảy thẳng tới **đúng 1 hàm**, đọc hàm đó thôi, đừng đọc cả file.
2. **Chạy demo trước, đọc code sau.** `./scripts/run_demo.sh --small` rồi mở `http://localhost:8501` — thấy hệ chạy rồi đọc code sẽ "khớp" ngay.
3. **Bỏ qua 3 nhóm file lúc đầu:** `experiments/` (benchmark), `demos/`, `scripts/` build dataset — chúng KHÔNG nằm trong luồng runtime (xem §Bỏ qua cuối bài).
4. **Đọc theo thứ tự 11 điểm dừng dưới** — chính là thứ tự 1 log đi qua hệ thống.

---

## 2. Hành trình 1 bản ghi log — 11 điểm dừng

Mỗi điểm: 🎯 bản chất · 📂 hàm cốt lõi (bấm vào) · ⚙️ công nghệ · 👀 thấy tận mắt · ➡️ đưa cho ai.

### ① Điểm vào hệ thống — `main.py`

- 🎯 **Bản chất:** nơi bật "trái tim". Mode `server` = khởi động vòng lặp subscriber; escalate thì gọi Agent.
- 📂 [main.py:82 `main()`](../../../main.py#L82) → [main.py:124 gọi `start_listening(...)`](../../../main.py#L124) với callback [main.py:50 `handle_escalated_batch`](../../../main.py#L50).
- ⚙️ `argparse` (server/scan/full). Dashboard chạy RIÊNG qua Docker, không ở đây.
- 👀 `.venv/bin/python main.py --mode server --log-level INFO`
- ➡️ Trao quyền cho **subscriber**.

### ② Tiêu thụ log từ hàng đợi — `subscriber.py`

- 🎯 **Bản chất:** đọc log từ Redis theo lô, gọi Tier-1 cho từng log, rồi định tuyến. Cũng đếm số liệu Noise-Reduction thật + phát hiện APT emergent.
- 📂 [subscriber.py:102 `start_listening()`](../../../src/streaming/subscriber.py#L102) — vòng lặp chính ở [subscriber.py:242 `xreadgroup`](../../../src/streaming/subscriber.py#L242).
- ⚙️ **Redis Streams** + consumer-group `sentinel_group` (nhiều consumer chia tải, at-least-once).
- 👀 `docker exec sentinel_redis redis-cli -a '...' XLEN queue_waf`
- ➡️ Mỗi log → `RuleEngine.evaluate(log)`.

### ③ Tier-1 — bộ lọc tốc độ đường truyền · `rule_engine.py` *(TRÁI TIM 1)*

- 🎯 **Bản chất:** 7 lớp tất định O(1) quyết định số phận mỗi log. Điểm hay nhất: **Welford** bắt zero-day KHÔNG cần mẫu tấn công.
- 📂 [rule_engine.py:562 `evaluate()`](../../../src/tier1_filter/rule_engine.py#L562) — đọc **theo thứ tự các lớp** (Whitelist → WAF sig → Injection sig → **Welford Z-score** → static → dynamic → session). Rồi mở lớp Welford: [rule_engine.py:35 `class RunningStats`](../../../src/tier1_filter/rule_engine.py#L35) (cập nhật μ, M2 online) + [rule_engine.py:420 `_seed_golden_baseline`](../../../src/tier1_filter/rule_engine.py#L420) (seed 300 flow benign).
- ⚙️ Thuật toán **Welford** (phương sai online O(1) RAM); regex biên dịch sẵn.
- 🔑 **Ý cốt lõi:** lệch > **3.5σ** → cờ zero-day; tổng điểm ≥ **15** → `ESCALATE`. Chỉ flow benign (DROP/LOG) mới cập nhật baseline (chống đầu độc).
- 👀 `.venv/bin/python demos/demo_tier1.py`
- ➡️ Trả `tier1_action` cho subscriber định tuyến.

### ④ Định tuyến 6 hành động — (trong `subscriber.py`)

- 🎯 **Bản chất:** `DROP/LOG` (bỏ, không phiền LLM) · `BLOCK_IP` (chặn ngay) · `AWAIT_HITL` (chờ người) · `ALERT` · **`ESCALATE`** (gom lô → Agent). **Chỉ ESCALATE mới tốn LLM** — đây là lý do hệ nhanh.
- 📂 Quay lại vòng định tuyến trong [subscriber.py:242+](../../../src/streaming/subscriber.py#L242).
- ➡️ Lô ESCALATE → `agent_app.invoke(...)`.

### ⑤ Đồ thị tác tử — `workflow.py` *(TRÁI TIM 2)*

- 🎯 **Bản chất:** Tier-2 KHÔNG phải "gọi LLM 1 phát". Nó là **máy trạng thái 6 nút** (DAG, không loop, không tool-calling) — LLM chỉ là 1 nút.
- 📂 [workflow.py:26 `create_agent_workflow()`](../../../src/agent/workflow.py#L26) — đọc thứ tự `add_node` + 2 `add_conditional_edges`. Singleton [workflow.py:88 `agent_app`](../../../src/agent/workflow.py#L88).
- ⚙️ **LangGraph** `StateGraph`; trạng thái = `SentinelState` (dataclass).
- 🔑 Luồng: `guardrails → rag_context → llm_triage →` **rẽ theo ACTION** `→ attack_mapper → action_executor / human_in_the_loop / END`.
- ➡️ Vào từng nút ở `nodes.py`.

### ⑥ Bộ não — `node_llm_triage` · `nodes.py`

- 🎯 **Bản chất:** dựng prompt → gọi LLM → **KHÔNG tin ngay**: kiểm chứng bằng validator + lá chắn đồng thuận, rồi mới ghi. LLM chết → suy biến an toàn về `AWAIT_HITL`.
- 📂 [nodes.py:132 `node_llm_triage`](../../../src/agent/nodes.py#L132). Kèm: [prompts.py:124 `build_triage_prompt`](../../../src/agent/prompts.py#L124) · [llm_client.py:65 `invoke`](../../../src/agent/llm_client.py#L65) · [decision_validator.py:148 `enforce_tier_consensus`](../../../src/guardrails/decision_validator.py#L148).
- ⚙️ **Gemma-2-9B-IT Q6_K** qua **llama.cpp** (OpenAI API), temp 0.1 + **seed 42** → tất định.
- 🔑 **Prompt Engineering nâng cao:** LLM bị ép phân tích chuỗi tấn công (Attack Chain) theo trình tự thời gian và đếm số lượng hành vi. Nó bắt buộc viết lý do bằng **ngôn ngữ tự nhiên (storytelling)** của chuyên gia SOC. Nếu gặp Zero-day không có trong RAG, nó được phép **Tự suy luận** kỹ thuật gần nhất, gắn nhãn `[Tự suy luận]`, và cấm ảo tưởng (hallucinate) các bước không có thật.
- 🔑 **`enforce_tier_consensus`** = tinh túy bảo mật: Tier-1 nói tấn công mà LLM hạ xuống LOG/DROP → hệ KHÔNG tin LLM, ép `AWAIT_HITL`.
- ➡️ Threat verdict → `node_attack_mapper`; benign → kết thúc.

### ⑦ Dual-RAG — `retriever.py`

- 🎯 **Bản chất:** để LLM không "bịa" technique/playbook, ta nạp ngữ cảnh THẬT từ MITRE + NIST. Kết hợp tìm-theo-nghĩa và tìm-theo-từ-khóa.
- 📂 [retriever.py:144 `_hybrid_search()`](../../../src/rag/retriever.py#L144) (gọi trong node [nodes.py:82 `node_rag_context`](../../../src/agent/nodes.py#L82)).
- ⚙️ **FAISS** (all-MiniLM-L6-v2, cosine) + **BM25** hợp nhất bằng **RRF k=60**; checksum SHA-256 fail-closed chống KB poisoning.
- 🔑 **Ý RRF:** gộp 2 bảng xếp hạng chỉ theo THỨ HẠNG `R(d)=Σ 1/(k+rank)` → khỏi cân 2 thang điểm khác nhau.
- 👀 `.venv/bin/python demos/demo_rag.py`
- ➡️ Ngữ cảnh ghép vào prompt ở bước ⑥.

### ⑧ Cấu trúc hóa MITRE — `node_attack_mapper` · `attack_mapper.py`

- 🎯 **Bản chất:** biến nhãn tự do "phát hiện SQLi" của LLM → bản ghi ATT&CK kiểm chứng được (tactic/technique/URL/response).
- 📂 [nodes.py:328 `node_attack_mapper`](../../../src/agent/nodes.py#L328) → `map_attack()` trong [attack_mapper.py](../../../src/agent/attack_mapper.py).
- ⚙️ **Pydantic** (schema luôn hợp lệ); 3 đường: curated (tra bảng) / anchor / RRF+LLM-select.
- ➡️ Quyết định đã làm giàu → executor.

### ⑨ Hành động + Audit chống giả mạo — `executor.py`

- 🎯 **Bản chất:** thực thi (chặn IP — MOCK) và ghi nhật ký **không thể sửa lén**.
- 📂 [nodes.py:508 `node_action_executor`](../../../src/agent/nodes.py#L508) → [executor.py:233 `block_ip`](../../../src/response/executor.py#L233); chuỗi HMAC ở [executor.py:193](../../../src/response/executor.py#L193); dò giả mạo [executor.py:311 `verify_audit_trail_integrity`](../../../src/response/executor.py#L311).
- ⚙️ **HMAC-SHA256 móc-xích** `Hᵢ = HMAC(Dᵢ ‖ Hᵢ₋₁, K)` (kiểu blockchain) → sửa/xóa 1 dòng là gãy chuỗi.
- 👀 Bấm 1 thẻ cảnh báo trên Dashboard → xem thẻ *Audit HMAC*.
- ➡️ Ghi `audit_trail.db` + `threat_memory.db`.

### ⑩ Trí nhớ dài hạn + APT — `threat_memory.py`

- 🎯 **Bản chất:** nhớ uy tín IP qua thời gian + ghép tấn công rải rác nhiều ngày thành **chuỗi APT**.
- 📂 [threat_memory.py:365 `check_apt_chain`](../../../src/agent/threat_memory.py#L365) · [threat_memory.py:205 `get_ip_reputation`](../../../src/agent/threat_memory.py#L205).
- ⚙️ **SQLite**; reputation **decay** theo thời gian im lặng; cờ APT khi `COUNT(DISTINCT apt_day) ≥ 2`.
- 🔑 **Khép vòng:** `get_ip_reputation` được **Tier-1 đọc** (bước ③) → IP tiền sử xấu bị chặn ngay, khỏi tốn LLM lần sau.
- ➡️ Nuôi cả Tier-1 lẫn prompt Tier-2.

### ⑪ Vòng phản hồi + Dashboard — `feedback_listener.py` + `ui/app.py`

- 🎯 **Bản chất:** Tier-2 sinh luật → **người duyệt** → Tier-1 nạp nóng → lần sau chặn ở tốc độ cao (hệ "học"). Con người là chốt chặn cuối. Giao diện (UI) hiển thị tường minh mọi suy luận của Agent.
- 📂 [feedback_listener.py:97 `receive_new_rule`](../../../src/tier1_filter/feedback_listener.py#L97) → [feedback_listener.py:237 `approve_rule`](../../../src/tier1_filter/feedback_listener.py#L237); UI ở [ui/app.py](../../../src/ui/app.py) và [components.py](../../../src/ui/components.py) (nơi bóc tách nhãn MITRE tự suy luận).
- ⚙️ Ghi `system_settings.yaml` atomic + FileLock; **Tier-1 hot-reload theo mtime mỗi 5s**; Dashboard **Streamlit** tự động render thẻ badge **🤖 AI Tự Suy Đoán** nếu phát hiện log không khớp RAG.
- 👀 Đăng nhập `manager` → **Approve** 1 rule → thấy nó thành ACTIVE. Xem log cảnh báo để thấy đoạn lập luận ngôn ngữ tự nhiên.
- ➡️ Quay lại ③ (Tier-1) — **vòng khép kín**.

---

## 3. Tra ngược — "bị hỏi X thì mở file nào?"

| Câu hỏi hội đồng | Câu trả lời nằm ở |
|---|---|
| Zero-day phát hiện thế nào? | `rule_engine.py` `RunningStats` (Welford) + `evaluate()` lớp Z-score |
| Sao không bị prompt-injection? | `prompt_filter.py` (nonce) + `decision_validator.py:148` (`enforce_tier_consensus`) |
| LLM bịa thì sao? | `retriever.py:144` (RAG grounding) + validator |
| Chống sửa nhật ký? | `executor.py:193/311` (HMAC chain) |
| Phát hiện APT đa-ngày? | `threat_memory.py:365` (`check_apt_chain`) |
| Hệ "học" ra sao? | `feedback_listener.py:97` → Tier-1 hot-reload |
| Vì sao nhanh hơn LLM-only? | ④ định tuyến (chỉ ESCALATE gọi LLM) + `measure_latency_baseline.py` (−82.97%) |
| LLM chết có sập không? | `nodes.py:132` (try/except → `AWAIT_HITL`) |

---

## 4. Bỏ qua lúc đầu (đọc sau khi đã nắm luồng)

- `experiments/*` — benchmark/rigor sinh số liệu luận văn (KHÔNG chạy runtime). Xem [codebase_summary.md](codebase_summary.md) §"Ngoài luồng".
- `demos/*`, `scripts/fetch_*`, `scripts/build_*` — dựng dữ liệu & minh họa.
- `src/guardrails/*` còn lại (`data_validator`, `state_monitor`, `constants`) — tiện ích bọc quanh, đọc khi cần chi tiết bảo mật.
- Neo4j `graph_builder.py` — Knowledge Graph V2 **tùy chọn**, luồng lõi không phụ thuộc.

## 5. Ba mạch đọc theo mục tiêu

- **Hiểu luồng để giải thích (bạn ở đây):** đọc §0 → 11 điểm dừng ①–⑪.
- **Hiểu tuyến phòng thủ bảo mật:** ⑥ consensus → ⑦ RAG checksum → ⑨ HMAC → `prompt_filter.py`/`output_sanitizer.py` (Phần B [codebase_summary.md](codebase_summary.md)).
- **Hiểu thực nghiệm/số liệu:** [RUN_PROJECT.md §3](../guides/RUN_PROJECT.md) → `evaluate_unified_stream.py` → `run_ablation.py`.

> **Kiểm tra bản thân:** giải thích lại được chuỗi `log → ③ Tier-1 (Welford) → ④ ESCALATE → ⑤ đồ thị → ⑥ LLM+consensus → ⑨ HMAC → ⑩ APT → ⑪ feedback` bằng lời của bạn là **đã hiểu hệ thống**.
