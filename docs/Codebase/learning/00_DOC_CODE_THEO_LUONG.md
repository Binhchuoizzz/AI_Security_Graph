# 🧭 Bắt đầu từ đâu — Đọc code SENTINEL theo LUỒNG (không bị ngợp)

> Bạn KHÔNG cần đọc hết ~40 file `src/`. Chỉ cần **bám theo hành trình của MỘT bản ghi log** đi qua hệ thống — mỗi điểm dừng học **1 khái niệm + 1 công nghệ + 1 hàm cốt lõi**, rồi chạy 1 lệnh để **thấy tận mắt**. Đọc xong 12 điểm dừng dưới đây là đủ hiểu + giải thích được toàn hệ.
>
> Tài liệu bạn đọc: **file này** (đọc code theo luồng) → [RUN_PROJECT.md](../guides/RUN_PROJECT.md) (cách chạy).

---

## 0. Mô hình tư duy trong 60 giây (đọc trước khi mở code)

SENTINEL giải **1 bài toán**: SOC bị ngập cảnh báo (alert fatigue), mà đưa MỌI log qua LLM thì quá chậm (4–6s/log) và LLM lại **bị tấn công thao túng được**. Giải pháp = **2 tầng**, có **Cổng ML** làm van giảm tải ở giữa:

- **Tier-1** (tất định, ~0.1ms/log): luật + thống kê **Welford** lọc phần lớn log ở "tốc độ đường truyền". Chỉ phần **mơ hồ** mới leo thang (`ESCALATE`).
- **Cổng ML** (LightGBM, ~0.3ms): ca `ESCALATE` đi qua đây TRƯỚC — chấm xác suất tấn công rồi tự quyết **68,19% số ca ESCALATE** (Chặn/Báo/Thả) mà **KHÔNG cần LLM**; chỉ ca ML "bỏ ngỏ" mới lên Tier-2. ⚠️ **68,19% này KHÁC mẫu số với 97,5% xả tải trên slide** — xem **§7 (Số nào là số nào)** ở cuối tài liệu trước khi trả lời hội đồng.
- **Tier-2** (nhận thức, ~vài giây/lô): tác tử **LangGraph** chạy LLM **Foundation-Sec-8B cục bộ** + **Dual-RAG** (MITRE/NIST) để suy luận có căn cứ, rồi hành động.

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

- 🎯 **Bản chất:** ca `ESCALATE` (Tier-1 thấy đáng ngờ nhưng chưa chắc) đi qua **LightGBM**: chấm `P(tấn công)` rồi tự quyết **68,19%** (Chặn/Báo/Thả) mà **KHÔNG gọi LLM**; chỉ ca ML "bỏ ngỏ" (dải `ESCALATE`) mới lên Tier-2. Đây là van cắt ~3× chi phí LLM.
- 📂 subscriber gọi [ml_gateway.py:115 `evaluate()`](../../../src/tier1_filter/ml_gateway.py#L115) tại [subscriber.py:370](../../../src/streaming/subscriber.py#L370); lõi phân dải [decision_policy.py:72 `classify_ml`](../../../src/guardrails/decision_policy.py#L72); mô hình nạp ở [ml_gateway.py:46 `class MLGateway`](../../../src/tier1_filter/ml_gateway.py#L46).
- ⚙️ **LightGBM** (full-feature, `predict_proba`) + **4 dải confidence** (`classify_ml`): `BLOCK_IP` ≥0.85 · `ESCALATE` 0.65–0.85 (→ LLM) · `ALERT` 0.40–0.65 (IP tái phạm → tự BLOCK) · `DROP` <0.40.
- 🔑 **Ý cốt lõi:** giảm tải LLM **68,19%** (761/1.116 ca), precision trên phần tự quyết **98,82%**; kháng né-tránh **98,75%** (chế độ KHÓ `extreme_broad`, 1.023/1.036). ML tự tin chặn → block-on-sight qua reputation.
- ⚠️ **Ba số trên lấy từ `ml_gate_results.json` / `ablation_mlgate_results.json` lượt 06/08/2026.** Bản tài liệu trước ghi 83,8% · 99,58% — đó là lượt đo cũ trên mẫu số khác. Đọc số ở tệp JSON, đừng đọc ở tài liệu.
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
- ⚙️ **Foundation-Sec-8B-Instruct Q4_K_M** qua **llama.cpp** (OpenAI API), temp 0.1 + **seed 42** → tất định. **`response_format=DECISION_JSON_SCHEMA`** (constrained decoding) ép server xuất **JSON HỢP LỆ** → dứt điểm "parse lỗi/prose bị cắt cụt", và reasoning đi thẳng field nên **bám tiếng Việt** đúng chỉ dẫn prompt.
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

### ⑫ Vòng phản hồi + Dashboard — `feedback_listener.py` + `app.py`

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
| Vì sao nhanh hơn LLM-only? | ④ định tuyến + ⑤ Cổng ML (chỉ ca ML bỏ ngỏ gọi LLM) + `experiments/measure_latency_baseline.py` (trung bình **−69,24%**, trung vị 17.174,7 → **0,88 ms**; 🔴 **p95 xấu đi**: 25.829 vs 21.434 ms) |
| LLM chết có sập không? | `nodes.py:240` (try/except → `AWAIT_HITL`) |
| LLM nói tấn công mà không có bằng chứng? | `nodes.py:1305` (`unverified_llm_claim` → `AWAIT_HITL`) + `nodes.py:1779` (`_shield_dest`) |
| Nhận diện prompt-injection bằng gì? | `llm_attack_signatures.py:190` `detect_families` (10 họ theo **cấu trúc ngữ pháp**, không phải danh sách từ khoá) |
| Ngưỡng chặn/báo/hoãn ai định? | `decision_policy.py:155` `classify_ml` + `:169` `classify_llm` — **một nguồn chân lý** cho cả 2 tầng |
| ML gặp dữ liệu lạ thì sao? | `ml_gateway.py:38` `OOD_SIGMA=6.0` / `OOD_FRACTION=0.30` → **từ chối trả lời**, đẩy lên LLM |
| Làm sao biết không mất log? | `backpressure.py:22` `LAG_UNKNOWN` (fail-closed) + `scripts/demo.py` `_verify_no_loss` |
| Khoá HMAC nằm ở đâu? | `executor.py:49` `_log_secret` (đọc `.env`) + `:73` `audit_key_is_default` cảnh báo khi chưa đặt |

---

## 4. Bỏ qua lúc đầu (đọc sau khi đã nắm luồng)

- `experiments/*` — benchmark/rigor sinh số liệu luận văn (KHÔNG chạy runtime). Xem `experiments/README.md`.
- `demos/*`, `scripts/fetch_*`, `scripts/build_*` — dựng dữ liệu & minh họa.
- `src/guardrails/*` còn lại (`data_validator`, `state_monitor`, `constants`) — tiện ích bọc quanh, đọc khi cần chi tiết bảo mật.
- Neo4j `graph_builder.py` — Knowledge Graph V2 **tùy chọn**, luồng lõi không phụ thuộc.

## 5. Ba mạch đọc theo mục tiêu

- **Hiểu luồng để giải thích (bạn ở đây):** đọc §0 → 12 điểm dừng ①–⑫.
- **Hiểu tuyến phòng thủ bảo mật:** ⑦ consensus → ⑧ RAG checksum → ⑩ HMAC → `prompt_filter.py`/`output_sanitizer.py` .
- **Hiểu thực nghiệm/số liệu:** [DEMO_BY_RQ.md](../guides/DEMO_BY_RQ.md) → `evaluate_unified_stream.py` → `run_ablation.py`.

> **Kiểm tra bản thân:** giải thích lại được chuỗi `log → ③ Tier-1 (Welford) → ④ ESCALATE → ⑤ Cổng ML → ⑥ đồ thị → ⑦ LLM+consensus → ⑩ HMAC → ⑪ APT → ⑫ feedback` bằng lời của bạn là **đã hiểu hệ thống**.

---

## 6. Tám chỗ code dễ bị soi nhất — mở đúng dòng, nói đúng điểm yếu

> Mỗi mục có ba phần: **hội đồng hỏi gì** · **mở dòng nào** · **điểm yếu thật + câu trả lời
> trung thực**. Phần thứ ba mới là phần quan trọng: chỗ nào có điểm yếu thì **nói trước khi
> bị hỏi**, đừng để bị bắt.

### 6.1 · Welford và ngưỡng 3,5σ — chỗ bị soi nhiều nhất

- **Hỏi:** *"Vì sao 3,5 sigma mà không phải 3? Baseline lấy từ đâu?"*
- **Mở:** [rule_engine.py:35 `RunningStats`](../../../src/tier1_filter/rule_engine.py#L35) · [rule_engine.py:450 `_seed_golden_baseline`](../../../src/tier1_filter/rule_engine.py#L450)
- **Nói:** Welford cập nhật μ và M2 **online O(1)**, không giữ lịch sử, ổn định số học hơn công thức tổng-bình-phương. Baseline seed từ 300 flow lành, và **chỉ flow benign mới được cập nhật baseline** — chống đầu độc mốc.
- ⚠️ **Điểm yếu phải tự nêu:**
  - Đặc trưng `Init Fwd Win Byts` dùng **`-1` làm giá trị "không đo được"**. Giá trị sentinel đó bị gộp vào thống kê thật, nên cửa sổ TCP tiêu chuẩn 64240 đọc ra **6,4σ thay vì 0,14σ** → Tầng 1 chặn nhầm. Đây là nguyên nhân gốc khiến **nhánh chặn bằng luật tĩnh chỉ đạt 31,13% độ chính xác**, trong khi nhánh qua Cổng ML + LLM đạt **99,84%**.
  - Z-score **phụ thuộc thứ tự nạp**: cùng 18 mẫu vùng xám cho ra 3 kết quả khác nhau tuỳ thứ tự. Vì vậy **chỉ trích số Tầng 1 từ lượt chạy sống**, không trích từ lượt dựng lại.
- **Câu trả lời gọn:** *"Đây là hạn chế em phát hiện được và đã ghi vào Chương 5. Giá trị sentinel âm lẫn vào mốc thống kê là lỗi tầng đo lường, không phải lỗi thuật toán Welford."*

### 6.2 · Luật tốc độ so-với-người-khác (leave-one-out) — chỗ nên khoe

- **Hỏi:** *"Một IP bắn nhanh thì so với cái gì mà biết là nhanh?"*
- **Mở:** [rule_engine.py:686–701](../../../src/tier1_filter/rule_engine.py#L686)
- **Nói:** Bản ngây thơ so tốc độ của một IP với **trung bình có chứa chính nó** — một IP nặng duy nhất tự kéo mốc lên, chỉ báo chết. Bản hiện tại **trừ chính nó ra** khỏi mẫu số:
  `_others = (_rate_sum - request_rate) / (_rate_n - 1)`, kèm **sàn** `_MIN_NORMAL_RATE = 1.0` và **tối thiểu 3 mẫu** (`_MIN_RATE_SAMPLES`) mới kết luận.
- **Vì sao đáng nói:** đây là bằng chứng bạn hiểu bẫy thống kê, không chỉ gọi thư viện.

### 6.3 · Cổng ML biết-mình-không-biết

- **Hỏi:** *"Log không giống dữ liệu huấn luyện thì mô hình đoán bừa à?"*
- **Mở:** [ml_gateway.py:38 `OOD_SIGMA` / `OOD_FRACTION`](../../../src/tier1_filter/ml_gateway.py#L38) · [ml_gateway.py:235](../../../src/tier1_filter/ml_gateway.py#L235)
- **Nói:** Ba lớp chống đầu vào lạ — (1) **sanitize** NaN/±Inf về mean, (2) **kẹp** z-score để một đặc trưng cực đoan không lái được dự đoán, (3) **từ chối trả lời**: quá **30% đặc trưng lệch quá 6σ**, hoặc log thiếu quá nhiều trong 76 đặc trưng CICIDS → **không đoán**, đẩy thẳng lên LLM.
- **Ví dụ cụ thể để nói:** *"Log DAPT chỉ có khoảng 1 trên 76 đặc trưng. Nếu không có lớp này thì vector gần như toàn giá trị trung bình và dự đoán vô nghĩa."*

### 6.4 · Bốn dải tin cậy — một nguồn chân lý cho cả hai tầng

- **Hỏi:** *"Ngưỡng 0,85 ai chọn? Tầng ML và tầng LLM có dùng chung không?"*
- **Mở:** [decision_policy.py:155 `classify_ml`](../../../src/guardrails/decision_policy.py#L155) · [decision_policy.py:169 `classify_llm`](../../../src/guardrails/decision_policy.py#L169)
- **Nói:** Cả hai tầng gọi **cùng một mô-đun**. Trước đây LLM tự chọn hành động nên có ca `confidence 0,75` mà vẫn ra `BLOCK`; giờ **độ tin cậy lái hành động**, không phải mô hình tự chọn. Đặt chung một nơi để hai tầng không trôi lệch nhau theo thời gian.
- **Nếu bị hỏi vì sao đúng 0,85:** *"Quét ngưỡng cho thấy dải 0,70–0,85 phẳng, trên 0,90 thì tụt. Em chọn mép trên của vùng phẳng. Kết quả quét nằm ở Chương 3."*

### 6.5 · Chống prompt injection theo **cấu trúc**, không theo từ khoá

- **Hỏi:** *"Chống prompt injection bằng danh sách đen à? Đổi chữ là qua?"*
- **Mở:** [llm_attack_signatures.py:190 `detect_families`](../../../src/guardrails/llm_attack_signatures.py#L190) · [llm_attack_signatures.py:198 `classify`](../../../src/guardrails/llm_attack_signatures.py#L198) · nối vào bộ lọc tại [prompt_filter.py:253](../../../src/guardrails/prompt_filter.py#L253)
- **Nói:** Danh sách 14 cụm từ cũ **trượt 84,2% mẫu injection và 30,5% mẫu jailbreak**. Bản hiện tại nhận dạng **10 họ theo cấu trúc ngữ pháp** — ghi đè chỉ dẫn, cướp nhiệm vụ, moi lời nhắc hệ thống, tiêm dấu phân định (`AML.T0051`); chiếm vai, gỡ ràng buộc, dập từ chối (`AML.T0054`). Khi cả hai cùng khớp thì **T0051 thắng**.
- **Chi tiết đắt giá nếu bị soi sâu:** họ `act as` bắt buộc phải có **đại từ ngôi hai** đi kèm, nếu không thì câu lành *"will act as a backup"* cũng bị gắn cờ. Kết quả: **0 báo nhầm trên 36.000 bản ghi CSIC**.
- ⚠️ **Điểm yếu tự nêu:** bộ nhận dạng này **chỉ làm việc trên tiếng Anh**.

### 6.6 · Lá chắn neo bằng chứng — và vì sao có `_shield_dest`

- **Hỏi:** *"LLM bịa mã kỹ thuật thì sao? Ai chặn?"*
- **Mở:** [nodes.py:1305 `unverified_llm_claim`](../../../src/agent/nodes.py#L1305) · [nodes.py:1763 `_apply_shield_action`](../../../src/agent/nodes.py#L1763) · [nodes.py:1779 `_shield_dest`](../../../src/agent/nodes.py#L1779)
- **Nói:** Bản cũ **hạ trần độ tin cậy xuống 0,84** — một cái phủ quyết bằng số, mập mờ. Bản hiện tại ra **quyết định định tuyến tường minh**: không neo được bằng chứng → `AWAIT_HITL` kèm lý do `unverified_llm_claim`.
- **Chi tiết đắt giá:** `_shield_dest` sinh ra vì lá chắn từng **in ra một đằng, định tuyến một nẻo** — 126/126 lần nó viết *"chuyển người xử lý"* trong khi thực tế đẩy về `ALERT`. Giờ câu chữ được suy ra từ **hành động cuối cùng**, không phải từ ý định ban đầu.
- **Vì sao đáng khoe:** *"Văn bản giải thích cho chuyên viên mà nói sai hành động thật thì còn nguy hiểm hơn không giải thích."*

### 6.7 · Toàn vẹn HMAC và khoá bí mật

- **Hỏi:** *"Khoá ký để đâu? Hardcode trong code à?"*
- **Mở:** [executor.py:49 `_log_secret`](../../../src/response/executor.py#L49) · [executor.py:73 `audit_key_is_default`](../../../src/response/executor.py#L73) · chuỗi băm [executor.py:224](../../../src/response/executor.py#L224)
- **Nói:** Khoá đọc từ biến môi trường `SENTINEL_LOG_SECRET` trong `.env` (**đã đặt** trên máy demo). Có giá trị dự phòng trong mã, nhưng hệ **tự phát hiện và ghi cảnh báo lớn** khi rơi vào dự phòng: lúc đó chuỗi chỉ chống sửa đổi vô tình, **không chống được kẻ đọc được mã nguồn**.
- **Bonus nếu ai hỏi OWASP LLM06 (Excessive Agency):** mở khối chú thích [executor.py:53–70](../../../src/response/executor.py#L53). Ở đó ghi rõ cặp hàm `generate_action_token`/`verify_action_token` **đã bị gỡ** vì **không nơi nào gọi** — mã bảo mật chết mà tự xưng là lớp phòng vệ thì tệ hơn không có. Chốt chặn LLM06 **thật** đang chạy là: lá chắn neo bằng chứng, `sanitize_target`, đối chiếu whitelist trong `block_ip`, và hàng đợi HITL.
- ⚠️ **Điểm yếu tự nêu:** chuỗi móc xích **không phát hiện được cắt cụt đuôi** — chống sửa, không chống xoá phần cuối.

### 6.8 · Làm sao biết hệ **không mất log** (câu hỏi ít ai nghĩ tới nhưng chí mạng)

- **Hỏi:** *"Tỉ lệ xả tải 97,5% — mẫu số có chắc đúng không? Hệ có nuốt mất log nào không?"*
- **Mở:** [backpressure.py:22 `LAG_UNKNOWN`](../../../src/streaming/backpressure.py#L22) · [backpressure.py:25 `consumer_group_lag`](../../../src/streaming/backpressure.py#L25) · `_verify_no_loss` trong [scripts/demo.py](../../../scripts/demo.py)
- **Nói:** Van áp lực ngược từng **hỏng-mở**: khi chưa đọc được trạng thái nhóm tiêu thụ nó trả về 0, tức là "không tắc", nên cứ đẩy tiếp — **mất âm thầm 18,4% luồng**. Bản hiện tại **hỏng-đóng**: không biết thì trả `LAG_UNKNOWN`, coi như tắc nặng.
- **Chi tiết chí mạng để nói:** đo tồn đọng bằng `XLEN` là **sai**, vì `xack` không làm ngắn stream. Phải đo bằng **`lag` của consumer-group**. Và khi `MAXLEN` cắt bớt stream, Redis **đẩy `entries-read` lên theo**, nên cả `lag` lẫn `entries-added == entries-read` **đều trông khoẻ mạnh** dù đã mất dữ liệu — không thể dùng hai chỉ số đó để kết luận "không mất".
- **Chốt:** cuối mỗi lượt đẩy, `_verify_no_loss` đối chiếu số đã đẩy với số đã tiêu thụ và in thẳng `TOÀN VẸN` hoặc `MẤT LOG — mọi tỉ lệ tính trên lượt chạy này đều SAI MẪU SỐ`. Lượt chạy dùng cho luận văn in **496.885 / 496.885**.

---

## 7. Số nào là số nào — chống mâu thuẫn slide ↔ code

> **Đây là rủi ro số một của buổi bảo vệ.** Tài liệu này, slide, và Chương 4 có những con số
> **khác nhau mà đều đúng**, vì **mẫu số khác nhau**. Nếu bạn đọc nhầm mẫu số, hội đồng sẽ
> thấy bạn tự mâu thuẫn với chính mình.

| Con số | Là gì | **Mẫu số** | Xuất hiện ở |
| :-- | :-- | :-- | :-- |
| **97,5%** | xả tải **tổng** (Tầng 1 + Cổng ML) | luồng 99.717 sự kiện, nền tấn công **9,8%** | slide 15, Ch4 |
| **90,6%** | **cùng phép đo**, hỗn hợp khác | nền tấn công **31,56%** | slide 15, Ch4 |
| **68,19%** | **riêng Cổng ML** tự quyết | **761/1.116 ca `ESCALATE`** — không phải toàn luồng | §0 và ⑤ của tài liệu này |
| **962 / 0 FP** | số lệnh tự chặn của Cổng ML | ca có độ tin cậy **≥ 0,85** trong lượt demo | slide 15, ▶2 |
| **84,24%** | giảm khối lượng cho chuyên viên | **1.066 cảnh báo** vào hàng đợi phân loại | slide 15, ▶5 |
| **31,13% / 99,84%** | độ chính xác nhánh luật tĩnh / nhánh có kiểm toán | hai nhánh chặn khác nhau | slide 19 (giới hạn) |

**Ba quy tắc phát ngôn:**

1. **Mỗi con số luôn đi kèm mẫu số.** Nói *"68,19%"* trần trụi là mời hội đồng đối chiếu với 97,5% rồi hỏi *"rốt cuộc bao nhiêu?"*.
2. **97,5% và 68,19% không mâu thuẫn** — một cái là tỉ lệ trên **toàn luồng**, một cái là tỉ lệ trên **riêng nhóm `ESCALATE`**. Nếu bị hỏi, vẽ nhanh: `toàn luồng → Tầng 1 lọc → nhóm ESCALATE → Cổng ML quyết 68,19% nhóm này`.
3. **Số trong tài liệu code có thể cũ hơn số trong luận văn.** Quy tắc bất di bất dịch: **số để báo cáo lấy từ Chương 4 và tệp JSON kết quả, không lấy từ tài liệu hướng dẫn đọc code.**

> 🔴 **Bẫy đã gặp thật:** bản tài liệu trước ghi `83,8%` và `99,58%` cho Cổng ML — đó là lượt
> đo cũ trên **mẫu số khác**. Số hiện hành nằm ở `ml_gate_results.json` và
> `ablation_mlgate_results.json`. **Đọc số ở tệp JSON, đừng đọc ở tài liệu.**

---

## 8. Ba câu hỏi code khó nhất — và câu trả lời đã soạn

**① *"Đây có thật là tác tử không, hay chỉ là một lời gọi LLM có RAG?"***

> *"Là máy trạng thái sáu nút trên LangGraph, có hai cạnh rẽ nhánh theo điều kiện. LLM chỉ
> là **một** nút trong sáu. Em thừa nhận nó **không** có vòng lặp tự gọi công cụ — đây là đồ
> thị có hướng không chu trình, chọn có chủ đích: trong bối cảnh an ninh, một tác tử được
> phép lặp vô hạn là một rủi ro vận hành, không phải một tính năng."*
> Mở: [workflow.py:26](../../../src/agent/workflow.py#L26)

**② *"Nếu Tầng 1 và LLM bất đồng thì ai thắng?"***

> *"Tầng 1 thắng, theo hướng an toàn. `enforce_tier_consensus`: Tầng 1 nói tấn công mà LLM
> hạ xuống LOG hoặc DROP thì hệ **không tin LLM** và ép sang hàng đợi chờ người. Lý do:
> Tầng 1 tất định nên **không thể bị thuyết phục**, còn LLM thì có thể."*
> Mở: [decision_validator.py:151](../../../src/guardrails/decision_validator.py#L151)

**③ *"Kết quả có tái lập được không?"***

> *"Có, ở mức mô hình: nhiệt độ 0,1 và seed 42, cộng với `response_format` ràng buộc bộ giải
> mã nên đầu ra luôn là JSON hợp lệ. Em nói rõ giới hạn: **Tầng 1 phụ thuộc thứ tự nạp** vì
> mốc thống kê cập nhật trực tuyến — nên số Tầng 1 phải trích từ lượt chạy sống, và em ghi
> điều đó trong luận văn."*
> Mở: [llm_client.py:88 `DECISION_JSON_SCHEMA`](../../../src/agent/llm_client.py#L88)
