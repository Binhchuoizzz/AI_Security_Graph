# Tổng kết Mã nguồn SENTINEL — theo LUỒNG HỆ THỐNG

Bám **luồng runtime 10 chặng** trong [Sơ đồ Luồng Hệ thống](https://claude.ai/code/artifact/92767877-313f-415b-a45a-7d8451bcf89b). Chỉ nêu file **nằm trên đường đi của một bản ghi log** — mỗi file 1 câu **bản chất chức năng**. Tham số (Z>3.5σ, warmup 100, risk 15, RRF k=60, reputation 70/50) trích thẳng từ code.

**Bản đồ:** 4 nguồn → Redis **①** → subscriber **②** → Tier-1 (7 lớp, O(1)) **③** → 6 action **④** → *(ESCALATE)* **Cổng ML** (LightGBM 4 dải) **⑤** → *(chỉ ca ML bỏ ngỏ)* LangGraph 6 node **⑥** → Audit HMAC **⑦** → 4 kho **⑧** → feedback hot-reload về Tier-1 **⑨** · Dashboard HITL **⑩**. Guardrails (5 lớp) bọc xuyên suốt.

**Trạng thái:** `pytest 306` · LangGraph 6 node · golden baseline **BẬT mặc định** (seed 300 flow) · **LLM triage ép JSON hợp lệ qua `response_format=json_schema`** (dứt "parse lỗi"/prose, reasoning tiếng Việt). **5D (benchmark cân bằng lại 2026-07-19: datatest 3204 = 15 lớp CICIDS đa-ngày + benign + DAPT day2-5 + zero-day 15 lớp + adv; ground_truth 1250; rerun full-ablation 2026-07-20):** **F1 — so sánh trên dữ liệu CÂN BẰNG (khử base-rate): luật thô 0.56 (precision cao, recall thấp) → tầng học 0.80–0.83 (Cổng ML 0.825 · pure-LLM 0.804). Số 0.967 là 2-tầng phát-hiện+HITL trên tập vận hành (94% attack) — base-rate, balanced khử còn 0.559 (luật ≈ 2-tầng ở đó); KHÔNG phải đỉnh thang.** **Cổng ML (LightGBM 1M, 4 dải 0.85/0.65/0.40): giảm tải LLM 83.8%** (761/908) · precision-on-bypass **98.82%** · F1(bypass) 0.9739 (Config G, ground_truth 1250) · model Test-F1 **0.9635** (189.907 held-out) · datatest 3204 dải ALERT-0.40 low-priority (chú thích training_report §4) · **kháng né-tránh ML 99.58%** (Inf/cực-đoan) · APT 3/3 (lag ~8 event), zero-day 12/15 · độ trễ Tier-1 rule **~0.12ms** / Cổng ML **~0.35ms** · **LLM-Judge 3.1/5** (rerun 2026-07-20, cross-family Llama-3-judge, n=908 escalated — benchmark khó hơn; mốc cũ 3.9 là n=188) · **adversarial Tier-2 100%** (12/12 resisted, 2026-07-20) · audit HMAC. **Full-ablation XONG 13:54:54 (2026-07-20).** Bonus *balanced* (230 cân bằng, khử base-rate): A≡F **0.559** / pure-LLM B **0.804** (R1.0/P.67) → xác nhận 0.967 = base-rate; *bcde* B–E **0.9655**. **tier2_decision (n=800, bỏ qua Cổng ML, escalate 95% benign):** recall 1.0 / specificity 0.0 / acc 0.0475=base-rate / rel 1.0 / **0 parse-fail** / 353 BLOCK·445 HITL·2 ALERT — lưới an toàn max-recall (Cổng ML mới tạo chọn lọc). Vận hành: [RUN_PROJECT.md](../guides/RUN_PROJECT.md); demo `scripts/run_demo.sh` (tự chạy `reset_all.py` trước).

> **Vì sao "đẩy nghìn log mà Dashboard hiện dần":** Tier-1 lọc phần lớn ở wire-speed; ca ESCALATE qua Cổng ML (~0.35ms) chặn 83.8%, chỉ ca ML bỏ ngỏ mới gọi Gemma-2-9B (~vài giây/lô, subscriber đơn luồng chặn đồng bộ). Là **đánh đổi có chủ đích**, không phải bug. Số benchmark lấy từ luồng **OFFLINE tất định** (`evaluate_unified_stream.py`), không phải từ demo.

---

## ① Thu nhận — 4 nguồn → Redis Streams (`xadd`, maxlen chống OOM, 3 queue firewall/waf/sysmon)

- **`streaming/publisher.py`** — stream CSV THÔ quy mô lớn (chunk 500 dòng, load-test) vào `queue_waf`.
- *(đã gỡ `scripts/simulate_traffic.py` — demo dùng `build_datatest.py`/`push_datatest.py` ở trên; ablation đọc thẳng `ground_truth.json`)*
- **`scripts/build_datatest.py` → `scripts/push_datatest.py`** (hoặc `build_demo.py` → `demo.py` bản ~100k) — luồng gộp CẢ 4 nguồn (CICIDS + DAPT + zero-day + adversarial), logic chung nằm ở `experiments/unified_dataset.py`. *Nguồn demo chính.*
- **`scripts/push_flow.py`** — đẩy RIÊNG 1 luồng (`--source cicids|dapt|zeroday|adversarial`, `--limit`) để demo tách bạch từng nguồn.

## ② Tiêu thụ — `streaming/subscriber.py`

Đọc consumer-group `sentinel_group`, mỗi log → `RuleEngine.evaluate` → định tuyến theo `tier1_action`. Đồng thời: **APT emergent** (metadata DAPT → `check_apt_chain` → ép ESCALATE khi ≥2 ngày) + đếm log thô/DROP ghi `pipeline_stats.json` (Noise Reduction thật cho Dashboard).

## ③ Tier-1 — `tier1_filter/rule_engine.py` *(CỐT LÕI)*

Màng lọc heuristic **O(1)/log** + phát hiện dị biệt thống kê online. `evaluate()` chạy 7 lớp: **L0** Whitelist → **L0.1** WAF sig (SQLi/XSS/Path/Cmd) → **L0.2** Injection/Jailbreak sig → **L0.5 Welford Z-score** (zero-day) → **L1** static rules → **L2** dynamic rules (học từ feedback, substring match cả IP lẫn HÀNH VI) → **L3** session baseline (port scan, TTL). Bản chất:

- **Welford** (`RunningStats`): cập nhật μ,M2 mỗi mẫu ~6 phép float, không lưu lịch sử → cờ zero-day khi **Z>3.5σ**. Cổng leo thang: **Σ score ≥ 15**.
- **Golden baseline (bật mặc định):** seed `(n,μ,M2)` từ 300 flow benign đã kiểm định → đo dị biệt ngay gói đầu, khỏi warmup mù.
- **Anti-poisoning:** chỉ flow benign (DROP/LOG) mới cập nhật baseline (chống "ếch luộc").
- **Reputation (Tầng 3.5):** đọc uy tín IP từ Threat Memory → ≥**70** `BLOCK_IP`, ≥**50** `AWAIT_HITL`, khỏi tốn LLM → **khép vòng ⑧→③**.
- Hot-reload config mỗi 5s.

## ④ Phân luồng 6 action (trong subscriber)

`DROP/LOG` (đếm, không leo thang) · `BLOCK_IP` (blacklist + sinh luật động) · `AWAIT_HITL` (queue_hitl) · `ALERT` (queue_decisions) · **`ESCALATE`** (→ **Cổng ML** ⑤ trước, KHÔNG gọi LLM ngay). **Chỉ ca Cổng ML bỏ ngỏ mới gọi LLM.**

## ⑤ Cổng ML — van giảm tải trước LLM · `tier1_filter/ml_gateway.py`

Ca `ESCALATE` đi qua **LightGBM** (`evaluate()` gọi trong subscriber): chấm `P(tấn công)` → `classify_ml` (`decision_policy.py`) phân **4 dải** `C≥0.85` BLOCK_IP (chặn + luật IP score 100) · `0.65–0.85` ESCALATE (→LLM) · `0.40–0.65` ALERT (IP tái phạm→tự BLOCK) · `<0.40` DROP (log sạch → noise reduction). **Tự quyết 83.8%** ca escalate (~0.35ms) mà KHÔNG gọi LLM (precision-on-bypass 98.82%, F1 0.9739); chỉ ca "bỏ ngỏ" mới `agent_app.invoke`. Cắt ~6× chi phí LLM. Model: LightGBM 1M (Test-F1 0.9635/190k), block-on-sight qua reputation.

## ⑥ Tier-2 — LangGraph 6 node *(CỐT LÕI)* · `agent/workflow.py` + `agent/nodes.py`

DAG có điều kiện, KHÔNG loop, KHÔNG tool-calling — LLM chỉ là 1/6 trạm. Chỉ ~16% ca escalate (ML bỏ ngỏ) vào đây.

- **`node_guardrails`** — Drain nén log trùng + bọc nonce `token_hex(8)` (LLM coi là DATA, không phải lệnh).
- **`node_rag_context`** — Dual-RAG (vô điều kiện) + inject lịch sử APT từ Threat Memory.
- **`node_llm_triage`** *(bộ não)* — prompt → LLM (**`response_format=DECISION_JSON_SCHEMA`** ép server llama.cpp xuất JSON HỢP LỆ → hết "parse lỗi"/prose; reasoning bám tiếng Việt) → `classify_llm` (confidence LÁI action: ≥0.85 BLOCK · 0.65–0.85 ALERT · <0.65 AWAIT_HITL) + `enforce_tier_consensus` → ghi audit + `record_incident`. **LLM chết/JSON hỏng → suy biến AWAIT_HITL** (không crash).
- **`route_after_triage`** — threat verdict → attack_mapper; benign LOG → kết thúc.
- **`node_attack_mapper`** — cấu trúc hóa MITRE (Pydantic): curated `WEB_ATTACK_MAP` tất định / anchor id / RRF+LLM-select.
- **`node_action_executor`** — `block_ip()` (audit HMAC) + sinh **2 luật PENDING**: theo IP (nhớ mặt) + theo HÀNH VI (nhớ ngón đòn → bắt IP mới cùng kỹ thuật). / **`node_human_in_the_loop`** — quyết định mơ hồ → analyst.

**Trợ lý luồng gọi:** `state.py` (`SentinelState`/`AgentDecision`) · `prompts.py` (rule chống social-engineering) · `llm_client.py` (Gemma-2-9B-IT Q6_K qua llama.cpp, temp 0.1 + **seed 42** → tất định) · `token_monitor.py` (quan sát ngân sách ngữ cảnh, n_ctx 8192).

## ⑦ Audit — `response/executor.py`

Ghi `audit_trail.db` chuỗi **HMAC-SHA256 móc-xích** `Hᵢ=HMAC(Dᵢ‖Hᵢ₋₁,K)` — sửa/xóa 1 dòng là gãy chuỗi, phát hiện tamper ngay. `block_ip()`=`[FIREWALL MOCK]` (enforcement thật là luật ACTIVE ở Tier-1).

## ⑧ 4 kho bền vững

`Redis blacklist:<ip>` (setex 3600s) · `dynamic_rules` YAML (enforcement thật) · `threat_memory.db` · `audit_trail.db`.

- **`agent/threat_memory.py`** — uy tín IP (decay `S·(1−λ)ᵗ` → không chặn vĩnh viễn) + chuỗi APT (cờ khi `COUNT(DISTINCT apt_day)≥2`); `get_ip_reputation` được cả Tier-1 đọc.

## ⑨ Vòng phản hồi → về Tier-1 · `tier1_filter/feedback_listener.py`

Luật PENDING → analyst duyệt trên Dashboard → ACTIVE → **RuleEngine hot-reload (mtime 5s)** → chặn wire-speed lần sau. Persist YAML atomic + FileLock (chmod 0666 cho cross-UID Docker). **`guardrails/feedback_validator.py`** = Zero-Trust cổng (chặn wildcard/CIDR quá rộng).

## ⑩ Dashboard SOC (HITL) · `ui/app.py`

Streamlit 5 tab (SIEM&Audit / Duyệt luật / APT / Blocklist&Whitelist / Graph); KPI đọc audit/threat_memory/pipeline_stats/llm_token_stats. Nút Duyệt → persist YAML → Tier-1 enforce (đóng vòng ⑨). `components.py` (card MITRE anti-XSS) · `auth.py` (PBKDF2 100k + RBAC L1/L3).

---

## Guardrails xuyên suốt (5 lớp — bảo vệ tầng nhận thức)

- **`prompt_filter.py`** — injection/jailbreak detect + encoding neutralize + nonce encapsulation → node_guardrails.
- **`template_miner.py`** — drain3 nén log + token budget 4000 (không thì ~100 log vỡ cửa sổ 8192).
- **`decision_policy.py`** — chính sách độ-tin-cậy THỐNG NHẤT (1 nguồn sự thật, chung Cổng ML + LLM). ML 4 dải: `C≥0.85` BLOCK · `0.65–0.85` ESCALATE · `0.40–0.65` ALERT · `<0.40` PASS. LLM: `≥0.85` BLOCK · `0.65–0.85` ALERT · `<0.65` AWAIT_HITL; log sạch → DROP. Confidence LÁI action (bỏ kiểu LLM tự chọn).
- **`decision_validator.py`** — confidence gate + Anti-Self-DoS + shield critical-asset (gắn cờ `_critical_shield` để remap không đẩy ngược) + **`enforce_tier_consensus`** (Tier-1 nói tấn công mà LLM hạ xuống → ép AWAIT_HITL).
- **`output_sanitizer.py`** — làm sạch đầu ra LLM (chống exfil/XSS).
- **`rag_sanitizer.py`** + **`rag/security.py`** — chống RAG poisoning; checksum SHA-256 fail-closed trước `pickle.load` BM25 (CWE-502).

## Tri thức RAG (build-time)

- **`rag/retriever.py`** *(runtime cốt lõi)* — Dense (all-MiniLM 384-chiều → FAISS `IndexFlatIP` cosine) + Sparse (BM25Okapi) hợp nhất **RRF k=60**. Dense bắt nghĩa, BM25 bắt mã/ID; RRF gộp chỉ theo thứ hạng.
- **`rag/semantic_cache.py`** — LRU 500 khóa SHA-256(template), TTL 1800s.
- **`rag/embedder.py`** + **`scripts/build_knowledge_base.py`** — build FAISS/BM25 + checksum (KB: 299 kỹ thuật MITRE + 7 playbook NIST).

## Gốc

- **`main.py`** — entrypoint `server`/`scan`/`full`; mode server = subscriber loop (trái tim luồng ONLINE).
- **`scripts/reset_all.py`** / **`run_demo.sh`** — reset sạch / full demo 1 lệnh.

---

## Ngoài luồng runtime (benchmark · rigor · dataset · demo)

- **Benchmark:** `evaluate_unified_stream.py` (F1 0.531) · `evaluate_ml_gate.py` (Cổng ML: F1 0.825, evasion 99.58%) · `run_ablation.py --mode {af,mlgate,bcde,balanced}` + `statistical_tests.py` (McNemar) · `evaluate_adversarial.py --mode {static,pipeline}` (100%, 12/12) · `evaluate_reasoning.py` (LLM-Judge chéo họ, 3.1/5) · `evaluate_tier2_decision.py` (chất lượng phán quyết trên ca escalate, mẫu strided) · `measure_latency_baseline.py` (−82.97%).
- **Rigor (chống phản biện):** `run_threshold_sensitivity` (Z không cherry-pick) · `run_zeroday_graded` (đường cong phát hiện) · `run_apt_negative_control` (Wilson CI + specificity 1.0) · `run_context_stress` (không tràn ngữ cảnh) · `run_llm_robustness` (determinism + suy biến an toàn) · `eval_attack_mapper` · `plot_results`.
- **Dataset/seed/demo:** `fetch_and_build_dataset` (CICIDS→ground_truth 1250) · `fetch_dapt2020`+`build_dapt_chains` (chuỗi APT) · `build_datatest`→`push_datatest` / `build_demo`→`demo.py` (luồng GỘP) · `push_flow.py` (đẩy RIÊNG 1 luồng cicids/dapt/zeroday/adversarial) · `build_adversarial_suite` (120 mẫu OWASP) · `demos/demo_{tier1,guardrails,rag}.py` · `e2e_test_runner.py` (22 kịch bản) · `tier1_filter/scanner.py` (Trivy SCA).
- **Test:** `pytest 306` (unit+tier1+adversarial+integration, gồm `test_decision_policy`) · `E2E 22/22`. Nổi bật: attack_mapper (35, no-LLM), behavioral_learning (14), executor (HMAC + repeat-offender), subscriber (chống lộ nhãn), auth (PBKDF2/RBAC).
