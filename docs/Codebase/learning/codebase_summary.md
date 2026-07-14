# Tổng kết Mã nguồn SENTINEL — theo LUỒNG HỆ THỐNG

Bám **luồng runtime 9 chặng** trong [Sơ đồ Luồng Hệ thống](https://claude.ai/code/artifact/92767877-313f-415b-a45a-7d8451bcf89b). Chỉ nêu file **nằm trên đường đi của một bản ghi log** — mỗi file 1 câu **bản chất chức năng**. Tham số (Z>3.5σ, warmup 100, risk 15, RRF k=60) trích thẳng từ code.

**Bản đồ:** 4 nguồn → Redis **①** → subscriber **②** → Tier-1 (7 lớp, O(1)) **③** → 6 action **④** → *(chỉ ESCALATE)* LangGraph 6 node **⑤** → Audit HMAC **⑥** → 4 kho **⑦** → feedback hot-reload về Tier-1 **⑧** · Dashboard HITL **⑨**. Guardrails (5 lớp) bọc xuyên suốt.

**Trạng thái:** `pytest 267` · `E2E 22/22` · LangGraph 6 node · golden baseline **BẬT mặc định (base benign duy nhất)**. **5D:** F1 **0.61** (P.95/R.45), Tier-2 escalate recall **1.00 (594/594)**, zero-day 7/7, APT 3/3 · độ trễ **−82.97%** · adversarial Tier-2 **100%**/guardrail 50% · LLM-Judge **3.9/5** · audit HMAC tamper-evident. Vận hành: [RUN_PROJECT.md](../guides/RUN_PROJECT.md); demo 1 lệnh `scripts/run_demo.sh`.

> **Vì sao "đẩy nghìn log mà Dashboard hiện dần":** Tier-1 lọc ~88–99% ở wire-speed; chỉ ESCALATE mới gọi Gemma-2-9B (~15–25s/lô, subscriber đơn luồng chặn đồng bộ). Là **đánh đổi có chủ đích**, không phải bug. Số benchmark lấy từ luồng **OFFLINE tất định** (`evaluate_unified_stream.py`), không phải từ demo.

---

## ① Thu nhận — 4 nguồn → Redis Streams (`xadd`, maxlen chống OOM, 3 queue firewall/waf/sysmon)

- **`streaming/publisher.py`** — stream CSV THÔ quy mô lớn (chunk 500 dòng, load-test).
- **`scripts/simulate_traffic.py`** — replay `ground_truth.json` (4267 mẫu có nhãn) cho demo/ablation.
- **`experiments/stream_unified_online.py`** — luồng gộp CICIDS+DAPT+zero-day; cờ `--include-adversarial` = 1 lệnh đẩy CẢ 4 nguồn (4796 sự kiện). *Nguồn demo chính.*
- **`scripts/live_log_collector.py`** — bắt log THẬT: tail `/var/log/auth.log` + decoy WAF (demo pentest).

## ② Tiêu thụ — `streaming/subscriber.py`

Đọc consumer-group `sentinel_group`, mỗi log → `RuleEngine.evaluate` → định tuyến theo `tier1_action`. Đồng thời: **APT emergent** (metadata DAPT → `check_apt_chain` → ép ESCALATE khi ≥2 ngày) + đếm log thô/DROP ghi `pipeline_stats.json` (Noise Reduction thật cho Dashboard).

## ③ Tier-1 — `tier1_filter/rule_engine.py` *(CỐT LÕI)*

Màng lọc heuristic **O(1)/log** + phát hiện dị biệt thống kê online. `evaluate()` chạy 7 lớp: **L0** Whitelist → **L0.1** WAF sig (SQLi/XSS/Path/Cmd) → **L0.2** Injection/Jailbreak sig → **L0.5 Welford Z-score** (zero-day) → **L1** static rules → **L2** dynamic rules (học từ feedback, substring match cả IP lẫn HÀNH VI) → **L3** session baseline (port scan, TTL). Bản chất:

- **Welford** (`RunningStats`): cập nhật μ,M2 mỗi mẫu ~6 phép float, không lưu lịch sử → cờ zero-day khi **Z>3.5σ**. Cổng leo thang: **Σ score ≥ 15**.
- **Golden baseline (bật mặc định):** seed `(n,μ,M2)` từ 300 flow benign đã kiểm định → đo dị biệt ngay gói đầu, khỏi warmup mù.
- **Anti-poisoning:** chỉ flow benign (DROP/LOG) mới cập nhật baseline (chống "ếch luộc").
- **Reputation (Tầng 3.5):** đọc uy tín IP từ Threat Memory → ≥70 `BLOCK_IP`, ≥50 `AWAIT_HITL`, khỏi tốn LLM → **khép vòng ⑦→③**.
- Hot-reload config mỗi 5s.

## ④ Phân luồng 6 action (trong subscriber)

`DROP/LOG` (đếm, không leo thang) · `BLOCK_IP` (blacklist + sinh luật động) · `AWAIT_HITL` (queue_hitl) · `ALERT` (queue_decisions) · **`ESCALATE`** (gom batch → Agent). **Chỉ ESCALATE mới gọi LLM.**

## ⑤ Tier-2 — LangGraph 6 node *(CỐT LÕI)* · `agent/workflow.py` + `agent/nodes.py`

DAG có điều kiện, KHÔNG loop, KHÔNG tool-calling — LLM chỉ là 1/6 trạm.

- **`node_guardrails`** — Drain nén log trùng + bọc nonce `token_hex(8)` (LLM coi là DATA, không phải lệnh).
- **`node_rag_context`** — Dual-RAG (vô điều kiện) + inject lịch sử APT từ Threat Memory.
- **`node_llm_triage`** *(bộ não)* — prompt → LLM → validate (`DecisionValidator` + `enforce_tier_consensus`) → ghi audit + `record_incident`. **LLM chết → suy biến AWAIT_HITL** (không crash).
- **`route_after_triage`** — threat verdict → attack_mapper; benign LOG → kết thúc.
- **`node_attack_mapper`** — cấu trúc hóa MITRE (Pydantic): curated `WEB_ATTACK_MAP` tất định / anchor id / RRF+LLM-select.
- **`node_action_executor`** — `block_ip()` (audit HMAC) + sinh **2 luật PENDING**: theo IP (nhớ mặt) + theo HÀNH VI (nhớ ngón đòn → bắt IP mới cùng kỹ thuật). / **`node_human_in_the_loop`** — quyết định mơ hồ → analyst.

**Trợ lý luồng gọi:** `state.py` (`SentinelState`/`AgentDecision`) · `prompts.py` (rule chống social-engineering) · `llm_client.py` (Gemma-2-9B-IT Q6_K qua llama.cpp, temp 0.1 + **seed 42** → tất định) · `token_monitor.py` (quan sát ngân sách ngữ cảnh, n_ctx 8192).

## ⑥ Audit — `response/executor.py`

Ghi `audit_trail.db` chuỗi **HMAC-SHA256 móc-xích** `Hᵢ=HMAC(Dᵢ‖Hᵢ₋₁,K)` — sửa/xóa 1 dòng là gãy chuỗi, phát hiện tamper ngay. `block_ip()`=`[FIREWALL MOCK]` (enforcement thật là luật ACTIVE ở Tier-1).

## ⑦ 4 kho bền vững

`Redis blacklist:<ip>` (setex 3600s) · `dynamic_rules` YAML (enforcement thật) · `threat_memory.db` · `audit_trail.db`.

- **`agent/threat_memory.py`** — uy tín IP (decay `S·(1−λ)ᵗ` → không chặn vĩnh viễn) + chuỗi APT (cờ khi `COUNT(DISTINCT apt_day)≥2`); `get_ip_reputation` được cả Tier-1 đọc.

## ⑧ Vòng phản hồi → về Tier-1 · `tier1_filter/feedback_listener.py`

Luật PENDING → analyst duyệt trên Dashboard → ACTIVE → **RuleEngine hot-reload (mtime 5s)** → chặn wire-speed lần sau. Persist YAML atomic + FileLock (chmod 0666 cho cross-UID Docker). **`guardrails/feedback_validator.py`** = Zero-Trust cổng (chặn wildcard/CIDR quá rộng).

## ⑨ Dashboard SOC (HITL) · `ui/app.py`

Streamlit 5 tab (SIEM&Audit / Duyệt luật / APT / Blocklist&Whitelist / Graph); KPI đọc audit/threat_memory/pipeline_stats/llm_token_stats. Nút Duyệt → persist YAML → Tier-1 enforce (đóng vòng ⑧). `components.py` (card MITRE anti-XSS) · `auth.py` (PBKDF2 100k + RBAC L1/L3).

---

## Guardrails xuyên suốt (5 lớp — bảo vệ tầng nhận thức)

- **`prompt_filter.py`** — injection/jailbreak detect + encoding neutralize + nonce encapsulation → node_guardrails.
- **`template_miner.py`** — drain3 nén log + token budget 4000 (không thì ~100 log vỡ cửa sổ 8192).
- **`decision_validator.py`** — confidence gate + Anti-Self-DoS + **`enforce_tier_consensus`** (Tier-1 nói tấn công mà LLM hạ xuống → ép AWAIT_HITL).
- **`output_sanitizer.py`** — làm sạch đầu ra LLM (chống exfil/XSS).
- **`rag_sanitizer.py`** + **`rag/security.py`** — chống RAG poisoning; checksum SHA-256 fail-closed trước `pickle.load` BM25 (CWE-502).

## Tri thức RAG (build-time)

- **`rag/retriever.py`** *(runtime cốt lõi)* — Dense (all-MiniLM 384-chiều → FAISS cosine) + Sparse (BM25) hợp nhất **RRF k=60**. Dense bắt nghĩa, BM25 bắt mã/ID; RRF gộp chỉ theo thứ hạng.
- **`rag/semantic_cache.py`** — LRU 500 khóa SHA-256(template), TTL 1800s.
- **`rag/embedder.py`** + **`scripts/build_knowledge_base.py`** — build FAISS/BM25 + checksum (KB: 299 kỹ thuật MITRE + 7 playbook NIST).

## Gốc

- **`main.py`** — entrypoint `server`/`scan`/`full`; mode server = subscriber loop (trái tim luồng ONLINE).
- **`scripts/reset_all.py`** / **`run_demo.sh`** — reset sạch / full demo 1 lệnh.

---

## Ngoài luồng runtime (benchmark · rigor · dataset · demo)

- **Benchmark:** `evaluate_unified_stream.py` (F1 0.61) · `run_ablation.py --mode {af,bcde,balanced}` + `statistical_tests.py` (McNemar) · `evaluate_adversarial.py --mode {static,pipeline}` · `evaluate_reasoning.py` (LLM-Judge chéo họ) · `measure_latency_baseline.py` (−82.97%).
- **Rigor (chống phản biện):** `run_threshold_sensitivity` (Z không cherry-pick) · `run_zeroday_graded` (đường cong phát hiện) · `run_apt_negative_control` (Wilson CI + specificity 1.0) · `run_context_stress` (không tràn ngữ cảnh) · `run_llm_robustness` (determinism + suy biến an toàn) · `eval_attack_mapper` · `plot_results`.
- **Dataset/seed/demo:** `fetch_and_build_dataset` (CICIDS→ground_truth 4267) · `fetch_dapt2020`+`build_dapt_chains` (chuỗi APT) · `seed_demo_data` · `build_adversarial_suite` (120 mẫu OWASP) · `demos/demo_{tier1,guardrails,rag}.py` · `e2e_test_runner.py` (22 kịch bản) · `tier1_filter/scanner.py` (Trivy SCA).
- **Test:** `pytest 267` (unit+tier1+adversarial+integration) · `E2E 22/22`. Nổi bật: attack_mapper (35, no-LLM), behavioral_learning (14), executor (HMAC), subscriber (chống lộ nhãn), auth (PBKDF2/RBAC).
