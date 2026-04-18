# SENTINEL — Next Implementation Steps

## Tổng quan trạng thái hiện tại

```
Pipeline thực tế:
CSV → DataPublisher → Redis → Subscriber → Tier1 RuleEngine → ESCALATE → ❌ DỪNG TẠI ĐÂY
                                                                           ↑
                                              Mọi thứ phía sau chưa có code
```

**Implemented (~2,022 lines):** DataPublisher, RuleEngine, FeedbackListener, PromptFilter, TemplateMiner, DataValidator, StateMonitor, SemanticCache, SentinelState — tất cả độc lập, chưa kết nối.

**Empty (0 bytes):** `embedder.py`, `retriever.py`, `workflow.py`, `nodes.py`, `prompts.py`, `app.py`, `auth.py`, `components.py`, `executor.py`, `main.py`

**Knowledge Base:** mitre_attack.json chỉ có 1 technique, iso_27001_controls.json chỉ có 1 control, FAISS index chưa tồn tại.

---

## Phase 1 — Knowledge Base + RAG Engine
*Phụ thuộc: chưa gì → phải làm đầu tiên vì Phase 2 (Agent) cần RAG*

- [ ] **1.1** Populate `knowledge_base/mitre_attack.json` — tối thiểu 30-50 techniques có liên quan (DoS, Brute Force, Recon, Web Attack, Lateral Movement). Download từ MITRE STIX official hoặc hand-pick.
- [ ] **1.2** Populate `knowledge_base/iso_27001_controls.json` — tối thiểu 20-30 controls từ Annex A.
- [ ] **1.3** Implement `src/rag/embedder.py` — load JSON, embed bằng `sentence-transformers/all-MiniLM-L7-v2`, build FAISS index riêng cho MITRE và ISO, save index file.
- [ ] **1.4** Implement `src/rag/retriever.py` — load FAISS index, nhận query string, trả top-k chunks từ cả hai index, tích hợp SemanticCache.
- [ ] **1.5** Test manual: `python -c "from src.rag.retriever import DualRetriever; r=DualRetriever(); print(r.retrieve('brute force ssh port 22'))"` → phải trả context MITRE T1110 + ISO A.9.4.2

## Phase 2 — LangGraph Agent (Trái tim hệ thống)
*Phụ thuộc: Phase 1 hoàn thành*

- [ ] **2.1** Implement `src/agent/prompts.py` — system prompt template với Dynamic Delimiter placeholder, few-shot examples, JSON output schema.
- [ ] **2.2** Implement `src/agent/nodes.py` — 4 node functions:
  - `ingest_node`: nhận escalated log, validate, update SentinelState
  - `guardrails_node`: chạy TemplateMiner → PromptFilter → build prompt
  - `analyze_node`: gọi LLM (Gemma 9B qua OpenAI-compatible API), parse JSON output
  - `decide_node`: routing logic (BLOCK/ALERT/LOG/AWAIT_HITL), update state, gọi FeedbackListener nếu cần
- [ ] **2.3** Implement `src/agent/workflow.py` — StateGraph assembly, compile, conditional edges
- [ ] **2.4** Implement `main.py` — wire toàn bộ pipeline: DataPublisher thread + Subscriber loop → Tier1 → Agent
- [ ] **2.5** Smoke test end-to-end: Chạy publisher với CICIDS2017 sample nhỏ (100 rows), xem Agent ra quyết định.

## Phase 3 — HITL Dashboard
*Phụ thuộc: Phase 2 hoàn thành (cần Agent tạo pending rules)*

- [ ] **3.1** Implement `src/ui/auth.py` — streamlit-authenticator với 2 users: L1_analyst (view-only), L3_manager (approve/reject)
- [ ] **3.2** Implement `src/ui/components.py` — alert card, IOC table, quarantine panel, latency chart
- [ ] **3.3** Implement `src/ui/app.py` — main Streamlit app: real-time alert feed, HITL rule approval workflow
- [ ] **3.4** Implement `src/response/executor.py` — mock actions: block_ip() log to audit_trail.db, alert(), log_event()
- [ ] **3.5** Update `src/tier1_filter/feedback_listener.py` — thêm `PENDING_APPROVAL` quarantine state trước khi persist

## Phase 4 — Tests + Experiments
*Phụ thuộc: Phase 2-3 hoàn thành*

- [ ] **4.1** `tests/unit/test_prompt_filter.py` — test Dynamic Delimiter, encoding neutralization
- [ ] **4.2** `tests/unit/test_template_miner.py` — test compression ratio, template extraction
- [ ] **4.3** `tests/unit/test_data_validator.py` — test schema validation, NaN handling
- [ ] **4.4** `tests/test_tier1_filter.py` — test Session Baselining, TTL eviction
- [ ] **4.5** `tests/conftest.py` — shared fixtures (mock Redis, sample logs)
- [ ] **4.6** Expand `experiments/ground_truth.json` từ 3 → 200 samples
- [ ] **4.7** Expand `experiments/reasoning_ground_truth.json` từ 6 → 30 samples
- [ ] **4.8** Implement `experiments/evaluate_accuracy.py` — chạy 6 ablation configs
- [ ] **4.9** Implement `experiments/evaluate_latency.py` — benchmark latency
- [ ] **4.10** Implement `experiments/evaluate_robustness.py` — adversarial test runner
- [ ] **4.11** Run VRAM benchmark thực tế (`experiments/vram_benchmark/`)
