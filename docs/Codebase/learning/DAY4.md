# SENTINEL — Tài liệu tham chiếu hàm (Function Reference) — NGÀY 4

> **Phạm vi:** Mô tả **chi tiết từng hàm** của **9 file** thuộc **Tầng nhận thức LangGraph Agent (Tier-2)** + **Tầng phản hồi & Audit** (`src/agent/` + `src/response/executor.py`) — bộ não suy luận ra quyết định, ánh xạ MITRE có cấu trúc, bộ nhớ đe dọa dài hạn và nhật ký chống-giả-mạo.
> **Cập nhật:** 2026-07-02 (đồng bộ số dòng theo code thực tế ở HEAD: đồ thị 6-node + node `attack_mapper` + `token_monitor` + seed tất định).
> **Quy ước:** Mỗi hàm ghi rõ *Mục đích → Tham số → Trả về → Luồng xử lý → Tham chiếu dòng*.

---

## 💡 Sơ đồ 1 phút (đọc để hình dung nhanh)

> Một batch log **ESCALATE** từ Tier-1 đi vào **`agent_app` (LangGraph)** — một máy trạng thái 6 trạm. Nghĩ như dây chuyền:
> **Gói an toàn** (guardrails) → **Tra cứu tri thức** (RAG + lịch sử APT) → **LLM phán quyết** (Gemma, kèm 2 lá chắn Consensus & suy biến an toàn) → nếu là mối đe dọa thì **Dán nhãn MITRE có cấu trúc** (attack_mapper) → **Thực thi + Ghi audit HMAC** hoặc **Đẩy cho người (HITL)**.
> Trạng thái chảy qua các trạm là **`SentinelState` (@dataclass)**. LLM chỉ được **APPEND** IOC (không sửa/xóa) để chống trôi ngữ nghĩa. Mọi quyết định BLOCK còn sinh **luật PENDING** cho vòng phản hồi về Tier-1 (DAY1).

---

## Mục lục

- [0. Bản đồ kiến trúc tổng thể (đồ thị 6-node)](#0-bản-đồ-kiến-trúc-tổng-thể)
- [NHÓM 1 — Bộ nhớ trạng thái & Đồ thị](#nhom-1)
  - [D1. `src/agent/state.py`](#d1-statepy)
  - [D2. `src/agent/workflow.py`](#d2-workflowpy)
- [NHÓM 2 — Logic tại các Trạm (Nodes)](#nhom-2)
  - [D3. `src/agent/nodes.py`](#d3-nodespy)
  - [D4. `src/agent/attack_mapper.py`](#d4-attack_mapperpy)
- [NHÓM 3 — Giao tiếp LLM & Quan sát ngữ cảnh](#nhom-3)
  - [D5. `src/agent/prompts.py`](#d5-promptspy)
  - [D6. `src/agent/llm_client.py`](#d6-llm_clientpy)
  - [D7. `src/agent/token_monitor.py`](#d7-token_monitorpy)
- [NHÓM 4 — Bộ nhớ Đe dọa & Phản hồi/Audit](#nhom-4)
  - [D8. `src/agent/threat_memory.py`](#d8-threat_memorypy)
  - [D9. `src/response/executor.py`](#d9-executorpy)
- [Phụ lục — Bảng đồng bộ & điểm cần lưu ý](#phụ-lục)

---

<a name="0-bản-đồ-kiến-trúc-tổng-thể"></a>
## 0. Bản đồ kiến trúc tổng thể (đồ thị 6-node)

```
Batch ESCALATE (từ subscriber #9, DAY1) ──► agent_app.invoke(SentinelState)   [workflow.py]

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  guardrails  │──►│  rag_context │──►│  llm_triage  │
  │ (nén+nonce)  │   │ FAISS+BM25   │   │  Gemma-2-9B  │
  │              │   │ +Threat Mem  │   │ seed=42,t0.1 │
  └──────────────┘   └──────────────┘   └──────┬───────┘
       #35a               #35b                 │  DecisionValidator + enforce_tier_consensus
                                               │  (LLM chết → suy biến AWAIT_HITL)
                                               ▼
                                   ┌──────────────────────────┐
                                   │  route_after_triage      │  (CỔNG theo ACTION)
                                   └───────┬──────────────┬────┘
                          threat verdict   │              │  benign LOG
                     {BLOCK_IP,ALERT,      ▼              ▼  → route thẳng theo action
                      AWAIT_HITL}   ┌──────────────┐
                                    │ attack_mapper│  cấu trúc hoá MITRE (tactic/technique/URL/
                                    │ WEB_MAP/anchor│  mapping_confidence/recommended_response)
                                    │ /RRF+LLM-sel │
                                    └──────┬───────┘
                                           │  route_triage_decision
              ┌────────────────────────────┼────────────────────────────┐
    execute_action                     await_hitl                    end_cycle
              ▼                             ▼                             ▼
  ┌──────────────────┐          ┌──────────────────┐                   END
  │ action_executor  │          │ human_in_the_loop│
  │ block_ip (MOCK)  │          │ đẩy hàng đợi     │
  │ +PENDING rule    │          │ analyst duyệt    │
  │ +record_incident │          └──────────────────┘
  │ +audit HMAC      │
  └──────────────────┘
              │
              ▼  (vòng phản hồi khép kín)
  FeedbackListener.receive_new_rule() ──► system_settings.yaml ──► Tier-1 hot-reload  (DAY1)
```

**Khớp nối tối quan trọng (xác minh đồng bộ với DAY1–DAY3):**
- `subscriber.py` (#9) gọi `handle_escalated_batch` (`main.py`) → `agent_app.invoke(SentinelState(current_batch_logs=...))`.
- `node_guardrails` tái dùng `GuardrailsPipeline` (DAY2 — G4) và `node_rag_context` tái dùng `DualRetriever` (DAY3 — R5) + `ThreatMemoryStore.get_context_for_prompt`.
- `node_attack_mapper` **tái dùng chính `DualRetriever` + `llm_client` singleton** (KHÔNG dựng store/endpoint song song) và KB `mitre_attack.json` (299 kỹ thuật, DAY3).
- Mọi trường LLM sinh ra đi qua `output_sanitizer` (DAY2 — G5) trước khi ghi DB/hiển thị.

---

<a name="nhom-1"></a>
# NHÓM 1 — Bộ nhớ trạng thái & Đồ thị

<a name="d1-statepy"></a>
## D1. `src/agent/state.py`
**Vai trò:** Định nghĩa **bộ nhớ trạng thái** mà LangGraph mang theo qua từng node. Dùng **`@dataclass`** (KHÔNG phải TypedDict) để có phương thức tiện ích + kiểm soát mutation (chống Semantic Drift).

### `class IOCEntry` *(@dataclass)*
- **Mục đích:** Một chỉ dấu tổn hại (Indicator of Compromise) bất biến: `ioc_type / value / severity / source_template`. LLM chỉ được **APPEND**, không sửa/xóa → chống trôi ngữ nghĩa.
- **Dòng:** [25-48](../../src/agent/state.py#L25-L48) (`to_dict` tại [39](../../src/agent/state.py#L39))

### `class AgentDecision` *(@dataclass)*
- **Mục đích:** Một quyết định của Agent cho một cụm log. Trường lõi: `action / target / confidence / reasoning / mitre_technique / nist_control / hitl_status`.
- **Trường MITRE có cấu trúc (do `node_attack_mapper` bồi đắp):** `mitre_tactic / mitre_tactic_id / mitre_technique_id / mitre_subtechnique(_id) / mitre_url / mapping_confidence / mapping_status / recommended_response`.
- **`to_dict()`** ([76](../../src/agent/state.py#L76)) xuất đầy đủ cả trường mapper.
- **Dòng:** [50-96](../../src/agent/state.py#L50-L96)

### `class SentinelState` *(@dataclass)* ⭐ Trạng thái đồ thị
| Trường / Hàm | Mục đích | Dòng |
|--------------|----------|------|
| Các trường | `current_batch_logs`, `current_batch_encapsulated`, `rag_mitre_context`, `rag_nist_context`, `decisions`, `narrative_summary`, `cycle_count`, IOCs, `hitl_status`... | [99-179](../../src/agent/state.py#L99-L179) |
| `add_ioc(...)` | APPEND một `IOCEntry` (chống ghi đè). | [180-205](../../src/agent/state.py#L180-L205) |
| `add_decision(**mitre_mapping)` | Thêm `AgentDecision`, nhận thêm các trường MITRE có cấu trúc từ mapper. | [206-249](../../src/agent/state.py#L206-L249) |
| `get_iocs_by_severity(severity)` | Lọc IOC theo mức. | [250-253](../../src/agent/state.py#L250-L253) |
| `get_iocs_summary_for_prompt(max_iocs=20)` | Tóm tắt IOC nhét vào prompt (có cap). | [254-271](../../src/agent/state.py#L254-L271) |
| `get_memory_for_prompt()` | Kết xuất narrative + IOC cho prompt vòng sau. | [272-303](../../src/agent/state.py#L272-L303) |
| `reset_current_batch()` | Xóa batch hiện tại giữa các chu kỳ. | [304-314](../../src/agent/state.py#L304-L314) |

---

<a name="d2-workflowpy"></a>
## D2. `src/agent/workflow.py`
**Vai trò:** Lắp ráp **đồ thị nhận thức** — `StateGraph` 6 node + 2 conditional edge. Compile ra `agent_app` (singleton).

### `create_agent_workflow() -> CompiledStateGraph`
- **Mục đích:** Dựng & compile đồ thị.
- **Luồng:**
  1. Thêm **6 node:** `guardrails / rag_context / llm_triage / attack_mapper / action_executor / human_in_the_loop`.
  2. `entry = guardrails`; **edge thẳng** `guardrails → rag_context → llm_triage`.
  3. **Conditional edge `route_after_triage`** từ `llm_triage`: nếu `action ∈ {BLOCK_IP, ALERT, AWAIT_HITL}` → `attack_mapper` (làm giàu MITRE); ngược lại (benign `LOG`) → route thẳng theo action.
  4. **Conditional edge `route_triage_decision`** từ `attack_mapper` → `execute_action`(→`action_executor`) / `await_hitl`(→`human_in_the_loop`) / `end_cycle`(→`END`).
  5. `action_executor → END`; `human_in_the_loop → END`.
- **⚠️ Quyết định thiết kế:** Cổng route theo **ACTION**, KHÔNG theo confidence — đo thực tế cho thấy triage gán `ALERT@0.6–0.7` nên ngưỡng `>0.7` cũ lọc mất gần hết verdict.
- **Dòng:** [26-88](../../src/agent/workflow.py#L26-L88)

---

<a name="nhom-2"></a>
# NHÓM 2 — Logic tại các Trạm (Nodes)

<a name="d3-nodespy"></a>
## D3. `src/agent/nodes.py` *(Cực kỳ quan trọng)*
**Vai trò:** Hàm xử lý tại mỗi "trạm" của đồ thị. Mỗi node nhận `SentinelState`, trả về `dict` cập nhật state.

### `node_guardrails(state) -> dict`
- **Mục đích:** Chạy `GuardrailsPipeline.process_batch` (DAY2) — nén Drain + đóng gói nonce → sinh `current_batch_encapsulated` + `system_instruction`.
- **Dòng:** [43-80](../../src/agent/nodes.py#L43-L80)

### `node_rag_context(state) -> dict`
- **Mục đích:** Truy xuất ngữ cảnh an ninh.
- **Luồng:** Build query từ metadata flow thật → `DualRetriever.retrieve` (FAISS+BM25+RRF, DAY3) lấy `rag_mitre_context` + `rag_nist_context`; **inject lịch sử Threat Memory** qua `get_context_for_prompt` (gồm **chuỗi APT đa-ngày**).
- **Dòng:** [81-130](../../src/agent/nodes.py#L81-L130)

### `node_llm_triage(state) -> dict` ⭐
- **Mục đích:** Gọi LLM ra phán quyết + kiểm duyệt.
- **Luồng:**
  1. `build_triage_prompt` (D5) từ log đóng gói + RAG context.
  2. `llm_client.invoke` (Gemma, seed=42) — **suy biến an toàn**: bọc `try/except`, nếu LLM cục bộ chết → log lỗi, response rỗng → đồ thị KHÔNG vỡ, đẩy `AWAIT_HITL` (Tier-1 vẫn bảo vệ độc lập).
  3. Parse JSON → `DecisionValidator.validate_decision` + **`enforce_tier_consensus`** (lá chắn social-engineering, DAY2 — G6): truyền `tier1_flagged_attack=True` khi log có `tier1_action ∈ {BLOCK_IP,ESCALATE,AWAIT_HITL,ALERT}` hoặc `tier1_score≥30`.
  4. Ghi `AuditLogger` (DAY2 — G9).
  5. **`threat_memory.record_incident`** (reputation + MITRE) cho action ∈ {BLOCK_IP, ALERT, AWAIT_HITL} + `check_apt_pattern`/`check_apt_chain` ([288](../../src/agent/nodes.py#L288)). *(record_incident nằm ở node NÀY, không phải action_executor.)*
- **Dòng:** [132-327](../../src/agent/nodes.py#L132-L327)

### `node_attack_mapper(state) -> dict`
- **Mục đích:** Với threat verdict → NEO vào technique-id triage đã gán, gọi `map_attack` (D4) cấu trúc hoá thành bản ghi MITRE, bồi đắp vào `AgentDecision`.
- **Dòng:** [328-446](../../src/agent/nodes.py#L328-L446)

### `node_action_executor(state) -> dict`
- **Mục đích:** Thực thi action + **học ngược luật cho Tier-1**.
- **Luồng:** `BLOCK_IP` → `block_ip()` (FIREWALL MOCK, D9) **VÀ** sinh **HAI** luật PENDING qua `FeedbackListener.receive_new_rule()`:
  - **(1) Luật IP** — `Source IP`, score 100 ("nhớ mặt" kẻ tấn công).
  - **(2) Luật HÀNH VI** — `_derive_behavioral_rule()` trích chữ ký công cụ trên `User-Agent` (sqlmap/nikto/nmap...) hoặc token tấn công trên `URI` (score 50, "nhớ NGÓN ĐÒN") → Tier-1 bắt nhanh **IP MỚI cùng kỹ thuật**. Suy biến nhẹ: không có chữ ký an toàn → chỉ giữ luật IP.
- `LoopDetector` chống vòng lặp vô hạn. *(record_incident KHÔNG ở đây — nó ở `node_llm_triage:287`.)*
- **Dòng:** [471-542](../../src/agent/nodes.py#L471-L542) · helper `_derive_behavioral_rule` [447-470](../../src/agent/nodes.py#L447-L470)

### `node_human_in_the_loop(state) -> dict`
- **Mục đích:** Nhánh `AWAIT_HITL` — đẩy quyết định mập mờ / bị Consensus-Guard ép xuống vào hàng đợi chờ analyst (KHÔNG tự thực thi) rồi kết thúc cycle.
- **Dòng:** [543-574](../../src/agent/nodes.py#L543-L574)

### `route_triage_decision(state) -> str`
- **Mục đích:** Cổng SAU mapper → `execute_action` / `await_hitl` / `end_cycle`.
- **Dòng:** [575-593](../../src/agent/nodes.py#L575-L593)

### `route_after_triage(state) -> str`
- **Mục đích:** Cổng SAU triage (theo ACTION): threat verdict → `attack_mapper`; benign `LOG` → thẳng theo action.
- **Dòng:** [594-611](../../src/agent/nodes.py#L594-L611)

---

<a name="d4-attack_mapperpy"></a>
## D4. `src/agent/attack_mapper.py` *(Lớp ánh xạ MITRE ATT&CK có cấu trúc)*
**Vai trò:** Biến `mitre_technique` dạng **văn bản tự do** của triage thành bản ghi MITRE **CÓ CẤU TRÚC, kiểm chứng được (Pydantic)**.

### Models Pydantic
| Model | Mục đích | Dòng |
|-------|----------|------|
| `AttackMapperInput` | Đầu vào: attack_type, triage technique-id, log text, RAG candidates... | [59-67](../../src/agent/attack_mapper.py#L59-L67) |
| `MitreMapping` | Đầu ra schema LUÔN hợp lệ: tactic/technique/sub/URL/`mapping_confidence`/`mapping_status`/`recommended_response`. | [68-145](../../src/agent/attack_mapper.py#L68-L145) |

### Hàm tiện ích
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `_entry(...)` | Dựng một `MitreMapping` chuẩn hoá. | [146-334](../../src/agent/attack_mapper.py#L146-L334) |
| `_kw_hit(kw, haystack)` | Match từ khoá **word-boundary** cho token chữ-số (tránh dương-tính-giả `"rce"⊂"force"`). | [335-343](../../src/agent/attack_mapper.py#L335-L343) |
| `normalize_attack_type(*texts)` | Suy ra loại tấn công chuẩn từ nhiều nguồn text. | [344-354](../../src/agent/attack_mapper.py#L344-L354) |
| `normalize_tactic(raw)` | Chuẩn hoá nhãn KB phi-chuẩn (`"Stealth"→Defense Evasion`) → `(tactic, TA-id)`. | [355-366](../../src/agent/attack_mapper.py#L355-L366) |
| `build_mitre_url(technique_id, framework)` | Sinh URL ATT&CK/ATLAS. | [367-378](../../src/agent/attack_mapper.py#L367-L378) |
| `_response_for(key, tactic)` | `recommended_response` rule-based theo tactic. | [379-388](../../src/agent/attack_mapper.py#L379-L388) |
| `_load_kb_index()` | Nạp index KB (299 kỹ thuật) cho anchor/RRF. | [389-402](../../src/agent/attack_mapper.py#L389-L402) |

### Ba đường ánh xạ (trong `map_attack`)
| Đường | Hàm | Cơ chế | Dòng |
|-------|-----|--------|------|
| (1) **Curated** | `_from_curated` | Web-attack phổ biến tra `WEB_ATTACK_MAP` (10 lớp: SQLi→T1190, XSS→T1059.007, cmd-inj→T1059, prompt-inj→ATLAS `AML.T0051`...) — **tất định, KHÔNG LLM**. | [403-423](../../src/agent/attack_mapper.py#L403-L423) |
| (2) **Anchor** | `_from_triage_anchor` | Neo vào technique-id hợp lệ triage đã sinh (regex `\bT\d{4}(?:\.\d{3})?\b`). | [541-584](../../src/agent/attack_mapper.py#L541-L584) |
| (3) **RRF** | `_from_rrf` + `_llm_select` | Top-3 từ KB (tái dùng `DualRetriever`, RRF k=60) + LLM chọn (graceful: LLM chết → fallback top-RRF). | [446-540](../../src/agent/attack_mapper.py#L446-L540) |
| Fallback | `_unresolved` | Luôn ghi structured + `mapping_status ∈ {resolved, low_confidence}`. | [424-445](../../src/agent/attack_mapper.py#L424-L445) |

### `map_attack(inp, retriever, llm) -> MitreMapping` ⭐
- **Mục đích:** Điều phối 3 đường (curated → anchor → RRF), luôn trả schema hợp lệ.
- **TRUNG THỰC (nêu trước hội đồng):** prompt-injection gắn cờ **ATLAS** (không Enterprise); IDOR không có technique riêng → T1190 confidence thấp — không "tô hồng" độ phủ.
- **Dòng:** [585-610](../../src/agent/attack_mapper.py#L585-L610)
- **Đo:** `scripts/eval_attack_mapper.py` (DAY5 #61b); test `tests/unit/test_attack_mapper.py` (35 test, không cần LLM).

---

<a name="nhom-3"></a>
# NHÓM 3 — Giao tiếp LLM & Quan sát ngữ cảnh

<a name="d5-promptspy"></a>
## D5. `src/agent/prompts.py`
**Vai trò:** Kho mẫu Prompt (System & User) — nơi cài **quy tắc chống social-engineering** và **Active Learning few-shot**.

### `load_few_shot_feedback_context() -> str`
- **Mục đích:** Tiêm few-shot Active Learning: các rule analyst đã **Approve/Reject** (từ `system_settings.yaml`) làm ví dụ để LLM học sở thích SOC.
- **Dòng:** [62-122](../../src/agent/prompts.py#L62-L122)

### `build_triage_prompt(log_data, rag_context) -> list[dict]`
- **Mục đích:** Ghép System + User prompt cho triage.
- **Nội dung chốt:** System prompt có **rule #7 chống social-engineering** (bỏ qua tuyên bố thẩm quyền/whitelist nhúng trong log) + **Decision Matrix** (BLOCK_IP cho brute-force/scan rõ ràng từ IP ngoài whitelist trên cổng nhạy cảm SSH/FTP/RDP/SMB; ALERT cho DoS/DDoS spoofed).
- **Dòng:** [123-150](../../src/agent/prompts.py#L123-L150)

---

<a name="d6-llm_clientpy"></a>
## D6. `src/agent/llm_client.py`
**Vai trò:** Client HTTP tới LLM cục bộ (`llama.cpp` server, chuẩn OpenAI) — tất định + bền bỉ.

### `class LLMClient`
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__(base_url, max_retries=3, timeout=300)` | Cấu hình endpoint (`LLM_API_BASE` env), retry, timeout. | [58-64](../../src/agent/llm_client.py#L58-L64) |
| `invoke(...)` | POST chat-completion: `temperature=0.1` + **`seed` cố định** (config `llm.seed=42`) → cùng prompt cho **output TẤT ĐỊNH** (tái lập); `DEFAULT_MODEL` từ env (hot-swap Llama-3 trọng tài); retry + exponential backoff. Tích hợp `token_monitor`: **`preflight_check` TRƯỚC** + **`record_usage` SAU**. `MOCK_LLM=1` trả JSON cố định (test offline). | [65-156](../../src/agent/llm_client.py#L65-L156) |
| `parse_llm_response(raw)` | Bóc JSON an toàn khỏi văn bản LLM (chịu được rác quanh JSON). | [157-185](../../src/agent/llm_client.py#L157-L185) |
| `check_health()` | Ping `/health` server LLM. | [186-197](../../src/agent/llm_client.py#L186-L197) |

---

<a name="d7-token_monitorpy"></a>
## D7. `src/agent/token_monitor.py` *(Quan sát ngân sách ngữ cảnh)*
**Vai trò:** BIẾT prompt cách trần `n_ctx` bao xa — trả lời lo ngại *"log quá dài/nhiều → tràn ngữ cảnh local LLM, theo dõi thế nào?"*.

| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `estimate_tokens(messages)` | Ước lượng token bảo thủ (`chars/3.5`). | [52-57](../../src/agent/token_monitor.py#L52-L57) |
| `preflight_check(messages, max_output)` | Log **WARNING + đếm** khi prompt ước lượng vượt 90% ngân sách input (degrade **CÓ quan sát**, không âm thầm). | [58-73](../../src/agent/token_monitor.py#L58-L73) |
| `record_usage(usage)` | Ghi token **THẬT** server trả về (`response.usage`) → mean/p95/max/utilization%. | [74-92](../../src/agent/token_monitor.py#L74-L92) |
| `_persist()` | Ghi bền vững `config/llm_token_stats.json` (thread-safe, **nuốt mọi lỗi ghi file** — không bao giờ làm hỏng luồng LLM). | [93-114](../../src/agent/token_monitor.py#L93-L114) |
| `get_stats()` | Trả số liệu cho Dashboard KPI "Context Utilization". | [115-121](../../src/agent/token_monitor.py#L115-L121) |

> `N_CTX=8192` đọc từ `llm.max_context_tokens` (server llama.cpp đặt 16384 → còn headroom). Dùng bởi `run_context_stress.py` (DAY5 #57).

---

<a name="nhom-4"></a>
# NHÓM 4 — Bộ nhớ Đe dọa & Phản hồi/Audit

<a name="d8-threat_memorypy"></a>
## D8. `src/agent/threat_memory.py`
**Vai trò:** Uy tín IP dài hạn + chuỗi APT đa-ngày + chống Memory Poisoning. Lưu **SQLite** (`config/threat_memory.db`).

### `class ThreatMemoryStore`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(db_path)` / `_init_db()` | Mở DB, tạo bảng `ip_reputation / known_entities / threat_events / apt_indicators`. | [45-135](../../src/agent/threat_memory.py#L45-L135) |
| `record_incident(ip, action, mitre)` | Ghi sự cố + cộng điểm uy tín (qua `output_sanitizer`). | [136-198](../../src/agent/threat_memory.py#L136-L198) |
| `get_ip_reputation(ip)` | Tra điểm uy tín một IP. | [199-209](../../src/agent/threat_memory.py#L199-L209) |
| `get_high_risk_ips(min_score, limit)` | Top IP nguy cơ cho Dashboard. | [210-225](../../src/agent/threat_memory.py#L210-L225) |
| `decay_reputation(decay_rate, inactive_days)` | **Giảm dần uy tín** IP im lặng lâu (≈ TTL mềm). | [226-250](../../src/agent/threat_memory.py#L226-L250) |
| `add/remove/is/get_all_known_entity` | Quản lý thực thể đã biết (whitelist mềm, C2 đã biết...). | [251-321](../../src/agent/threat_memory.py#L251-L321) |
| `record_apt_event(...)` | Ghi sự kiện APT lẻ vào kho. | [322-350](../../src/agent/threat_memory.py#L322-L350) |
| `check_apt_chain(src_ip)` ⭐ | BẬT cờ APT khi IP xuất hiện ở **≥2 NGÀY khác nhau** (không phải "≥3 giai đoạn"). | [351-378](../../src/agent/threat_memory.py#L351-L378) |
| `ingest_dapt_chains(chains_path)` | Bulk seed 9 chuỗi APT cho Dashboard. | [379-411](../../src/agent/threat_memory.py#L379-L411) |
| `check_apt_pattern(...)` / `record_apt_indicator(...)` | Đối chiếu & ghi chỉ dấu APT (vd `multi_day_chain`). | [412-500](../../src/agent/threat_memory.py#L412-L500) |
| `get_context_for_prompt(source_ip, max_tokens=300)` ⭐ | Kết xuất reputation + known-entity + **CHUỖI APT đa-ngày** nhét vào prompt LLM. | [501-556](../../src/agent/threat_memory.py#L501-L556) |
| `get_stats / get_all_threat_events / get_threat_events_for_ip` | Số liệu & sự kiện cho Dashboard. | [557-600](../../src/agent/threat_memory.py#L557-L600) |

> **Mối quan hệ:** ghi bởi `node_action_executor`; đọc bởi `node_rag_context`; `subscriber` ghi APT emergent (DAY1).

---

<a name="d9-executorpy"></a>
## D9. `src/response/executor.py`
**Vai trò:** **Audit trail không thể chối cãi (HMAC móc-xích)** + hành động ứng phó (MOCK) + khoá đăng nhập.

### `class ActionValidator`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `validate_action(action)` | Chỉ cho action ∈ `ALLOWED_ACTIONS = {BLOCK_IP, QUARANTINE, ALERT, LOG, AWAIT_HITL}` (chặn `HACK_BACK`...). | [45-49](../../src/response/executor.py#L45-L49) |
| `sanitize_target(target)` | Làm sạch IP/host đích. | [50-64](../../src/response/executor.py#L50-L64) |
| `sanitize_reason(reason)` | Làm sạch lý do (chống injection vào audit). | [65-76](../../src/response/executor.py#L65-L76) |

### Hàm module
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `_init_db()` | Tạo `config/audit_trail.db` (bảng `audit_trail` + cột `integrity_hash`, + bảng login-lock). | [77-113](../../src/response/executor.py#L77-L113) |
| `_log_to_db(action, target, reason)` ⭐ | Ghi audit + **móc-xích HMAC-SHA256**: đọc `integrity_hash` dòng TRƯỚC → hash cùng bản ghi mới → chuỗi không thể sửa 1 dòng mà không vỡ. | [114-156](../../src/response/executor.py#L114-L156) |
| `block_ip / quarantine_host / raise_alert` | **`[FIREWALL MOCK]`** — ghi audit, **KHÔNG** gọi iptables/OS (enforcement thật là luật ACTIVE ở Tier-1, DAY1). | [157-173](../../src/response/executor.py#L157-L173) |
| `get_audit_trail / get_audit_trail_for_ip` | Đọc audit cho Dashboard. | [174-201](../../src/response/executor.py#L174-L201) |
| `verify_audit_trail_integrity()` | Duyệt lại toàn chuỗi HMAC → phát hiện giả mạo (True/False + vị trí). | [202-242](../../src/response/executor.py#L202-L242) |
| `get/increment/reset_login_attempts`, `lock_user` | Khoá brute-force đăng nhập Dashboard (dùng bởi `auth.py`, DAY5). | [243-327](../../src/response/executor.py#L243-L327) |

> ⚠️ **Đánh đổi (nêu trước hội đồng):** `_log_to_db` ghi **tuần tự** (đọc hash dòng trước rồi insert) → không ghi song song; đánh đổi throughput lấy **toàn vẹn** (tamper-evidence). Đúng ưu tiên cho audit.

---

<a name="phụ-lục"></a>
# Phụ lục — Bảng đồng bộ & điểm cần lưu ý

| # | Mức độ | Vấn đề / Lưu ý | Vị trí |
|---|--------|----------------|--------|
| 1 | 🟢 Tốt | **Suy biến an toàn (graceful degradation):** LLM cục bộ chết → `node_llm_triage` không vỡ, ép `AWAIT_HITL`; Tier-1 vẫn bảo vệ độc lập. Kiểm bởi `run_llm_robustness.py` (DAY5 #58B). | [nodes.py:131](../../src/agent/nodes.py#L131) |
| 2 | 🟢 Tốt | **Tất định (determinism):** `seed=42` + `temperature=0.1` → cùng prompt cho cùng action. Kiểm bởi `run_llm_robustness.py` (#58A). | [llm_client.py:65](../../src/agent/llm_client.py#L65) |
| 3 | 🟢 Tốt | **Consensus Guard:** Tier-1 coi tấn công + LLM hạ LOG/DROP → ép `AWAIT_HITL` (đóng lỗ hổng social-engineering 16.7%→0%). | [nodes.py:131](../../src/agent/nodes.py#L131), decision_validator (DAY2) |
| 4 | 🟢 Tốt | **Cổng route theo ACTION** (không theo confidence) — vá việc ngưỡng `>0.7` cũ lọc mất verdict `ALERT@0.6–0.7`. | [workflow.py:26](../../src/agent/workflow.py#L26) |
| 5 | 🟢 Tốt | **Mapper tái dùng** `DualRetriever` + `llm_client` singleton + KB 299 kỹ thuật — KHÔNG dựng endpoint song song. | [attack_mapper.py:585](../../src/agent/attack_mapper.py#L585) |
| 6 | 🟢 Tốt | **Audit HMAC móc-xích** — `verify_audit_trail_integrity` phát hiện sửa 1 dòng; KHÁC bảng `audit_log` research của `state_monitor` (DAY2 — G9). | [executor.py:114](../../src/response/executor.py#L114) |
| 7 | 🟡 Vừa | Luật `ACTIVE` do HITL duyệt hiện **không có TTL** (sống mãi, cho demo). Production cần eviction (LRU/TTL 24h) — trùng lưu ý DAY1 (feedback_listener). | feedback_listener (DAY1) |
| 8 | 🟢 Trung thực | `map_attack` gắn cờ ATLAS cho prompt-injection (không Enterprise), IDOR→T1190 confidence thấp — **không tô hồng** độ phủ KB. | [attack_mapper.py:585](../../src/agent/attack_mapper.py#L585) |

### Cải tiến tích cực (nên nêu trước hội đồng)
- ✅ **Đồ thị 6-node tường minh** (LangGraph) — dễ chèn node, graceful degradation, cổng theo ACTION.
- ✅ **Tự tiến hoá (self-evolving) học 2 cấp:** Tier-2 ghi ngược Tier-1 cả **luật IP** ("nhớ mặt") lẫn **luật HÀNH VI** ("nhớ ngón đòn" — chữ ký UA/URI) → IP MỚI cùng kỹ thuật bị Tier-1 bắt ở **~10µs** thay vì ~11s gọi LLM; vẫn qua Zero-Trust `FeedbackValidator` + HITL. Đo bởi `tests/unit/test_behavioral_learning.py` (14 test).
- ✅ **LLM tất định** (seed=42) + **suy biến an toàn** (LLM chết → AWAIT_HITL, hệ không vỡ).
- ✅ **Ánh xạ MITRE có cấu trúc, kiểm chứng Pydantic** — 3 đường (curated/anchor/RRF), trung thực về giới hạn.
- ✅ **Bộ nhớ Đe dọa đa-ngày** — APT emergent + reputation decay; chống Memory Poisoning bằng `output_sanitizer`.
- ✅ **Audit HMAC móc-xích** — tamper-evidence kiểu blockchain (VƯỢT phạm vi sách System Design).
- ✅ **Quan sát ngân sách ngữ cảnh** (`token_monitor`) — degrade có quan sát, không âm thầm.

---

*Tài liệu sinh từ phân tích mã nguồn (Ngày 4) — đối chiếu lại số dòng nếu mã thay đổi. Xem thêm: [DAY1](DAY1.md) (Tier-1/Streaming) · [DAY2](DAY2.md) (Guardrails) · [DAY3](DAY3.md) (Dual-RAG) · [DAY5](DAY5.md) (UI + Đánh giá) · tổng quan [codebase_summary](../codebase_summary.md).*
