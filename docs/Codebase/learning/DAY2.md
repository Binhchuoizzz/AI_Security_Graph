# SENTINEL — Tài liệu tham chiếu hàm (Function Reference) — NGÀY 2

> **Phạm vi:** Mô tả **chi tiết từng hàm** của **11 file** thuộc **Tầng An toàn Guardrails** (`src/guardrails/` + `demos/demo_guardrails.py`) — lá chắn AI nằm giữa Tier-1 và LLM Agent.
> **Cập nhật:** 2026-06-11 (đồng bộ lại số dòng theo code thực tế sau đợt mở rộng `EncodingNeutralizer` + refactor cấu trúc thư mục).
> **Quy ước:** Mỗi hàm ghi rõ *Mục đích → Tham số → Trả về → Luồng xử lý → Tham chiếu dòng*.

---

## 💡 Sơ đồ 1 phút (đọc để hình dung nhanh)

> **Guardrails = lá chắn AI giữa Tier-1 và LLM**, phòng thủ 2 chiều (defense-in-depth).
> **Đầu vào:** batch ESCALATE → chuẩn hoá key → validate schema → *phát hiện injection/jailbreak* (chỉ ĐÁNH DẤU, không xoá) → *trung hoà encoding* (base64/hex/homoglyph/zero-width) → *nén Drain + entropy + token budget* (giữ context trong tầm) → *bọc nonce delimiter* (chỉ giữ `ALLOWED_FIELDS`, chống buôn lậu dấu phân tách) → LLM.
> **Đầu ra LLM:** *validate decision* (enum guard · confidence gate · Anti-Self-DoS · **Tier-Consensus** ép AWAIT_HITL khi LLM bị "nói chuyện" hạ cấp) → *sanitize XSS/markdown/base64*.
> Ý tưởng cốt lõi: **coi log là DATA ONLY**, tầng deterministic (Tier-1) làm trọng tài kiểm tra tầng LLM.

---

## Mục lục

- [0. Bản đồ kiến trúc tổng thể](#0-bản-đồ-kiến-trúc-tổng-thể)
- [NHÓM 1 — Chuẩn hóa & Nén đầu vào](#nhom-1)
  - [G1. `src/guardrails/constants.py`](#g1-constantspy)
  - [G2. `src/guardrails/template_miner.py`](#g2-template_minerpy)
- [NHÓM 2 — Phòng thủ Prompt Injection đầu vào](#nhom-2)
  - [G3. `src/guardrails/data_validator.py`](#g3-data_validatorpy)
  - [G4. `src/guardrails/prompt_filter.py`](#g4-prompt_filterpy)
- [NHÓM 3 — Phòng thủ ĐẦU RA & Quyết định](#nhom-3)
  - [G5. `src/guardrails/output_sanitizer.py`](#g5-output_sanitizerpy)
  - [G6. `src/guardrails/decision_validator.py`](#g6-decision_validatorpy)
- [NHÓM 4 — Phòng thủ RAG & Vòng phản hồi](#nhom-4)
  - [G7. `src/guardrails/rag_sanitizer.py`](#g7-rag_sanitizerpy)
  - [G8. `src/guardrails/feedback_validator.py`](#g8-feedback_validatorpy)
- [NHÓM 5 — Giám sát runtime & Đóng gói](#nhom-5)
  - [G9. `src/guardrails/state_monitor.py`](#g9-state_monitorpy)
  - [G10. `src/guardrails/__init__.py`](#g10-__init__py)
  - [G11. `demos/demo_guardrails.py`](#g11-demo_guardrailspy)
- [Phụ lục — Bảng đồng bộ & điểm cần lưu ý](#phụ-lục)

---

## 0. Bản đồ kiến trúc tổng thể

```
ESCALATE từ Tier-1 (batch logs) ─────────────────────────────────────┐
                                                                       ▼
                                       [constants.normalize_log_keys]  chuẩn hóa tên trường
                                                                       ▼
                                       [data_validator.validate]       kiểm schema / ép kiểu / IP-port
                                                                       ▼
        ┌──────────────────  GuardrailsPipeline.process_batch  ──────────────────┐
        │  PromptInjectionDetector.scan   → cờ injection (_isolation HIGH)        │
        │  JailbreakDetector.scan         → cờ jailbreak  (_isolation CRITICAL)   │
        │  EncodingNeutralizer.neutralize → giải base64/url/hex, strip zero-width │
        │  LogTemplateMiner (drain3)      → nén volume thành template            │
        │  EntropyScorer                  → ưu tiên giữ log entropy cao          │
        │  TokenBudgetManager             → cắt theo ngân sách token             │
        │  DelimitedDataEncapsulator      → bọc nonce + strip delimiter smuggling│
        └────────────────────────────────────────────────────────────────────────┘
                                                                       ▼
                          encapsulated_text + system_instruction  ──►  LLM Agent (Tier-2, Ngày 4)
                                                                       │ (quyết định JSON)
                                                                       ▼
   [decision_validator.validate_decision]  enum guard · confidence gate · anti-Self-DoS · sanitize reasoning
   [decision_validator.enforce_tier_consensus]  Tier-1 nói tấn công + LLM hạ LOG/DROP → ép AWAIT_HITL
                                                                       ▼
   [output_sanitizer.sanitize]  strip XSS/markdown/base64-hex obfuscation  ──►  UI / DB
                                                                       ▼
   [feedback_validator]  (khi Agent đẩy rule về Tier-1) Zero-Trust validate rule/whitelist

XUYÊN SUỐT:
   [rag_sanitizer]  bảo vệ RAG ingest/retrieve/cache (Ngày 3 dùng)
   [state_monitor]  AuditLogger (SQLite) · LoopDetector · ContextOverflowGuard
```

**Khớp nối tối quan trọng:** mọi module dùng chung `KEY_ALIASES`/`normalize_log_keys` (G1) để đồng bộ tên trường; và `load_config()` của `prompt_filter` (G4) là **single source of truth** cho `injection_patterns`/`jailbreak_patterns` (được `rag_sanitizer` import lại).

---

<a name="nhom-1"></a>
# NHÓM 1 — Chuẩn hóa & Nén đầu vào

<a name="g1-constantspy"></a>
## G1. `src/guardrails/constants.py`
**Vai trò:** Nguồn chuẩn hóa tên trường log dùng chung toàn tầng Guardrails — chống sai lệch cấu trúc dữ liệu giữa các module.

### Hằng số
| Tên | Mô tả |
|-----|-------|
| `KEY_ALIASES` | Ánh xạ biến thể (`src_ip`, `dst_port`, `user_agent`, `uri`...) → tên chuẩn (`Source IP`, `Destination Port`, `User-Agent`, `URI`). |

### `normalize_log_keys(log_entry: dict) -> dict`
- **Mục đích:** Trả về dict MỚI với key đã chuẩn hóa qua `KEY_ALIASES`.
- **Luồng:** Duyệt `(k,v)`; tra `KEY_ALIASES.get(k.lower(), k)`; key không có trong bảng → giữ nguyên.
- **Dòng:** [26-35](../src/guardrails/constants.py#L26-L35)

---

<a name="g2-template_minerpy"></a>
## G2. `src/guardrails/template_miner.py`
**Vai trò:** Nén volume logs (drain3) + chấm entropy + quản ngân sách token để LLM không bị quá tải context.

### `load_config() -> dict`
- **Lazy loader** import `prompt_filter.load_config` trong thân hàm để **phá vòng import vòng (circular)**. **Dòng:** [20-22](../src/guardrails/template_miner.py#L20-L22)

### `class LogTemplateMiner` — nén log bằng Drain3
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__(max_samples=3)` | Đọc `drain3.*` từ config (depth/sim/max_children/max_clusters), 3 `MaskingInstruction` (IP→`<IP>`, hash→`<HASH>`, số→`<NUM>`); guard ép kiểu `max_samples`. | [31-64](../src/guardrails/template_miner.py#L31-L64) |
| `templates` (property) | Trả `dict template_key → {template, count, samples, time_range}` (tương thích test cũ). | [66-86](../src/guardrails/template_miner.py#L66-L86) |
| `add_log(log_str, timestamp=None)` | `drain3.add_log_message` → phân cluster; giữ ≤`max_samples` mẫu gốc; cập nhật time-range. | [88-111](../src/guardrails/template_miner.py#L88-L111) |
| `add_log_dict(log_entry)` | Trích các trường chính (Source IP, Destination Port...) thành chuỗi rồi `add_log`. | [113-138](../src/guardrails/template_miner.py#L113-L138) |
| `get_summary()` | List cluster, **sắp xếp theo count giảm dần**. | [140-155](../src/guardrails/template_miner.py#L140-L155) |
| `get_compression_ratio()` | `total_logs_processed / số_cluster` (vd 1000→5 = 200x). | [157-161](../src/guardrails/template_miner.py#L157-L161) |
| `format_for_llm()` | Format template + count + time-range + vài mẫu → text cho prompt. | [163-184](../src/guardrails/template_miner.py#L163-L184) |
| `reset()` | Khởi tạo lại miner cho time-window mới. | [186-191](../src/guardrails/template_miner.py#L186-L191) |

### `class EntropyScorer` — Shannon entropy
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(threshold=None)` | Đọc `guardrails.entropy_threshold` (mặc định 4.5). | [199-205](../src/guardrails/template_miner.py#L199-L205) |
| `calculate(text)` *(static)* | `H = -Σ p·log2(p)`. Benign ≈3-4; base64/hex ≈5-6. | [207-215](../src/guardrails/template_miner.py#L207-L215) |
| `is_high_entropy(log_str)` | `calculate > threshold`. | [217-218](../src/guardrails/template_miner.py#L217-L218) |
| `score(log_str)` | `{entropy, is_high_entropy, priority}`. | [220-226](../src/guardrails/template_miner.py#L220-L226) |

### `class TokenBudgetManager` — ngân sách token
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(budget=None)` | **Tham số tường minh ưu tiên hơn config**; không truyền → đọc `guardrails.token_budget` (mặc định 4000). | [234-251](../src/guardrails/template_miner.py#L234-L251) |
| `estimate_tokens(text)` *(static)* | Heuristic `len//4` (4 ký tự ≈ 1 token) — **không dùng tiktoken**. | [253-255](../src/guardrails/template_miner.py#L253-L255) |
| `fit_to_budget(template_text, high_entropy_logs=None)` | 40% budget cho log entropy cao + 60% cho template; vượt → `[TRUNCATED due to token budget]`. | [257-289](../src/guardrails/template_miner.py#L257-L289) |

---

<a name="nhom-2"></a>
# NHÓM 2 — Phòng thủ Prompt Injection đầu vào

<a name="g3-data_validatorpy"></a>
## G3. `src/guardrails/data_validator.py`
**Vai trò:** Chốt chặn schema đầu vào trước khi log lên Tier-2 (chống Schema Abuse).

### Hằng số
- `REQUIRED_FIELDS = ["Source IP", "Destination Port", "Protocol"]` — thiếu 1 → `_is_valid=False`. **Dòng:** [12](../src/guardrails/data_validator.py#L12)

### `class DataValidator`
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__(required_fields=None)` | Normalize `required_fields` qua `KEY_ALIASES`. | [20-26](../src/guardrails/data_validator.py#L20-L26) |
| `validate(log_entry)` | **7 bước:** normalize key → `None/NaN→""` → kiểm required → ép kiểu (Port/Proto→int, Packets/Duration→float) → validate IP (`ipaddress`) → port `[0,65535]` → protocol `[0,255]`; gắn `_validation_errors`, `_is_valid`. | [28-88](../src/guardrails/data_validator.py#L28-L88) |
| `validate_batch(batch, filter_invalid=False, raise_on_error=False)` | Validate lô; `filter_invalid` loại log lỗi; `raise_on_error` ném `ValueError` ở log lỗi đầu. | [90-108](../src/guardrails/data_validator.py#L90-L108) |

---

<a name="g4-prompt_filterpy"></a>
## G4. `src/guardrails/prompt_filter.py` ⭐ (Lõi phòng thủ Injection)
**Vai trò:** 3 tầng chống Direct Prompt Injection + orchestrator nén/đóng gói batch trước khi vào LLM.

### Hằng số & hàm module
- `CONFIG_PATH` — đường dẫn `system_settings.yaml`. **Dòng:** [19-21](../src/guardrails/prompt_filter.py#L19-L21)
- `load_config()` — **nguồn config trung tâm** (được `rag_sanitizer`, `decision_validator`, `template_miner` import lại); fallback hardcode 17 `injection_patterns` + 15 `jailbreak_patterns`. **Dòng:** [24-52](../src/guardrails/prompt_filter.py#L24-L52)

### `class PromptInjectionDetector` *(Tầng 1)*
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(patterns=None)` | Load + compile regex `injection_patterns` (IGNORECASE). | [63-66](../src/guardrails/prompt_filter.py#L63-L66) |
| `scan(log_entry)` | Normalize key → match từng field (bỏ field `_`) → **chỉ đánh dấu, không xóa**: `_injection_detected/_patterns/_fields/_isolation_level` (HIGH/NORMAL). | [68-94](../src/guardrails/prompt_filter.py#L68-L94) |

### `class JailbreakDetector` *(Tầng 1b)*
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(patterns=None)` | Load `jailbreak_patterns` + regex `role_play_re` (you are now / act as / pretend...). | [105-115](../src/guardrails/prompt_filter.py#L105-L115) |
| `scan(log_entry)` | Phát hiện DAN/Developer Mode/roleplay → set `_isolation_level=CRITICAL`. | [117-148](../src/guardrails/prompt_filter.py#L117-L148) |

### `class EncodingNeutralizer` *(Tầng 2)*

> ⚠️ **Mở rộng so với phiên bản gốc:** Nay bổ sung thêm `_CONFUSABLE_MAP` (Cyrillic/Greek homoglyph folding, [156-168](../src/guardrails/prompt_filter.py#L156-L168)), `_LEET_MAP` (leetspeak, [171-174](../src/guardrails/prompt_filter.py#L171-L174)), `_DECODE_TRIGGERS` + `_looks_malicious()` ([177-188](../src/guardrails/prompt_filter.py#L177-L188)), và 4 decoder mới (`fold_homoglyphs`, `normalize_leetspeak`, `decode_rot13`, `decode_if_base32`) cùng `_expose_obfuscated()` tổng hợp.

| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `decode_if_base64(text)` *(static)* | Decode base64; nếu printable → phơi bày `[BASE64_DECODED: …]`. | [197-210](../src/guardrails/prompt_filter.py#L197-L210) |
| `neutralize_html_entities(text)` *(static)* | `<script>/<img>/<iframe>` → placeholder; tag còn lại xóa. | [213-231](../src/guardrails/prompt_filter.py#L213-L231) |
| `normalize_unicode(text)` *(static)* | NFKC normalize + xóa zero-width (`​-‍`, `﻿`, `­`, `\x00`). | [234-239](../src/guardrails/prompt_filter.py#L234-L239) |
| `fold_homoglyphs(text)` *(static)* 🆕 | Map Cyrillic/Greek look-alike chars → ASCII Latin (chống homoglyph bypass). | [242-244](../src/guardrails/prompt_filter.py#L242-L244) |
| `normalize_leetspeak(text)` *(static)* 🆕 | Fold leetspeak (`1gn0r3` → `ignore`). | [247-249](../src/guardrails/prompt_filter.py#L247-L249) |
| `decode_rot13(text)` *(static)* 🆕 | ROT13 decode (chỉ shift ASCII letters). | [252-254](../src/guardrails/prompt_filter.py#L252-L254) |
| `decode_if_base32(text)` *(static)* 🆕 | Decode base32 nếu ≥16 ký tự, trả decoded hoặc `None`. | [257-266](../src/guardrails/prompt_filter.py#L257-L266) |
| `decode_url_and_hex(text)` *(static)* | URL-decode + `\xNN` hex-escape. | [269-279](../src/guardrails/prompt_filter.py#L269-L279) |
| `_expose_obfuscated(text)` 🆕 | Thử base32/rot13/leet/homoglyph → nếu decoded chứa trigger injection mà original không → append `[XXX_DECODED: …]`. Guarded: không mangle text benign. | [281-298](../src/guardrails/prompt_filter.py#L281-L298) |
| `neutralize(log_entry)` | Pipeline mỗi field: unicode → url/hex → base64 → **expose_obfuscated** → html. | [300-314](../src/guardrails/prompt_filter.py#L300-L314) |

### `class DelimitedDataEncapsulator` *(Tầng 3 — Core Defense)*
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__()` | Sinh **nonce `secrets.token_hex(8)`** → `data_start/data_end` riêng mỗi instance (kẻ tấn công không đoán được). | [327-330](../src/guardrails/prompt_filter.py#L327-L330) |
| `_sanitize_delimiter_smuggling(text)` | Regex `<<<[^>]*>>>` → `[DELIMITER_STRIPPED]` (chống giả mạo delimiter thoát vùng data). | [332-335](../src/guardrails/prompt_filter.py#L332-L335) |
| `get_system_instruction()` | Sinh system prompt động chứa delimiter thật + chỉ thị "treat as DATA ONLY". | [337-348](../src/guardrails/prompt_filter.py#L337-L348) |
| `encapsulate(text, isolation_level="NORMAL")` | Bọc text trong delimiter; `HIGH` → thêm cảnh báo. | [350-360](../src/guardrails/prompt_filter.py#L350-L360) |
| `encapsulate_fields(log_entry)` | **Chỉ giữ `ALLOWED_FIELDS`** (Source IP, Port, payload, URI, User-Agent...) rồi encapsulate — chống leak field nội bộ `_*`. | [362-383](../src/guardrails/prompt_filter.py#L362-L383) |

### `class GuardrailsPipeline` — Orchestrator
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__()` | Khởi tạo 4 component (Injection, Jailbreak, Encoding, Encapsulator). | [397-401](../src/guardrails/prompt_filter.py#L397-L401) |
| `process(log_entry)` | `normalize → injection_scan → jailbreak_scan → neutralize → encapsulate_fields`; trả `{sanitized_log, encapsulated_text, injection/jailbreak_detected, isolation_level, system_instruction}`. | [403-423](../src/guardrails/prompt_filter.py#L403-L423) |
| `process_batch(logs)` | `process` từng log → nén `LogTemplateMiner` → ưu tiên `EntropyScorer` → cắt `TokenBudgetManager` → chọn isolation cao nhất → encapsulate. | [425-473](../src/guardrails/prompt_filter.py#L425-L473) |

---

<a name="nhom-3"></a>
# NHÓM 3 — Phòng thủ ĐẦU RA & Quyết định

<a name="g5-output_sanitizerpy"></a>
## G5. `src/guardrails/output_sanitizer.py`
**Vai trò:** Làm sạch **đầu ra LLM** trước khi render UI / ghi DB — chống Data Exfiltration & XSS/Markdown.

### `class OutputSanitizer`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__()` | Compile 11 regex nguy hiểm (markdown image/link, `<script>/<img>/<iframe>/<svg>/<object>/<embed>/<style>`, data URI). | [46-51](../src/guardrails/output_sanitizer.py#L46-L51) |
| `_sanitize_base64(text)` | Decode khối base64 ≥8 ký tự; chứa trigger (`<script`, `javascript:`, `onerror=`...) → `[BASE64_OBFUSCATED_STRIPPED]`. | [53-81](../src/guardrails/output_sanitizer.py#L53-L81) |
| `_sanitize_hex(text)` | Tương tự với hex ≥8 → `[HEX_OBFUSCATED_STRIPPED]`. | [83-106](../src/guardrails/output_sanitizer.py#L83-L106) |
| `sanitize(text)` | Pipeline: strip zero-width → strip ANSI → 11 regex → base64 sâu → hex sâu → log cảnh báo. | [108-144](../src/guardrails/output_sanitizer.py#L108-L144) |
| `sanitize_for_db(text)` | Wrapper cho path ghi DB (SQLite dùng parameterized query). | [146-153](../src/guardrails/output_sanitizer.py#L146-L153) |
| `last_strip_count` (property) | Số pattern bị strip lần gần nhất (metrics). | [156-158](../src/guardrails/output_sanitizer.py#L156-L158) |

> **Singleton:** `output_sanitizer = OutputSanitizer()` — dùng bởi `decision_validator`, `threat_memory`, `nodes`.

---

<a name="g6-decision_validatorpy"></a>
## G6. `src/guardrails/decision_validator.py` ⭐ (Kiểm duyệt quyết định LLM)
**Vai trò:** Thẩm định & làm an toàn quyết định LLM trước khi thực thi — chống Hallucination / Self-DoS / **Social-Engineering ngữ nghĩa**.

### `class DecisionValidator`
- `__init__()` — load **`critical_infrastructure_subnets`** (HẸP: loopback + IP hạ tầng cụ thể, KHÔNG phải toàn RFC1918); `allowed_actions=["BLOCK_IP","ALERT","AWAIT_HITL","LOG","DROP"]`. **Dòng:** [19-30](../src/guardrails/decision_validator.py#L19-L30)
- **Lưu ý:** `class DecisionValidator` khai báo ở [dòng 13](../src/guardrails/decision_validator.py#L13).

### `validate_decision(decision) -> dict` — 4 lớp bảo vệ
| Lớp | Việc | Dòng |
|-----|------|------|
| 1 — Action Enum Guard | Action ngoài enum → ép `AWAIT_HITL` (chặn `HACK_BACK`...). | [32-37](../src/guardrails/decision_validator.py#L32-L37) |
| 2 — Confidence Gate | `BLOCK_IP` & `confidence<0.5` → hạ `AWAIT_HITL`. | [39-51](../src/guardrails/decision_validator.py#L39-L51) |
| 3 — Anti-Self-DoS Shield | `BLOCK_IP` lên **hạ tầng trọng yếu** (`critical_infrastructure_subnets` HẸP: loopback + gateway/DNS cụ thể) → hạ `ALERT`. Closure `parse_ip_or_network` parse **dotted/CIDR/hex `0x`/octal/decimal** chống bypass. **KHÔNG dùng toàn RFC1918** — nếu coi cả 10/8, 172.16/12, 192.168/16 là "không chặn" thì attacker nội bộ/lateral/insider sẽ KHÔNG bao giờ bị BLOCK (vá 2026-06). | [53-125](../src/guardrails/decision_validator.py#L53-L125) |
| 4 — Reasoning Sanitization | `output_sanitizer.sanitize()` cho `reasoning/mitre/nist` (chống XSS-SSRF UI). | [127-136](../src/guardrails/decision_validator.py#L127-L136) |
- **Dòng tổng:** [26-136](../src/guardrails/decision_validator.py#L26-L136)

### `enforce_tier_consensus(validated, tier1_flagged_attack) -> dict` 🛡️ *(mới)*
- **Mục đích:** Lá chắn chống **social-engineering ngữ nghĩa** (giả mạo thẩm quyền/ngữ cảnh trong log).
- **Luồng:** Nếu `tier1_flagged_attack=True` (Tier-1 xác định coi là tấn công) NHƯNG LLM hạ xuống `LOG/DROP` → **KHÔNG tin LLM**: ép `AWAIT_HITL`, gắn cờ `_tier_consensus_override`, chèn ghi chú kiểm duyệt. Tier-1 không thể bị "nói chuyện" hạ cấp như LLM.
- **Tham chiếu gọi:** `node_llm_triage` truyền `tier1_flagged_attack` (bất kỳ log nào có `tier1_action ∈ {BLOCK_IP,ESCALATE,AWAIT_HITL,ALERT}` hoặc `tier1_score≥30`).
- **Dòng:** [138-162](../src/guardrails/decision_validator.py#L138-L162)

---

<a name="nhom-4"></a>
# NHÓM 4 — Phòng thủ RAG & Vòng phản hồi

<a name="g7-rag_sanitizerpy"></a>
## G7. `src/guardrails/rag_sanitizer.py`
**Vai trò:** Chống RAG Poisoning / Indirect Prompt Injection tại 3 điểm (ingest, retrieve, semantic-cache). *(Tích hợp sâu ở Ngày 3 — `src/rag/`.)*

### `class RAGSanitizer`
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__()` | Load + compile `injection_patterns` & `jailbreak_patterns` (từ `prompt_filter.load_config`). | [22-39](../src/guardrails/rag_sanitizer.py#L22-L39) |
| `sanitize_ingest(text, max_length=1500)` *(static)* | **Lúc nạp KB:** NFKC normalize (chống homoglyph) → strip control/zero-width → strip HTML/JS → strip markdown image/link → truncate. | [42-88](../src/guardrails/rag_sanitizer.py#L42-L88) |
| `sanitize_retrieve(text)` | **Lúc truy xuất:** strip `<<<...>>>` → trung hòa injection (`[POISONOUS_INSTRUCTION_NEUTRALIZED]`) → trung hòa jailbreak. | [90-127](../src/guardrails/rag_sanitizer.py#L90-L127) |
| `sanitize_cache_entry(entry)` | **Cache-HIT path:** làm sạch `mitre_results[*].text`, `nist_results[*].text`, `mitre_context`, `nist_context` (chống Semantic Cache Poisoning). | [129-176](../src/guardrails/rag_sanitizer.py#L129-L176) |

---

<a name="g8-feedback_validatorpy"></a>
## G8. `src/guardrails/feedback_validator.py`
**Vai trò:** Zero-Trust kiểm duyệt rule động & whitelist trước khi đẩy về Tier-1 (tích hợp trong `FeedbackListener`).

### `class FeedbackValidator`
- `__init__()` — load `trusted_internal_subnets`; `allowed_fields=[Source IP, Destination Port, Protocol, URI, User-Agent]`. **Dòng:** [21-30](../src/guardrails/feedback_validator.py#L21-L30)

### `validate_rule(field, pattern, score) -> (bool, errors)` — 5 kiểm tra
| # | Kiểm tra | Dòng |
|---|----------|------|
| 1 | Field ∈ `allowed_fields` (sau normalize). | [39-45](../src/guardrails/feedback_validator.py#L39-L45) |
| 2 | Pattern không rỗng. | [47-52](../src/guardrails/feedback_validator.py#L47-L52) |
| 3 | Chặn wildcard `0.0.0.0/0`, `*`, `any`, `all`, `::/0`. | [53-58](../src/guardrails/feedback_validator.py#L53-L58) |
| 4 | Field=Source IP: cấm IP hạ tầng, CIDR `< /8`, cấm match network-address. | [60-93](../src/guardrails/feedback_validator.py#L60-L93) |
| 5 | URI/User-Agent: validate regex `re.compile`; score ∈ `[0,100]`. | [95-108](../src/guardrails/feedback_validator.py#L95-L108) |

| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `validate_whitelist_ip(ip_str)` | Chỉ cho whitelist IP/CIDR nằm hoàn toàn trong subnet tin cậy; public IP (8.8.8.8) → từ chối. | [110-157](../src/guardrails/feedback_validator.py#L110-L157) |
| `get_allowed_fields()` | Trả `allowed_fields`. | [159-160](../src/guardrails/feedback_validator.py#L159-L160) |

---

<a name="nhom-5"></a>
# NHÓM 5 — Giám sát runtime & Đóng gói

<a name="g9-state_monitorpy"></a>
## G9. `src/guardrails/state_monitor.py`
**Vai trò:** Giám sát runtime Agent — audit log SQLite, chống vòng lặp vô hạn, kiểm soát context window.

### Hằng số & hàm module
- `_db_lock = threading.Lock()` — bảo vệ ghi SQLite đa luồng. **Dòng:** [17](../src/guardrails/state_monitor.py#L17)
- `load_config()` — bản local (fallback `llm.max_context_tokens`, `guardrails.token_budget`, `logging.audit_db_path`). **Dòng:** [20-39](../src/guardrails/state_monitor.py#L20-L39)

### `class ContextOverflowGuard`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__()` | Đọc `max_tokens` (8192) + `log_budget` (4000). | [48-55](../src/guardrails/state_monitor.py#L48-L55) |
| `check(prompt_tokens, log_tokens)` | `total>max` → `{is_overflow:True, action:"TRUNCATE_LOGS"}`, ngược lại `"PASS"`. | [57-65](../src/guardrails/state_monitor.py#L57-L65) |

### `class LoopDetector`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(max_iterations=10)` | Khởi tạo `node_counter`. | [74-76](../src/guardrails/state_monitor.py#L74-L76) |
| `record_visit(node_name)` | Vượt ngưỡng → `FORCE_STOP`, ngược lại `CONTINUE`. | [78-92](../src/guardrails/state_monitor.py#L78-L92) |
| `reset()` | Xóa counter — **gọi trước mỗi `agent_app.invoke()`**. | [94-95](../src/guardrails/state_monitor.py#L94-L95) |

### `class AuditLogger`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__()` | Đọc `audit_db_path` (`logs/guardrails_audit.db`), gọi `_init_db()`. | [107-112](../src/guardrails/state_monitor.py#L107-L112) |
| `_init_db()` | Tạo bảng `audit_log` (lock + try/finally đóng connection). | [114-140](../src/guardrails/state_monitor.py#L114-L140) |
| `log_event(event)` | Insert audit (timestamp, tier1_score/action, guardrail_injected, agent_decision/reasoning, mitre/nist, latency, metadata JSON). | [142-184](../src/guardrails/state_monitor.py#L142-L184) |

> **Singletons:** `loop_detector`, `context_overflow_guard`, `audit_logger`.
> *(Lưu ý: `audit_log` ở `logs/guardrails_audit.db` (metadata nghiên cứu) — KHÁC bảng `audit_trail` HMAC ở `config/audit_trail.db` của `response/executor.py`, Ngày 4. Tên file đã tách riêng để tránh nhầm lẫn.)*

---

<a name="g10-__init__py"></a>
## G10. `src/guardrails/__init__.py`
**Vai trò:** Re-export để code ngoài chỉ cần `from src.guardrails import ...`.
- `__all__` xuất 20 symbol: `DataValidator`, `output_sanitizer/OutputSanitizer`, `PromptInjectionDetector`, `JailbreakDetector`, `EncodingNeutralizer`, `DelimitedDataEncapsulator`, `GuardrailsPipeline`, `loop_detector/context_overflow_guard/audit_logger`, `LoopDetector/ContextOverflowGuard/AuditLogger`, `LogTemplateMiner/EntropyScorer/TokenBudgetManager`, `RAGSanitizer`, `DecisionValidator`, `FeedbackValidator`. **Dòng:** [32-53](../src/guardrails/__init__.py#L32-L53)

---

<a name="g11-demo_guardrailspy"></a>
## G11. `demos/demo_guardrails.py`
**Vai trò:** Script minh họa 8 lớp phòng thủ Guardrails (chạy tuần tự, không có hàm).

| # | Lớp minh họa | Module |
|---|--------------|--------|
| 1 | Phát hiện Prompt Injection | `PromptInjectionDetector` |
| 2 | Phát hiện Jailbreak (DAN → CRITICAL) | `JailbreakDetector` |
| 3 | Nonce Delimiter + strip smuggling | `DelimitedDataEncapsulator` |
| 4 | Trung hòa Encoding/HTML | `EncodingNeutralizer` |
| 5 | Làm sạch RAG (ingest + retrieve) | `RAGSanitizer` |
| 6 | Kiểm duyệt quyết định LLM (downgrade SOC host) | `DecisionValidator` |
| 7 | Zero-Trust Feedback (chặn wildcard, whitelist ngoài subnet) | `FeedbackValidator` |
| 8 | Pipeline tích hợp batch (injection_count + đóng gói) | `GuardrailsPipeline` |

---

<a name="phụ-lục"></a>
# Phụ lục — Bảng đồng bộ & điểm cần lưu ý

| # | Mức độ | Vấn đề / Lưu ý | Vị trí |
|---|--------|----------------|--------|
| 1 | 🟢 Tốt | `load_config()` của `prompt_filter` là **single source of truth** cho injection/jailbreak patterns; `rag_sanitizer` import lại → đồng bộ tuyệt đối. | [prompt_filter.py:24](../src/guardrails/prompt_filter.py#L24) |
| 2 | 🟢 Tốt | `enforce_tier_consensus` đóng lỗ hổng social-engineering ngữ nghĩa (compromise 16.7%→0%). | [decision_validator.py:138](../src/guardrails/decision_validator.py#L138) |
| 3 | 🟢 Đã sửa | **Hai DB audit** từng trùng tên → đã tách: `logs/guardrails_audit.db` bảng `audit_log` (state_monitor, metadata research) vs `config/audit_trail.db` bảng `audit_trail` (executor, HMAC chain UI). | [state_monitor.py:107](../src/guardrails/state_monitor.py#L107) |
| 4 | 🟢 Đã sửa | `TokenBudgetManager(budget=...)` từng bị config `token_budget:4000` nuốt tham số → nay tham số tường minh ưu tiên, config chỉ là mặc định khi không truyền. | [template_miner.py:234](../src/guardrails/template_miner.py#L234) |
| 5 | 🟢 Thấp | `SemanticCache` (Ngày 3) là **exact-match SHA-256** chứ không phải cosine — `rag_sanitizer.sanitize_cache_entry` vẫn cần vì cache lưu trước khi sanitize retrieve. | [rag_sanitizer.py:129](../src/guardrails/rag_sanitizer.py#L129) |
| 6 | 🟢 Thấp | `EncodingNeutralizer` **strip** `<script>` thành `[SCRIPT_STRIPPED]` (an toàn hơn HTML-escape) — test E2E T08 đã đồng bộ theo hành vi này. | [prompt_filter.py:213](../src/guardrails/prompt_filter.py#L213) |
| 7 | 🟢 Mới | `EncodingNeutralizer` bổ sung **6 phương thức mới** (homoglyph/leet/rot13/base32/expose_obfuscated) đóng lỗ hổng encoding bypass, `neutralize()` nay gọi `_expose_obfuscated()` trước `neutralize_html_entities()`. | [prompt_filter.py:191-314](../src/guardrails/prompt_filter.py#L191-L314) |

### Cải tiến tích cực (nên nêu khi bảo vệ)
- ✅ **Defense-in-depth đầu vào:** 3 tầng (pattern detect → encoding neutralize → nonce encapsulation) + chỉ giữ `ALLOWED_FIELDS`.
- ✅ **Defense-in-depth đầu ra:** sanitize reasoning + strip XSS/markdown + giải obfuscation base64/hex sâu.
- ✅ **Tier-1/Tier-2 Consensus Guard:** tầng deterministic làm trọng tài kiểm tra tầng LLM bị thao túng.
- ✅ **Anti-Self-DoS Shield** parse cả hex/octal/decimal IP chống bypass.
- ✅ **Chống RAG/Cache/Memory Poisoning** xuyên 3 điểm ingest/retrieve/cache.
- ✅ **Nén volume drain3 + entropy + token budget** giữ context LLM trong tầm kiểm soát.

---

*Tài liệu sinh từ phân tích mã nguồn (Ngày 2) — đối chiếu lại số dòng nếu mã thay đổi. Xem thêm: [DAY1](DAY1.md) (Tier-1) · [DAY3](DAY3.md) (Dual-RAG) · [DAY4](DAY4.md) (Agent + Audit) · [DAY5](DAY5.md) (UI + Đánh giá) · [codebase_summary](../codebase_summary.md).*
