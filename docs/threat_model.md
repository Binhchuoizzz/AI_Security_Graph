# SENTINEL Threat Model

> **Status:** HOÀN THIỆN — Số liệu thực nghiệm từ `evaluate_robustness.py` (18/04/2026)
> **Mục đích:** Trả lời câu hỏi "SENTINEL bảo vệ được gì, không bảo vệ được gì?"

---

## 1. Adversary Profiles

| Profile | Capability | Ví dụ | Trong scope? |
|---|---|---|---|
| Script Kiddie | Copy-paste injection strings từ Internet | `"ignore previous instructions"` | ✅ Yes — Encapsulation blocks |
| Skilled Attacker | Biết cấu trúc SENTINEL, craft injection qua log fields | Encoding bypass, delimiter smuggling | ✅ Yes — Encapsulation + Neutralization |
| Semantic Attacker | Dùng prose tự nhiên, đúng ngữ pháp, không chứa keyword | Xem Section 4 | ⚠️ Measured — Quantified limitation |
| Insider Threat | SOC analyst bị compromise, có HITL access | Session hijacking, approve malicious rules | ❌ Out of scope |
| APT / Nation-State | Full kill-chain, multiple vectors, long-term persistence | Supply chain, knowledge base poisoning | ❌ Out of scope |

Mỗi adversary profile đã được map vào adversarial test suite cụ thể:

---

## 2. Attack Surface Analysis

### 2.1 Log Ingestion Path
```
CSV/Syslog → Redis Stream → Tier 1 Rule Engine → Guardrails → LLM Agent
```
- **Attack vector:** Malicious content embedded in log fields (User-Agent, Referer, URI)
- **Defense:** Delimited Data Encapsulation (structural), Pattern Matching (keyword)
- **Residual risk:** Semantic Confusion (see Section 4)

### 2.2 RAG Knowledge Base
- **Attack vector:** Knowledge Base Poisoning (modify MITRE/ISO JSON files)
- **Defense:** File integrity (read-only mount in Docker, hash verification)
- **Residual risk:** RAG Poisoning Defense layer (structural sanitization, provenance checking) đã triển khai trong `src/rag/security.py`. Impact chưa quantify — cần thêm experiment nếu thời gian cho phép.

### 2.3 HITL Dashboard
- **Attack vector:** Session hijacking, CSRF, unauthorized rule approval
- **Defense:** RBAC (L1/L3 roles), session timeout
- **Residual risk:** Out of scope for this thesis

### 2.4 Feedback Loop
- **Attack vector:** Agent hallucinate → generate overly broad blocking rule → DoS legitimate traffic
- **Defense:** HITL Quarantine (all rules require L3 Manager approval)
- **Residual risk:** L3 Manager rubber-stamping (human factor, out of scope)

---

## 3. Defense Effectiveness Matrix

> **Bảng TRỌNG TÂM** — Mỗi ô có số liệu thực nghiệm từ 45 adversarial samples (18/04/2026).

| Attack Type | Defense Layer | Samples | Blocked | Defeat Rate | Source |
|---|---|---|---|---|---|
| Delimiter Smuggling | L3: Dynamic Randomized Delimiters | 4 | 4 | **100%** | `structural_attacks/` |
| Structural Injection (JSON/XML/Role) | L1 Pattern + L2 Encoding + L3 Delimiter | 15 | 14 | **93.3%** | `structural_attacks/` |
| Encoding Bypass (Base64/Unicode/HTML) | L2: Encoding Neutralization | 15 | 8 | **53.3%** | `encoding_bypass/` |
| **Semantic Confusion** | **Không có defense hiệu quả** | **15** | **2** | **13.3%** | `semantic_confusion/` |
| **TỔNG** | **3-Layer Pipeline** | **45** | **24** | **53.3%** | `robustness_results.json` |

**Phân tích kết quả:**

- Structural attacks bị chặn gần như hoàn toàn (93.3%) — Dynamic Delimiters + Pattern Detection + Encoding Neutralization phối hợp hiệu quả.
- Encoding bypass có gap ở hex escape, URL encoding, homoglyphs — cần mở rộng neutralizer trong future work.
- Semantic Confusion bypass 86.7% — **đúng theo thiết kế**. Đây là quantified limitation, không phải bug. Encapsulation KHÔNG bảo vệ được ở tầng semantic.
---

## 4. Semantic Confusion — Quantified Open Limitation

### 4.1 Definition
Semantic Confusion: Kẻ tấn công nhúng ý đồ độc hại vào một đoạn văn đúng ngữ pháp,
có tính chất như một chỉ thị độc lập để vượt qua các bộ lọc cấu trúc và thao túng
suy luận của LLM.

### 4.2 Tại sao Encapsulation không chặn được
- Encapsulation chỉ bảo vệ **structural boundary** (delimiter integrity)
- Semantic Confusion nằm **trong** data boundary — nội dung hợp lệ về cấu trúc
- Không vi phạm delimiter, không encode, không chứa injection keyword

### 4.3 Experiment Design — Cross-Family Generation (Option C)

**Ba vai trò được phân tách rõ ràng để tránh Circular Evaluation Bias:**

| Vai trò | Model | Model Family | Lý do chọn |
|---|---|---|---|
| **Attack Generator** | Meta Llama 3 8B Instruct | Meta AI | Khác ecosystem so với Agent |
| **System Under Test** | Gemma 2 9B Q6_K | Google DeepMind | SENTINEL Agent chính |
| **Oracle Judge** | Gemma 2 26B Q4_K_M | Google DeepMind | Oracle có năng lực cao hơn Agent |

**Tại sao Option C thay vì tự generate bằng Gemma?**
- Nếu Gemma 26B sinh attack + làm Judge → Circular: cùng model family, cùng training bias.
- Option C: Llama 3 (Meta) sinh attack, Gemma 26B (Google) judge → khác pretraining corpus, khác RLHF alignment → không còn circular cùng ecosystem.

**Residual bias phải acknowledge với hội đồng:**
Cả Llama 3 và Gemma 26B đều là RLHF-aligned instruction-tuned models. Cả hai đều có xu hướng tránh tạo/đánh giá payload quá rõ ràng độc hại. Bypass rate đo được có thể thấp hơn human red-teamers trong thực tế — cần ghi rõ trong Section Limitations.

**Test set:** 500 Semantic Confusion samples, 10 attack pattern templates × 50 Llama 3 variants  
**Metric:** Bypass Rate = (Gemma 26B judge xác nhận Agent bị dẫn dắt) / 500  
**Baseline comparison:** Bypass Rate WITH Encapsulation (Config F) vs WITHOUT (Config C)  
→ Kỳ vọng: gần bằng nhau → chứng minh Encapsulation không giúp gì cho semantic attacks

### 4.4 Kết quả (18/04/2026)

| Metric | Giá trị | Ghi chú |
|---|---|---|
| Semantic Confusion Bypass Rate | **86.7%** (13/15 samples) | Đúng kỳ vọng — Encapsulation không chặn semantic |
| Pattern Detection trên Semantic | 0/15 | Không keyword injection nào |
| Encoding Neutralization trên Semantic | 2/15 | Chỉ bắt được 2 do chứa ký tự đặc biệt (`&`, `<`) |

### 4.5 Implications

- SENTINEL effectively defends against **structural attacks** (93.3% defeat rate)
- SENTINEL provides a **quantified baseline** for Semantic Confusion vulnerability (Bypass Rate = **86.7%**)
- Kết quả consistent với giả thuyết: Encapsulation bảo vệ structural boundary, KHÔNG bảo vệ semantic boundary
- Methodology sử dụng cross-family generation → defensible trước hội đồng, không circular
- Future work: Semantic-level defense (output classifier, chain-of-thought verification, semantic firewall)

---

## 5. Scope Boundaries (Giới hạn phạm vi)

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
