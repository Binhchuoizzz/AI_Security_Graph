# Literature Review — Search Protocol (PRISMA-ScR)

> **Status:** SKELETON — Điền trước khi bắt đầu search
> **Framework:** PRISMA for Scoping Reviews (Tricco et al., 2018)

---

## 1. Research Questions for Review

- RQ-LR1: Những hệ thống nào đã kết hợp LLM với SOC automation, và giới hạn của chúng là gì?
- RQ-LR2: Có defense mechanism nào bảo vệ LLM inference boundary trong security context chưa?
- RQ-LR3: RAG đã được áp dụng cho threat intelligence / MITRE mapping ở mức nào?
- RQ-LR4: Phương pháp evaluation nào đã được dùng cho LLM-based security tools?

---

## 2. Search Databases

- [ ] IEEE Xplore
- [ ] ACM Digital Library
- [ ] arXiv (cs.CR + cs.AI + cs.CL)
- [ ] Google Scholar
- [ ] Semantic Scholar

---

## 3. Search Strings

| # | Search String | Target DB | Expected Results |
|---|---|---|---|
| S1 | `"LLM" AND "SOC" AND ("automation" OR "security operations")` | IEEE, ACM | 8-15 |
| S2 | `"prompt injection" AND "defense" AND ("log" OR "security")` | arXiv, Scholar | 10-20 |
| S3 | `"RAG" AND ("MITRE" OR "threat intelligence" OR "ATT&CK")` | arXiv, Scholar | 5-10 |
| S4 | `"LLM agent" AND ("intrusion detection" OR "IDS" OR "SIEM")` | IEEE, ACM | 5-10 |
| S5 | `"LLM-as-a-Judge" AND "evaluation"` | arXiv | 5-8 |
| S6 | `"log template" AND ("mining" OR "parsing") AND "security"` | IEEE | 5-8 |
| S7 | `"agentic" AND ("cybersecurity" OR "security") AND "LLM"` | arXiv, Scholar | 5-10 |

---

## 4. Inclusion Criteria

- Published 2020–2026
- Peer-reviewed OR arXiv with >10 citations (hoặc <6 tháng tuổi)
- English language
- Directly relevant to LLM + Security / Prompt Injection / RAG for threat intel

## 5. Exclusion Criteria

- General chatbot / NLP papers không liên quan security
- Papers chỉ về traditional ML IDS (CNN/LSTM/RF) mà không dùng LLM
- Duplicate entries across databases
- Workshop papers < 4 trang (trừ khi highly cited)

---

## 6. Paper Categories (Taxonomy)

| Category Code | Category Name | Target Count |
|---|---|---|
| `llm_soc` | LLM-based SOC / IDS Automation | 8-10 |
| `rag_cybersecurity` | RAG for Cybersecurity / Threat Intel | 5-7 |
| `prompt_injection_defense` | Prompt Injection Attack & Defense | 8-10 |
| `log_parsing` | Log Parsing / Template Mining | 4-5 |
| `llm_evaluation` | LLM Evaluation Methodology | 5-6 |
| `agentic_ai_security` | Agentic AI / Multi-agent Security | 5-7 |
| **TOTAL** | | **40+** |

---

## 7. Data Extraction Template

Mỗi paper điền vào `paper_taxonomy.csv` với columns:
- id, title, authors, year, venue, category
- key_finding: Phát hiện chính (1-2 câu)
- gap_identified: Gap mà paper này chưa giải quyết (liên quan SENTINEL)
- relevance_to_sentinel: Mức độ liên quan (high/medium/low)
- url: Link tới paper

---

## 8. PRISMA Flow Diagram

TODO: Sau khi hoàn thành search, vẽ PRISMA flow diagram:
- Records identified through database searching: N
- Records after duplicates removed: N
- Records screened (title/abstract): N
- Full-text articles assessed: N
- Studies included in review: N (target ≥ 40)
