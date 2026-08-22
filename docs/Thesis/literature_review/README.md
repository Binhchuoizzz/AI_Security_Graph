# Literature Review — ghi chú giai đoạn khảo sát

> ⛔ **TÀI LIỆU LỊCH SỬ — ĐÃ BỊ THAY THẾ. Không trích, không dùng để kiểm tra danh mục.**
>
> Đây là ghi chú lập kế hoạch từ giai đoạn đầu, viết **trước khi** danh mục tài liệu thật được
> dựng và rà tận nguồn. Nó đã sai ở hai chỗ có thể gây hiểu nhầm nghiêm trọng, và được giữ lại
> chỉ để lưu vết quá trình:
>
> 1. **Danh sách bên dưới không phải danh mục của luận văn.** Luận văn dùng **41 mục**
>    `\bibitem`, phần lớn không có trong danh sách này. Nguồn sự thật là
>    [`../CITATION_AUDIT.md`](../CITATION_AUDIT.md) — sổ tra tận nguồn của cả 41 mục — kiểm tự
>    động bằng `scripts/audit_thesis_refs.py`.
> 2. **Mục E ghi "CICIDS2017"; luận văn dùng CSE-CIC-IDS2018.** Cùng nhóm tác giả
>    (Sharafaldin, Lashkari, Ghorbani · ICISSP 2018) nhưng **khác bộ dữ liệu**. Nhầm hai bộ này
>    là lỗi nặng vì mọi số của Chương 4 đo trên bộ 2018.
>
---

## Danh sách khảo sát ban đầu *(giữ nguyên văn, KHÔNG cập nhật)*

### A. LLM Agent trong SOC Automation

1. Oniagbi et al. (2024) — "LLMs in the SOC: An Empirical Study" — Đánh giá GPT-4/Llama 3 cho SOC Triage.
2. "The Dark Side of LLM-Powered Security Automation" (2024) — Rủi ro khi dùng LLM Agent trong bảo mật.
3. Audit-LLM / LanG — Multi-agent collaboration cho log analysis và rule generation.
4. D3 Security (2025) — Agentic SOAR: Từ copilot đến autonomous agent.

### B. RAG & Threat Intelligence

5. RAG-ATT&CK (2024) — RAG-based MITRE ATT&CK technique mapping.
6. TECHNIQUERAG (2024) — Retrieval-augmented threat classification.
7. Knowledge Graph + RAG Hybrid (Srivastava, 2025) — Graph-augmented CTI reasoning.

### C. Adversarial AI & Guardrails

8. OWASP Top 10 for LLM Applications (2025 Edition) — Chuẩn bảo mật LLM.
9. MITRE ATLAS — Framework adversarial tactics chống AI systems.
10. Agent Security Bench (ASB) (2024, MDPI) — Benchmark tấn công/phòng thủ LLM Agent.
11. Indirect Prompt Injection research — Tấn công qua dữ liệu log ngầm.

### D. Log Analysis & Template Mining

12. He et al. (2017) — "Drain: An Online Log Parsing Approach" — Thuật toán Drain gốc.
13. Drain3 (IBM Research) — Phiên bản streaming production-grade của Drain.

### E. IDS Datasets & Evaluation

14. Sharafaldin et al. (2018) — CICIDS2017 dataset. *(⚠️ luận văn dùng **CSE-CIC-IDS2018**.)*

### F. Agentic AI Frameworks

15. LangGraph Documentation — State management cho LLM workflows.
16. CACAO Playbook Standard — Machine-readable IR playbook format.

### G. Evaluation Methodology

17. RAGAS Framework — Automated RAG evaluation (Context Relevance, Faithfulness).
18. TruLens — LLM evaluation and observability.
