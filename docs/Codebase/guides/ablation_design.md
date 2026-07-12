# Ablation Study Design for the Two-Tier Architecture

> **Status:** IMPLEMENTED (v4 — 2026-06)
> **Update:** Mở rộng từ 4 → 6 configs (thêm MITRE-only RAG và NIST-only RAG) và bổ sung Statistical Validity Framework. **v4:** Configs B–E nay ĐÃ triển khai script tự động (`run_ablation_bcde.py`) với trục cô lập **gate Welford + từng tầng RAG**, và bổ sung **bản cân bằng 150/150** (`run_ablation_balanced.py`) chạy cả A–F để khắc phục hiệu ứng base-rate. Xem §1b để biết ánh xạ thiết kế-YAML ↔ runner thật.
> **Trả lời câu hỏi:** "Mỗi component contribute gì? Sự khác biệt có ý nghĩa thống kê (statistically significant) không?"

---

## 1. Configuration Matrix

| Config | Tier 1 | Guardrails (Drain3) | Guardrails (Encapsulation) | LLM Agent | RAG | Mục đích chính |
|---|---|---|---|---|---|---|
| **A** | ✅ | ❌ | ❌ | ❌ | ❌ | Baseline: Rule-only IDS. Chứng minh LLM thêm giá trị. |
| **B** | ❌ | ❌ | ❌ | ✅ | Dual | LLM-only (không lọc trước). Chứng minh 2-Tier tối ưu latency. |
| **C** | ✅ | ✅ Drain3 | ❌ No Encapsulation | ✅ | Dual | Chứng minh Encapsulation chặn injection. |
| **D** | ✅ | ✅ | ✅ | ✅ | **MITRE only** | **Isolate NIST SP 800-61r2 RAG contribution.** |
| **E** | ✅ | ✅ | ✅ | ✅ | **NIST only** | **Isolate MITRE ATT&CK RAG contribution.** |
| **F** | ✅ | ✅ | ✅ | ✅ | Dual | **Full Architecture** — Complete system. |

> Bảng trên là **thiết kế khai báo** (các tệp `config/ablation/*.yaml`). Runner Python thực tế cô lập theo một trục hơi khác (xem §1b).

---

## 1b. Implemented Runners (khớp code ở HEAD)

| Config | Runner thật | Ngữ nghĩa thực đo | Output JSON |
|---|---|---|---|
| **A** | `run_ablation_study.py` | Tier-1 đầy đủ, KHÔNG LLM | `ablation_results.json` |
| **B** | `run_ablation_bcde.py` | Pure LLM (không gate / RAG / guardrails) | `ablation_bcde_results.json` |
| **C** | `run_ablation_bcde.py` | Welford-gate + LLM (không RAG) | `ablation_bcde_results.json` |
| **D** | `run_ablation_bcde.py` | gate + **dense-RAG** (FAISS-only) | `ablation_bcde_results.json` |
| **E** | `run_ablation_bcde.py` | gate + **hybrid-RAG** (FAISS+BM25+RRF) | `ablation_bcde_results.json` |
| **F** | `run_ablation_study.py` | full agent + Consensus Guard | `ablation_results.json` |
| **A–F cân bằng** | `run_ablation_balanced.py` | 150 benign + 150 tấn công (đều 15 lớp), warmup Welford benign thật, McNemar B-vs-gated | `ablation_balanced_results.json` |

> **Lý do hai trục khác nhau:** thiết kế YAML cô lập *loại tri thức RAG* (MITRE-only vs NIST-only); runner `run_ablation_bcde.py` cô lập *kiến trúc truy xuất* (no-RAG → dense → hybrid) vì đây là đóng góp kỹ thuật cốt lõi (RRF hybrid). Gate Welford tính 1 lần/mẫu dùng chung C/D/E nên hiệu số D−C, E−D tách đúng đóng góp từng tầng. Bản cân bằng giải quyết hiệu ứng base-rate (tập gốc 93% tấn công → mọi cấu hình suy biến về dự đoán toàn-dương, F1 ≈ base rate).

---

## 2. Statistical Validity Framework (New)

Để đảm bảo kết quả đánh giá không phải do yếu tố ngẫu nhiên, các metric sẽ được kiểm định thống kê:

| Đối tượng so sánh | Metric đo lường | Phương pháp kiểm định (Statistical Test) | Ngưỡng ý nghĩa (Threshold) |
|---|---|---|---|
| Hiệu năng mô hình (A vs F, D vs E vs F) | F1-Score, Precision, Recall | Paired t-test hoặc McNemar's test (cho dữ liệu phân loại) | p < 0.05 |
| Độ trễ hệ thống (2-Tier vs 1-Tier) | Reasoning Latency | Mann-Whitney U test (non-parametric vì latency thường skewed) | p < 0.05 |
| Độ chính xác Mapping (MITRE Accuracy) | Mapping Accuracy (trên 30 cases) | Binomial Proportion Confidence Interval | 95% CI |
| Tối ưu hiệu năng Embedding | Semantic Cache Hit Rate | Không kiểm định (Report Mean ± Std) | Report CI 95% |

*Tất cả kết quả báo cáo p-value cụ thể. P-value < 0.05 được coi là statistically significant.*

---

## 3. Expected Results & Hypotheses

### Classification Metrics (F1/Precision/Recall)
- F > D > E > A : Dual-RAG > Single-RAG > No-LLM (với p < 0.05)
- B ≈ F for F1, BUT B >> F for latency : LLM-only accurate but slow
- C < F for Robustness : No Encapsulation = vulnerable to injection

### Operational Metrics (Latency)
- A << B : Rule-only extremely fast, LLM-only very slow
- F < B : 2-Tier filters 70%+ traffic, reducing LLM calls (với p < 0.05 bằng Mann-Whitney U)
- F ≈ D ≈ E : RAG type doesn't significantly affect latency

### Robustness Metrics (Adversarial)
- F ≈ D ≈ E for structural : Encapsulation works regardless of RAG type
- C << F for structural : No Encapsulation = high defeat rate
- F ≈ C for Semantic Confusion : Encapsulation doesn't help with semantic attacks

### Context Quality, Explainability & Statistical Validity
- F > D > E for Context Relevance : Dual contexts richer than single
- D > E for MITRE Mapping Accuracy : MITRE RAG directly provides technique data
- E > D for Recommendation Quality : NIST phases provide specific response actions
- **5D Framework Integration**:
  - Classification & Operational metrics use **Statistical Evaluation (McNemar + Mann-Whitney U)** để đảm bảo tính khách quan.
  - Context Quality dùng **Cross-Family LLM-as-a-Judge (Llama 3 đánh giá Gemma)** lấy cảm hứng từ RAGAS để chống Self-Enhancement Bias.
  - Explainability dùng deterministic logic (Audit Completeness).

### Critical Decision Point
- **IF D ≈ F** → NIST RAG provides minimal value → Simplify system, drop Dual-RAG claim
- **IF E ≈ F** → MITRE RAG provides minimal value → Unlikely but would reshape contribution
- **IF D >> E** → NIST RAG contribution proven, Dual-RAG justified

---

## 4. Ablation Run Plan

| Run | Config | Script | Dataset | Sample Size | Estimated Time |
|---|---|---|---|---|---|
| 1 | A & F (Rule-only ↔ Full) | `run_ablation_study.py` | Ground Truth (stratified) | 300 | ~20-30 min (LLM cho F) |
| 2 | B, C, D, E | `run_ablation_bcde.py` | Ground Truth (cùng 300 mẫu) | 300 | ~30-60 min (LLM) |
| 3 | A–F cân bằng | `run_ablation_balanced.py` | 150 benign + 150 attack | 300 | ~30-60 min (LLM) |

> **Lưu ý (v4):** Config A & F là hai đầu mút cốt lõi trả lời RQ1 (Rule-only vs Full SENTINEL) và sinh `Config_F.reasoning_outputs` cho LLM-as-Judge. Các Config B–E nay ĐÃ có script tự động (`run_ablation_bcde.py`, trục no-RAG→dense→hybrid) và bản cân bằng 150/150 (`run_ablation_balanced.py`). Run #2/#3 chạy trên cùng tập (hoặc tập cân bằng) để so sánh nhất quán.

---

## 5. Implementation Notes

### Switching RAG configs
```python
# config/ablation/config_d_mitre_only.yaml
rag:
  enabled_sources: ["mitre"]  # Only MITRE ATT&CK index

# config/ablation/config_e_nist_only.yaml
rag:
  enabled_sources: ["nist"]    # Only NIST SP 800-61r2 index

# config/ablation/config_f_full.yaml
rag:
  enabled_sources: ["mitre", "nist"]  # Dual-RAG (default)
```

### MLflow Experiment Tracking
- Tất cả runs log vào MLflow experiment: `Sentinel_Ablation_Study`
- Mỗi run tag: `config=A|F`
- **5D Metrics (v2_5D):**
  - Classification: F1, Precision, Recall, FPR
  - Operational: MTTD_Proxy_Tier1_sec, MTTR_Proxy_Tier2_sec, HITL_Escalation_Rate_pct, RAG_Cache_Hit_Rate_pct
  - Context Quality (RAGAS-inspired): Context_Precision, Answer_Relevancy, Faithfulness, Context_Recall
  - Explainability: Audit_Completeness_Rate_pct
