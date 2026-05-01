# Ablation Study Design for the Two-Tier Architecture

> **Status:** IMPLEMENTED (v3 — 22/04/2026)
> **Update:** Mở rộng từ 4 → 6 configs (thêm MITRE-only RAG và ISO-only RAG) và bổ sung Statistical Validity Framework.
> **Trả lời câu hỏi:** "Mỗi component contribute gì? Sự khác biệt có ý nghĩa thống kê (statistically significant) không?"

---

## 1. Configuration Matrix

| Config | Tier 1 | Guardrails (Drain3) | Guardrails (Encapsulation) | LLM Agent | RAG | Mục đích chính |
|---|---|---|---|---|---|---|
| **A** | ✅ | ❌ | ❌ | ❌ | ❌ | Baseline: Rule-only IDS. Chứng minh LLM thêm giá trị. |
| **B** | ❌ | ❌ | ❌ | ✅ | Dual | LLM-only (không lọc trước). Chứng minh 2-Tier tối ưu latency. |
| **C** | ✅ | ✅ Drain3 | ❌ No Encapsulation | ✅ | Dual | Chứng minh Encapsulation chặn injection. |
| **D** | ✅ | ✅ | ✅ | ✅ | **MITRE only** | **Isolate ISO 27001 RAG contribution.** |
| **E** | ✅ | ✅ | ✅ | ✅ | **ISO only** | **Isolate MITRE ATT&CK RAG contribution.** |
| **F** | ✅ | ✅ | ✅ | ✅ | Dual | **Full Architecture** — Complete system. |

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
- E > D for Recommendation Quality : ISO controls provide specific response actions
- **5D Framework Integration**: 
  - Classification & Operational metrics use **Statistical Evaluation (McNemar + Mann-Whitney U)** để đảm bảo tính khách quan.
  - Context Quality dùng **Cross-Family LLM-as-a-Judge (Llama 3 đánh giá Gemma)** lấy cảm hứng từ RAGAS để chống Self-Enhancement Bias.
  - Explainability dùng deterministic logic (Audit Completeness).

### Critical Decision Point
- **IF D ≈ F** → ISO RAG provides minimal value → Simplify system, drop Dual-RAG claim
- **IF E ≈ F** → MITRE RAG provides minimal value → Unlikely but would reshape contribution
- **IF D >> E** → ISO RAG contribution proven, Dual-RAG justified

---

## 4. Ablation Run Plan

| Run | Config | Dataset | Sample Size | Estimated Time |
|---|---|---|---|---|
| 1 | A (Rule-only) | Ground Truth | 101 | ~1 min (no GPU) |
| 2 | F (Full SENTINEL) | Ground Truth | 101 | ~20-30 min (LLM inference) |
| **TOTAL** | | | | **~30 min** |

> **Lưu ý:** Các Config B-E được thiết kế nhưng chưa triển khai script tự động. Config A và F là hai cấu hình cốt lõi để trả lời RQ1 (Rule-only vs Full SENTINEL).

---

## 5. Implementation Notes

### Switching RAG configs
```python
# config/ablation_configs/config_d_mitre_only.yaml
rag:
  enabled_sources: ["mitre"]  # Only MITRE ATT&CK index

# config/ablation_configs/config_e_iso_only.yaml
rag:
  enabled_sources: ["iso"]    # Only ISO 27001 index

# config/ablation_configs/config_f_full.yaml
rag:
  enabled_sources: ["mitre", "iso"]  # Dual-RAG (default)
```

### MLflow Experiment Tracking
- Tất cả runs log vào MLflow experiment: `Sentinel_Ablation_Study`
- Mỗi run tag: `config=A|F`
- **5D Metrics (v2_5D):**
  - Classification: F1, Precision, Recall, FPR
  - Operational: MTTD_Proxy_Tier1_sec, MTTR_Proxy_Tier2_sec, HITL_Escalation_Rate_pct, RAG_Cache_Hit_Rate_pct
  - Context Quality (RAGAS-inspired): Context_Precision, Answer_Relevancy, Faithfulness, Context_Recall
  - Explainability: Audit_Completeness_Rate_pct

