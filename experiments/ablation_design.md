# Ablation Study — 6 Configuration Design

> **Status:** SKELETON
> **Update:** Mở rộng từ 4 → 6 configs (thêm MITRE-only RAG và ISO-only RAG)
> **Trả lời câu hỏi:** "Mỗi component contribute gì? ISO RAG có thực sự cần thiết không?"

---

## Configuration Matrix

| Config | Tier 1 | Guardrails (Drain3) | Guardrails (Encapsulation) | LLM Agent | RAG | Mục đích chính |
|---|---|---|---|---|---|---|
| **A** | ✅ | ❌ | ❌ | ❌ | ❌ | Baseline: Rule-only IDS. Chứng minh LLM thêm giá trị. |
| **B** | ❌ | ❌ | ❌ | ✅ | Dual | LLM-only (không lọc trước). Chứng minh 2-Tier tối ưu latency. |
| **C** | ✅ | ✅ Drain3 | ❌ No Encapsulation | ✅ | Dual | Chứng minh Encapsulation chặn injection. |
| **D** | ✅ | ✅ | ✅ | ✅ | **MITRE only** | **Isolate ISO 27001 RAG contribution.** |
| **E** | ✅ | ✅ | ✅ | ✅ | **ISO only** | **Isolate MITRE ATT&CK RAG contribution.** |
| **F** | ✅ | ✅ | ✅ | ✅ | Dual | **SENTINEL Full** — Complete system. |

---

## Expected Results & Hypotheses

### Classification Metrics (F1/Precision/Recall)
- F > D > E > A : Dual-RAG > Single-RAG > No-LLM
- B ≈ F for F1, BUT B >> F for latency : LLM-only accurate but slow
- C < F for Robustness : No Encapsulation = vulnerable to injection

### Operational Metrics (Latency)
- A << B : Rule-only extremely fast, LLM-only very slow
- F < B : 2-Tier filters 70%+ traffic, reducing LLM calls
- F ≈ D ≈ E : RAG type doesn't significantly affect latency

### Robustness Metrics (Adversarial)
- F ≈ D ≈ E for structural : Encapsulation works regardless of RAG type
- C << F for structural : No Encapsulation = high defeat rate
- F ≈ C for Semantic Confusion : Encapsulation doesn't help with semantic attacks

### Context Quality (RAGAS + LLM-as-Judge)
- F > D > E for Context Relevance : Dual contexts richer than single
- D > E for MITRE Mapping Accuracy : MITRE RAG directly provides technique data
- E > D for Recommendation Quality : ISO controls provide specific response actions

### Critical Decision Point
- **IF D ≈ F** → ISO RAG provides minimal value → Simplify system, drop Dual-RAG claim
- **IF E ≈ F** → MITRE RAG provides minimal value → Unlikely but would reshape contribution
- **IF D >> E** → ISO RAG contribution proven, Dual-RAG justified

---

## Ablation Run Plan

| Run | Config | Dataset | Sample Size | Estimated GPU Time |
|---|---|---|---|---|
| 1 | A (Rule-only) | CICIDS2017 + UNSW-NB15 | Full 2.8M | ~10 min (no GPU) |
| 2 | B (LLM-only) | CICIDS2017 | 5,000 stratified | ~8h |
| 3 | C (No Encapsulation) | CICIDS2017 | 5,000 + 1,000 adversarial | ~10h |
| 4 | D (MITRE-only RAG) | CICIDS2017 | 5,000 stratified | ~8h |
| 5 | E (ISO-only RAG) | CICIDS2017 | 5,000 stratified | ~8h |
| 6 | F (Full SENTINEL) | CICIDS2017 + UNSW-NB15 | 5,000 + 1,000 adversarial | ~12h |
| **TOTAL** | | | | **~46h GPU** |

---

## Implementation Notes

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
- Tất cả 6 runs log vào cùng 1 MLflow experiment: `sentinel_ablation_study`
- Mỗi run tag: `config=A|B|C|D|E|F`
- Metrics: F1, Precision, Recall, Latency, Cache Hit Rate, Bypass Rate, MITRE Accuracy
