# VRAM Benchmark — Empirical Validation

> **Status:** SKELETON — Cần chạy trên RTX 4060 Ti thực tế
> **Priority:** #4 — Validate VRAM claims
> **Mục đích:** Thay thế bảng "lý thuyết ước tính" trong proposal bằng số liệu thực

---

## Test Protocol

### Hardware
- GPU: NVIDIA RTX 4060 Ti 16GB
- RAM: ???GB
- OS: Linux
- Inference Server: Ollama / llama.cpp / vLLM (ghi rõ version)

### Models to Test
| Model | Quantization | Theoretical VRAM | Test |
|---|---|---|---|
| Gemma 2 9B IT | Q6_K | ~7 GB | ✅ |
| Gemma 2 9B IT | Q4_K_M | ~5.5 GB | ✅ |
| Gemma 2 27B IT | Q4_K_M | ~15 GB | ✅ (test OOM) |

### Test Prompts (Simulate Real Workload)

#### Prompt 1: Minimal (System prompt only)
- Tokens: ~200
- Purpose: Baseline VRAM measurement

#### Prompt 2: Realistic (System + RAG context + 10 logs)
- Tokens: ~2,000
- Purpose: Typical workload

#### Prompt 3: Heavy (System + RAG + Memory + 50 logs)
- Tokens: ~4,000
- Purpose: Near max context window

#### Prompt 4: Max Stress (System + RAG + Memory + 100 logs)
- Tokens: ~6,000
- Purpose: OOM boundary test

---

## Measurements per Test

```bash
# Before model load
nvidia-smi --query-gpu=memory.used --format=csv,noheader

# After model load (idle)
nvidia-smi --query-gpu=memory.used --format=csv,noheader

# During inference (peak)
nvidia-smi --query-gpu=memory.used --format=csv,noheader -l 1

# Capture screenshots
nvidia-smi > benchmark_results/model_name_prompt_N.txt
```

| Metric | Tool |
|---|---|
| VRAM at idle (model loaded) | nvidia-smi |
| VRAM peak (during inference) | nvidia-smi with -l 1 |
| Latency: Time to First Token (TTFT) | Server logs |
| Latency: Tokens per second (TPS) | Server logs |
| OOM occurred? | Y/N |

---

## Results Template

| Model | Quant | Prompt | VRAM Idle | VRAM Peak | TTFT (s) | TPS | OOM? |
|---|---|---|---|---|---|---|---|
| Gemma 2 9B | Q6_K | Minimal | TODO | TODO | TODO | TODO | N |
| Gemma 2 9B | Q6_K | Realistic | TODO | TODO | TODO | TODO | N |
| Gemma 2 9B | Q6_K | Heavy | TODO | TODO | TODO | TODO | N |
| Gemma 2 9B | Q6_K | Max Stress | TODO | TODO | TODO | TODO | ? |
| Gemma 2 27B | Q4_K_M | Minimal | TODO | TODO | TODO | TODO | ? |
| Gemma 2 27B | Q4_K_M | Realistic | TODO | TODO | TODO | TODO | ? |
| Gemma 2 27B | Q4_K_M | Heavy | TODO | TODO | TODO | TODO | ? |

---

## Key Questions to Answer

1. **9B Q6_K có thực sự ổn định ở context 4000+ tokens không?** → Justify primary model choice
2. **27B Q4_K_M có OOM không? Ở ngưỡng nào?** → Justify không dùng 27B cho agent
3. **27B Q4_K_M có chạy được batch_size=1 short context (cho Oracle Judge)?** → Justify sequential loading
4. **Latency gap giữa 9B và 27B là bao nhiêu?** → Data cho Ablation comparison

---

## Screenshots Directory
```
experiments/vram_benchmark/
├── screenshots/           # nvidia-smi screenshots
├── results.csv            # Parsed results
└── README.md              # This file
```
