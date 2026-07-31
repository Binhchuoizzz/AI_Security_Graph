# Bảng tra chỉ số SENTINEL

> Mỗi dòng: **lệnh chạy · tập dữ liệu · đo gì · trích số nào**.
> Cập nhật 31/07/2026, sau đợt vá 7 lỗi tầng đo.

## Trước khi chạy bất cứ thứ gì

```bash
docker-compose up -d                        # Redis + llama.cpp + MLflow + Dashboard
export SENTINEL_FREEZE_DYNAMIC_RULES=1      # BẮT BUỘC cho MỌI lượt đo
```

Không đóng băng luật động thì phép đo tự sinh luật rồi tự hưởng lợi ở lượt sau.

**Thứ tự dựng dữ liệu — sai chiều là hỏng cả lượt đo:**

```text
csic.json → ground_truth.json + datatest.json → golden_baseline.json → demo.json
```

`golden_baseline` phải dựng **sau** `datatest` vì nó dùng datatest để lập tập chữ ký loại trừ
(chống rò benchmark vào seed Welford). Kiểm nhanh: dựng lại rồi `diff` — không đổi là đúng.

---

## Ba tập dữ liệu, ba việc khác nhau

| tập | cỡ | dùng cho |
| :-- | --: | :-- |
| `data/datatest.json` | 4.240 (cân bằng, 1.036 CSIC) | Cổng ML — cần cân bằng lớp |
| `experiments/ground_truth.json` | 1.750 → **1.700 khi chấm** | ablation, quy kết, chất lượng lập luận |
| `build_stream()` | 25.799 (10 ngày CICIDS + DAPT + CSIC + zero-day) | xả tải, toàn tuyến, độ trễ, APT |

`ground_truth` lệch lớp nặng nên **F1 nhị phân trên nó vô nghĩa** (xấp xỉ base rate). Thước đo
chính là chấm-theo-hành-động và chấm-theo-quy-kết.

### 50 mẫu bị loại khỏi mọi tỉ lệ

`fetch_and_build_dataset.py` cố ý chèn 50 mẫu đối địch **do tác giả biên soạn** vào
`ground_truth.json` để thử Guardrails. Chúng ở lại tệp (`evaluate_adversarial.py` cần), nhưng
`unified_dataset.drop_authored()` loại chúng khỏi mọi phép chấm. Không loại thì:

- 50/300 mẫu chấm-được-quy-kết là tự viết — **16,7%**;
- cả 50 cùng đáp án `T1190`, đẩy T1190 từ 52 lên 102 mẫu.

Sau khi loại: **250 mẫu thật**, phân bố `T1595.003` 130 · `T1190` 52 · `T1059.007` 30 ·
`T1071.001` 26 · `T1083` 12.

> **Sàn đoán bừa 52%.** `T1595.003` chiếm 130/250, nên đoán luôn mã đó đã được ~52%. Mọi tỉ lệ
> khớp kỹ thuật phải đọc **so với 52%**, không phải so với 0. Khoá bằng
> `tests/unit/test_authored_sample_exclusion.py`.

---

## RQ1 — Xả tải và độ trễ

| lệnh | tập | đo gì | trích số nào |
| :-- | :-- | :-- | :-- |
| `experiments/evaluate_ml_gate.py` | datatest | Cổng ML phân loại + kháng né tránh | `mcc` · `balanced_accuracy` · `auto_block_precision` · `evasion_resistance.extreme_broad` |
| `run_ablation.py --mode mlgate` | ground_truth | Cổng ML gỡ tải LLM bao nhiêu | `ml_bypass_rate` |
| `experiments/run_cache_efficiency.py` | build_stream | Bộ đệm Tầng 1.75 trên truy vấn RAG thật | `hit_rate` · `speedup_x` |
| `experiments/measure_latency_baseline.py` | build_stream (strided) | Hai tầng so với LLM-only | `latency_reduction_pct` + `stage_breakdown` |
| `experiments/evaluate_unified_stream.py` | build_stream | Toàn tuyến trên luồng gộp | `classification_cicids.mcc` · `ip_containment` |

Độ trễ **phải** lấy mẫu theo tỉ lệ luồng thật. Ép 50/50 thì Tier-1 chỉ loại được 11% và kết
quả ra "chậm hơn LLM-only". Script nay tự gắn `metric_valid=false` nếu xả tải < 50%.

**Không** trích `ablation_mlgate_results.json` cho tuyên bố độ trễ — chính tệp đó ghi rõ nó
chỉ đo tỉ lệ gỡ tải, không đo thời gian.

---

## RQ2 — Rào chắn AI và toàn vẹn pháp y

| lệnh | tập | đo gì | trích số nào |
| :-- | :-- | :-- | :-- |
| `evaluate_adversarial.py --mode static` | 120 mẫu, 5 nhóm | Guardrail **tĩnh** chặn được bao nhiêu | `summary.block_rate_pct` + `by_category` |
| `evaluate_adversarial.py --mode pipeline` | **75** mẫu, 4 nhóm ngữ nghĩa | Tier-2 có bị thao túng không | `resistance_rate_pct` + **`coverage_pct`** |
| `experiments/run_audit_tamper.py` | `audit_trail.db` | Chuỗi HMAC phát hiện giả mạo | `overall_detection_rate_core` |
| `experiments/run_llm_robustness.py` | ground_truth | Tất định + đổi seed | `determinism` · `seed_variance.flip_rate` |

Hai con số **bổ sung** nhau, không thay thế nhau. Lớp tĩnh chặn **60/120** — nhưng đó gần
như toàn bộ nhóm `encoding_bypass` (45/45), còn `semantic_confusion` nó chặn **0/20**. Chính
60 mẫu lọt qua ấy đều nằm trong 4 nhóm ngữ nghĩa mà Tier-2 nhận. Tier-2 chạy cả **75** mẫu
của 4 nhóm đó — **siêu tập** của 60 mẫu lọt, nên `coverage_pct = 100` là thật.

Trích 100% của pipeline mà giấu 50% của static là chọn số.

`audit_tamper` tách riêng `xoá_dòng_cuối` — cắt đuôi chuỗi thì log-chaining về nguyên lý không
phát hiện được. Đó là giới hạn phải nêu, không phải số để làm đẹp.

---

## RQ3 — Tác tử có trạng thái và quy kết ATT&CK

| lệnh | tập | đo gì | trích số nào |
| :-- | :-- | :-- | :-- |
| `scripts/eval_attack_mapper.py --mode rrf` | 250 mẫu CSIC có payload | Bộ ánh xạ **tất định** (không LLM) | `technique_exact_match_pct` |
| `scripts/eval_attack_mapper.py --mode e2e` | như trên | **Toàn tuyến** — thứ hệ thật làm | `technique_exact_match_pct` |
| `run_ablation.py --mode af` | ground_truth phân tầng | Tắt LLM (A) so với đủ LLM (F) | `action_scores` |
| `run_ablation.py --mode bcde` | **250** mẫu thật (có payload + có mã) | Đóng góp từng bậc RAG | `attribution_scores` |
| `run_ablation.py --mode balanced` | 150/150 cân bằng | Khử ảnh hưởng base-rate | `action_scores` |
| `experiments/evaluate_reasoning.py` | phán quyết từ `--mode af` | Trọng tài **khác họ** chấm lập luận | 4 trục thang 1–5 + `evidence_grounding` |
| `experiments/evaluate_tier2_decision.py` | build_stream, đã qua Tier-1 **và** Cổng ML | Phán quyết Tier-2 + hiệu chỉnh niềm tin | `threat_recall` · `mcc` · `confidence_calibration.ece` |
| `experiments/run_apt_negative_control.py` | DAPT2020 đa ngày | Tương quan chuỗi APT | `recall` · `specificity` |
| `experiments/evaluate_rag_retrieval.py` | ground_truth đã leo thang | Chất lượng truy xuất RAG | `recall@k` · `mrr` |

`rrf` chạy `llm=None` — đó là cấu hình **tắt LLM**. Trích nó làm thành tích của LLM là gom số
sai. Chênh lệch `rrf` với `e2e` chính là thứ LLM làm với một kết quả truy xuất đã đúng.

`bcde` phải chạy **đủ 300 mẫu**: C/D/E chỉ gọi LLM khi Tier-1 leo thang (~17%), cỡ nhỏ thì mỗi
cấu hình chỉ vài ca. Script tự gắn `attribution_underpowered=true` nếu < 30 ca.

`evaluate_reasoning` phải đổi model trọng tài **bằng biến môi trường**, không chỉ sửa `.env`
(docker-compose ưu tiên biến môi trường):

```bash
LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf LLAMA_ARG_CTX_SIZE=32768 \
  docker-compose up -d --force-recreate --no-deps llm
SENTINEL_AGENT_MODEL=Foundation-Sec-8B-Instruct-Q4_K_M.gguf \
  .venv/bin/python experiments/evaluate_reasoning.py
```

Script **chặn cứng** nếu trọng tài trùng bị cáo. Đọc kèm `run_health.n_deliberate_abstention`:
ca hệ chủ ý trả `N/A` là rào chắn hoạt động đúng, **không** phải thiếu schema.

---

## Bài phụ trợ

| lệnh | đo gì | lưu ý |
| :-- | :-- | :-- |
| `run_context_stress.py` | Nén log theo template | Báo **cả hai** pool: đồng nhất (1000×) và đa dạng (**125×** — số thật) |
| `run_zeroday_graded.py` | Bắt bất thường theo cấp độ σ | |
| `run_threshold_sensitivity.py` | Độ nhạy ngưỡng Welford 3.5 | |
| `run_baseline_comparison.py` | So với Zero-R, chữ ký tĩnh, ML phẳng | |
| `audit_tier_capability.py` | **Phép thử CHỨC NĂNG**, 15 ca viết tay | `is_benchmark_metric: false` — KHÔNG xếp cạnh chỉ số benchmark |

---

## Chạy hết, đúng thứ tự

```bash
export SENTINEL_FREEZE_DYNAMIC_RULES=1

# A. Offline, không cần LLM (~2 phút)
for s in evaluate_ml_gate run_cache_efficiency run_audit_tamper run_context_stress \
         run_zeroday_graded run_threshold_sensitivity run_apt_negative_control \
         evaluate_unified_stream run_baseline_comparison; do
  .venv/bin/python experiments/$s.py
done
.venv/bin/python experiments/run_ablation.py --mode mlgate

# B. Cần LLM (~3–4 giờ)
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload
.venv/bin/python experiments/run_ablation.py --mode af
.venv/bin/python experiments/run_ablation.py --mode bcde
.venv/bin/python experiments/run_ablation.py --mode balanced
.venv/bin/python experiments/evaluate_tier2_decision.py --limit 800
.venv/bin/python experiments/evaluate_adversarial.py --mode all
.venv/bin/python experiments/run_llm_robustness.py
.venv/bin/python experiments/measure_latency_baseline.py

# C. Trọng tài khác họ (đổi model trước — xem RQ3)
.venv/bin/python experiments/evaluate_reasoning.py

# D. Gom báo cáo
.venv/bin/python scripts/export_final_report.py   # -> reports/KET_QUA_CHOT_<ngày>.md
```

---

## Bảy điều kiểm trước khi trích bất kỳ con số nào

1. `metric_valid` / `metric_health` / `run_health` trong tệp kết quả — script tự gắn cờ thì tin nó.
2. **Mẫu số**: `n_invoked`, `coverage_pct`, `n_scorable`. Tỉ lệ không có mẫu số là tỉ lệ không kiểm chứng được.
2b. Log lượt chạy có dòng `Loại 50 mẫu BIÊN SOẠN` — không thấy dòng đó nghĩa là bộ lọc chưa chạy.
3. Mốc thời gian tệp kết quả **mới hơn** tệp dữ liệu nó đọc.
4. Không gộp số từ hai tập khác nhau thành một "dải".
5. `reasoning_eval_results.json` có `judge_model` **≠** `agent_model`.
6. Số luật động trong `config/system_settings.yaml` không đổi sau lượt đo.
7. Phép thử **chức năng** (15 ca viết tay) không đứng cạnh chỉ số **benchmark**.
