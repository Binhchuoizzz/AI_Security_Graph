# `experiments/` — Bản đồ thí nghiệm SENTINEL

Mỗi script ở đây **chống lưng một mục trong Chương 4 luận văn** (EN + VI). Không file
nào là "rác": nhóm rigor (độ nhạy ngưỡng, đối chứng âm, độ trễ…) chính là phần bảo vệ
luận văn trước phản biện hội đồng. Bảng dưới cho biết chạy gì, ra file kết quả nào, và
nó phục vụ mục luận văn nào.

> Số liệu đã trích trong luận văn nằm ở `results/*.json` + `reports/`. **Đừng chạy lại
> full experiment** nếu chỉ muốn thử — dùng cờ `--limit`/`--out` để ghi ra chỗ tạm.

---

## 1. Nền tảng dùng chung (không phải experiment)

| File | Vai trò |
| :--- | :--- |
| `unified_dataset.py` | **Bộ dựng luồng gộp** (CICIDS + DAPT2020 + Zero-day REAL-DERIVED, trộn theo thời gian). `build_stream()`/`map_cicids()` được luồng online, eval offline và các thí nghiệm rigor **cùng import** — 1 nguồn sự thật, hết "lòng vòng". |
| `plot_results.py` | Vẽ hình PNG (`results/plots/`) cho các mục Chương 4. |
| `build_golden_baseline.py` | Dựng golden baseline benign cho hiệu chỉnh. |
| `e2e_test_runner.py` | Smoke-test end-to-end offline (kiểm luồng gộp hợp lệ) — không trích số. |

## 2. Đánh giá CHÍNH (trích số vào Chương 4)

| File | Chạy | Output | Mục luận văn (Ch.4) |
| :--- | :--- | :--- | :--- |
| `evaluate_unified_stream.py` | `python -m experiments.evaluate_unified_stream` | `results/unified_stream_results.json` + `reports/` | §Classification Accuracy + §Emergent APT + §Zero-Day (offline, tất định, không LLM) |
| `run_ablation.py` | `--mode {af,bcde,balanced,all}` | `ablation_results / ablation_bcde_results / ablation_balanced_results.json` | §Ablation Study (Two-Tier Latency) + §Controlled Balanced Ablation |
| `statistical_tests.py` | `python -m experiments.statistical_tests` | (in ra) | Mann-Whitney U + McNemar trong §Ablation |
| `evaluate_adversarial.py` | `--mode {static,pipeline,all}` | `robustness_results.json` + `adversarial_pipeline_results.json` | §Adversarial Robustness (guardrails tĩnh 50% + pipeline Tier-2 100%) |
| `evaluate_reasoning.py` | `python -m experiments.evaluate_reasoning` | `reasoning_eval_results.json` | §Integrity & Reasoning Quality (LLM-as-Judge / RAGAS) |

## 3. Thí nghiệm RIGOR — chống phản biện (GIỮ, đừng xoá)

| File | Chống mục gì | Output | Mục luận văn (Ch.4) |
| :--- | :--- | :--- | :--- |
| `measure_latency_baseline.py` | "0.6ms Tier-1 / −99% so LLM" — **claim độ trễ chủ đạo** | `latency_benchmark.json` | §Two-Tier Latency Trade-off |
| `run_threshold_sensitivity.py` | "sao chọn 3.5σ? cherry-pick?" — quét ngưỡng Welford | `threshold_sensitivity_results.json` | §Welford Threshold Sensitivity |
| `run_zeroday_graded.py` | "7/7 nhị phân là may?" — đường cong phát hiện phân cấp | `zeroday_graded_results.json` | §Graded Detection Boundary |
| `run_apt_negative_control.py` | "có báo APT nhầm không?" — đối chứng âm + specificity | `apt_negative_control_results.json` | §Emergent APT (negative control) |
| `run_llm_robustness.py` | "LLM có tất định? chết thì sao?" — determinism + suy biến | `llm_robustness_results.json` | §Decision Determinism + §Graceful Degradation |
| `run_context_stress.py` | "prompt có tràn n_ctx?" — token vs số log + nén Drain | `context_stress_results.json` | §Context-Budget Observability & Stress |

## 4. Luồng ONLINE / demo (chứng minh vận hành, không trích số)

| File | Chạy | Ghi chú |
| :--- | :--- | :--- |
| `stream_unified_online.py` | `python -m experiments.stream_unified_online [--include-adversarial] [--dry-run]` | Đẩy luồng gộp lên Redis → chảy qua **toàn hệ thống thật** (subscriber → Agent → Dashboard). `--include-adversarial` nối thêm 120 payload OWASP LLM để 1 lệnh đẩy **tất cả** nguồn. Dùng chung `build_stream()` với eval offline. |

## 5. Dữ liệu

- `ground_truth.json` — CICIDS2018 đã gán nhãn (nguồn phân loại + nền zero-day).
- `adversarial/<nhóm>/samples.json` — 120 payload OWASP LLM Top-10 (5 nhóm).
- `results/*.json`, `results/plots/*.png` — **số liệu + hình đã trích trong luận văn**.
- `.unified_eval_memory.db` — DB threat-memory tạm của eval offline (tự sinh, gitignored).
