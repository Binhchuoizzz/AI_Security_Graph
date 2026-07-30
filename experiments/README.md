# `experiments/` — Bản đồ thí nghiệm SENTINEL

Mỗi script ở đây **chống lưng một mục trong Chương 4 luận văn** (EN + VI). Không file nào
là "rác": nhóm rigor (độ nhạy ngưỡng, đối chứng âm, baseline ngoài, vòng phản hồi…) chính
là phần bảo vệ luận văn trước phản biện hội đồng.

> **Định nghĩa chỉ số** nằm ở [`docs/Codebase/learning/05_CHI_SO_DANH_GIA.md`](../docs/Codebase/learning/05_CHI_SO_DANH_GIA.md)
> — từ điển bản chất từng chỉ số, không số liệu. **Số liệu** nằm ở `results/*.json`
> (nguồn sự thật) + `reports/`. Muốn thử nhanh thì dùng `--limit`/`--out` ghi ra chỗ tạm,
> đừng chạy full rồi ghi đè kết quả đã trích.

---

## 1. Nền tảng dùng chung (không phải experiment)

| File | Vai trò |
| :--- | :--- |
| `unified_dataset.py` | **Bộ dựng luồng gộp** (CICIDS + DAPT2020 + Zero-day REAL-DERIVED, trộn theo thời gian) **và bộ CHẤM luồng** `score_stream()`. Luồng online, eval offline và các thí nghiệm rigor **cùng import** — 1 nguồn sự thật. |
| `metrics_core.py` | **Module chỉ số dùng chung**: MCC, Wilson/bootstrap CI, bóc theo lớp, throughput, gánh nặng cảnh báo, neo bằng chứng, Cohen's κ, chi phí tài nguyên, **hiệu chuẩn (Brier/ECE)**, **ngăn chặn mức IP**, **truy xuất (Recall@k/MRR/nDCG)**. Thuần Python → unit-test trong CI. |
| `action_scoring.py` | **Chấm theo hành động cuối cùng** — thước đo CHÍNH của ablation (thay thước đo nhị phân đã bão hoà). |
| `_eval_isolation.py` | Snapshot/khôi phục 4 kho trạng thái quanh script eval có side effect → phép đo không tự làm nhiễm chính nó. |
| `build_golden_baseline.py` | Dựng golden baseline benign (loại trừ flow trùng benchmark) cho hiệu chỉnh Welford. |
| `plot_results.py` | Vẽ hình PNG (`results/plots/`) cho các mục Chương 4. |
| `e2e_test_runner.py` | Smoke-test end-to-end offline — không trích số. |
| `statistical_tests.py` | McNemar + Mann-Whitney U trên kết quả ablation đã lưu. |

## 2. Đánh giá CHÍNH (trích số vào Chương 4)

| File | Chạy | Output | Mục luận văn (Ch.4) |
| :--- | :--- | :--- | :--- |
| `evaluate_unified_stream.py` | `python -m experiments.evaluate_unified_stream` | `unified_stream_results.json` + `reports/` | §Classification + §Emergent APT + §Zero-Day. Offline, tất định, **không cần LLM**. Xuất MCC · CI bootstrap · **bảng per-class 15 lớp** · sổ kế toán nguồn · **ngăn chặn mức IP** (tách IP thật / IP tổng hợp) |
| `evaluate_ml_gate.py` | `python -m experiments.evaluate_ml_gate` | `ml_gate_results.json` | §ML Gateway. Xuất MCC · per-class · **throughput** · **gánh nặng cảnh báo** · `auto_block_precision` · **hiệu chuẩn Brier/ECE** · kháng né-tránh **tách 3 chế độ** |
| `evaluate_rag_retrieval.py` | `python -m experiments.evaluate_rag_retrieval` | `rag_retrieval_results.json` | §RAG. **Recall@k · MRR · nDCG@k** đo THẲNG bộ truy xuất — offline, **không cần LLM**. Báo cả trần phủ kho lẫn trần cấu trúc |
| `run_ablation.py` | `--mode {af,bcde,balanced,mlgate,all}` | `ablation_*.json` | §Ablation. Xuất **chấm-theo-hành-động** + **bảng chéo 4 lớp** + cờ `metric_health.is_base_rate_artifact` |
| `evaluate_adversarial.py` | `--mode {static,pipeline,all}` | `robustness_results.json` · `adversarial_pipeline_results.json` | §Adversarial Robustness (lớp tĩnh theo nhóm + pipeline đầy đủ) |
| `evaluate_reasoning.py` | `python -m experiments.evaluate_reasoning` | `reasoning_eval_results.json` | §Reasoning Quality. LLM-as-Judge 4 chiều + **neo bằng chứng** (thay `audit_completeness`) |
| `evaluate_tier2_decision.py` | `python -m experiments.evaluate_tier2_decision` | `tier2_decision_results.json` | §Tier-2 Adjudication. Xuất MCC + Wilson CI cho recall/specificity + **hiệu chuẩn confidence** (kiểm chứng giả định nền của chính sách 4 dải) |

## 3. Thí nghiệm RIGOR — chống phản biện (GIỮ, đừng xoá)

| File | Chống câu hỏi nào | Output | Cần LLM? |
| :--- | :--- | :--- | :-: |
| `run_baseline_comparison.py` | *"Hơn một IDS truyền thống ở chỗ nào?"* + *"Hơn các dự án LLM-SOC khác ở chỗ nào?"* — H0 ZeroR · H1 chữ ký tĩnh · H2 ML đơn tầng · **H3 LLM-only** (`--with-llm`) vs SENTINEL | `baseline_comparison_results.json` | ✗ (H3: ✓) |
| `evaluate_feedback_loop.py` | *"Vòng phản hồi có thật sự giảm tải không?"* — chạy 2 vòng, đo Δ leo thang + chốt `detection_preserved` | `feedback_loop_results.json` | ✗ |
| `run_threshold_sensitivity.py` | *"Sao chọn 3.5σ? cherry-pick?"* — quét ngưỡng Welford | `threshold_sensitivity_results.json` | ✗ |
| `run_ml_threshold_sweep.py` | *"Sao chọn 0.85/0.65/0.40?"* — quét ngưỡng Cổng ML (đối xứng với sweep Welford) | `ml_threshold_sweep_results.json` | ✗ |
| `run_zeroday_graded.py` | *"Đếm nhị phân là may?"* — đường cong phát hiện phân cấp | `zeroday_graded_results.json` | ✗ |
| `run_apt_negative_control.py` | *"Có báo APT nhầm không?"* — đối chứng âm + specificity + Wilson CI | `apt_negative_control_results.json` | ✗ |
| `run_context_stress.py` | *"Prompt có tràn n_ctx?"* — token vs số log + nén Drain3 | `context_stress_results.json` | ✗ |
| `measure_latency_baseline.py` | Claim độ trễ chủ đạo (hai tầng vs LLM-only) | `latency_benchmark.json` | ✓ |
| `run_llm_robustness.py` | *"LLM tất định? đổi seed có đổi kết luận? chết thì sao? tốn bao nhiêu?"* — determinism + **variance đa seed** + suy biến + **chi phí tài nguyên** | `llm_robustness_results.json` | ✓ |
| `audit_tier_capability.py` | Ma trận năng lực 3 tầng trên các họ tấn công | `tier_capability_audit.json` | ✓ |
| `export_judge_sample.py` | *"Ai kiểm định chính trọng tài LLM?"* — xuất mẫu cho người chấm → Cohen's κ | `judge_agreement_results.json` | ✗ (cần **người**) |

## 4. Luồng ONLINE / demo (chứng minh vận hành, không trích số)

| File | Chạy | Ghi chú |
| :--- | :--- | :--- |
| `scripts/demo.py` · `scripts/push_datatest.py` | `python scripts/build_datatest.py && python scripts/push_datatest.py` | Đẩy luồng gộp lên Redis → chảy qua **toàn hệ thống thật**. Dùng chung `build_stream()`/`enrich()` với eval offline. |

**Luồng DEMO trước hội đồng** dùng `data/demo.json` (≈100k sự kiện) hoặc
`data/demo_small.json` (5k, phân tầng cho đủ mọi panel). Dựng lại bằng
`scripts/build_demo.py` rồi `scripts/build_demo_small.py`. Tỉ lệ tấn công của tập nhỏ
**cao hơn** luồng đầy đủ do phân tầng — script in cả hai cạnh nhau, đừng trích tỉ lệ của
tập nhỏ như thể đó là hồ sơ tải của hệ thống.

## 5. Dữ liệu

- `ground_truth.json` — CICIDS2018 đã gán nhãn (nguồn phân loại + nền zero-day).
- `adversarial/<nhóm>/samples.json` — 120 payload OWASP LLM Top-10 (5 nhóm).
- `results/*.json`, `results/plots/*.png` — **số liệu + hình đã trích trong luận văn**.
- `.unified_eval_memory.db` — DB threat-memory tạm của eval offline (tự sinh, gitignored).

---

## 6. Quy ước bắt buộc khi thêm/sửa script đo

1. **Chỉ số dẫn xuất phải gọi `metrics_core`**, không tự tính lại. Ma trận nhầm lẫn → dùng
   `confusion_report()` để mọi script cùng xuất MCC + mốc đối chứng theo một định dạng.
2. **Vòng chấm luồng Tier-1 phải gọi `unified_dataset.score_stream()`.** Trước đây tồn tại
   hai bản sao của vòng này và cả hai mang y hệt hai lỗi (bỏ sót nguồn `*_max` khiến ~25k
   sự kiện biến mất khỏi ma trận; chấm cả tập warmup nên đo lớp benign trên chính dữ liệu
   đã dùng để học). Một nguồn sự thật nghĩa là sửa một lần là hết.
3. **Nguồn sự kiện mới phải được khai báo.** `score_stream()` đưa nguồn lạ vào nhánh
   `UNHANDLED:` và hét lên trong log — đừng làm nó im lặng trở lại.
4. **Mọi tỉ lệ trên n nhỏ phải kèm CI.** Wilson cho tỉ lệ, bootstrap cho F1/MCC/accuracy
   hành động. Không có CI thì không được viết "cấu hình X tốt hơn Y".
5. **Chỉ số phải CÓ THỂ TRƯỢT.** Một số luôn bằng 100 (hoặc luôn bằng 1,00) ở mọi lần chạy
   không phải phép đo — nó là kiểm tra tính đúng đắn, và chỗ của nó là khối `run_health`
   hoặc một unit test, không phải bảng kết quả. Tương tự, đừng xuất một con số **suy ra
   bằng hằng số giả định** cạnh một con số **đo thật** cùng đơn vị: người đọc không có cách
   nào phân biệt. Đã có bốn chỉ số bị gỡ vì đúng hai lý do này.
6. **Phép đo phải đặt hệ vào ĐÚNG điều kiện vận hành.** Chấm một sự kiện mà Tier-1 vốn cho
   qua là đo một quy trình không tồn tại. Điều kiện-hoá theo leo thang (như
   `evaluate_tier2_decision.py` và `evaluate_rag_retrieval.py`), và **báo số ca bị loại**
   để không ai tưởng mẫu số là toàn bộ tập.
7. **Script eval có side effect phải bọc `_eval_isolation.isolated_state()`** — bất kỳ
   script nào gọi `agent_app.invoke()` đều ghi vào audit DB, threat memory, luật động và
   Redis blacklist, và cả bốn thứ đó quay lại nuôi Tier-1 ở lần đo sau.
