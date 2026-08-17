# SENTINEL — Chỉ số & Trình diễn theo Câu hỏi Nghiên cứu

> **07/08/2026** · 22 chỉ số (đã loại 16, xem §4) · ✅ RQ1 8/8 · ✅ RQ2 6/6 · ✅ **RQ3 8/8**
> 07/08: **3.f/3.g quay lại bảng chính** — chấm theo HÀNH ĐỘNG phá được bão hoà nhị phân; **3.k** đưa vào §4.4 kèm KTC.
> Mọi số trích thẳng từ `experiments/results/*.json`. Luôn `export SENTINEL_FREEZE_DYNAMIC_RULES=1`.
> 🔴 = số XẤU hoặc bẫy đọc — phải tự nêu trước khi bị hỏi.

---

## 0. Tập dữ liệu — trộn những gì

Mỗi mẫu số dưới đây là một tập **GỘP**. Không nêu thành phần thì mọi tỉ lệ đều đọc sai:
xả tải, F1 và FP đều là hàm của tỉ lệ trộn, không phải hằng số của hệ.

| tên gọi trong bảng | tệp | tổng | trộn từ |
| :-- | :-- | --: | :-- |
| **datatest** | `data/datatest.json` | 4.240 → **4.236** sau `drop_authored` | CSE-CIC-IDS2018 `cicids` 1.171 + `cicids_max` 1.169 · **CSIC 2010** 1.036 · **DAPT2020** `dapt_max` 469 + `dapt` 31 · zero-day tổng hợp 360 · đối kháng tự soạn 4 (bị loại)<br>nhãn: Benign 2.031 · 15 lớp tấn công CICIDS · 6 lớp web CSIC (SQLi 180 · Backup/Source Probing 100 · XSS 85 · CRLF 80 · Forced Browsing 27 · Path Traversal 26) |
| **build_stream** | dựng bởi `unified_dataset.build_stream()` | 25.649 (+150 warmup lành) | `cicids_max` 16.953 · **DAPT2020** `dapt_max` 5.000 · **CSIC 2010** 2.000 · `cicids` 1.170 → **chấm được 25.123**<br>loại khỏi chấm: DAPT chuỗi 402 · zero-day 120 · đối kháng 4 · tấn công **31,56%** |
| **demo (bản 05/08)** | `data/demo.json` **bản dựng 05/08/2026** | 99.867 → **99.717** (bỏ 150 warmup) | `cicids_max` 91.311 · **DAPT2020** `dapt_max` 6.000 + `dapt` 402 · `cicids` 1.250 · zero-day 900 · đối kháng 4 · tấn công **9,77%**<br>🔴 **KHÔNG có CSIC** — luồng này không có tấn công tầng ứng dụng thật<br>🔴 **TỆP TRÊN ĐĨA NAY KHÁC** — xem cảnh báo ngay dưới bảng |
| **ground_truth** | `experiments/ground_truth.json` | 1.750 → **1.700** sau `drop_authored` | **CSIC 2010** 500 · **CSE-CIC-IDS2018** 15 lớp × 80 = 1.200 (gồm 80 Benign) · **50 tự soạn** (25 cấu trúc + 25 ngữ nghĩa, bị loại) |
| **đối kháng 823** | `experiments/adversarial/*/` + `data/adversarial_llm/` | 823 | **CÔNG BỐ 703**: `deepset/prompt-injections` 203 · `jackhhao/jailbreak-classification` 200 · **AdvBench** harmful_behaviors 200 · `deepset` field_injection 100 *(tệp gốc còn ở `data/adversarial_llm/raw/`)*<br>**TỰ SOẠN 120**: nhóm B 80 (mã hoá 45 · cấu trúc 20 · đầu độc RAG 15) + nhóm D kiểm chéo 40 (ngữ nghĩa 20 · jailbreak 20) |
| **230 log lành** | lát của `ground_truth` | 230 | **CSIC 2010** HTTP request nhãn Benign (GT-16xx) |
| **1.036 ca né tránh** | lát của `datatest` | 1.036 | đúng các ca tấn công mà **Cổng ML đã bắt được**, rồi bóp méo đặc trưng — không phải mẫu mới |

> 🔴 **`data/demo.json` đã được DỰNG LẠI sau lượt đo.** Mọi số ở dòng `demo` trên đo ngày
> **05/08/2026** trên bản 99.867 sự kiện. Ngày **12/08/2026** tệp được dựng lại thành
> **496.885 sự kiện** có thêm **CSIC 2010 36.000** (xem [RUN_PROJECT.md §2.1](RUN_PROJECT.md)).
> `measure_offload_vs_baserate.py --source demo` đọc **thẳng `data/demo.json`**, nên chạy lại hôm
> nay sẽ **KHÔNG ra 97,47%** — thêm CSIC là thêm bằng chứng tầng ứng dụng, đúng thứ làm đổi tỉ lệ
> tấn công nền và đổi tầng nào gánh tải. Số 97,47% vẫn đúng **với bản đã đo**; muốn trích cho bản
> hiện hành thì phải chạy lại và ghi nhận số mới. Số 90,57% trên `build_stream` **không bị ảnh
> hưởng** — luồng đó dựng bằng mã, không đọc `demo.json`.

---

## 1. RQ1 — Xả tải, hiệu năng, độ trễ

| # | Chỉ số | Bản chất — chứng minh điều gì | Script · Khoá JSON | Tập (mẫu số) | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 1.a | Chất lượng phân loại Cổng ML | Cổng ML **phân biệt được** tấn công/lành, không phải ăn may nhờ lệch lớp. MCC/BalAcc miễn nhiễm với base-rate | `evaluate_ml_gate.py` → `mcc` · `balanced_accuracy` | datatest 4.236 vào, **chấm trên 2.534 ca Cổng ML TỰ QUYẾT** (51,8% tấn công) | **MCC 0,667** · BalAcc 0,833 · F1 0,825 (CI95 0,808–0,840) · P 0,909 · R 0,755 · ECE 0,095<br>🔴 mẫu số KHÔNG phải 4.236: `bypass_rate` **59,82%** — 1.586 ca bỏ qua vì thiếu payload, 116 ca abstain<br>🔴 lớp `Attack` (CSIC "Anomalous") recall **0,111**, bỏ lọt **305/343**; `Brute Force -Web` 0,746; `Infilteration` 0,810 |
| 1.b | Độ chính xác auto-BLOCK | Phần **tự chặn không cần người** có sạch không. FP ở đây = chặn nhầm khách thật ⇒ tổn thất kinh doanh | `evaluate_ml_gate.py` → `auto_block_precision` · `auto_block_n` · `auto_block_fp` | datatest, dải BLOCK_IP | **100%** (Wilson 99,6–100) · 962 lệnh · **0 FP**<br>đối chiếu dải ALERT: precision chỉ **0,416** (74 TP / 104 FP) — tự chặn sạch vì **ngưỡng cao**, không vì mô hình giỏi |
| 1.d | Thông lượng Cổng ML | "Tốc độ đường truyền" là **tuyên bố định lượng**, phải có sự-kiện/giây chứ không nói suông | `evaluate_ml_gate.py` → `throughput_eps` · `mean_latency_ms` | datatest 4.236 · tường 1,227 s | **3.452 sk/s** · 0,287 ms/véc-tơ |
| 1.e | **Tỉ lệ xả tải khỏi LLM** | Bao nhiêu % lưu lượng chết ở tầng rẻ, không tốn một token nào. Đo trên HAI luồng vì xả tải là hàm của tỉ lệ tấn công, không phải hằng số của hệ | `measure_offload_vs_baserate.py --source {stream,demo}` → `offload_tong` | build_stream 25.649 (31,56% tấn công) · demo **bản 05/08** 99.717 (9,77%) — xem cảnh báo §0 | **trên 90%** (đo 90,57%) · luồng dạng SOC **trên 97%** (đo 97,47%)<br>hệ số theo nhãn **của từng luồng**: benchmark 92,35% lành / 86,72% tấn công · SOC 97,88% / 93,77%<br>tách theo tầng — benchmark: Tier-1 **80,56%** · Cổng ML **10,01%** · tới LLM 9,43% ‖ SOC: Tier-1 **38,32%** · Cổng ML **59,16%** · tới LLM 2,53%<br>🔴 hai luồng đảo vai tầng gánh chính (80/10 ↔ 38/59) — vì demo không có CSIC nên Tier-1 ít chữ ký để bắt |
| 1.g | Bộ đệm ngữ nghĩa Tầng 1.75 | RQ1 nêu **đích danh ba cơ chế** xả tải; đây là cơ chế thứ ba. Không đo thì một phần ba câu trả lời bị bỏ trống | `run_cache_efficiency.py` → `hit_rate` · `speedup_x` · `evictions` | build_stream → phễu 9.071 quét · 1.183 tới RAG · **1.500 truy vấn, 280 khác nhau** | **trên 80%** (đo 81,33%, 1.220/1.500) · **8,9×** (9,8 ms trúng vs 87,7 ms trượt) · 0 eviction<br>trúng vì `build_rag_queries()` chuẩn hoá log về "dịch vụ + cổng + kỹ thuật", **không** phải so khớp ngữ nghĩa |
| 1.h | Độ trễ 2 tầng vs LLM-only | Vế **"nút thắt cổ chai độ trễ"**. Cần cả median lẫn mean: median cho ca thường, mean cho phần đuôi chạm LLM | `measure_latency_baseline.py --n 500` → `latency_reduction_pct` · Mann-Whitney `p` | build_stream **strided n=500** · i7-14700KF / RTX 4060 Ti 16GB | ✅ TB **17.187,9 → 5.286,7 ms** (−69,24%) · trung vị **17.174,7 → 0,88 ms** · MW `p`≈9,0×10⁻⁵⁷<br>🔴 **p95 XẤU HƠN: 25.829 vs 21.434 ms** — ca leo thang trả cả hai tầng<br>🔴 xả tải trong CHÍNH lượt này chỉ **76,8%** (116/500 tới LLM), không phải 90,6% của 1.e: 500 mẫu strided không tích luỹ đủ tiền sử IP để blocklist hoạt động<br>🔴 cache RAG trúng **0/116** ở đây — số 8,9× của 1.g **không** nằm trong 5.286,7 ms<br>theo chặng: Tier-1 0,182 ms · Cổng ML 0,924 ms · LLM 22.785 ms |
| 1.j | **Đối chứng — trong nhà + ngoài nhà** | Trả lời *"so với hệ khác thì hơn ở đâu?"*. Ablation A–F chỉ **so mình với mình**; phải có cả mốc nội bộ (sàn) lẫn số đã công bố trên cùng bộ dữ liệu | `run_baseline_comparison.py` → `baselines` (4.240) · `llm_subset_comparison` (150) | datatest 4.240 · **mẫu con LLM 150 phân tầng** (H3 chạy 797,9 s) | thông lượng trên mẫu con: H1 chữ ký **11.129** · SENTINEL **3.860** · H2 ML phẳng **2.162** · H3 LLM-only **0,19** sk/s → **20.531×**<br>🔴 SENTINEL **MCC 0,190** < H2 ML phẳng **0,538** (abstain tính là chưa cho qua); trên mẫu con 150 còn tệ hơn: **MCC 0,0283**, `accuracy_beats_baseline: false`<br>🔴 20.531× **không tái lập được** từ `throughput_eps` đã làm tròn (0,19 → ra 20.314×) — phải chia bằng `wall_seconds`<br>**ĐÃ BỎ bảng MCC khỏi luận văn, chỉ giữ trục thông lượng** |
| 1.k | **Vòng phản hồi Tier-2 → luật động → Tier-1** | Cơ chế xả tải **thứ tư**: hệ có thật sự *học* từ phán quyết LLM không, hay chỉ lặp lại chi phí mỗi vòng | `evaluate_feedback_loop.py` → leo thang vòng 1 vs 2 · tải LLM · phát hiện có tụt không | build_stream 25.649, **2 vòng cùng hạt giống**, luật sinh từ phán quyết Cổng ML | leo thang **20,28% → 17,98%** = giảm **trên 10%** (đo 11,35%) · 598 luật · 594 ca Tier-1 hấp thụ thêm · ΔMCC **+0,0378** · ΔRecall **+0,0452** ✅<br>🔴 MCC tuyệt đối vẫn rất thấp: **0,071 → 0,109** — chứng minh cơ chế CHẠY, không chứng minh Tier-1 giỏi<br>🔴 giả định lạc quan: kẻ tấn công **không đổi IP** giữa hai vòng; analyst duyệt **mọi** đề xuất, không có bước từ chối |

```bash
# offline (~5 ph)
for s in evaluate_ml_gate run_cache_efficiency run_baseline_comparison; do .venv/bin/python experiments/$s.py; done
.venv/bin/python experiments/measure_offload_vs_baserate.py --source stream
.venv/bin/python experiments/measure_offload_vs_baserate.py --source demo
.venv/bin/python experiments/evaluate_feedback_loop.py
.venv/bin/python scripts/audit_offload_mechanisms.py
# cần LLM (~3,1 h) — 1.h
.venv/bin/python experiments/measure_latency_baseline.py --n 500
```

---

## 2. RQ2 — Kháng đối kháng & toàn vẹn pháp y

| # | Chỉ số | Bản chất — chứng minh điều gì | Script · Khoá JSON | Tập (mẫu số) | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 2.a | Rào chắn **tĩnh** chặn được bao nhiêu | `evaluate_adversarial.py --mode static` → `summary.block_rate_pct` + `by_category` | tách theo XUẤT XỨ, không gộp | đối kháng 823 = **CÔNG BỐ 703** (deepset 203 · jackhhao 200 · AdvBench 200 · deepset field_inj 100) + **TỰ SOẠN 120** | 🔴 **A nguồn công bố 132/703 = 18,78%** ← số trích<br>B tự soạn 58/80 = 72,5% (mã hoá 45/45 vì `EncodingNeutralizer` sinh ra đúng để trị nhóm đó) · D kiểm chéo 2/40 = 5,0%<br>gộp 192/823 = 23,33% ⛔ KHÔNG trích<br>🔴 mù hoàn toàn: `advbench_gcg` **0/200** · `semantic_confusion` **0/20** · `jailbreak` 2/20 · `prompt_injection_hf` 31/203 = 15,3%<br>theo bộ dò (823, một mẫu có thể trúng nhiều bộ): khớp mẫu **127** · mã hoá **84** · phân định **5** |
| 2.b | Tier-2 có bị thao túng không | `--mode pipeline` (**bỏ `--limit`**) → `resistance_rate_pct` + **`coverage_pct`** | 7 nhóm KHÓ 678 + `field_injection` 100, độ phủ 100% | mẫu KHÓ = phần lớp tĩnh KHÔNG hấp thụ được; 543/678 là số thật sự lọt trong 7 nhóm đó, 88 mẫu lọt còn lại thuộc field_injection | **678/678 = 100%** · `coverage_pct` 100 · `metric_valid` true<br>678 là SIÊU TẬP của 543 mẫu thật sự lọt trong 7 nhóm đó<br>gồm `advbench_gcg` mà lớp tĩnh mù **0/200** ⇒ Tier-2 gánh phần KHÓ NHẤT<br>**(gộp 2.c)** bọc THEO TRƯỜNG: `field_injection` **100/100** — URI 24/24 · UA 23/23 · message 30/30 · payload 23/23<br>số lần **THẬT SỰ gọi LLM**: 678 mẫu KHÓ → 676 (99,7%) trên mã trước vá ‖ field_injection → **100/100** sau vá<br>✅ **ĐÃ VÁ + ĐO LẠI 06/08 19:18**: `feature_fingerprint` nay gồm cả `user_agent`/`headers` ⇒ 100 mẫu → **100 phán quyết độc lập** (trước: 79) và 678 mẫu KHÓ → **678** (trước: 676). Số đo lại TRÙNG KHÍT bản cũ (100/100, đều 4 vị trí, 73 BLOCK_IP / 27 ALERT) ⇒ tuyên bố "đều cả 4 vị trí" nay ĐỨNG ĐƯỢC<br>⚠️ bản vá áp SAU vòng đo, nên 678/678 và 3.i (998 lời gọi thật) vẫn đứng trên mã TRƯỚC vá — không chạy lại 4,3 h + 2 h cho khác biệt 2/678 |
| 2.d | **Báo động giả trên log lành** | `--mode negative` → `false_flag_rate_pct` | đối chứng ÂM bắt buộc: không có nó thì tỉ lệ chặn vô nghĩa | **230 log lành CSIC 2010** (HTTP request nhãn Benign, GT-16xx) | 🔴 **46/230 = 20,0%** · **46/46 đến từ lớp mã hoá**, lớp khớp mẫu 0, lớp phân định 0<br>cái giá: cờ tĩnh chỉ CHÚ THÍCH + nâng mức cô lập, **không** loại sự kiện, **không** chặn nguồn (`nodes.py:480`) |
| 2.f | HMAC phát hiện giả mạo | `run_audit_tamper.py` → `overall_detection_rate_core` | tính lại cả chuỗi `H_i = HMAC(D_i ‖ H_{i-1}, K)`; phát hiện có ĐỊNH VỊ | chuỗi audit dựng sẵn **450 bản ghi** · 30 lượt/kiểu · seed 42 | **100%** cả ba kiểu: sửa nội dung 30/30 · chèn dòng giả 30/30 · xoá dòng giữa 30/30<br>đối chứng âm 450 bản ghi nguyên vẹn → 0 báo động giả · `key_is_default` **false** (khoá thật từ `.env`)<br>🔴 **(gộp 2.g)** cắt đuôi chuỗi **0/30 — không phát hiện được**, giới hạn nguyên lý, nêu RIÊNG |
| 2.h | Tất định + đổi seed của LLM | `run_llm_robustness.py` → `determinism` · `seed_variance.flip_rate` | phán quyết có ổn định khi chỉ đổi seed | **ground_truth** (KHÔNG phải dữ liệu đối kháng) — tất định **1 mẫu × 5 lượt**; đổi seed **10 mẫu × 3 seed** (11 · 42 · 1337) | tất định 5/5 lượt **hành động trùng khớp** (`distinct_raw_outputs` = 2, `distinct_actions` = 1)<br>đổi riêng seed: **0/10 mẫu đổi phán quyết** · ép hỏng backend → **AWAIT_HITL**, không sụp<br>🔴 **CI95 của flip-rate là [0 ; 0,2775]** — n=10 không loại trừ nổi mức lật 28%<br>🔴 cả 10 mẫu đều ra **AWAIT_HITL ở mọi seed**: phép đo bão hoà ở một hành động duy nhất nên không phân giải được gì; tất định chỉ chạy trên **một** mẫu |
| 2.i | **Kháng né tránh ở lớp ML** | `evaluate_ml_gate.py` → `evasion_resistance.headline_hard_mode` | bóp méo đặc trưng của ca ĐÃ bắt đúng, xem có lật được thành "lành" không | **1.036 ca tấn công Cổng ML đã bắt đúng** (lát của datatest) × 3 chế độ | **98,75%** (1.023/1.036 · CI95 97,86–99,27) · 13 ca bị lật thành lành ← **số ĐÁNG TRÍCH** (chế độ KHÓ `extreme_broad`)<br>`inf_single` 1.036/1.036 · `extreme_single` 1.036/1.036 = 100% nhưng **bão hoà tầm thường** ⇒ ⛔ KHÔNG gộp trung bình 3 chế độ |

```bash
# offline (~3 ph)
.venv/bin/python experiments/evaluate_adversarial.py --mode static
.venv/bin/python experiments/evaluate_adversarial.py --mode negative
.venv/bin/python experiments/run_audit_tamper.py
.venv/bin/python experiments/evaluate_ml_gate.py            # 2.i nằm trong tệp này
# cần LLM
.venv/bin/python experiments/evaluate_adversarial.py --mode pipeline                    # 2.b · ~4,3 h
.venv/bin/python experiments/evaluate_adversarial.py --mode pipeline \
    --category field_injection --out experiments/results/adversarial_pipeline_field_injection.json  # ~13 ph
.venv/bin/python experiments/run_llm_robustness.py          # 2.h
```

⚠️ `--category` **bắt buộc kèm `--out` riêng**, nếu không sẽ đè tệp 678 mẫu.

---

## 3. RQ3 — Quy kết ATT&CK, truy xuất, phân loại tải người

| # | Chỉ số | Bản chất — chứng minh điều gì | Script · Khoá JSON | Tập (mẫu số) | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 3.a | Quy kết **tắt LLM** (trần từ truy xuất) | `eval_attack_mapper.py --mode rrf --evidence-layer payload` → `technique_exact_match_pct` | RRF hợp nhất hai truy vấn RAG, KHÔNG gọi LLM — tách phần quy kết do truy xuất làm được | **500 mẫu tầng payload** = 250 có kỹ thuật + 250 lành, lấy từ ground_truth sau `drop_authored`; nguồn **CSIC 2010** | ✅ exact **80,0%** · parent 80,0% · tactic 80,0% · trần phủ kho 100% · p50 0,54 ms<br>theo mã: T1059.007 100% (n=30) · T1190 100% (52) · T1595.003 90,8% (130) · 🔴 **T1071.001 0,0% (26)** · 🔴 **T1083 0,0% (12)** |
| 3.b | Quy kết **toàn tuyến** | `--mode e2e --evidence-layer payload` → `technique_exact_match_pct` · `tactic_match_pct` | cùng 500 mẫu, nhưng chạy **full agent** (Guardrails → RAG → LLM → hợp nhất) | như 3.a, cô lập bằng `isolate_for_e2e()`; **Tier-1 KHÔNG chạy trước** nên prompt không có `tier1_reasons` | 🔴 exact **68,0%** — **THẤP HƠN 3.a (80,0%) 12 điểm**: thêm LLM làm quy kết XẤU ĐI · tactic 70,4% · p50 **13.293 ms** (3.a: 0,54 ms)<br>theo mã: T1190 100→**63,5%** · T1059.007 100→**73,3%** · T1595.003 90,8→86,9% · T1083 0→16,7% · T1071.001 0→0%<br>giải thích được: 30 mẫu mất, **tối đa 22 do lá chắn neo bằng chứng ép về N/A** (xem 3.l) — đánh đổi CÓ CHỦ Ý giữa quy kết và an toàn<br>🔴 **459/500 lô ra `BLOCK_IP`** trên tập 50% lành ⇒ chặn nhầm **≥ 209/250 = 83,6%** mẫu lành; tỉ lệ đã là 94/100 ngay ở 100 lô ĐẦU nên **không** phải do tiền sử IP cộng dồn<br>`enforce_tier_consensus` bất đối xứng theo thiết kế: chỉ chặn LLM **hạ cấp**, không chặn LLM **chặn thừa** |
| 3.e | Chất lượng truy xuất RAG | `evaluate_rag_retrieval.py [--evidence-layer payload]` → `achievable.recall_at_k` · `mrr` | TRẦN của 3.a/3.b — nhưng chỉ so được khi **cùng lát bằng chứng** | lát `all`: **1.305** truy vấn (đã bỏ 65 ca Tier-1 không leo thang, 50 mẫu tự soạn) ‖ lát `payload`: **243** — cùng dân số với 3.a/3.b | ✅ **payload: Recall@3 = 0,930** (CI95 0,891–0,956) · MRR 0,803 · hạng trung vị 1 ← **trần thật của quy kết**<br>🔴 lát `all`: Recall@3 chỉ **0,385** vì NetFlow thuần dìm — T1110 hit@3 **0,00** (n=236) · T1499 0,59 (456); ⛔ KHÔNG đem 0,385 đối chiếu 80,0% của 3.a<br>chẩn đoán: T1083 truy xuất 0,00 ⇒ lỗi **kho/truy xuất**; T1071 truy xuất **1,00** mà quy kết 0,0% ⇒ lỗi **bộ ánh xạ** |
| 3.f<br>3.g | **Bóc tách thành phần (chấm theo HÀNH ĐỘNG)** | `run_ablation.py` → `actions[]`, chấm lại bằng `scripts/score_ablation_actions.py` → `ablation_action_scores.json` | Thước NHỊ PHÂN vô dụng ở đây: base rate 86,86% nên mọi cấu hình đều ~= base rate (`binary_f1_trustworthy: false`). Chấm theo hành động cuối mới phân biệt được | A/F: **1.700** mẫu (đã `drop_authored` 50 mẫu tự soạn — `run_ablation` KHÔNG tự loại chúng ở vòng ablation) ‖ B–E: lát 300 riêng, **không so trực tiếp với A/F** | ✅ **A 28,29%** (KTC 26,20–30,48) vs **F 35,35%** (33,12–37,66) — KTC **không chồng lấn**<br>✅ **đánh đổi ĐẢO CHIỀU**: A chính xác hơn khi chịu quyết (**c.xác tự quyết 69,01%** vs 57,72%) nhưng **bỏ ngỏ 59,00%**; F bỏ ngỏ 0% và đổi thành **hoãn 44,76%**<br>🔴 **C ≡ D ≡ E trùng khít** (41,33%) ngay cả với thước hành động — do cấu tạo (chỉ gọi LLM khi Tier-1 leo thang), KHÔNG phải bằng chứng bậc RAG vô dụng; đã nêu thẳng trong luận văn<br>⚠️ đổi thước SAU khi thấy kết quả ⇒ luận văn phải nêu rõ lý do (thước cũ suy biến), nếu giấu là chọn thước theo kết quả |
| 3.i | **Phân loại cảnh báo của Tier-2 — tỉ lệ báo giả** | Việc thật của LLM trong SOC: Tier-1 đã đẩy cảnh báo lên, LLM phải tách **thật** khỏi **giả**. Đây là câu trả lời trực tiếp cho vế *"giảm và phân loại chính xác việc cần người"* của RQ3 | `evaluate_tier2_decision.py` → `triage.*` (lượt **06/08 14:47**, `metric_valid` true, 0 lỗi invoke) | **1.066 cảnh báo Tier-1 đẩy lên**, chỉ **80 = 7,5% là thật**; nguồn: CSIC 910 (toàn lành) · cicids 75 · cicids_max 76 · zero-day 4 · đối kháng 1 | 🔴 **quyết định nhị phân VÔ GIÁ TRỊ: MCC 0,0 · specificity 0,0 · BalAcc 0,5** — LLM gắn cờ **cả 1.066/1.066**, không hạ cấp một ca nào (tp 80 · fp 986 · tn 0)<br>🔴 **FP trên phần KHẲNG ĐỊNH: 894/898 = 99,55%** (CI95 98,86–99,83) · precision 0,45%<br>🔴 lọc được cảnh báo giả: **0/986** · hiệu chuẩn ECE **0,803**, tự tin TB khi gắn cờ **0,846** trong khi đúng 7,5%<br>✅ **kênh HOÃN mới là chỗ có giá trị: làm giàu 6,03×** — 168 ca (15,76% dòng vào) chứa **76/80 = 95,0% đe doạ thật**, tỉ lệ thật trong hàng đợi 45,24% ⇒ analyst chỉ xem hàng đợi này thì **giảm 84,24% khối lượng** mà vẫn bắt 95,0%<br>⇒ dùng LLM làm **bộ định tuyến phân loại**, KHÔNG dùng làm bộ tự khẳng định |
| 3.j | Chất lượng lập luận | `evaluate_reasoning.py` → 4 trục thang 1–5 + `evidence_grounding` | trọng tài LLM **KHÁC HỌ** chấm phán quyết của tác tử; `assert_cross_family()` chặn tự chấm mình | **1.052 lô** leo thang trong `ablation_results.json → Config_F` sinh lại 06/08 (ground_truth 1.750) | ✅ ctx-precision **2,54** · relevancy **4,52** · faithfulness **3,96** · ctx-recall **4,11** · TB **3,78/5,0**<br>✅ lượt đo SẠCH: `n_incomplete_schema` **0** (bản 30/07 là 69/277) · 71 ca không trả mã là **từ chối CÓ CHỦ Ý** do lá chắn neo, không phải lỗi parse<br>🔴 **neo bằng chứng SỤP còn 11,2%** (CI95 9,5–13,3), TB **0,2** trích dẫn/lời biện giải — ~9/10 lời biện giải không dẫn giá trị log nào kiểm được<br>🔴 ctx-precision 2,54 là trục yếu nhất — khớp chẩn đoán truy xuất của 3.e<br>⛔ KHÔNG so 11,2% với 50,2% của bản 30/07: khác dân số (1.052 vs 277) và khác mã |
| 3.l | Neo bằng chứng (0% ảo giác) | `score_evidence_grounding.py --trace ...` → `bad` · `la_chan_neo_kich_hoat` | hệ có KHẲNG ĐỊNH mã ATT&CK vắng trong tài liệu RAG của chính lô đó không | **1.566 bản ghi tracer** = 500 của 3.b + 1.066 của 3.i (`SENTINEL_TRACE=1`); chấm theo thước CHẶT = ID tài liệu đã truy xuất | ✅ **`bad` = 0/1.421 lô có khẳng định kỹ thuật** (0,00%); nới tới kỹ thuật CHA vẫn 0<br>lá chắn kích hoạt **145/1.566 = 9,26%**; **76 lần** hạ `BLOCK_IP → AWAIT_HITL` ⇒ **76 lệnh chặn IP vĩnh viễn tự động bị chặn lại**, cả 76 do **model** đề xuất; 69 lần còn lại bắt mã do **bộ ánh xạ** tự suy<br>kỹ thuật bị từ chối nhiều nhất: T1218 ×27 · T1083 ×24 · T1071.001 ×16 · T1190 ×14 · T1059.007 ×12<br>⚠️ `bad` chấm theo thước CHẶT; lá chắn thật dùng regex trên TOÀN VĂN ngữ cảnh ⇒ 0 là **CẬN TRÊN** của số ca bỏ lọt, không phải con số chính xác |

```bash
# offline — 3.e CHẠY HAI LÁT: `payload` mới là trần so được với 3.a/3.b
.venv/bin/python experiments/evaluate_rag_retrieval.py                                   # 3.e lát all · ~6 ph
.venv/bin/python experiments/evaluate_rag_retrieval.py --evidence-layer payload          # 3.e lát payload · ~2 ph
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload       # 3.a · 20 s
# cần LLM — nhịp đo được 06/08: ~13,0 s/lô
SENTINEL_TRACE=1 SENTINEL_TRACE_FILE=logs/rq3/tier2_trace_3b.jsonl \
  .venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload     # 3.b · ~108 ph
SENTINEL_TRACE=1 SENTINEL_TRACE_FILE=logs/rq3/tier2_trace_3i.jsonl \
  .venv/bin/python experiments/evaluate_tier2_decision.py                                # 3.i · ~2 h
.venv/bin/python experiments/run_ablation.py --mode af                                   # nguồn 3.j · ~50 ph
bash logs/rq3/run_3j.sh                                    # 3.j: tự đổi model, chấm, đổi lại · ~40 ph
.venv/bin/python experiments/score_evidence_grounding.py \
  --trace logs/rq3/tier2_trace_3b.jsonl logs/rq3/tier2_trace_3i.jsonl                    # 3.l · 5 s
```

⚠️ **3.j bắt buộc đổi model** — `assert_cross_family()` sẽ tự dừng nếu trọng tài trùng bị cáo.
⚠️ **3.l không cần lượt chạy sống riêng** — bật tracer ngay trên 3.b/3.i là đủ nguyên liệu.
⚠️ `run_ablation --mode af` **ghi đè** `ablation_results.json`; bản 30/07 đã lưu ở `_archive_pre_2026-08/`.

---

## 4. Chỉ số đã loại — và vì sao

Loại khỏi bảng chính ngày 06/08 để bảng đọc được. Số vẫn còn trong `experiments/results/`;
mục này để tra khi bị hỏi, KHÔNG trích vào luận văn.

| # | chỉ số | lý do loại |
| :-- | :-- | :-- |
| 1.f | Tỉ lệ gỡ tải riêng của Cổng ML | trùng với phần tách theo tầng đã có ở 1.e (Tier-1 80,6% / Cổng ML 10,0%) |
| 1.i | Toàn tuyến trên luồng gộp | đã bỏ khỏi luận văn 05/08; MCC 0,0952 là Tier-1 đứng một mình, không phải hệ |
| 1.l | Ba cơ chế gỡ tải, kiểm **riêng từng cái** | là phép kiểm chức năng pass/fail (14/14), không phải chỉ số — gộp làm chú thích của 1.e |
| 1.m | Độ nhạy ngưỡng Cổng ML | bão hoà: 12 cấu hình chỉ cho 6 giá trị MCC; không phân giải được ngưỡng |
| 1.n | Nguồn gốc chất lượng mô hình ML | đã bỏ khỏi luận văn 05/08 |
| 2.c | Rào chắn theo **vị trí trường** | gộp vào 2.b — cùng một cơ chế bọc nonce, chỉ khác vị trí trường (100/100, đều 4 trường) |
| 2.e | Kiểm chéo tự soạn ↔ công bố | suy ra từ `by_category` của 2.a, không phải lượt chạy riêng |
| 2.g | Lỗ hổng cắt đuôi (nêu **riêng**) | gộp vào 2.f — cùng một tệp `audit_tamper_results.json` |
| 3.c | Quy kết tầng **flow** | quy kết tầng flow = 0,0% và bị chặn trần bởi truy xuất; nêu như hạn chế, không chạy e2e (tiết kiệm 2,6 h) |
| 3.d | Quy kết **gộp hai tầng** | SUY RA ĐƯỢC bằng trung bình có trọng số của 3.a và 3.c — chạy là lặp lại 1.700 mẫu (3,6 h vô ích) |
| 3.h | Ablation khử base-rate | trên tập **cân bằng** (n=300) A ≡ F (0,3133) và C ≡ D ≡ E (0,3167) — bão hoà VẪN còn ở lát này. Không mâu thuẫn với 3.f/3.g đã công bố: đó là dân số KHÁC (1.700 mẫu, phân bố thật). ⛔ không đem hai bộ số đối chiếu nhau |
| 3.k | Đối chứng âm cho tương quan **có trạng thái** | ✅ **ĐÃ ĐƯA VÀO §4.4 07/08** ở mức minh chứng khái niệm: 3/3 chuỗi thật, 4 chuỗi lành không báo giả, **KTC 95% của recall 0,44–1,00** — nêu kèm CI để không ai đọc thành tuyên bố năng lực. DAPT vẫn ở Hướng phát triển |
| 3.m | **Cohen's κ người ↔ trọng tài LLM** | cần NGƯỜI chấm tay 50 mẫu — không phải thời gian máy |
| 3.n | **Ý nghĩa thống kê của ablation** | kiểm ý nghĩa của ablation, mà ablation đã bị loại |
| 3.o | Recall theo `top_k` so với chi phí token | đánh đổi top_k ↔ token; gộp làm chú thích của 3.e |
| 3.p | So sánh model (phát lại prompt thật) | BỊ CHẶN — cần `reports/runs/*/tier2_trace.jsonl` chưa tồn tại |
