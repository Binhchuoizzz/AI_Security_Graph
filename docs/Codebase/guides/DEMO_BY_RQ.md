# SENTINEL — Chỉ số & Trình diễn theo Câu hỏi Nghiên cứu

> **Tài liệu DUY NHẤT cho mọi phép đo.** Gộp từ `DEMO_BY_RQ.md` + `BENCHMARK_GUIDE.md` (đã xoá).
> Cách vận hành hệ thống: [RUN_PROJECT.md](RUN_PROJECT.md) · Kịch bản demo UI: [DEMO_FLOWS.md](DEMO_FLOWS.md)
>
> **Trạng thái: KHUNG — cột "Số đo" đang trống (⬜) chờ đợt chạy lại toàn bộ.**
> Cập nhật 03/08/2026.

---

## 0. Luật chung — đọc trước khi chạy bất cứ thứ gì

### 0.1 Khởi động

```bash
docker-compose up -d                        # Redis + llama.cpp + MLflow + Dashboard
export SENTINEL_FREEZE_DYNAMIC_RULES=1      # BẮT BUỘC cho MỌI lượt đo
```

Không đóng băng luật động thì phép đo tự sinh luật rồi tự hưởng lợi ở lượt sau.

### 0.2 Thứ tự dựng dữ liệu — sai chiều là hỏng cả lượt đo

```text
csic.json → ground_truth.json + datatest.json → golden_baseline.json → demo.json
```

`golden_baseline` phải dựng **sau** `datatest` vì nó dùng datatest để lập tập chữ ký loại trừ
(chống rò benchmark vào seed Welford). Kiểm nhanh: dựng lại rồi `diff` — không đổi là đúng.

### 0.3 Bốn tập dữ liệu, bốn việc khác nhau

| tập | cỡ | dùng cho | KHÔNG dùng cho |
| :-- | --: | :-- | :-- |
| `data/datatest.json` | 4.240 (cân bằng) | Cổng ML — cần cân bằng lớp | tỉ lệ xả tải (phụ thuộc phân bố) |
| `experiments/ground_truth.json` | 1.750 → **1.700 khi chấm** | ablation, quy kết, chất lượng lập luận | F1 nhị phân (lệch lớp nặng) |
| `build_stream()` | 25.799 (10 ngày CICIDS + DAPT + CSIC + zero-day) | xả tải, độ trễ, toàn tuyến, APT | chất lượng phân loại (base-rate) |
| `experiments/adversarial/` | 703 công bố + 80 biên soạn | rào chắn đối kháng RQ2 | mọi thứ khác |

**Nguyên tắc xuyên suốt: mẫu số phải khớp câu hỏi.** Tỉ lệ *phụ thuộc phân bố* (xả tải, báo
động giả) lấy từ `build_stream`; chất lượng *phân loại* (MCC, BalAcc) lấy từ tập cân bằng.
Cùng một script, hai câu hỏi khác nhau thì hai tập khác nhau.

### 0.4 50 mẫu biên soạn bị loại khỏi mọi tỉ lệ

`fetch_and_build_dataset.py` cố ý chèn 50 mẫu đối địch **do tác giả biên soạn** vào
`ground_truth.json` để thử Guardrails. Chúng ở lại tệp (`evaluate_adversarial.py` cần), nhưng
`unified_dataset.drop_authored()` loại chúng khỏi mọi phép chấm. Không loại thì:

- 50/300 mẫu chấm-được-quy-kết là tự viết — **16,7%**;
- cả 50 cùng đáp án `T1190`, đẩy T1190 từ 52 lên 102 mẫu.

Sau khi loại, tầng payload còn **250 mẫu thật**: `T1595.003` 130 · `T1190` 52 · `T1059.007` 30
· `T1071.001` 26 · `T1083` 12.

> **Sàn đoán bừa 52%.** `T1595.003` chiếm 130/250 ⇒ đoán luôn mã đó đã được ~52%. Mọi tỉ lệ
> khớp kỹ thuật ở tầng payload phải đọc **so với 52%**, không phải so với 0.
> Khoá bằng `tests/unit/test_authored_sample_exclusion.py`.

### 0.5 Bảy điều kiểm trước khi trích bất kỳ con số nào

1. `metric_valid` / `metric_health` / `run_health` trong tệp kết quả — script tự gắn cờ thì tin nó.
2. **Mẫu số**: `n_invoked`, `coverage_pct`, `n_scorable`. Tỉ lệ không có mẫu số là tỉ lệ không kiểm chứng được.
3. Log lượt chạy phải có dòng `Loại 50 mẫu BIÊN SOẠN` — không thấy nghĩa là bộ lọc chưa chạy.
4. Mốc thời gian tệp kết quả **mới hơn** tệp dữ liệu nó đọc.
5. Không gộp số từ hai tập khác nhau thành một "dải".
6. `reasoning_eval_results.json` có `judge_model` **≠** `agent_model`.
7. Số luật động trong `config/system_settings.yaml` không đổi sau lượt đo.
8. Phép thử **chức năng** (15 ca viết tay) không đứng cạnh chỉ số **benchmark**.

---

## 1. RQ1 — Hiệu năng đường ống & kinh tế học tầng lọc

### 1.1 Câu hỏi nguyên văn

> **TV (Ch.1 §1.2):** *"Câu hỏi nghiên cứu thứ nhất (RQ1) về hiệu năng đường ống và kinh tế học
> tầng lọc: Làm thế nào để thiết kế một kiến trúc phân tầng có khả năng xả tải tự động luồng dữ
> liệu an ninh ở tốc độ đường truyền nhằm giải quyết triệt để vấn đề 'nút thắt cổ chai' về độ trễ
> và tiêu thụ tài nguyên của các Mô hình Ngôn ngữ Lớn?"*
>
> **EN:** *"How can a multi-tiered architecture be designed to autonomously offload security
> telemetry at wire-speed, thereby resolving the latency bottlenecks and resource consumption
> inherent in Large Language Models?"*

### 1.2 Bảng chỉ số

| # | Chỉ số | Script + cờ | Tập (mẫu số) | Khoá JSON | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 1.a | Chất lượng phân loại Cổng ML | `evaluate_ml_gate.py` | datatest (4.240 cân bằng) | `mcc` · `balanced_accuracy` | ⬜ |
| 1.b | Độ chính xác auto-BLOCK | `evaluate_ml_gate.py` | datatest | `auto_block_precision` · `n_auto_blocked` | ⬜ |
| 1.c | Kháng né tránh | `evaluate_ml_gate.py` | datatest, biến thể `extreme_broad` | `evasion_resistance.extreme_broad` | ⬜ |
| 1.d | Thông lượng Cổng ML | `evaluate_ml_gate.py` | datatest | `latency_ms_per_flow` | ⬜ |
| 1.e | **Tỉ lệ xả tải khỏi LLM** | `measure_latency_baseline.py` | **build_stream** (92% lành) | `stage_breakdown` · số lần gọi LLM tránh được | ⬜ |
| 1.f | Tỉ lệ gỡ tải của riêng Cổng ML | `run_ablation.py --mode mlgate` | ground_truth | `ml_bypass_rate` | ⬜ |
| 1.g | Bộ đệm ngữ nghĩa Tầng 1.75 | `run_cache_efficiency.py` | build_stream (truy vấn RAG thật) | `hit_rate` · `speedup_x` · `evictions` | ⬜ |
| 1.h | Độ trễ 2 tầng vs LLM-only | `measure_latency_baseline.py --n 1000` | build_stream (strided, giữ 92/8) | `latency_reduction_pct` · median · mean · Mann-Whitney `p` | ⬜ |
| 1.i | Toàn tuyến trên luồng gộp | `evaluate_unified_stream.py` | build_stream | `classification_cicids.mcc` · `ip_containment` | ⬜ |
| 1.j | Đối chứng nền | `run_baseline_comparison.py` | ground_truth | Zero-R · chữ ký tĩnh · ML phẳng | ⬜ chưa chạy |
| 1.k | **Vòng phản hồi Tier-2 → luật động → Tier-1** | `evaluate_feedback_loop.py` | build_stream, 2 vòng cùng hạt giống | tỉ lệ leo thang vòng 1 vs vòng 2 · tải LLM · năng lực phát hiện có tụt không | ⬜ chưa chạy |
| 1.l | Ba cơ chế gỡ tải, kiểm **riêng từng cái** | `scripts/audit_offload_mechanisms.py` | kịch bản dựng sẵn | BLOCKLIST · WHITELIST · CACHE | ⬜ chưa chạy |
| 1.m | Độ nhạy ngưỡng Cổng ML (0.85/0.65/0.40) | `run_ml_threshold_sweep.py` | datatest | đường đánh đổi auto-BLOCK ↔ tải LLM | ⬜ chưa chạy |
| 1.n | Nguồn gốc chất lượng mô hình ML | `ml_lab/train_1m.py` → `train_1m_metrics.json` | ~1M mẫu, hold-out riêng | F1 · precision · recall lúc huấn luyện | ⬜ |

**Vì sao 1.k–1.n là chỉ số RQ1 chứ không phải phụ trợ:**

- **1.k** — README gọi vòng phản hồi là *"the loop that matters"*, Chương 3 mô tả kiến trúc chi
  tiết, nhưng trước đây **không có một phép đo nào**. Đây là cơ chế xả tải **thứ tư** (sau luật
  tĩnh, Cổng ML, bộ đệm) và là đóng góp được tuyên bố mà chưa từng được chứng minh bằng số.
- **1.l** — tỉ lệ xả tải gộp (1.e) không nói **cơ chế nào** đang chạy; hỏng cũng không chỉ ra
  hỏng ở đâu. Script này kiểm từng cơ chế với đầu vào tự kiểm soát.
- **1.m** — trả lời phản biện *"ba ngưỡng đó lấy ở đâu ra?"*, đúng loại câu hỏi mà
  `run_threshold_sensitivity` đã trả lời cho ngưỡng Welford 3.5σ. Thiếu nó thì chính sách 4 dải
  là con số trời cho.
- **1.n** — MCC ở 1.a đo mô hình **nào**? Không có chỉ số huấn luyện thì con số ấy không truy
  nguyên được về một lượt train cụ thể.

### 1.3 Lệnh chạy

```bash
export SENTINEL_FREEZE_DYNAMIC_RULES=1
.venv/bin/python experiments/evaluate_ml_gate.py
.venv/bin/python experiments/run_cache_efficiency.py
.venv/bin/python experiments/evaluate_unified_stream.py
.venv/bin/python experiments/run_baseline_comparison.py
.venv/bin/python experiments/run_ml_threshold_sweep.py
.venv/bin/python experiments/run_ablation.py --mode mlgate
.venv/bin/python scripts/audit_offload_mechanisms.py
.venv/bin/python experiments/evaluate_feedback_loop.py              # cần LLM
.venv/bin/python experiments/measure_latency_baseline.py --n 1000   # cần LLM
```

### 1.4 Bẫy đo

- **Không** lấy tỉ lệ xả tải từ `datatest.json`. Tập ép cân bằng làm tỉ lệ đó thành hiện vật
  của cách lấy mẫu, không phải tính chất của hệ.
- Độ trễ **phải** lấy mẫu theo tỉ lệ luồng thật. Ép 50/50 thì Tier-1 chỉ loại được 11% và kết
  quả ra "chậm hơn LLM-only". Script tự gắn `metric_valid=false` nếu xả tải < 50%.
- `n=100` là **không đủ**: median ~0,7 ms nhưng mean ~2.800 ms ⇒ trung bình bị chi phối bởi
  ~8 ca chạm LLM. Dùng `n=1000` để có ~80 ca.
- **Không** trích `ablation_mlgate_results.json` cho tuyên bố độ trễ — chính tệp đó ghi rõ nó
  chỉ đo tỉ lệ gỡ tải, không đo thời gian.
- **Không** tuyên bố "giải phóng >75% VRAM" — không script nào đo VRAM. Dùng *số lần gọi LLM
  tránh được* (đo được, và trả lời đúng vế "tiêu thụ tài nguyên").

### 1.5 Kiểm chứng trên UI

Dashboard SIEM → thẻ **Xả tải** (tỉ lệ chặn ở Tầng 1) và thẻ **Độ trễ tầng**.

---

## 2. RQ2 — Rào chắn an ninh AI & toàn vẹn pháp y

### 2.1 Câu hỏi nguyên văn

> **TV (Ch.1 §1.2):** *"Câu hỏi nghiên cứu thứ hai (RQ2) về rào chắn an ninh AI và tính toàn vẹn
> vết pháp y: Phương pháp luận và cơ chế bảo mật nào có khả năng chống lại các rủi ro đối kháng
> (điển hình như tiêm nhiễm prompt qua nhật ký) nhằm bảo vệ luồng suy luận của AI, đồng thời đảm
> bảo tính toàn vẹn và không thể chối bỏ của các vết chứng cứ pháp y?"*
>
> **EN:** *"What methodologies and security mechanisms can effectively withstand adversarial risks
> (such as log-substrate prompt injection) to protect the AI's reasoning flow, while simultaneously
> ensuring the integrity and non-repudiation of forensic audit trails?"*

⚠️ **Câu chữ phải sửa trong luận văn:** HMAC dùng **khoá đối xứng dùng chung** ⇒ chỉ chứng minh
được **toàn vẹn / phát hiện giả mạo**, KHÔNG phải **chống chối bỏ** (cần chữ ký bất đối xứng).
Nâng lên Ed25519 để mục Hướng phát triển.

### 2.2 Bốn bảng dữ liệu đối kháng — không trộn

| bảng | nhóm | n | nguồn | vai trò |
| :-- | :-- | --: | :-- | :-- |
| **A — nguồn công bố** | `advbench_gcg` 200 · `jailbreak_hf` 200 · `prompt_injection_hf` 203 · `field_injection` 100 | **703** | AdvBench · jackhhao · deepset · `data/adversarial_llm` | **tỉ lệ chính của luận văn** |
| **B — tác giả biên soạn** | `encoding_bypass` 45 · `structural_attacks` 20 · `rag_poisoning` 15 | **80** | tự soạn (ghi rõ) | ba cơ chế không bộ công bố nào phủ |
| **C — đối chứng âm** | log lành tính, gồm ca "khó" chứa từ dễ nhầm | ~250 | `ground_truth` benign | vế âm bắt buộc |
| **D — kiểm chéo** | `jailbreak` 20 · `semantic_confusion` 20 | 40 | tự soạn, trùng vector với A | so tự soạn ↔ công bố |

**Vì sao giữ B:** `encoding_bypass` cần base64/hex/homoglyph (deepset toàn chữ thường),
`rag_poisoning` là đầu độc kho tri thức, `structural_attacks` là delimiter smuggling — không bộ
công bố nào phủ ba chiều này.
**Vì sao giữ D:** cùng vector với A ⇒ chênh lệch A↔D cho biết mẫu tự soạn dễ hay khó bất thường.
**Vì sao cần `field_injection`:** cả 603 mẫu cũ đều gán cứng `payload_field: "payload"`. Cơ chế
đóng gói nonce bọc **theo trường**, nên vị trí trường quyết định payload nằm trong hay ngoài vùng
bọc. Bộ mới rải qua 4 trường: URI 24 · User-Agent 23 · message 30 · payload 23.

### 2.3 Bảng chỉ số

| # | Chỉ số | Script + cờ | Tập (mẫu số) | Khoá JSON | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 2.a | Rào chắn **tĩnh** chặn được bao nhiêu | `evaluate_adversarial.py --mode static` | bảng A · B riêng | `summary.block_rate_pct` + `by_category` | ⬜ |
| 2.b | Tier-2 có bị thao túng không | `evaluate_adversarial.py --mode pipeline` (**bỏ `--limit`**) | mẫu lọt lớp tĩnh, A · B riêng | `resistance_rate_pct` + **`coverage_pct`** | ⬜ |
| 2.c | Rào chắn theo **vị trí trường** | `--mode pipeline`, nhóm `field_injection` | 100 mẫu, 4 trường | tỉ lệ chặn theo từng trường | ⬜ |
| 2.d | **Báo động giả trên log lành** | `evaluate_adversarial.py --mode negative` | bảng C (~250) | `false_flag_rate_pct` | ⬜ |
| 2.e | Kiểm chéo tự soạn ↔ công bố | so 2.a/2.b giữa bảng A và D | 40 vs 400 | chênh lệch tỉ lệ chặn | ⬜ |
| 2.f | HMAC phát hiện giả mạo | `run_audit_tamper.py` | `audit_trail.db` | `overall_detection_rate_core` | ⬜ |
| 2.g | Lỗ hổng cắt đuôi (nêu **riêng**) | `run_audit_tamper.py` | như trên | `xoá_dòng_cuối` | ⬜ |
| 2.h | Tất định + đổi seed của LLM | `run_llm_robustness.py` | **ground_truth** (KHÔNG phải dữ liệu đối kháng) | `determinism` · `seed_variance.flip_rate` | ⬜ |

> ⚠️ **Quy gán sai đang có trong bản cũ:** `run_llm_robustness.py` chạy trên `ground_truth.json`
> và đo tất định/đổi seed. Nó **không** đo kháng tiêm nhiễm, và kết quả nằm ở
> `llm_robustness_results.json` chứ không phải `robustness_results.json`.

### 2.4 Lệnh chạy

```bash
export SENTINEL_FREEZE_DYNAMIC_RULES=1
.venv/bin/python scripts/ingest_adversarial_datasets.py     # dựng lại bảng A (gồm field_injection)
.venv/bin/python experiments/evaluate_adversarial.py --mode static
.venv/bin/python experiments/evaluate_adversarial.py --mode pipeline    # KHÔNG --limit, cần LLM
.venv/bin/python experiments/evaluate_adversarial.py --mode negative    # đối chứng âm, cần LLM
.venv/bin/python experiments/run_audit_tamper.py
.venv/bin/python experiments/run_llm_robustness.py          # cần LLM
```

Trình diễn luồng đối kháng trên UI:

```bash
.venv/bin/python scripts/push_flow.py --source adversarial
```

### 2.5 Demo thủ công — bắt quả tang giả mạo HMAC

**Cách 1 — Giả mạo nội dung** (sửa `BLOCK_IP` thành `LOG`):

```bash
sqlite3 config/audit_trail.db "UPDATE audit_trail SET action = 'LOG' WHERE target = '198.51.100.15';"
.venv/bin/python -c "import sys; sys.path.insert(0, '.'); from src.response.executor import verify_audit_trail_integrity as v; print(v()[1])"
```

→ Terminal báo `⚠️ PHÁT HIỆN GIẢ MẠO! Dòng log ID ... đã bị sửa đổi...`; Dashboard chuyển ĐỎ.

**Cách 2 — Cắt đuôi chuỗi** (xoá dòng cuối cùng):

```bash
sqlite3 config/audit_trail.db "DELETE FROM audit_trail WHERE id = (SELECT MAX(id) FROM audit_trail);"
.venv/bin/python -c "import sys; sys.path.insert(0, '.'); from src.response.executor import verify_audit_trail_integrity as v; print(v()[1])"
```

→ Terminal báo `✅ Hệ thống nhật ký toàn vẹn`. Vì $H_i$ chỉ phụ thuộc $H_{i-1}$, cắt đuôi không
làm hỏng chuỗi còn lại. **Đây là giới hạn phải nêu trong luận văn, không phải số để làm đẹp.**

### 2.6 Bẫy đo

- **Vế dương một mình không chứng minh được gì.** "Kháng 100%" chỉ trả lời *"log tấn công có bị
  ép thành lành tính không"*. Một hệ gắn cờ **mọi thứ** là tấn công cũng đạt đúng 100% ấy. Bắt
  buộc phải có 2.d đi kèm.
- **Không trộn A với B thành một tỉ lệ.** Trộn thì (a) không so được với benchmark công bố,
  (b) vi phạm quy tắc "dữ liệu tự soạn không vào tỉ lệ luận văn".
- `--mode pipeline --limit 35` cho `coverage_pct ≈ 5,2%` và script **tự gắn `metric_valid: false`**.
- Trích 100% của pipeline mà giấu tỉ lệ của lớp tĩnh là chọn số. Hai con số **bổ sung** nhau.

---

## 3. RQ3 — Tác tử có trạng thái & quy kết kỹ thuật ATT&CK

### 3.1 Câu hỏi nguyên văn

> **TV (Ch.1 §1.2):** *"Câu hỏi nghiên cứu thứ ba (RQ3) về suy luận tác tử có trạng thái và quy kết
> kỹ thuật: Làm thế nào để tích hợp năng lực suy luận có trạng thái và khả năng tra cứu tri thức
> chuyên ngành vào Tác tử AI nhằm tự động hóa quy trình phân tích, quy kết kỹ thuật tấn công chính
> xác và sinh ra các báo cáo pháp y minh bạch, thay thế sự can thiệp thủ công của con người?"*
>
> **EN:** *"How can stateful reasoning capabilities and domain-specific knowledge retrieval be
> integrated into an AI Agent to automate intrusion analysis, accurately attribute attack techniques,
> and generate transparent forensic reports, effectively replacing manual human intervention?"*

⚠️ **Câu chữ phải sửa:** "**thay thế** sự can thiệp thủ công" → "**giảm tải / phân loại việc cần
người**". Kiến trúc **cố ý** chuyển người (`hitl_deferrals`); tuyên bố "thay thế" tự mâu thuẫn
với thiết kế — mà thiết kế mới là cái đúng.

### 3.2 Bảng chỉ số

| # | Chỉ số | Script + cờ | Tập (mẫu số) | Khoá JSON | Số đo |
| :-- | :-- | :-- | :-- | :-- | :-- |
| 3.a | Quy kết **tắt LLM** (trần từ truy xuất) | `eval_attack_mapper.py --mode rrf --evidence-layer payload` | CSIC 250 | `technique_exact_match_pct` | ⬜ |
| 3.b | Quy kết **toàn tuyến** | `eval_attack_mapper.py --mode e2e --evidence-layer payload` | CSIC 250 | `technique_exact_match_pct` · `tactic_match_pct` | ⬜ |
| 3.c | Quy kết tầng **flow** | `--evidence-layer flow` (cả rrf + e2e) | CICIDS **1.120** | như trên | ⬜ |
| 3.d | Quy kết **gộp hai tầng** | `--evidence-layer all` | 1.370 | như trên | ⬜ |
| 3.e | Chất lượng truy xuất RAG | `evaluate_rag_retrieval.py` | ground_truth đã leo thang (cả CSIC + CICIDS) | `recall@3` · `recall@10` · `mrr` | ⬜ |
| 3.f | Ablation A↔F (tắt/đủ LLM) | `run_ablation.py --mode af` | ground_truth phân tầng | `action_scores` | ⬜ |
| 3.g | Ablation B–E (đóng góp từng bậc RAG) | `run_ablation.py --mode bcde` | **250** mẫu có payload + có mã | `attribution_scores` · `attribution_underpowered` | ⬜ |
| 3.h | Ablation khử base-rate | `run_ablation.py --mode balanced` | 150/150 | `action_scores` | ⬜ |
| 3.i | Phán quyết Tier-2 | `evaluate_tier2_decision.py` | build_stream, đã qua Tier-1 **và** Cổng ML | `threat_recall` · `specificity` · `mcc` · `confidence_calibration.ece` | ⬜ |
| 3.j | Chất lượng lập luận | `evaluate_reasoning.py` | phán quyết từ `--mode af` | 4 trục thang 1–5 + `evidence_grounding` | ⬜ |
| 3.k | Đối chứng âm cho tương quan **có trạng thái** (Threat Memory có báo nhầm chuỗi trên luồng nhiễu hợp lệ không — **không** phải tuyên bố phát hiện APT) | `run_apt_negative_control.py` | DAPT2020 đa ngày | `recall` · `specificity` | ⬜ |
| 3.l | Neo bằng chứng (0% ảo giác) | one-liner §3.5 | `logs/tier2_trace.jsonl` | `bad = 0` | ⬜ |
| 3.m | **Cohen's κ người ↔ trọng tài LLM** | `export_judge_sample.py export --n 50` rồi `score` | 50 mẫu phân tầng theo điểm trọng tài | `cohens_kappa` | ⬜ chưa chạy |
| 3.n | **Ý nghĩa thống kê của ablation** | `statistical_tests.py` | `ablation_results.json` | McNemar `p-value` | ⬜ chưa chạy |
| 3.o | Recall theo `top_k` so với chi phí token | `scripts/sweep_rag_topk.py` | 69 sự kiện web-attack có payload | recall theo từng `top_k` | ⬜ chưa chạy |
| 3.p | So sánh model (phát lại prompt thật) | `scripts/compare_llm_models.py` | prompt đã ghi trong `tier2_trace.jsonl` | JSON hỏng % · đúng kỹ thuật · neo bằng chứng · p50/p95 | ⬜ chưa chạy |

**Vì sao 3.m–3.p là chỉ số RQ3 chứ không phải phụ trợ:**

- **3.m** — không có κ thì điểm 4 trục ở **3.j vô nghĩa**: điểm thấp không phân biệt được
  *(a) tác tử suy luận kém* với *(b) trọng tài chấm sai*. Một trọng tài, không mẫu nào được
  người đối chiếu — đó là điểm yếu hội đồng thấy ngay.
- **3.n** — mọi hiệu số ablation (A↔F, B–E) cần kiểm định. Không có p-value thì "A hơn B" chỉ
  là nhiễu chưa loại trừ.
- **3.o** — RQ3 hỏi thẳng về *"khả năng tra cứu tri thức chuyên ngành"*. `top_k` không miễn
  phí: mỗi tài liệu thêm ~1.000 token trong khi ngân sách mỗi slot chỉ 8.192. Phải cân recall
  tăng được bao nhiêu so với token bỏ ra.
- **3.p** — biện minh cho việc chọn Foundation-Sec-8B bằng so sánh **có kiểm soát** (cùng
  prompt, cùng seed, phát lại từ lượt chạy thật) thay vì khẳng định suông.

### 3.3 Lệnh chạy

```bash
export SENTINEL_FREEZE_DYNAMIC_RULES=1

# Offline, không cần LLM (~10 phút)
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer flow
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer all
.venv/bin/python experiments/evaluate_rag_retrieval.py
.venv/bin/python experiments/run_apt_negative_control.py
.venv/bin/python scripts/sweep_rag_topk.py

# Cần LLM (~3–4 giờ)
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer flow
.venv/bin/python experiments/run_ablation.py --mode af
.venv/bin/python experiments/run_ablation.py --mode bcde
.venv/bin/python experiments/run_ablation.py --mode balanced
.venv/bin/python experiments/evaluate_tier2_decision.py --limit 800
.venv/bin/python experiments/statistical_tests.py          # sau khi có ablation_results.json
.venv/bin/python scripts/compare_llm_models.py             # phát lại prompt đã ghi

# Trọng tài KHÁC HỌ — phải đổi bằng biến môi trường, không chỉ sửa .env
LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf LLAMA_ARG_CTX_SIZE=32768 \
  docker-compose up -d --force-recreate --no-deps llm
SENTINEL_AGENT_MODEL=Foundation-Sec-8B-Instruct-Q4_K_M.gguf \
  .venv/bin/python experiments/evaluate_reasoning.py

# Kiểm định trọng tài bằng NGƯỜI (2 bước, làm sau khi có reasoning_eval_results.json)
.venv/bin/python experiments/export_judge_sample.py export --n 50   # -> CSV, người điền điểm
.venv/bin/python experiments/export_judge_sample.py score           # -> Cohen's κ
```

**Quy ước tên tệp kết quả mapper.** Bỏ trống `--tag` thì script tự đặt `{mode}_{layer}` ⇒
`attack_mapper_eval_e2e_payload.json`, `..._rrf_flow.json`… Tên tệp tự nói lên cấu hình.
Chỉ đặt `--tag` bằng tay khi thật sự cần một lượt riêng (ví dụ so trước/sau khi nạp thêm KB).
Tag tự chế kiểu `clean_rag`, `test_fix` đã từng sinh ra **bốn tệp mâu thuẫn nhau** — xem
`experiments/results/_archive_pre_2026-08/README.md`.

Trình diễn luồng DAPT đa ngày trên UI: `.venv/bin/python scripts/push_flow.py --source dapt`

Chạy nhanh để thử nghiệm (không dùng cho luận văn):

```bash
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --per-class 20 --tag e2e_subsample
```

Cơ chế cô lập của `--mode e2e` (cold-start thực chiến): SQLite tạm `/tmp/mapper_e2e_xxxx/`
(xoá sạch blacklist + điểm uy tín cũ) và `response_cache.clear()` trước **mỗi** mẫu ⇒ 100% mẫu
phải qua GPU suy luận thật.

### 3.5 Kiểm chứng không ảo giác bằng trace log

```bash
.venv/bin/python -c "
import json,re
TECH=re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
rows=[json.loads(l) for l in open('logs/tier2_trace.jsonl') if l.strip()]
bad=0
for r in rows:
    a=r.get('attack_mapper') or {}; fin=a.get('final_technique_id') or ''
    if not fin: continue
    ids=set(TECH.findall(json.dumps(r.get('rag') or {},ensure_ascii=False)))
    if ids and fin not in ids: bad+=1
print(f'{len(rows)} lô | quy kết KHÔNG neo trong RAG: {bad}')"
```

*Kỳ vọng:* `bad = 0` (bất biến cốt lõi). Lưu ý regex trên **không** bắt mã ATLAS dạng `AML.T0051`.

### 3.6 Bẫy đo

- **`rrf` chạy `llm=None`** — đó là cấu hình **tắt LLM**. Trích riêng nó cho RQ3 "Tác tử" là gán
  công bộ truy xuất cho tác tử. Trình bày **thành cặp**: `rrf` = trần từ truy xuất, `e2e` = thứ
  hệ thật làm, **hiệu số chính là đóng góp của LLM** (dương hay âm).
- **Không bỏ tầng flow.** Chỉ chạy `--evidence-layer payload` là bỏ **82% dữ liệu có nhãn**.
  Lý do "NetFlow không suy ra được kỹ thuật bằng bất kỳ phương pháp nào" là **quá mạnh** —
  T1499.002 (400 mẫu) và T1110.001 (160 mẫu) suy ra được từ đặc trưng flow, chính Tier-1 đang
  làm bằng luật. Báo **riêng từng tầng** mạnh hơn một số gộp.
- **Bỏ `accuracy` của `tier2_decision`.** Trên tập 92% lành tính, `accuracy` bằng đúng majority
  baseline và `MCC = 0` ⇒ vô nghĩa. Báo recall/specificity + MCC.
  `specificity = 0` là **phát hiện thật**: Tier-2 đơn độc là lưới an toàn tối đa hoá recall,
  tính chọn lọc do Cổng ML đảm nhiệm. Nói đúng như vậy thì nó thành luận điểm kiến trúc.
- `--mode bcde` phải chạy **đủ 300 mẫu**: C/D/E chỉ gọi LLM khi Tier-1 leo thang (~17%), cỡ nhỏ
  thì mỗi cấu hình chỉ vài ca. Script tự gắn `attribution_underpowered=true` nếu < 30 ca.
- `evaluate_reasoning` **chặn cứng** nếu trọng tài trùng bị cáo. Đọc kèm
  `run_health.n_deliberate_abstention`: ca hệ chủ ý trả `N/A` là rào chắn hoạt động đúng,
  **không** phải thiếu schema.

---

## 4. Chỉ số thêm — KHÔNG thuộc RQ nào

Nhóm này **không** dùng để trả lời RQ1/RQ2/RQ3. Đặt riêng để tránh xếp lẫn với chỉ số
benchmark khi bảo vệ.

| lệnh | đo gì | lưu ý |
| :-- | :-- | :-- |
| `run_context_stress.py` | Nén log theo template | Báo **cả hai** pool: đồng nhất (1000×) và đa dạng (**125×** — số thật) |
| `run_zeroday_graded.py` | Bắt bất thường theo cấp độ σ | zero-day/APT là **proof-of-concept → Hướng phát triển**, không phải đóng góp tiêu đề — cả ba RQ đều không nhắc tới. Đừng kéo lên thành chỉ số RQ |
| `run_threshold_sensitivity.py` | Độ nhạy ngưỡng Welford 3.5σ | bác bỏ nghi ngờ "3.5σ là cherry-pick" |
| `audit_tier_capability.py` | **Phép thử CHỨC NĂNG**, 15 ca viết tay | `is_benchmark_metric: false` — KHÔNG xếp cạnh chỉ số benchmark |
| `e2e_test_runner.py` | Kiểm thử trơn tru toàn tuyến, 22 bài | kiểm thử, không phải đo. Chỉ **đọc** `latency_benchmark.json`, không ghi |
| `verify_kb_against_mitre.py` | Đối chiếu tên kỹ thuật với MITRE gốc | chống lỗi "đúng ID sai tên"; chạy sau mỗi lần dựng lại KB |
| `plot_results.py` | Vẽ biểu đồ từ tệp kết quả | |
| `compare_pushes.py` · `diff_pipeline_stats.py` | So hai lượt chạy | công cụ gỡ lỗi |
| `audit_live_run.py` · `audit_ui_functions.py` | Rà soát nội bộ | không sinh chỉ số luận văn |

> **Hai mục đã chuyển LÊN RQ1** (trước đây nằm ở mục này): `evaluate_feedback_loop` → **1.k**
> và `run_ml_threshold_sweep` → **1.m**. Cả hai là bằng chứng RQ cốt lõi, không phải phụ trợ.

---

## 4b. Phụ lục — tệp kết quả ↔ script ghi ra nó

Tra ngược khi cầm một tệp JSON mà không nhớ ai sinh ra nó. **Hai cặp tên rất dễ nhầm** đứng
đầu bảng.

| tệp kết quả | script ghi ra nó | trạng thái |
| :-- | :-- | :-- |
| ⚠️ `robustness_results.json` | **`evaluate_adversarial.py`** — KHÔNG phải `run_llm_robustness` | có |
| ⚠️ `llm_robustness_results.json` | **`run_llm_robustness.py`** | có |
| `ml_gate_results.json` | `evaluate_ml_gate.py` | có |
| `cache_efficiency_results.json` | `run_cache_efficiency.py` | có |
| `latency_benchmark.json` | `measure_latency_baseline.py` (`e2e_test_runner` chỉ đọc) | có |
| `unified_stream_results.json` | `evaluate_unified_stream.py` | có |
| `ablation_{results,bcde,balanced,mlgate}_results.json` | `run_ablation.py --mode {af,bcde,balanced,mlgate}` | có |
| `adversarial_pipeline_results.json` | `evaluate_adversarial.py --mode pipeline` | có |
| `tier2_decision_results.json` | `evaluate_tier2_decision.py` | có |
| `reasoning_eval_results.json` | `evaluate_reasoning.py` | có |
| `apt_negative_control_results.json` | `run_apt_negative_control.py` | có |
| `context_stress_results.json` | `run_context_stress.py` | có |
| `zeroday_graded_results.json` | `run_zeroday_graded.py` | có |
| `threshold_sensitivity_results.json` | `run_threshold_sensitivity.py` | có |
| `tier_capability_audit.json` | `audit_tier_capability.py` | có |
| `attack_mapper_eval_{mode}_{layer}.json` | `scripts/eval_attack_mapper.py` | ⬜ **chạy lại theo tag mới** |
| `audit_tamper_results.json` | `run_audit_tamper.py` | ⬜ **chưa chạy lần nào** |
| `baseline_comparison_results.json` | `run_baseline_comparison.py` | ⬜ **chưa chạy lần nào** |
| `rag_retrieval_results.json` | `evaluate_rag_retrieval.py` | ⬜ **chưa chạy lần nào** |
| `ml_threshold_sweep_results.json` | `run_ml_threshold_sweep.py` | ⬜ **chưa chạy lần nào** |
| `feedback_loop_results.json` | `evaluate_feedback_loop.py` | ⬜ **chưa chạy lần nào** |
| `judge_agreement_results.json` | `export_judge_sample.py score` | ⬜ **chưa chạy lần nào** |
| `ml_lab/train_1m_metrics.json` | `ml_lab/train_1m.py` | có |

Sáu dòng ⬜ **chưa chạy lần nào** đều là chỉ số vừa bổ sung ở đợt này — script có sẵn và chạy
được, chỉ là chưa ai bấm.

`experiments/results/_archive_pre_2026-08/` chứa 4 tệp mapper lỗi thời, **mâu thuẫn nhau**
(68,4% với 2,33% cho cùng chế độ e2e) và chạy trước `drop_authored()`. Không trích.

---

## 5. Chạy hết, đúng thứ tự

```bash
export SENTINEL_FREEZE_DYNAMIC_RULES=1

# A. Offline, không cần LLM (~20 phút)
for s in evaluate_ml_gate run_cache_efficiency run_audit_tamper run_context_stress \
         run_zeroday_graded run_threshold_sensitivity run_ml_threshold_sweep \
         run_apt_negative_control evaluate_unified_stream run_baseline_comparison \
         evaluate_rag_retrieval; do
  .venv/bin/python experiments/$s.py
done
.venv/bin/python scripts/audit_offload_mechanisms.py
.venv/bin/python scripts/sweep_rag_topk.py
.venv/bin/python experiments/run_ablation.py --mode mlgate
.venv/bin/python experiments/evaluate_adversarial.py --mode static
for L in payload flow all; do
  .venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer $L
done

# B. Cần LLM — chạy RQ2 trước vì tốn nhất (~2 giờ)
.venv/bin/python experiments/evaluate_adversarial.py --mode pipeline
.venv/bin/python experiments/evaluate_adversarial.py --mode negative
.venv/bin/python experiments/run_llm_robustness.py
.venv/bin/python experiments/measure_latency_baseline.py --n 1000
.venv/bin/python experiments/evaluate_feedback_loop.py

# C. Cần LLM — RQ3 (~2 giờ)
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer flow
.venv/bin/python experiments/run_ablation.py --mode af
.venv/bin/python experiments/run_ablation.py --mode bcde
.venv/bin/python experiments/run_ablation.py --mode balanced
.venv/bin/python experiments/evaluate_tier2_decision.py --limit 800
.venv/bin/python experiments/statistical_tests.py     # cần ablation_results.json ở trên
.venv/bin/python scripts/compare_llm_models.py        # cần tier2_trace.jsonl của lượt chạy thật

# D. Trọng tài khác họ (đổi model trước — xem §3.3)
.venv/bin/python experiments/evaluate_reasoning.py

# E. Kiểm định trọng tài bằng NGƯỜI — có bước người điền CSV, không tự động được
.venv/bin/python experiments/export_judge_sample.py export --n 50
#   … người chấm 50 mẫu trong CSV rồi mới chạy tiếp:
.venv/bin/python experiments/export_judge_sample.py score

# F. Gom báo cáo
.venv/bin/python scripts/export_final_report.py   # -> reports/KET_QUA_CHOT_<ngày>.md
```

**Ba ràng buộc thứ tự** (chạy sai chiều thì script đọc phải tệp cũ hoặc tệp rỗng):

1. `statistical_tests.py` **sau** `run_ablation.py --mode af` — nó đọc `ablation_results.json`.
2. `export_judge_sample.py` **sau** `evaluate_reasoning.py` — nó lấy mẫu từ điểm trọng tài.
3. `compare_llm_models.py` cần `reports/runs/<nhãn>/tier2_trace.jsonl` của một lượt chạy thật.

---

## 6. Bảng đối chiếu nhanh

| RQ | Vế phải chứng minh | Script trụ cột | Tập chuẩn | Vị trí kiểm chứng |
| :-- | :-- | :-- | :-- | :-- |
| **RQ1** (14 chỉ số) | xả tải ở tốc độ đường truyền · cắt độ trễ · giảm tiêu thụ tài nguyên | `evaluate_ml_gate` · `measure_latency_baseline` · `run_cache_efficiency` · `evaluate_feedback_loop` | datatest (phân loại) + build_stream (tỉ lệ) | Dashboard → thẻ Xả tải |
| **RQ2** (8 chỉ số) | kháng tiêm nhiễm (**dương + âm**) · toàn vẹn vết pháp y | `evaluate_adversarial` (static/pipeline/negative) · `run_audit_tamper` | bảng A 703 · B 80 · C 250 · D 40 | Terminal HMAC · Dashboard alert |
| **RQ3** (16 chỉ số) | quy kết ATT&CK · truy xuất tri thức · báo cáo minh bạch · giảm tải người | `eval_attack_mapper` (rrf↔e2e) · `evaluate_rag_retrieval` · `run_ablation` · `evaluate_reasoning` + `export_judge_sample` | CSIC 250 + CICIDS 1.120 | `logs/tier2_trace.jsonl` · Dashboard |

### Ba lỗi câu chữ phải sửa song song trong luận văn

1. "không thể chối bỏ" → "**toàn vẹn, phát hiện giả mạo**" (khoá đối xứng).
2. "thay thế sự can thiệp thủ công" → "**giảm tải / phân loại việc cần người**".
3. "giải phóng >75% VRAM" → "**số lần gọi LLM tránh được**" (VRAM không đo được).
