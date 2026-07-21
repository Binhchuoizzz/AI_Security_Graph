# Từ điển Chỉ số Đánh giá SENTINEL

Mỗi chỉ số: **giá trị thật** → **file/dòng code tính ra nó** → **công thức** → **bản chất & cách đọc**.

> ⚠️ **TRẠNG THÁI SỐ:** mọi giá trị dưới đây đo **trước** đợt sửa 2026-07-21 (bằng chứng tới LLM ·
> chữ ký WAF 4→29 họ · đối chiếu tên MITRE · luật tái phạm · **thước đo theo hành động** ·
> **golden baseline 300→10k + log1p**). **Phải đo lại trước khi trích vào luận văn.**
>
> Số **KHÔNG** lấy từ demo. Demo là luồng live không tất định; benchmark chạy đường **offline tất
> định** (`evaluate_*.py`, `run_ablation.py`) trên tập cố định.

---

## ⛔ ĐỌC TRƯỚC TIÊN — thước đo nhị phân cũ đã BÃO HOÀ

Trước 2026-07-21, ablation chấm bằng câu hỏi nhị phân *"có gắn cờ hay không"*, gộp
`ESCALATE` (Tầng 1 chuyển tiếp) và `AWAIT_HITL` (hoãn cho người) vào **cùng ô** với
`BLOCK_IP`. Hệ quả đo được:

```text
TẬP THIÊN TẤN CÔNG (ground_truth phân tầng)
  Config A ≡ Config F                      GIỐNG HỆT TỪNG BIT
  Config B ≡ C ≡ D ≡ E   (F1 = 0,9655)     GIỐNG HỆT TỪNG BIT

TẬP CÂN BẰNG (150/150)
  Config B               F1 0,8043 · P 0,6726 · R 1,000   ← TÁCH RIÊNG được
  Config A ≡ C ≡ D ≡ E ≡ F   F1 0,5586 · P 0,8611 · R 0,4133
```

Trên tập thiên tấn công, `P = 0,9333 = 140/150` chính là tỷ lệ tấn công của tập ⇒ **mọi cấu
hình đều gắn cờ tất cả**; F1 = 0,9655 là điểm của một hàm `return True`, không phải năng lực.
Đó cũng là lý do McNemar cho `p = 1,0`.

**Trên tập cân bằng, B CÓ tách ra** (không có cổng Tier-1 nên gắn cờ mọi thứ: R = 1,0 nhưng
P chỉ 0,67). Nhưng phần còn lại tệ hơn:

| So sánh | Thêm gì | Kết quả |
|---|---|---|
| C → D | dense RAG | **không đổi** |
| D → E | hybrid RAG + RRF | **không đổi** |
| E → F | rào chắn + agent đầy đủ | **không đổi** |
| **A → C** | **cả tầng LLM** | **không đổi** |

`A ≡ C` nghĩa là tầng LLM **không đổi một phán quyết nào** so với luật thô. Nguyên nhân cấu
trúc: khi cổng Welford không escalate, C/D/E/F đều rơi về đúng `tier1_verdict` — **giống nhau
theo thiết kế**. Khác biệt chỉ có thể xuất hiện trên **tập con escalate**, mà thước đo nhị
phân lại để phán quyết Tier-1 nuốt mất tín hiệu đó.

⇒ **RQ3 (đóng góp Dual-RAG) và vế "đóng gói" của RQ2 KHÔNG có bằng chứng nào từ ablation.**
Bằng chứng thật của chúng nằm ở phép đo khác: quy kết MITRE (§4) và bộ đối kháng (§5).

**Thước đo mới:** `experiments/action_scoring.py` — chấm bằng **khớp hành động cuối cùng**
với `expected_action`. Xem §11.

**Áp thước đo mới lên chính dữ liệu cũ (Config F):**

| Thước đo | Giá trị |
|---|---:|
| F1 nhị phân (cũ) | 0,9655 |
| **Khớp hành động (mới)** | **0,2472** |
| Tự quyết (không hoãn) | 0,2736 |
| **Đúng khi tự quyết** | **0,7018** |

Bảng chéo cho biết hệ sai **kiểu gì** — thứ thước đo cũ giấu mất:

```text
Kỳ vọng ALERT     (770) → 609 hoãn HITL · 81 chặn quá tay · CHỈ 80 đúng
Kỳ vọng BLOCK_IP  (320) → 160 đúng · 160 hoãn (lẽ ra phải chặn)
Kỳ vọng LOG        (80) → 70 hoãn · 10 CHẶN NHẦM · 0 ĐÚNG
```

Hàng cuối là bằng chứng độc lập xác nhận `specificity = 0.0`: **không một mẫu lành tính nào
được cho qua đúng**.

---

## 0. Bốn ô gốc — mọi thứ khác sinh ra từ đây

Mọi chỉ số phát hiện đều quy về ma trận nhầm lẫn. Hiểu 4 ô này là hiểu tất cả.

| Ô | Tên | Nghĩa trong SENTINEL |
|---|---|---|
| **TP** | True Positive | Tấn công thật, hệ **có** gắn cờ → đúng |
| **FP** | False Positive | Lành tính, hệ **lại** gắn cờ → **báo động giả**, làm phiền analyst |
| **TN** | True Negative | Lành tính, hệ cho qua → đúng |
| **FN** | False Negative | Tấn công thật, hệ **bỏ lọt** → **nguy hiểm nhất** |

```text
Precision = TP/(TP+FP)     "hệ báo thì có đáng tin không"   → trị FP
Recall    = TP/(TP+FN)     "tấn công thật bắt được bao nhiêu" → trị FN
F1        = 2·P·R/(P+R)    trung bình ĐIỀU HOÀ — phạt nặng khi lệch
Accuracy  = (TP+TN)/tổng   ⚠️ VÔ DỤNG khi dữ liệu mất cân bằng
```

**Vì sao F1 dùng trung bình điều hoà, không phải cộng chia đôi:** một hệ hô "tất cả đều tấn công"
có Recall = 1,0, Precision ≈ tỷ lệ tấn công. Cộng chia đôi cho điểm cao giả tạo; điều hoà kéo tụt
về gần số nhỏ hơn. Cài đặt: [`evaluate_ml_gate.py:58-64`](../../../experiments/evaluate_ml_gate.py#L58-L64).

---

## 1. Phát hiện tấn công

| Chỉ số | Giá trị | Code tính | Công thức / Bản chất |
|---|---:|---|---|
| Precision (Cổng ML) | **0,9088** | [`evaluate_ml_gate.py:59`](../../../experiments/evaluate_ml_gate.py#L59) | `tp/(tp+fp)` — 100 lần báo thì 91 lần đúng |
| Recall (Cổng ML) | **0,7551** | [`evaluate_ml_gate.py:60`](../../../experiments/evaluate_ml_gate.py#L60) | `tp/(tp+fn)` — 100 tấn công bắt được 76, **lọt 24** |
| F1 (Cổng ML) | **0,8248** | [`evaluate_ml_gate.py:61`](../../../experiments/evaluate_ml_gate.py#L61) | Số đại diện chất lượng phát hiện |
| Ma trận | tp 1036 · fp 104<br>tn 1058 · fn 336 | [`evaluate_ml_gate.py:67`](../../../experiments/evaluate_ml_gate.py#L67) | Bốn ô gốc trên `datatest.json` (3.204 sự kiện) |
| **Majority baseline** | **0,5247** | [`evaluate_tier2_decision.py:191`](../../../experiments/evaluate_tier2_decision.py#L191) | `n_threat/n_scored` — điểm của một stub hô "tấn công" cho **mọi** đầu vào |
| F1 luồng gộp (Tier-1) | **0,5311** | [`evaluate_unified_stream.py:161`](../../../experiments/evaluate_unified_stream.py#L161) | Tier-1 **một mình**, recall chỉ 0,3726 |

### ⚠️ Luôn đọc F1 kèm Majority baseline
`majority_baseline = 0,5247` nghĩa là **đoán bừa "tất cả đều tấn công" đã được 52%**. Một F1 nào đó
mà không vượt rõ mốc này thì **mô hình không học được gì**. Đây là lý do code cố ý in mốc này cạnh
accuracy — xem chú thích tại [`evaluate_tier2_decision.py:189-191`](../../../experiments/evaluate_tier2_decision.py#L189-L191).

### Thang F1 ba bậc (cách trình bày ĐÚNG cho luận văn)

| Cấu hình | F1 | Ý nghĩa |
|---|---:|---|
| Chỉ luật Tier-1 | 0,531 | Sàn — luật cứng đơn thuần |
| + Cổng ML | 0,825 | Tầng học máy đóng góp |
| 2 tầng phát hiện + HITL | 0,967 | Trên tập **vận hành** (94% tấn công) |

**KHÔNG bao giờ nêu mỗi 0,531.** Và **0,967 không phải đỉnh thang** — nó chịu ảnh hưởng base-rate;
khi cân bằng lại dữ liệu (`--mode balanced`) con số này tụt về **0,559**, gần bằng luật thô. Trung
thực là phải nói cả hai.

---

## 2. Hiệu năng & Giảm tải

| Chỉ số | Giá trị | Code tính | Công thức / Bản chất |
|---|---:|---|---|
| Tỷ lệ giảm tải Cổng ML | **83,81%** | [`run_ablation.py:629-660`](../../../experiments/run_ablation.py#L629-L660) | `n_ml_bypass / n_escalated` = 761/908 — phần lẽ ra gọi LLM mà ML tự quyết |
| F1 trên phần ML tự quyết | **0,9739** | Config G | Chất lượng của riêng phần ML "cắt" đi. Cao ⇒ **cắt an toàn** |
| Precision trên phần bypass | **0,9882** | Config G | Trong 761 ca ML tự quyết, sai chưa tới 1,2% |
| Độ trễ 2 tầng | **4.577 ms** | [`measure_latency_baseline.py:195`](../../../experiments/measure_latency_baseline.py#L195) | Trung bình/sự kiện, đo thật |
| Độ trễ chỉ-LLM | **26.882 ms** | cùng file | Mốc đối chứng |
| Giảm độ trễ | **82,97%** | [`measure_latency_baseline.py:197`](../../../experiments/measure_latency_baseline.py#L197) | `(baseline−two_tier)/baseline×100` |
| Độ trễ Tier-1 (luật) | 0,025 ms | `ablation_results.json` | Đường nhanh, gần như miễn phí |

> **Cảnh báo:** `projected_latency_saved_pct = 83,81` trong Config G **không phải phép đo mới** —
> nó nhân số ca bypass với hằng số tham chiếu `LLM_MS = 5000` / `ML_MS = 0.3`
> ([`run_ablation.py:651-652`](../../../experiments/run_ablation.py#L651-L652)). Là **phép chiếu**,
> đừng trình bày như đo trực tiếp.

---

## 3. Chất lượng suy luận LLM (LLM-as-Judge, thang 1–5)

Một LLM **khác họ** (Llama-3) chấm đầu ra của Gemma-2 → tránh thiên vị tự chấm.
Cài đặt: [`evaluate_reasoning.py:84-132`](../../../experiments/evaluate_reasoning.py#L84-L132),
tổng hợp `np.mean` tại [`:256-270`](../../../experiments/evaluate_reasoning.py#L256-L270).

| Chỉ số | Giá trị | Bản chất — câu hỏi nó trả lời |
|---|---:|---|
| **Context Precision** | **2,25** ± 0,57 | *Tài liệu RAG lấy về có đúng trọng tâm không?* → **YẾU NHẤT**: lấy về nhiều thứ lạc đề |
| Answer Relevancy | 3,56 ± 1,25 | *Câu trả lời có bám vấn đề không?* — độ lệch chuẩn lớn = chất lượng thất thường |
| Faithfulness | 3,30 ± 0,55 | *Có bịa ra thứ không nằm trong bằng chứng không?* — thấp = hay tự chém |
| Context Recall | — | *Có lấy đủ tài liệu cần không?* |
| **LLM-Judge tổng** | **3,1/5** | Rerun 2026-07-20, n=908 (mốc cũ **3,9** là n=188, tập dễ hơn — **đừng lẫn**) |

---

## 4. Ánh xạ MITRE ATT&CK

| Chỉ số | Web attack | Toàn tập | Bản chất |
|---|---:|---:|---|
| Technique exact match | **64,0%** | **0,0%** | Gán đúng **chính xác** mã kỹ thuật |
| Tactic match | 57,5% | 15,79% | Gán đúng **nhóm chiến thuật** (tiêu chí lỏng hơn) |
| Trần phủ của KB | 80,0% | **77,3%** | KB 299 kỹ thuật chỉ chứa 77% cái cần → **không thể vượt trần này** |
| Tỷ lệ ánh xạ ra kết quả | 100% | 100% | Luôn trả lời, không bỏ trống |

**Cách đọc trung thực:** `exact match 0,0%` trên tập tổng quát **không có nghĩa hệ hỏng hoàn toàn** —
trần KB là 77,3%, và phần lớn tập tổng quát là luồng mạng thuần (không payload) nên không có gì để
ánh xạ. Nhưng **64% trên web attack là con số nên trích**, kèm nêu rõ giới hạn.

**Đã sửa 2026-07-21:** thêm `verify_technique_label()`
([`attack_mapper.py`](../../../src/agent/attack_mapper.py)) chống lỗi "đúng ID, sai tên"
(ca thật: `T1087` bị gán nhãn *Network Service Discovery*, thực ra là *Account Discovery*).
Chỉ số này **sẽ đổi** khi đo lại.

---

## 5. Bền vững trước tấn công đối kháng

**Hai chế độ đo — TUYỆT ĐỐI KHÔNG lẫn:**

| Chế độ | Kết quả | Đo cái gì |
|---|---:|---|
| `--mode static` | **50,0%** (60/120) | Chỉ **guardrails tĩnh** (regex/pattern) chặn được bao nhiêu |
| `--mode pipeline` | **100%** (12/12) | **Toàn bộ** 2 tầng + LLM đối phó payload đã lọt lớp tĩnh |

Con số **50% KHÔNG phải "một nửa tấn công xuyên thủng hệ thống"** — đó là năng lực của riêng lớp
regex. Bóc theo nhóm ([`robustness_results.json`](../../../experiments/results/robustness_results.json)):

| Nhóm | Chặn | Đọc thế nào |
|---|---:|---|
| encoding_bypass | **100%** (45/45) | Regex rất mạnh với né tránh bằng mã hoá |
| rag_poisoning | 40% (6/15) | |
| structural_attacks | 35% (7/20) | |
| jailbreak | 10% (2/20) | |
| semantic_confusion | **0%** (0/20) | Regex **về bản chất không thể** bắt lừa dối ngữ nghĩa |

**Đây chính là luận điểm kiến trúc:** lớp tĩnh giỏi cú pháp, dốt ngữ nghĩa → nên mới cần tầng LLM.
Hai con số 50% và 100% **cùng nhau** kể câu chuyện đó; tách riêng con nào cũng sai lệch.

| Chỉ số khác | Giá trị | Code | Bản chất |
|---|---:|---|---|
| Kháng né-tránh Cổng ML | **99,58%** | [`evaluate_ml_gate.py:195-201`](../../../experiments/evaluate_ml_gate.py#L195-L201) | Nhét `Inf`/cực đoan hòng lật ML. `resisted/attempts` |
| — chế độ `extreme_broad` | 98,75% | cùng file | Nhóm khó nhất: 13/1036 bị lật sang "lành tính" |
| Tính tất định | 2 output / 5 lần | `llm_robustness_results.json` | Chữ khác nhau nhưng **hành động luôn giống** (1 action) — điều thực sự quan trọng |

---

## 6. APT & Zero-day

| Chỉ số | Giá trị | Code | Bản chất |
|---|---:|---|---|
| APT recall | **1,00** (3/3) | [`run_apt_negative_control.py:94`](../../../experiments/run_apt_negative_control.py#L94) | `detected/positives` — bắt đủ chuỗi APT đa ngày |
| **APT specificity** | **1,00** (0/4) | cùng file `:98-101` | **Đối chứng ÂM** — 4 IP lành tính hoạt động ≥2 ngày, **không báo nhầm ca nào** |
| Wilson CI | có | `:95` | Khoảng tin cậy cho n nhỏ — 3/3 không đồng nghĩa "hoàn hảo" |
| Ngưỡng Z-score | 3,5σ | [`rule_engine.py`](../../../src/tier1_filter/rule_engine.py) | Điểm vận hành phát hiện dị biệt |
| Warm-up Welford | 100 mẫu | `rule_engine.py:532` | Chưa đủ mẫu thì **không** báo — chống cold-start |
| Golden baseline | **n=300** | `config/golden_baseline.json` | Hồ sơ benign đã kiểm định, seed cho Welford |

**`specificity = 1,00` mới là con số đắt giá.** Recall 3/3 một mình vô nghĩa — một hệ hô "APT" cho
mọi IP đa ngày cũng đạt 3/3. Đối chứng âm chứng minh hệ **phân biệt được**, không phải hô bừa.

---

## 7. Vận hành

| Chỉ số | Giá trị | Bản chất |
|---|---:|---|
| Agent reliability | **1,00** | 800/800 lượt gọi LangGraph không crash / không parse-fail |
| Tỷ lệ chuyển người (HITL) | cao | Phần hệ **không tự quyết**, đẩy analyst. Cao = an toàn nhưng ít tự động |
| Audit năng lực 3 tầng | **15/15** | [`audit_tier_capability.py`](../../../experiments/audit_tier_capability.py) — ma trận 15 họ tấn công chạy đúng đường thật |
| Chuỗi audit HMAC | Toàn vẹn | HMAC-SHA256 móc xích — sửa 1 dòng là gãy chuỗi |

---

## 8. 🔴 Ba chỉ số đang XẤU — phải nắm trước khi bảo vệ

### 8.1 `benign_specificity = 0.0` (nghiêm trọng nhất)

`tier2_decision_results.json`, n=800 — [`evaluate_tier2_decision.py:188`](../../../experiments/evaluate_tier2_decision.py#L188)

```text
threat_recall      = 1.0     bắt đúng 38/38 tấn công
benign_specificity = 0.0     nhưng 762/762 log LÀNH TÍNH cũng bị gắn cờ
accuracy           = 0.0475  ═══ BẰNG ĐÚNG majority_baseline 0.0475
```

**Accuracy bằng chằn chặn baseline ⇒ tầng LLM ở phép đo này KHÔNG có năng lực phân biệt** — nó nói
"có" với mọi thứ. Khớp chính xác với đo trên demo: **98,2% phán quyết LLM là `AWAIT_HITL`**.

**Ngữ cảnh bào chữa (thật, nhưng phải nêu kèm):** phép đo này **cố ý bỏ qua Cổng ML** và đẩy thẳng
95% log benign vào LLM — không phải đường vận hành thật. Ở đường thật, Cổng ML đã lọc trước. Dù vậy
con số vẫn cho thấy **LLM một mình không phải bộ phân loại**, nó là **lưới an toàn max-recall**.

### 8.2 Robustness tĩnh 50%
Xem §5 — đọc kèm pipeline 100%, và kèm bảng theo nhóm. Không được trích riêng.

### 8.3 Context Precision 2,25/5
Mắt xích yếu nhất của RAG. Đợt sửa 2026-07-21 đã đổi hẳn truy vấn RAG (cụm chuẩn tiếng Anh đặt
đầu, payload cắt xuống cuối) → **con số này gần như chắc chắn đã đổi**, phải đo lại trước khi kết luận.

---

## 9. Chỉ số nào đo bằng lệnh nào

| Script | Sinh ra file | Cần LLM? |
|---|---|:-:|
| `evaluate_ml_gate.py` | `ml_gate_results.json` | ✗ |
| `evaluate_unified_stream.py` | `unified_stream_results.json` | ✗ |
| `run_ablation.py --mode af` | `ablation_results.json` | ✓ |
| `run_ablation.py --mode mlgate` | `ablation_mlgate_results.json` | ✗ |
| `run_ablation.py --mode balanced` | `ablation_balanced_results.json` | ✓ |
| `evaluate_reasoning.py` | `reasoning_eval_results.json` | ✓ |
| `evaluate_tier2_decision.py` | `tier2_decision_results.json` | ✓ |
| `evaluate_adversarial.py --mode static` | `robustness_results.json` | ✗ |
| `evaluate_adversarial.py --mode pipeline` | `adversarial_pipeline_results.json` | ✓ |
| `measure_latency_baseline.py` | `latency_benchmark.json` | ✓ |
| `run_apt_negative_control.py` | `apt_negative_control_results.json` | ✗ |
| `scripts/eval_attack_mapper.py` ⚠️ | `attack_mapper_eval_*.json` | tuỳ mode |
| `audit_tier_capability.py` | `tier_capability_audit.json` | ✓ |

Chạy trọn bộ: `bash scripts/run_full_ablation.sh` (~6–8 giờ).

---

## 10. Ba lỗi đọc số dễ mắc nhất

1. **Trích Accuracy mà bỏ Majority baseline.** `accuracy = 0.0475` nghe như thảm hoạ, nhưng baseline
   cũng đúng 0,0475 — vấn đề thật là *bằng nhau*, không phải *thấp*.
2. **Trích 0,967 làm đỉnh thang F1.** Nó là số base-rate trên tập 94% tấn công; cân bằng lại còn
   0,559. Nêu cả hai.
3. **Trích riêng 50% robustness.** Đó là guardrails tĩnh; pipeline đầy đủ đạt 100%. Tách ra là bóp
   méo theo cả hai chiều.

---

---

## 11. Thước đo THEO HÀNH ĐỘNG (mới, 2026-07-21) — thước đo CHÍNH

Cài đặt: [`experiments/action_scoring.py`](../../../experiments/action_scoring.py) ·
Test: [`tests/unit/test_action_scoring.py`](../../../tests/unit/test_action_scoring.py) (11 ca)

**Nguyên tắc.** `expected_action` trong `ground_truth.json` có đủ **4 nhãn**:
`ALERT` 770 · `BLOCK_IP` 320 · `AWAIT_HITL` 80 · `LOG` 80. Điểm mấu chốt: **`AWAIT_HITL` là
ĐÁP ÁN ĐÚNG cho 80 mẫu** — hoãn cho người đôi khi chính là hành động đúng. Nên phải chấm
bằng **khớp hành động**, không phải "có gắn cờ hay không".

| Chỉ số | Công thức | Trả lời câu hỏi gì |
|---|---|---|
| **action_accuracy** | khớp chính xác / tổng | *Hệ có làm ĐÚNG việc cần làm không?* — **thước đo chính** |
| **autonomy_rate** | ra hành động cuối / tổng | *Hệ tự quyết được bao nhiêu phần?* (cao = tự động hoá nhiều) |
| **autonomous_precision** | tự quyết ĐÚNG / tự quyết | *Khi hệ dám tự hành động, nó có đáng tin?* — **câu hỏi vận hành thật** |
| **defer_rate** | AWAIT_HITL / tổng | Phần đẩy cho analyst |
| **unresolved_rate** | ESCALATE hoặc ERROR / tổng | Pipeline **chưa quyết xong** — chỉ Config A (thiếu tầng sau) mới có |
| **confusion** | bảng chéo kỳ vọng × thực tế | Hệ sai **KIỂU GÌ**, không chỉ sai bao nhiêu |

**Ba tính chất khiến nó phân biệt được (bị test khoá):**

1. `ESCALATE` **không bao giờ** tính là phát hiện — nó nghĩa là *chưa quyết xong*.
2. Hoãn trong khi lẽ ra phải chặn → **sai**; hoãn khi kỳ vọng là hoãn → **đúng**.
3. `autonomous_precision` bỏ qua ca hoãn, nên một hệ "hoãn tất cả" **không** ăn điểm.

**Cặp chỉ số nên trích cùng nhau:** `autonomy_rate` (tự động hoá bao nhiêu) + `autonomous_precision`
(tự động hoá có đáng tin không). Một mình `autonomy_rate` cao có thể là liều lĩnh; một mình
`autonomous_precision` cao có thể là do hệ hầu như không dám quyết gì.

---

## 12. Ánh xạ chữ ký → chuẩn công nghiệp (mới, 2026-07-21)

Trả lời phản biện *"luật do các anh tự nghĩ ra"*. Chi tiết:
[06_ANH_XA_CHU_KY_OWASP_CRS.md](06_ANH_XA_CHU_KY_OWASP_CRS.md) ·
code [`src/tier1_filter/crs_mapping.py`](../../../src/tier1_filter/crs_mapping.py)

| Chỉ số | Giá trị | Bản chất |
|---|---:|---|
| Tổng họ chữ ký | **29** | Đếm từ `_WAF_PATTERNS` |
| Khớp OWASP CRS 3.3 | **22** | Trên **11** file luật `REQUEST-9xx-*` |
| Hạng mục OWASP Top 10 phủ | **10** | |
| Ngoài phạm vi CRS | **7** | Hành vi endpoint/mạng → khung Sigma + ATT&CK |

Test `tests/unit/test_crs_mapping.py` bắt buộc mọi họ chữ ký phải có ánh xạ ⇒ thêm chữ ký
mà quên map thì **CI đỏ**, bảng không trôi được.

---

## 13. Golden baseline (cập nhật 2026-07-21)

| | Trước | Sau |
|---|---:|---:|
| Cỡ mẫu | 300 | **10.000** |
| Nguồn | `ground_truth.json` (**chính tập benchmark** → rò rỉ) | CSV CICIDS gốc, **loại trừ flow trùng benchmark** |
| Phân bố | 1 nguồn | **trải đều 10 ngày** |
| Không gian thống kê | tuyến tính | **log1p** cho đặc trưng khối-lượng/thời-lượng/tốc-độ |

**Hiệu quả log-transform (sd/mean, càng gần 1 càng hợp giả định Gauss):**

| Đặc trưng | Trước | Sau |
|---|---:|---:|
| Flow Pkts/s | **7,17** | **1,44** |
| Total Length of Bwd Packets | **7,25** | **1,58** |
| Flow Duration | 1,96 | 0,36 |

**Hai lỗi thật phát hiện khi dựng lại:**

1. `learn_baseline` **không lọc Inf/NaN** (đường `evaluate` thì có) → một giá trị `Inf` từ
   `Flow Pkts/s` (khi `Flow Duration=0`) làm hỏng đặc trưng đó thành `nan` **vĩnh viễn**.
   Sau khi sửa: `n=9930/10000`, tức 70 giá trị Inf bị loại đúng.
2. `_RAW_TO_CANONICAL` **thiếu alias tên cột CICIDS thô** (`Tot Fwd Pkts`, `TotLen Fwd Pkts`…)
   → 4/11 đặc trưng im lặng không được học.

**Hai đặc trưng CỐ Ý không log-hoá** dù sd/mean vẫn cao: `Bwd Pkt Len Min` (**79,3%** giá trị
≤0, median = 0) và `Init Bwd Win Byts` (**48,9%** ≤0). Đây là phân phối **dồn tại 0**, không
phải đuôi dài — log-transform không chữa được. Nêu ở Giới hạn.

**Chốt an toàn:** `golden_baseline.json` ghi cờ `transform: "log1p-v1"`; RuleEngine **từ chối
nạp** baseline dựng ở thang khác thay vì tính Z sai im lặng.

---

## 14. Gray-zone probes & llm_select (demo, 2026-07-21)

**Vì sao LLM không "chặn" trên NetFlow thuần — KHÔNG phải bug.** Đo trên demo: chỉ **0,33%**
sự kiện có nội dung tầng ứng dụng (`message`/`payload`). Payload web lộ liễu bị 29 họ chữ ký
Tier-1 chặn NGAY (12/18 mẫu né-tránh vẫn bị bắt — bằng chứng tốt cho RQ2), không tới LLM.
Cái tới LLM là ca mơ hồ port-lạ → đúng vai **liên kết + biện minh + hoãn**. Đây là **thiết kế**
2 tầng, không phải khiếm khuyết. Phạm vi luận văn (Chương 1) đã khai: *"metadata PCAP thay vì
soi payload sâu"*.

**Gray-zone probes** (`GRAYZONE_SPECS` trong `experiments/unified_dataset.py`): **18 mẫu BIÊN
SOẠN** mô tả hành vi mạng bằng NGỮ NGHĨA (C2/exfil/lateral) — port lạ + 1 flow-feature cực trị
+ message không khớp chữ ký cú pháp. Đã kiểm chứng qua đường THẬT: **18/18 tới được LLM**.
Nhãn nguồn RIÊNG `grayzone`, KHÔNG trộn CICIDS/DAPT thật, chỉ MINH HOẠ demo — **KHÔNG dùng
tính bất kỳ "tỉ lệ" nào** trong luận văn.

**Bug thật đã sửa — `llm_select` chưa bao giờ chạy được.** `_llm_select` trong `attack_mapper`
parse phản hồi bằng `parse_llm_response` (validate theo schema TRIAGE, đòi field `action`),
trong khi phản hồi chọn-MITRE có schema riêng (`technique_id`) → MỌI lần fail-validate → rơi
về low_confidence → lá chắn ép AWAIT_HITL. Tính năng chết âm thầm vì mặc định off. Đã thay bằng
`_parse_json_object` (parse độc lập, chịu lỗi). Test hồi quy trong `test_attack_mapper.py`.

**Đánh đổi khi BẬT `tier2.attack_mapper.llm_select`** (đã bật trong demo này): mapper `resolved`
được technique cho ca ngữ nghĩa → không bị lá chắn → LLM conf ≥0,85 ra BLOCK. Cái giá: **+1 LLM
call mỗi ca mơ hồ** (độ trễ tăng). Mặc định trong benchmark vẫn TẮT để không đổi số đã đo.

---

*Nguồn: `experiments/results/*.json` + mã tính trong `experiments/`. Không con số nào trong tài liệu
này được nhập tay — tất cả đọc từ file kết quả thật.*
