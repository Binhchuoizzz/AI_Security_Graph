# SENTINEL — Sổ tay đo đạc

> Mỗi chỉ số đứng trên tập dữ liệu nào, đo cái gì, vì sao chọn tập đó, và cạm bẫy khi đọc.
> Cập nhật 2026-07-30, sau đợt vá 6 lỗi đo lường.

---

## 0. Ba tập dữ liệu — và ranh giới giữa chúng

Cả dự án chỉ có **ba** tệp dữ liệu được phép sinh ra con số. Mọi tệp khác là trung gian.

| tệp | n | thành phần | dùng cho |
| :-- | --: | :-- | :-- |
| `experiments/ground_truth.json` | 1.750 | 1.200 flow CICIDS + 300 CSIC có payload + 250 đối kháng | ablation A–F, quy kết kỹ thuật, độ trễ, kháng nhiễu |
| `data/datatest.json` | 4.240 | cicids 2.340 · csic 1.036 · dapt 500 · zeroday 360 · adv 4 | Cổng ML (cân bằng ~52/48) |
| `build_stream()` (dựng tại chỗ) | 25.799 | cicids_max 17.023 · dapt 5.402 · csic 2.000 · zeroday 120 · adv 4 | đo toàn tuyến, tương quan APT, quét ngưỡng Welford |

`data/demo.json` (107.867) và `data/demo_small.json` (5.000) **chỉ để demo trực quan** — tuyệt đối
không trích số từ chúng vào luận văn.

### Vì sao ba tập chứ không một

Ba tập trả lời ba câu hỏi khác nhau, và trộn chúng lại là làm hỏng cả ba:

- **`datatest` cân bằng ~50/50** vì F1 chỉ có nghĩa khi hai lớp tương đương. Cổng ML là bộ
  phân loại nhị phân, nên nó phải được chấm trên nền cân bằng.
- **`ground_truth` thiên tấn công 86,9%** — cố ý. Nó không dùng để chấm F1 (script tự gắn cờ
  `binary_f1_trustworthy: false`) mà để chấm **hành động**: với một luồng đã lọc còn toàn ca
  đáng ngờ, hệ chọn BLOCK/ALERT/HITL/LOG đúng bao nhiêu lần.
- **`build_stream()` là luồng "đời thật"** — đại đa số benign, tấn công rải rác. Nó đo
  **xả tải**, thứ không đo được trên tập cân bằng nhân tạo.

### Cạm bẫy đã cắn một lần

`build_stream()` từng mặc định `csic_max=0` và chỉ nạp **một** ngày CICIDS
(`Thursday-01-03` = chỉ Infiltration). Chín script gọi nó trần, nên mọi số "toàn tuyến" của
dự án từng đứng trên luồng **không có một tấn công web nào** và **chỉ một lớp tấn công** —
trong khi phạm vi nghiên cứu tuyên bố hai tập CSE-CIC-IDS2018 **và** CSIC 2010. Con số
"26.521 sự kiện" trong bản luận văn cũ chính là luồng khuyết tật đó. Đã sửa mặc định
(2026-07-30): 10 ngày đủ 15 lớp + 2.000 CSIC + 120 zero-day.

`cicids_max_rows` là **tổng**, chia đều cho các ngày — nên phủ 10 ngày không làm luồng phình.

---

## 1. Dựng lại dữ liệu — thứ tự BẮT BUỘC

```bash
.venv/bin/python scripts/fetch_and_build_dataset.py   # 1. ground_truth.json
.venv/bin/python scripts/build_datatest.py            # 2. datatest.json  (đọc ground_truth)
.venv/bin/python experiments/build_golden_baseline.py # 3. seed Welford   (đọc datatest)
.venv/bin/python scripts/build_demo.py                # 4. demo.json (tuỳ chọn, chỉ để demo)
```

Sai thứ tự thì baseline Welford lệch pha với phân phối dữ liệu, và **mọi** số zero-day /
ngưỡng phía sau sai theo mà không có gì báo.

`build_golden_baseline.py` dùng `datatest.json` **chỉ để LOẠI TRỪ** chữ ký các flow đã nằm
trong benchmark (chống rò rỉ), còn flow benign để seed thì lấy thẳng từ CSV thô. Mặc định
`--n 10000`.

---

## 2. Chạy toàn bộ

```bash
bash scripts/run_full_ablation.sh              # đầy đủ, cần LLM server
bash scripts/run_full_ablation.sh --offline-only
```

Điều kiện: llama.cpp phục vụ tại `http://127.0.0.1:5000/v1`.

> **Đừng chạy `pytest` song song với đo đạc.** Nó ghi ~1.400 luật động vào
> `config/system_settings.yaml`. Từ 2026-07-30 có thể tránh bằng
> `SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest`.

---

## 3. Từng chỉ số

### 3.1 Cổng ML — `evaluate_ml_gate.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `data/datatest.json` (4.240, cân bằng, **có 1.036 CSIC**) |
| **Đo** | Cổng LightGBM tự quyết đúng bao nhiêu, và chịu được né tránh tới đâu |
| **Chỉ số chính** | MCC, BalAcc — **không phải** F1 |

Vì sao MCC chứ không F1: F1 bỏ qua ô true-negative, nên một bộ phân loại hô "tấn công" với
mọi thứ vẫn có F1 đẹp. MCC dùng cả bốn ô, và bằng 0 đúng lúc bộ phân loại vô dụng.

**Phải đọc kèm `Skip payload`.** CSIC là request HTTP chỉ có 5 trường luồng, thiếu đặc trưng
CICFlowMeter, nên Cổng ML **từ chối quyết** và đẩy tiếp — đúng kiến trúc, vì tấn công web là
việc của chữ ký WAF chứ không phải của bộ phân loại NetFlow. Hệ quả đo được khi trộn CSIC
vào: F1 **không đổi một chữ số** (0,8248, ma trận nhầm lẫn y hệt) nhưng tỉ lệ tự quyết tụt
**79,1% → 59,8%**. Con số phải trích là 59,8%, kèm giải thích.

Kháng né tránh **tách theo độ khó** — chỉ trích chế độ KHÓ (`extreme_broad`, nhiễu toàn bộ
đặc trưng). Hai chế độ dễ (`inf_single`, `extreme_single`) đều đạt 1.0 nên gộp trung bình ba
chế độ sẽ thổi phồng con số.

### 3.2 Ablation A/F — `run_ablation.py --mode af`

| | |
| :-- | :-- |
| **Dữ liệu** | `experiments/ground_truth.json` (1.750) |
| **Đo** | Tầng 2 thêm được gì so với chỉ có Tier-1 |
| **Chỉ số chính** | `action_accuracy` + `autonomous_precision` — **không phải** F1 nhị phân |

`metric_health` tự gắn cờ `binary_f1_trustworthy: false` vì base rate tấn công 86,9%: F1 nhị
phân xấp xỉ base rate nên không phân biệt nổi cấu hình nào.

**Dòng đáng đọc nhất là `unresolved_rate`**, không phải accuracy. Config A bỏ ngỏ ~30% số ca
(Tier-1 nói ESCALATE mà không có tầng sau để xử); Config F bỏ ngỏ 0%. Đó mới là đóng góp của
Tầng 2 — không phải vài điểm accuracy.

> **Lỗi đã vá 2026-07-30 — baseline bị chính treatment nâng đỡ.** `run_af` dựng MỘT
> `rule_engine` dùng chung cho cả A và F. Mỗi luật động do tác tử của F sinh ra được ghi vào
> config, và `feedback_listener` chủ động xoá cache nên luật có hiệu lực **ngay** ở mẫu kế
> tiếp — kể cả với A. Config A, vốn là kịch bản "giả sử không có Tầng 2", lại hưởng đúng
> những luật mà chỉ Tầng 2 mới tạo nổi. Quan sát được: luật phình **745 → 1.498** trong một
> lượt, tức chạy lại lần nữa ra số khác. Nay `run_ablation` đặt
> `SENTINEL_FREEZE_DYNAMIC_RULES=1` nên tập luật đứng yên suốt lượt đo.

`--mode balanced` (150/150) mới là chỗ so độ chính xác; `--mode bcde` bóc tách B–E.

### 3.3 Quy kết kỹ thuật MITRE — `eval_attack_mapper.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `ground_truth.json` **+ cờ `--evidence-layer payload`** → 550 mẫu, trong đó **300 chấm được** |
| **Đo** | Hệ có gọi đúng mã ATT&CK không |
| **Chế độ** | `rrf` = tất định (không LLM) · `e2e` = qua toàn tuyến |

**Cờ `--evidence-layer payload` là bắt buộc.** Phần CICIDS của đề là NetFlow thuần, không có
một ký tự payload — "kỹ thuật kỳ vọng" của nó không suy ra được từ đầu vào. Trộn vào sẽ kéo
tụt chỉ số vì lý do chẳng liên quan gì tới năng lực hệ thống.

250 mẫu đối kháng trong 550 không mang mã kỳ vọng nên bị loại khỏi phần chấm quy kết, còn
lại đúng 300 mẫu CSIC.

`kb_coverage_ceiling` phải bằng 100% — nếu thấp hơn nghĩa là đáp án không có trong KB, và
lúc đó chỉ số đo độ phủ KB chứ không đo năng lực truy xuất.

**Đọc `exact` cạnh `parent`.** Chênh lệch giữa hai cột là phần hệ tìm đúng họ kỹ thuật nhưng
hụt cấp con.

> **Lỗi đã vá 2026-07-30 — luôn nhặt kỹ thuật CHA.** Khâu chọn lấy `candidates[0]`, mà
> ATT&CK viết mô tả kỹ thuật cha bằng cách liệt kê con (đo được **47 cặp** trong chính KB
> này), nên cha khớp mọi truy vấn của mọi con và thắng hạng nhờ phủ từ vựng rộng hơn. Đo
> trực tiếp: với 15 mẫu nhãn T1595.003, kỹ thuật con nằm **hạng 2 ở 14/15 ca** — bộ truy
> xuất đúng, chỉ khâu chọn sai. `_prefer_subtechnique` nay nâng con lên khi cả cha và con
> cùng được truy xuất. Kết quả: exact **28,0% → 67,33%**, riêng T1595.003 **0% → 90,8%**.

### 3.4 Chất lượng lập luận — `evaluate_reasoning.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `reasoning_outputs` đã lưu trong `ablation_results.json` (Config F) |
| **Đo** | Bốn trục kiểu RAGAS: context precision · answer relevancy · faithfulness · context recall |
| **Bắt buộc** | Trọng tài phải **khác họ** với model tác tử |

Không cần chạy lại ablation — phán quyết đã lưu sẵn, chỉ chấm lại.

```bash
LLM_MODEL_FILE=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf LLAMA_ARG_CTX_SIZE=32768 \
  docker-compose up -d --force-recreate --no-deps llm
SENTINEL_AGENT_MODEL=Foundation-Sec-8B-Instruct-Q4_K_M.gguf \
  .venv/bin/python experiments/evaluate_reasoning.py
```

`docker-compose` **ưu tiên biến môi trường hơn tệp `.env`** — chỉ sửa `.env` là không đủ,
container sẽ dựng lại bằng đúng model cũ.

> **Lỗi đã vá 2026-07-30 — trọng tài chính là bị cáo.** `call_llm_judge` gọi thẳng
> `LLM_API_BASE` với `"model": "judge"`, nhưng llama.cpp bỏ qua trường đó và phục vụ model
> đang nạp. Runner không đổi model (docstring ghi "Unload Gemma → Load Llama 3" nhưng đó là
> thao tác **tay**). Lượt 2026-07-29 vì thế là Foundation-Sec tự chấm chính nó, trong khi
> tệp kết quả ghi *"Different model family eliminates Self-Enhancement Bias"*. Tên model
> cũng là chuỗi cứng `"Gemma 2 9B Q6_K"` bất kể model nào thật sự chạy. Nay
> `assert_cross_family()` đọc model thật từ `/v1/models` và **chặn cứng** khi trùng.

Đọc kèm `run_health.n_incomplete_schema` — lớn hơn 0 nghĩa là có phán quyết thiếu trường bắt
buộc, và script tự tuyên bố lượt đo không đáng tin.

### 3.5 Phán quyết Tier-2 — `evaluate_tier2_decision.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `build_stream()` → lọc lấy ca Tier-1 ESCALATE (**8.323** ca) |
| **Đo** | Chất lượng phán quyết của tác tử, **có điều kiện** trên việc đã escalate |

**Luôn dùng `--limit`.** Chạy hết 8.323 ca mất ~19 giờ. Script lấy mẫu **strided đều trên
toàn tập** (không phải N ca đầu), nên `--limit 800` cho khoảng tin cậy đủ chặt trong ~2 giờ.

Chỉ số tách làm hai tầng, cố ý: `agent_reliability` (tỉ lệ tác tử cho ra được phán quyết) và
ma trận nhầm lẫn **chỉ trên ca chấm được**. Trộn ca crash vào ma trận là tính một cú crash
thành "bắt đúng đe doạ".

`metric_valid` chỉ bật khi tỉ lệ lỗi ≤ 5%.

### 3.6 Toàn tuyến — `evaluate_unified_stream.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `build_stream()` — 25.799 sự kiện, 22 lớp tấn công |
| **Đo** | Tier-1 phát hiện + xả tải trên luồng giống đời thật |

Đây là nguồn của con số **xả tải** cho RQ1. Đọc `scored_by_source` để biết mỗi nguồn đóng
góp bao nhiêu, và `excluded_by_source` để biết cái gì bị loại và vì sao.

### 3.7 Welford — `run_zeroday_graded.py` · `run_threshold_sensitivity.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `build_stream()` + `ground_truth.json` |
| **Đo** | Bắt dị biệt không chữ ký; độ nhạy theo ngưỡng τ |

> **Z-score Welford phụ thuộc THỨ TỰ.** Cùng một tập grayzone từng cho ba kết quả khác nhau
> tuỳ thứ tự nạp. Chỉ trích số Tier-1 từ lượt chạy **sống**, không từ thăm dò ngoại tuyến.

Hai script này **chấp nhận được** khi không có CSIC, vì CSIC là request HTTP gần như không
có đặc trưng luồng — thêm vào chỉ làm nhiễu thống kê chứ không thêm tín hiệu.

### 3.8 An ninh — `evaluate_adversarial.py` · `run_llm_robustness.py` · `audit_tier_capability.py`

| | |
| :-- | :-- |
| **Dữ liệu** | 250 mẫu đối kháng OWASP trong `ground_truth.json` |
| **Đo** | Rào chắn có bị tiêm nhiễm câu lệnh qua nhật ký thô không |

Đây là nhóm chỉ số **mạnh nhất** của dự án, vì nó là bảo chứng **kiến trúc** — không phụ
thuộc model tốt hay xấu. Đóng gói phân định bằng nonce ngẫu nhiên mỗi lô: kẻ tấn công không
đoán được mốc phân cách nên không thoát ra khỏi vùng dữ liệu được.

### 3.9 Độ trễ — `measure_latency_baseline.py`

| | |
| :-- | :-- |
| **Dữ liệu** | `ground_truth.json` |
| **Đo** | Đầu-cuối hai tầng so với thuần LLM |

Trích **p50 và p95**, không trích trung bình — phân phối độ trễ lệch phải nặng, trung bình
bị vài ca chậm kéo đi.

---

## 4. Hằng số hệ thống (đọc thẳng từ mã, 2026-07-30)

| hằng số | giá trị | nơi định nghĩa |
| :-- | :-- | :-- |
| Ngưỡng leo thang Tier-1 | `risk_threshold: 15` | `config/system_settings.yaml` |
| Ngưỡng Z-score | `3.5` | `rule_engine.py` |
| Họ chữ ký WAF | **30** | `_WAF_PATTERNS` |
| Dải quyết định ML | 0,85 BLOCK · 0,65 ESCALATE · 0,40 ALERT | `decision_policy.py` |
| Dải quyết định LLM | 0,85 BLOCK · 0,65 ALERT · dưới → AWAIT_HITL | `decision_policy.py` |
| Cache phán quyết | LRU 10.000 · TTL 3.600s | `response_cache.py` |
| RRF | `k = 60` | `retriever.py` |
| Mục tri thức MITRE | **433** | `knowledge_base/mitre_attack.json` |
| Ngân sách ngữ cảnh | **16.384** token | `config/system_settings.yaml` |
| Model tác tử | **Foundation-Sec-8B-Instruct Q4_K_M** | `.env` |
| Ngữ cảnh llama.cpp | `-c 32768 -np 2` → **16.384/khe** | `docker-compose.yml` |

> `-np N` **chia** `-c` cho N khe. Gemma-2-9B từng hỏng 60/60 lượt trong 0,02 giây vì
> `-c 8192 -np 2` = 4.096 token/khe, trong khi prompt thật p50 khoảng 7.700 token. Đó là lỗi
> cấu hình, **không phải** kết luận về chất lượng model.

---

## 5. Danh mục kiểm trước khi trích số vào luận văn

- [ ] Tệp kết quả **mới hơn** lần dựng dữ liệu gần nhất — `gt_id` đúc theo chỉ số sự kiện,
      nên dựng lại dataset là mọi trace cũ trỏ sang sự kiện khác mà vẫn tra được khoá
- [ ] `metric_valid` / `metric_health` không gắn cờ đỏ
- [ ] Số mẫu (`n`) ghi kèm mọi tỉ lệ phần trăm
- [ ] `judge_model` **khác** `agent_model` trong `reasoning_eval_results.json`
- [ ] `config/system_settings.yaml` không dính luật do pytest hoặc lượt đo sinh ra
- [ ] Số Tier-1 lấy từ lượt chạy **sống**, không từ thăm dò ngoại tuyến
- [ ] Tên model trong tệp kết quả khớp model **thật sự** đã chạy
