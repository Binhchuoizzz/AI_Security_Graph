# 🎓 Demo Hội Đồng — SENTINEL (chạy FULL bằng **1 lệnh**)

> Bản trình diễn cuối cùng trước hội đồng: **một lệnh duy nhất** đẩy **toàn bộ 4 nguồn dữ liệu
> thật** (CICIDS + DAPT2020 + Zero-day + Adversarial) chảy qua **toàn bộ hệ thống thật**
> (Tier-1 Welford → APT emergent → Tier-2 LLM cục bộ → HITL → Dashboard). Không cần chạy 4
> lệnh rời rạc như trước.
>
> Thiết lập môi trường chi tiết: [RUN_PROJECT.md](RUN_PROJECT.md) · Từng luồng cô lập:
> [DEMO_FLOWS.md](DEMO_FLOWS.md).
>
> **Thông điệp cốt lõi (1 câu):** *Tier-1 lọc rẻ (O(1)) ~88% lưu lượng, chỉ đẩy ca mơ hồ lên
> Tier-2 (LLM cục bộ air-gapped) — **giảm 82.97% độ trễ** mà vẫn phát hiện APT đa ngày, zero-day
> không nhãn, và kháng tấn công đối kháng, có con người giám sát (HITL) + nhật ký ký HMAC.*

---

## ⏻ TẮT HỆ THỐNG (giải phóng RAM khi không demo)

> Container **`sentinel_llm` ăn ~8 GB RAM/VRAM** (Gemma-2-9B) — nặng nhất. Tắt khi không dùng:

```bash
# 1) Tắt subscriber chạy trên host (Tier-1 + Tier-2)
pkill -f "main.py --mode server"

# 2) Dừng TẤT CẢ container → giải phóng RAM (llm 8GB + dashboard + neo4j + mlflow + redis)
docker-compose stop              # tạm dừng, GIỮ container (bật lại nhanh: docker-compose start)
#   hoặc nhẹ nhất, xoá hẳn container (vẫn giữ image + volume dữ liệu):
docker-compose down
```

**Kiểm tra đã tắt:** `docker ps | grep sentinel` (rỗng = đã tắt) · `nvidia-smi` (VRAM đã nhả).
**Bật lại để demo:** `docker-compose up -d` → `./scripts/switch_model.sh gemma` → `.venv/bin/python scripts/reset_all.py` (xem §0).

---

## 0. Chuẩn bị (~3 phút) — 3 lệnh

```bash
# 1) Hạ tầng: Redis + LLM cục bộ (llama.cpp) + Dashboard
docker compose up -d && docker compose ps          # chờ tất cả (healthy)

# 2) Nạp đúng model Agent (Gemma-2-9B-IT Q6_K)
./scripts/switch_model.sh gemma                     # chờ báo ONLINE & HEALTHY

# 3) Reset SẠCH + bật lại ĐÚNG 1 subscriber (Tier-1 + Tier-2) trong 1 lệnh
.venv/bin/python scripts/reset_all.py               # DỪNG → XOÁ DB/config/Redis/blacklist → BẬT LẠI
```

- `reset_all.py` tự chống 2 lỗi hay gặp: chạy **>1 subscriber** (chia log → Dashboard thiếu) và **quên bật lại**. Xem trước bằng `--dry-run`.
- Mở `http://localhost:8501`, đăng nhập **`manager`** (thấy nút duyệt luật + reset).
- Mở sẵn 3 tab Dashboard: **Tổng quan Demo** · **Giám sát APT & Threat Intel** · **Live Threat Feed**.

---

## 1. ▶️ LỆNH CHẠY FULL (điểm nhấn — 1 lệnh, tất cả năng lực)

```bash
.venv/bin/python experiments/stream_unified_online.py --include-adversarial
```

**Lệnh này làm gì:** phát **4.796 sự kiện thật** (150 benign warmup làm ấm Welford + luồng chính
trộn theo thời gian golden-ratio) lên Redis → subscriber → pipeline đầy đủ:

| Nguồn | Số sự kiện | Chứng minh năng lực |
| :--- | ---: | :--- |
| **CICIDS** | 4.267 | Phân loại + giảm tải Tier-1 (Noise Reduction) |
| **DAPT2020** | 402 | APT **nổi lên dần** đa ngày (Threat Memory) |
| **Zero-day** | 7 | Welford Z-score bắt cái luật tĩnh bỏ sót |
| **Adversarial** | 120 | Kháng OWASP LLM Top-10 (Guardrails + Tier-2) |

> **Nói:** *Đây là toàn bộ hệ thống chạy thật trên MỘT dòng thời gian.* Cùng dữ liệu, cùng bộ
> dựng luồng (`unified_dataset.build_stream`) với benchmark offline — **không bịa thêm**. Tier-1
> xử lý mọi sự kiện ở tốc độ đường truyền; **chỉ ca đáng ngờ được ESCALATE mới gọi LLM** (đúng
> thiết kế SOC) — đó chính là gốc của con số giảm 82.97% độ trễ.

*(Kiểm tra logic không cần Redis: thêm `--dry-run`. Bỏ `--include-adversarial` nếu chỉ muốn luồng
phân loại CICIDS+DAPT+Zero-day.)*

---

## 2. Vừa chạy vừa thuyết minh — **5 trục đánh giá (5D)** trên Dashboard

Trong khi luồng chảy, chỉ vào từng tab (số liệu benchmark ở §5, đọc từ file kết quả — không bịa):

| # | Trục | Nhìn ở đâu trên Dashboard | Nói (số bỏ túi) |
| :-- | :--- | :--- | :--- |
| 1 | **Accuracy** | Tab *Tổng quan* → thẻ header `LOGS THÔ`, **`TỶ LỆ GIẢM TẢI`**, phân bố `BLOCK/ALERT/DROP` | Đa số benign **DROP ở Tier-1**, không phiền LLM. F1 phân loại **0.594** — thành thật recall **0.43** (Tier-1 ưu tiên tốc độ, đẩy ca tinh vi lên Tier-2). |
| 2 | **APT (Accuracy)** | Tab *Giám sát APT* → *Nhật ký chuỗi tấn công APT (DAPT2020)* | Bước lẻ tín hiệu thấp → thường DROP. Khi 1 IP xuất hiện ở **≥2 ngày**, bản án `is_apt` **nổi lên** & leo thang. **Recall 3/3 = 1.00**, **specificity 1.00** (0 báo động giả / 4 chuỗi benign đa ngày). |
| 3 | **Zero-day (Accuracy)** | Tab *Live Feed* → event `zeroday` chuyển **AWAIT_HITL/ESCALATE** | 7 biến thể; luật **tĩnh bỏ sót cả 7** (DROP). Welford bắt được: Z từ **~7.5 → ~318.000** (≫ 3.5σ) — phát hiện **không cần nhãn**. |
| 4 | **Security** | Tab *Tổng quan* → *🔁 Vòng phản hồi Hai tầng* + *Live Threat Feed* | 120 payload OWASP LLM đi qua **toàn bộ** Tier-1 (điển hình ~104 DROP + 2 BLOCK + 14 ESCALATE). Guardrail Tier-2 kháng **100%** khi payload tới nơi. **Trung thực:** payload mã hoá/ngữ nghĩa Tier-1 không giải mã sẽ **lọt bằng DROP** — giới hạn của bộ lọc chữ ký, đã nêu trong luận văn. |
| 5 | **Explainability + Integrity** | Bấm 1 thẻ cảnh báo → *🔍 Xem LOG THÔ đầu vào* + thẻ *Audit HMAC-SHA256* | Đầu vào LLM **đã loại nhãn/đáp án** (chống lộ nhãn). Mỗi quyết định kèm **MITRE + suy luận 4 phần + playbook NIST**. Nhật ký ký chuỗi HMAC — chống sửa. LLM-as-Judge chéo họ **3.9/5**. |

---

## 3. ⭐ Vòng phản hồi khép kín (HITL) — *ăn tiền nhất*

Sau khi luồng chạy, Agent đã đề xuất một số luật chặn (PENDING). Diễn khép kín:

```bash
# B1: (đã có sẵn từ lệnh FULL ở §1) — 1 IP adversarial bị ESCALATE → Tier-2 BLOCK → sinh luật PENDING
#     ví dụ 198.51.100.15

# B2: Dashboard → tab "Phê duyệt Luật (HITL)" → DUYỆT luật cho 198.51.100.15

# B3: đẩy lại traffic từ đúng IP đó (snippet đầy đủ ở DEMO_FLOWS.md §5)
.venv/bin/python scripts/push_flow.py --source adversarial      # phát lại toàn bộ adversarial, gồm .15
```

> **Kỳ vọng (đã kiểm chứng live):** `198.51.100.15` xuất hiện ở **“Tier-1 đã chặn”** với reason
> `Luật động [từ Tác tử]: Source IP=...`; blacklist +.15; **audit_trail KHÔNG tăng** ⇒ **không leo
> Tier-2, không tốn LLM**.
>
> **Nói:** *Analyst duyệt → luật persist → RuleEngine hot-reload → Tier-1 tự enforce.* Con người
> dạy máy **một lần**, máy tự chặn kẻ tái phạm ở tốc độ đường truyền — **vòng phản hồi khép kín**.

---

## 4. Chốt hạ — số liệu benchmark bằng **1 lệnh offline** (tất định, không LLM)

Số trên Dashboard phụ thuộc timing/LLM nên **không** dùng làm benchmark. Con số cho luận văn lấy từ
lệnh offline tất định (cùng luồng gộp, bộ nhớ SẠCH):

```bash
.venv/bin/python experiments/evaluate_unified_stream.py
# -> reports/unified_stream_evaluation_report.md + experiments/results/unified_stream_results.json
```

### Bảng số liệu “bỏ túi” (đọc từ file kết quả, KHÔNG bịa)

| Trục 5D | Chỉ số | Giá trị | Nguồn |
| --- | --- | --- | --- |
| Accuracy | F1 phân loại (P / R) | **0.594** (0.939 / 0.435) | `unified_stream_results.json` |
| Accuracy | APT recall / độ trễ | **3/3 = 1.00** / ~8.33 sự kiện | `unified_stream_results.json` |
| Accuracy | APT specificity | **1.00** (0 báo động giả / 4 benign đa ngày) | `apt_negative_control_results.json` |
| Accuracy | Zero-day bắt được | **7/7** (Welford, static bỏ sót cả 7) | `unified_stream_results.json` |
| Performance | Giảm độ trễ (2-tier vs LLM-only) | **82.97%** (26.882 → 4.577 ms) | `latency_benchmark.json` |
| Security | Guardrail Tier-2 kháng adversarial | **100%** (4/4 nạp thẳng) | `adversarial_pipeline_results.json` |
| Security | Guardrail-only block (120 payload) | **50%** (encoding 100% · structural 35% · rag 40% · jailbreak 10% · semantic 0%) | `robustness_results.json` |
| Explainability | LLM-as-Judge chéo họ (300 mẫu) | **3.9 / 5** (audit 100%, faithfulness 4.0) | `reasoning_eval_results.json` |
| Integrity | Chuỗi audit HMAC-SHA256 | tamper-evident | `executor.py` / audit DB |

---

## 5. Câu hỏi hay gặp — trả lời ngắn

- **“Sao chỉ ít lên Tier-2?”** → Tier-1 lọc ~88% (DROP + chặn chữ ký); chỉ ca mơ hồ mới escalate ⇒ đó chính là cơ chế giảm 82.97% trễ.
- **“Recall 0.43 thấp?”** → thành thật: Tier-1 ưu tiên tốc độ, đánh đổi recall; bù lại Tier-2 + APT đa ngày + Welford bắt các lớp khác. Không tuyên bố tuyệt đối.
- **“Chống lộ nhãn?”** → subscriber `_strip_dataset_labels` loại `gt_expected_*`/`apt_*`/`zd_*` trước khi vào LLM (unit test `tests/unit/test_subscriber.py`); xem trực tiếp qua expander “LOG THÔ đầu vào”.
- **“LLM có gửi data ra ngoài?”** → không: Gemma-2-9B chạy **cục bộ** qua llama.cpp, air-gapped.
- **“Số Dashboard vs số luận văn?”** → Dashboard = chứng minh end-to-end realtime; số benchmark lấy từ `evaluate_unified_stream.py` (offline, tất định) — §4.

---

## 6. (Tùy chọn) Trình diễn TỪNG năng lực cô lập

Nếu hội đồng muốn xem riêng một năng lực (thay vì luồng gộp), đẩy đúng một nguồn — cùng bộ dữ liệu,
qua cùng hệ thống thật:

```bash
.venv/bin/python scripts/push_flow.py --source cicids --limit 300   # phân loại + giảm tải
.venv/bin/python scripts/push_flow.py --source dapt                 # APT emergent đa ngày
.venv/bin/python scripts/push_flow.py --source zeroday              # Welford bắt zero-day
.venv/bin/python scripts/push_flow.py --source adversarial          # kháng OWASP LLM Top-10
```
