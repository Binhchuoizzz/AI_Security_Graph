# 🎓 Demo Hội Đồng — SENTINEL (chạy FULL bằng **1 lệnh**)

> Bản trình diễn cuối cùng trước hội đồng: **một lệnh duy nhất** đẩy **toàn bộ 4 nguồn dữ liệu
> thật** (CICIDS + DAPT2020 + Zero-day + Adversarial) chảy qua **toàn bộ hệ thống thật**
> (Tier-1 (Welford + Cổng ML) → Tier-2 LLM cục bộ → HITL → Dashboard). Không cần chạy 4
> lệnh rời rạc như trước.
>
> Thiết lập môi trường chi tiết: [RUN_PROJECT.md](RUN_PROJECT.md) · Từng luồng cô lập:
> [DEMO_FLOWS.md](DEMO_FLOWS.md).
>
> **Thông điệp cốt lõi (1 câu):** *Tier-1 lọc rẻ (O(1)) phần lớn lưu lượng; Cổng ML (thuộc Tier-1) phân loại nhanh (early-exit); Tier-2: LLM cục bộ air-gapped xử lý ca phức tạp — **giảm 82.97% độ trễ** (đo trên dataset trước 2026-07-16 — cần đo lại sau khi đổi ground_truth) mà vẫn phát hiện APT đa ngày, zero-day*
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

## ⚡ CHẠY FULL — **1 LỆNH DUY NHẤT** (khuyến nghị)

> Một script gộp TẤT CẢ: containers (Redis + LLM + MLflow + Dashboard) → reset sạch +
> bật đúng 1 subscriber (Tier-1 + Tier-2) → Dashboard → **đẩy luồng gộp 4 nguồn** vào UI.

```bash
./scripts/run_demo.sh --fresh      # FULL + reset SẠCH: đẩy ~100.000 sự kiện (data/demo.json) vào Dashboard
# ./scripts/run_demo.sh            # như trên nhưng GIỮ trạng thái hiện tại (không reset)
# ./scripts/run_demo.sh --no-push  # chỉ dựng hạ tầng (subscriber + UI), tự đẩy sau
# ./scripts/run_demo.sh --small    # tương tự chạy full, dùng cho test nhanh
```

`data/demo.json` (~100k sự kiện, ~167MB) KHÔNG track trong git — tái tạo bằng `python scripts/build_demo.py`.

> Xong → mở **http://localhost:8501** (đăng nhập **`manager`**). Dashboard điền dần theo tốc
> độ LLM (đúng thiết kế SOC). Muốn chạy TỪNG BƯỚC bằng tay (giải thích rõ) → xem §0–§1 dưới.

**Tắt sau demo:** `pkill -f "main.py --mode server"` rồi `docker-compose stop` (xem đầu file).

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

## 1. ▶️ LỆNH CHẠY HỆ THỐNG (Khởi động hạ tầng & Bơm luồng dữ liệu)

Hệ thống được thiết kế với 2 kịch bản chạy song song để phục vụ báo cáo và kiểm thử:

### 🌟 Chế độ 1: BÁO CÁO HỘI ĐỒNG (DEMO)

```bash
./scripts/run_demo.sh
```

**Lệnh này làm gì:** Tự động dựng toàn bộ hạ tầng (Redis, MLflow, Dashboard, LLM) và phát **~100.000 sự kiện thật** (`data/demo.json`) lướt qua toàn bộ pipeline:

| Nguồn | Số sự kiện | Chứng minh năng lực |
| :--- | ---: | :--- |
| **CICIDS Attacks** | 2000 | Tấn công mạng thực tế (Tier 1 & 2 xử lý) |
| **CICIDS Benign** | 7579 | Phân loại + giảm tải độ trễ (Noise Reduction) |
| **DAPT2020** | 402 | APT **nổi lên dần** đa ngày (Threat Memory) |
| **Zero-day** | 15 | Welford Z-score bắt cái luật tĩnh bỏ sót |
| **Adversarial** | 4 | Kháng OWASP LLM Top-10 (Guardrails + Tier-2 LLM) |

### 🧪 Chế độ 2: KIỂM THỬ MỞ RỘNG (TEST)

```bash
./scripts/run_test.sh
```

**Lệnh này làm gì:** Kiểm thử khả năng chịu tải và độ chính xác phân loại tập trung vào CICIDS với **2.219 sự kiện** (`data/datatest.json`):

| Nguồn | Số sự kiện | Mục tiêu kiểm thử |
| :--- | ---: | :--- |
| **CICIDS Attacks** | 1000 | Test độ nhạy và F1-score của bộ phân loại |
| **CICIDS Benign** | 1000 | Test tỷ lệ False Positive |
| **DAPT/ZD/Adv** | 219 | Xác nhận các module phát hiện phức tạp vẫn hoạt động |
> **Nói:** *Đây là toàn bộ hệ thống chạy thật trên MỘT dòng thời gian.* Cùng dữ liệu với benchmark offline — **không bịa thêm**. Tier 1 và Tier 2
> xử lý mọi sự kiện ở tốc độ đường truyền; **chỉ ca đáng ngờ được ESCALATE mới gọi LLM của Tier-2** (đúng
> thiết kế SOC) — đó chính là gốc của con số giảm 82.97% độ trễ.

*(Kiểm tra logic không cần Redis: thêm `--dry-run` vào code)*

---

## 2. Vừa chạy vừa thuyết minh — **5 trục đánh giá (5D)** trên Dashboard

Trong khi luồng chảy, chỉ vào từng tab (số liệu benchmark ở §5, đọc từ file kết quả — không bịa):

| # | Trục | Nhìn ở đâu trên Dashboard | Nói (số bỏ túi) |
| :-- | :--- | :--- | :--- |
| 1 | **Accuracy** | Tab *Tổng quan* → thẻ header `LOGS THÔ`, **`TỶ LỆ GIẢM TẢI`**, phân bố `BLOCK/ALERT/DROP` | Đa số benign **DROP ở Tier-1**, không phiền LLM. Số F1/recall của gate Tier-1 lấy từ `reports/unified_stream_evaluation_report.md` MỚI NHẤT (dataset vừa đổi 2026-07-16 — chạy lại eval trước khi trích). |
| 2 | **APT (Accuracy)** | Tab *Giám sát APT* → *Nhật ký chuỗi tấn công APT (DAPT2020)* | Bước lẻ tín hiệu thấp → thường DROP. Khi 1 IP xuất hiện ở **≥2 ngày**, bản án `is_apt` **nổi lên** & leo thang. **Recall 3/3 = 1.00**, **specificity 1.00** (0 báo động giả / 4 chuỗi benign đa ngày). |
| 3 | **Zero-day (Accuracy)** | Tab *Live Feed* → event `zeroday` chuyển **AWAIT_HITL/ESCALATE** | 15 biến thể; luật **tĩnh bỏ sót cả 15** (DROP). Welford bắt **12/15**: Z từ **~5.3 → ~118.000** (≫ 3.5σ) — phát hiện **không cần nhãn**. Trung thực: 3 biến thể tinh vi (Z 2.5–2.9 < 3.5σ) thoát — giới hạn đã nêu. |
| 4 | **Security** | Tab *Tổng quan* → *🔁 Vòng phản hồi* + *Live Threat Feed* | 120 payload OWASP LLM đi qua **toàn bộ** Tier 1 và Tier 2 (điển hình ~104 DROP + 2 BLOCK + 14 ESCALATE). Guardrail Tier-2 kháng **100%** khi payload tới nơi. **Trung thực:** payload mã hoá/ngữ nghĩa Tier-1 không giải mã sẽ **lọt bằng DROP** — giới hạn của bộ lọc chữ ký, đã nêu trong luận văn. |
| 5 | **Explainability + Integrity** | Bấm 1 thẻ cảnh báo → *🔍 Xem LOG THÔ đầu vào* + thẻ *Audit HMAC-SHA256* | Đầu vào LLM **đã loại nhãn/đáp án** (chống lộ nhãn). Mỗi quyết định kèm **MITRE + suy luận 4 phần + playbook NIST**. Nhật ký ký chuỗi HMAC — chống sửa. LLM-as-Judge chéo họ **3.9/5**. |
