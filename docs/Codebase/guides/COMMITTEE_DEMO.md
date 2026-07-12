# 🎓 Kịch Bản Demo Trước Hội Đồng — SENTINEL (~15 phút)

> Bản trình diễn tối thiểu nhưng đầy đủ để chứng minh **kiến trúc nhận thức hai tầng** và
> **5 trục đánh giá (5D)**. Lệnh chi tiết từng luồng xem [DEMO_FLOWS.md](DEMO_FLOWS.md);
> thiết lập môi trường xem [RUN_PROJECT.md](RUN_PROJECT.md).
>
> **Thông điệp cốt lõi (1 câu):** *Tier-1 lọc rẻ (O(1)) ~88% lưu lượng, chỉ đẩy ca mơ hồ lên
> Tier-2 (LLM cục bộ air-gapped) để suy luận sâu — giảm 82.97% độ trễ mà vẫn giữ khả năng
> phát hiện APT đa ngày, zero-day, và kháng tấn công đối kháng, có con người giám sát (HITL)
> và nhật ký ký HMAC.*

---

## 0. Trước khi hội đồng vào phòng (chuẩn bị ~5 phút)

```bash
docker compose up -d && docker compose ps           # tất cả (healthy)
# subscriber host = Tier-1 + Tier-2
nohup .venv/bin/python main.py --mode server > logs/subscriber.log 2>&1 &
```
- Reset sạch (nút UI của `manager`, hoặc script trong DEMO_FLOWS.md §0).
- Mở sẵn `http://localhost:8501`, đăng nhập vai **L3_Manager** (thấy nút duyệt luật + reset).
- Mở sẵn 2 tab trình duyệt: **Tổng quan Demo** và **Giám sát APT**.

---

## 1. Mở đầu — Kiến trúc (2 phút, KHÔNG cần chạy gì)

Chỉ vào tab **“Tổng quan Demo (Hội đồng)”**:
- Băng phía trên: **Tier-1 Welford O(1) → Tier-2 LangGraph (Gemma-2-9B-IT Q6_K, llama.cpp) +
  Dual-RAG (MITRE ATT&CK / NIST SP 800-61r2)**, có rào chắn mật mã + HITL.
- Thẻ **“Trạng thái Hệ thống”**: LLM cục bộ air-gapped · Audit HMAC toàn vẹn · Ngân sách ngữ cảnh.

**Nói:** hệ hai tầng để *vừa nhanh vừa sâu*; LLM chạy **cục bộ** (không gửi dữ liệu ra ngoài).

---

## 2. Luồng CICIDS — Giảm tải & phân loại (2 phút)

```bash
.venv/bin/python scripts/push_flow.py --source cicids --limit 300
```
Chỉ vào **thẻ header**: `LOGS THÔ`, **`TỶ LỆ GIẢM TẢI`**, phân bố `BLOCK/ALERT/DROP`.

**Nói:** đa số lưu lượng benign bị **DROP ở Tier-1** — không bao giờ phiền LLM. Đây là gốc rễ
của con số **giảm 82.97% độ trễ** (26.882 ms → 4.577 ms, `latency_benchmark.json`).
**Trục 1 (Accuracy):** F1 = 0.594 trên luồng gộp — thành thật: recall 0.43 (bỏ sót nhiều ca
tinh vi) là giới hạn đã nêu trong luận văn.

---

## 3. Luồng APT đa ngày — “nổi lên dần” (3 phút, ĐIỂM NHẤN)

```bash
.venv/bin/python scripts/push_flow.py --source dapt
```
Chuyển tab **“Giám sát APT & Threat Intel”** → **“Nhật ký chuỗi tấn công APT (DAPT2020)”**.

**Nói:** từng bước lẻ (recon, foothold, lateral…) tín hiệu thấp, Tier-1 thường DROP. Nhưng
Threat Memory **tương quan đa ngày** — khi một IP xuất hiện ở **≥2 ngày** thì bản án `is_apt`
**nổi lên** và leo thang. **Trục 1:** APT recall **3/3 = 1.00**, specificity **1.00** (0 báo
động giả trên 4 chuỗi benign đa ngày — `apt_negative_control_results.json`).
- Nhấn mạnh phân biệt: **điểm danh tiếng** (một lần chặn) ≠ **APT** (cần chuỗi ≥2 ngày).

---

## 4. Luồng Zero-day — Welford bắt cái static bỏ sót (2 phút)

```bash
.venv/bin/python scripts/push_flow.py --source zeroday
```
**Nói:** 7 biến thể zero-day; luật **tĩnh bỏ sót cả 7** (đều DROP). Nhưng **Welford Z-score**
(baseline đã ấm bằng warmup) bắt được — Tier-1 chuyển sang **AWAIT_HITL/ESCALATE**. Z-score
từ **7.5 → 318.000** (`unified_stream_results.json`). Đây là năng lực **phát hiện không cần
nhãn** — nền tảng cho phát hiện bất thường thật.

---

## 5. Luồng Adversarial + VÒNG PHẢN HỒI (4 phút, ĐIỂM NHẤN NHẤT)

```bash
.venv/bin/python scripts/push_flow.py --source adversarial
```
Tab **“Tổng quan” → “🔁 Vòng phản hồi Hai tầng”** và **Live Threat Feed**.

**Nói (Trục 3 — Security):**
- 120 payload OWASP LLM Top-10 đi qua **toàn bộ** Tier-1. Điển hình: **104 DROP + 2 BLOCK
  (Tier-1) + 14 ESCALATE → Tier-2**. Guardrail Tier-2 kháng **100%** khi payload tới nơi
  (`adversarial_pipeline_results.json`).
- **Trung thực:** payload mã hoá/ngữ nghĩa mà Tier-1 không giải mã sẽ **lọt bằng DROP** — đây
  là giới hạn của bộ lọc chữ ký, đã nêu trong luận văn (không tuyên bố tuyệt đối).

**Rồi diễn VÒNG PHẢN HỒI khép kín (ăn tiền nhất):**
1. Tab **“Phê duyệt Luật (HITL)”** → **DUYỆT** luật cho `198.51.100.15`.
2. Đẩy lại traffic IP đó (đoạn lệnh ở [DEMO_FLOWS.md §5](DEMO_FLOWS.md)).
3. Chỉ vào **“Tier-1 đã chặn”**: `.15` bị **Tier-1 TỰ CHẶN** (reason *luật động*), **audit
   KHÔNG tăng** ⇒ không tốn LLM.

**Nói:** *Analyst duyệt → luật persist → RuleEngine hot-reload → Tier-1 enforce.* Con người
dạy máy một lần, máy tự chặn kẻ tái phạm ở tốc độ đường truyền — **vòng phản hồi khép kín**.

---

## 6. Kết — Giải trình & Toàn vẹn (2 phút)

- Mở expander **“🔍 Xem LOG THÔ đầu vào”** trong một thẻ cảnh báo: chứng minh **đầu vào LLM
  đã loại nhãn/đáp án** (chống lộ nhãn) — trục **Explainability**.
- Thẻ **“Audit HMAC-SHA256: Toàn vẹn”**: nhật ký ký chuỗi, chống sửa — trục **Integrity**.
- **Trục Explainability:** LLM-as-Judge **3.9/5**; mỗi quyết định kèm MITRE + suy luận 4 phần
  + playbook NIST.

---

## Bảng số liệu “bỏ túi” (đọc từ file kết quả, không bịa)

| Trục 5D | Chỉ số | Giá trị | Nguồn |
|---|---|---|---|
| Accuracy | F1 (P/R) luồng gộp | **0.594** (0.94 / 0.43) | `unified_stream_results.json` |
| Accuracy | APT recall / specificity | **3/3 = 1.00** / **1.00** | `apt_negative_control_results.json` |
| Accuracy | Zero-day bắt được | **7/7** (Welford) | `unified_stream_results.json` |
| Performance | Giảm độ trễ (2-tier vs LLM-only) | **82.97%** (26.882→4.577 ms) | `latency_benchmark.json` |
| Security | Guardrail Tier-2 kháng adversarial | **100%** (4/4 nạp thẳng) | `adversarial_pipeline_results.json` |
| Security | Guardrail-only block (120 payload) | **~50%** (encoding 100%, semantic 0%) | `robustness_results.json` |
| Explainability | LLM-as-Judge (chéo họ) | **3.9 / 5** | `reasoning_eval_results.json` |
| Integrity | Chuỗi audit HMAC-SHA256 | tamper-evident | `executor.py` / audit DB |

## Câu hỏi hội đồng hay hỏi — trả lời ngắn

- **“Sao chỉ ít lên Tier-2?”** → Tier-1 lọc ~88% (DROP + chặn chữ ký); chỉ ca mơ hồ mới escalate
  ⇒ đó chính là cơ chế giảm 82.97% trễ.
- **“Recall 0.43 thấp?”** → thành thật: Tier-1 ưu tiên tốc độ, đánh đổi recall; bù lại Tier-2
  + APT đa ngày + Welford bắt các lớp khác. Không tuyên bố tuyệt đối.
- **“Chống lộ nhãn?”** → subscriber `_strip_dataset_labels` loại `gt_expected_*`/`apt_*`/`zd_*`
  trước khi vào LLM (có unit test `tests/unit/test_subscriber.py`); xem trực tiếp qua expander
  “LOG THÔ đầu vào”.
- **“LLM có gửi data ra ngoài?”** → không: Gemma-2-9B chạy **cục bộ** qua llama.cpp, air-gapped.
