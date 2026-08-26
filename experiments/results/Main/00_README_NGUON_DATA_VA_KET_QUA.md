# 📊 SỔ TAY NGUỒN DỮ LIỆU & KẾT QUẢ BENCHMARK (FOLDER MAIN)

---

## 1. TIỀN XỬ LÝ & ĐỒNG HÓA DỮ LIỆU (SCHEMA HOMOGENIZATION)

* **Vấn đề:** 5 nguồn dữ liệu dị thể (NetFlow 76 cột, HTTP text thô, APT đa ngày, Prompt Injection).
* **Cách đồng hóa (`experiments/unified_dataset.py` & `scripts/build_csic_dataset.py`):**
  1. **Đóng gói Envelope:** Bọc HTTP thô vào "phong bì" NetFlow giả lập để Tier-1 xử lý, đồng thời giữ nguyên raw payload cho Tier-2.
  2. **Phân dải IP:** Gán IP `198.19.x.x` (CSIC 2010) và `198.18.x.x` (Adversarial) để kiểm thử đúng phân vùng mà không sửa payload.
  3. **Bảo tồn tỷ lệ thực:** Lấy mẫu bước nhảy (Strided Sampling) giữ nguyên tỷ lệ tấn công thực tế **5,24% – 9,8%**, không ép 50/50.

---

## 2. BẢNG NGUỒN DATA ⇄ FILE PYTHON ⇄ NƠI LƯU TRỮ

| Tập Dữ Liệu | Số Lượng Mẫu | File Python Xử Lý | Nơi Lưu Trữ Dữ Liệu | Vai Trò Kỹ Thuật |
| :--- | :---: | :--- | :--- | :--- |
| **1. CSE-CIC-IDS2018** | **456.849** | 🐍 `download_cicids2018.sh`<br/>🐍 `unified_dataset.py` | 📂 `data/raw/cicids2018/` | Huấn luyện Cổng LightGBM (76 đặc trưng) & đo xả tải Tier 1. |
| **2. CSIC 2010 HTTP** | **36.000** | 🐍 `scripts/build_csic_dataset.py` | 📄 `data/csic.json` *(25.3 MB)* | Payload web thật (SQLi, XSS...) kiểm thử WAF, RAG & Grounding. |
| **3. DAPT2020** | **1.902** | 🐍 `scripts/build_dapt_chains.py` | 📂 `data/raw/dapt2020/` | Kiểm thử bộ nhớ ngữ cảnh Threat Memory & chuỗi APT đa ngày. |
| **4. Adversarial Benchmark** | **730** | 🐍 `scripts/build_adversarial_suite.py` | 📄 `data/adversarial_llm/` | Mẫu độc hại (deepset, jackhhao) kiểm thử rào chắn Nonce. |
| **5. Zero-Day Probes** | **154** | 🐍 `experiments/unified_dataset.py` | 📄 Nhúng trong code | Kiểm thử phát hiện dị thường Welford $Z > 3.5\sigma$. |
| **TỔNG GOM (DEMO FULL)** | **496.885** | 🐍 `scripts/build_demo.py` | 📄 `data/demo.json` *(869 MB)* | Tích hợp toàn bộ 5 nguồn thành 1 dòng stream hoàn chỉnh. |
| **TỔNG GOM (DEMO SMALL)** | **8.650** | 🐍 `scripts/build_demo_small.py` | 📄 `data/demo_small.json` *(15 MB)* | Luồng nén chạy demo nhanh 3 phút tại Hội đồng. |

---

## 3. BẢNG 9 BÀI BENCHMARK ⇄ FILE CHẠY ⇄ KẾT QUẢ CỐT LÕI

| Tệp JSON Kết Quả | File Python Chạy Thực Nghiệm | Tập Data Kiểm Thử | Con Số Cốt Lõi Cần Nhớ |
| :--- | :--- | :--- | :--- |
| **1. `latency_benchmark.json`** | 🐍 `measure_latency_baseline.py` | 500 sự kiện đối đầu phân tầng | **Độ trễ trung vị `0,88 ms`** *(đơn tầng 17.174 ms)*. |
| **2. `offload_vs_baserate_stream.json`** | 🐍 `measure_offload_vs_baserate.py` | 99.717 sự kiện luồng tổng hợp | **Tỷ lệ xả tải `97,5%`** *(chỉ 2.5% gọi tới LLM)*. |
| **3. `tier2_decision_results.json`** | 🐍 `evaluate_tier2_decision.py` | 1.066 cảnh báo vùng xám | **Giảm `84,24%` tải SOC**, bắt trúng **`95,0%` đe dọa**. |
| **4. `adversarial_pipeline_results.json`** | 🐍 `evaluate_adversarial.py` | 678 mẫu tấn công khó | **Kháng cự `100.0%`** (678/678) nhờ bọc Nonce ngẫu nhiên. |
| **5. `evidence_grounding_results.json`** | 🐍 `score_evidence_grounding.py` | 1.566 lô log CSIC + CICIDS | **`0` mã bịa đặt (`0.0%` ảo giác)**, chặn 76 lệnh Block sai. |
| **6. `audit_tamper_results.json`** | 🐍 `run_audit_tamper.py` | 450 dòng log SQLite | **Phát hiện `100.0%`** sửa/chèn/xóa log qua chuỗi HMAC. |
| **7. `ml_gate_results.json`** | 🐍 `evaluate_ml_gate.py` | 949k train / 4.2k test | **`100.0%` Auto-BLOCK Precision**, thông lượng **3.452 eps**. |
| **8. `reasoning_eval_results.json`** | 🐍 `evaluate_reasoning.py` | 1.052 lô quyết định | **`3,78 / 5,0` điểm chất lượng** *(Llama-3-8B chấm chéo)*. |
| **9. `thesis_number_audit.json`** | 🐍 `scripts/audit_thesis_numbers.py` | 134 phép đối chiếu LaTeX | **106 đúng · 0 token lệch EN↔VI** (khớp số 100%). |

---

## 🎙️ CÂU NÓI 20 GIÂY KHI THẦY HỎI NGUỒN DATA:
> *"Dữ liệu thực nghiệm của em gồm **496.885 sự kiện thật** từ 5 nguồn chuẩn (CICIDS2018, CSIC2010, DAPT2020, Adversarial...). Em xây dựng module `experiments/unified_dataset.py` để đóng gói phong bì mạng cho HTTP payloads và lấy mẫu bước nhảy giữ đúng tỷ lệ tấn công thực tế (5.24% – 9.8%) mà không làm biến dạng payload gốc."*
