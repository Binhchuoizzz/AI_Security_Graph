# Báo Cáo Huấn Luyện & So Sánh Mô Hình ML (Tier 2 Filter)

Tài liệu này mô tả chi tiết quá trình chuẩn bị dữ liệu, chiến lược huấn luyện, so sánh và kết luận rút ra từ các mô hình Machine Learning truyền thống, được sử dụng làm **Tier 2** trong hệ thống Agentic AI (SENTINEL).

## 1. Mục Đích
Kiến trúc SENTINEL phân tầng quy trình phát hiện tấn công để tối ưu hóa giữa **Tốc độ (Latency)** và **Chiều sâu suy luận (Reasoning capability)**:
- **Tier 1**: Welford Rule Engine (Thống kê Z-Score & Luật tĩnh).
- **Cổng ML — thuộc Tier-1 (Mục tiêu của Lab này)**: chặng lọc MÁY HỌC của Tier-1 (chạy sau luật/Welford, TRƯỚC khi escalate lên Tier-2 LLM), dùng mô hình siêu nhẹ (LightGBM) làm bộ lọc Early Exit. Đặt ở Tier-1 để giải quyết Head-of-Line blocking: chặn đứng ngay các cuộc DDoS/Brute-force rõ ràng ở đường đọc, KHÔNG để nghẽn hàng đợi LLM. Kiến trúc luận văn vẫn là HAI TẦNG: Tier-1 (luật + Welford + Cổng ML) và Tier-2 (LLM Agent).
- **Tier 2 — LLM Agent**: chặng sau của cùng Tier-2 — GenAI/LLM Triage (xử lý zero-day và ngữ cảnh tinh vi). Kiến trúc luận văn là HAI tầng: ML và LLM là 2 chặng trong một Tier-2.

## 2. Quá Trình Chuẩn Bị Dữ Liệu (bản 1 TRIỆU — 2026-07-18)
Script `build_1m_dataset.py` tổng hợp tập `dataset_1m.csv` gồm **949.535 mẫu** (NetFlow metrics)
từ **CICIDS2018**, tỉ lệ **~79% attack / ~21% benign** (mục tiêu 80/20; sau khử trùng lặp còn):
1. **Benign (Bình thường):** 200.000 mẫu (~21%).
2. **Attack (đa dạng):** 749.535 mẫu (~79%) — BruteForce (FTP/SSH), DoS (Hulk/GoldenEye/
   Slowloris/SlowHTTP), DDoS (HOIC/LOIC-UDP), Botnet, Infiltration, Web (BruteForce/XSS/SQLi).

Đọc **CHUNKED** từ 9 file-ngày CICIDS (bỏ Tuesday-20 do lỗi trích xuất nghiêm trọng), **khử
trùng lặp** (dữ liệu thô ~17% trùng → chống rò rỉ train/test), tách cột định danh (IP/Timestamp),
chỉ giữ 76 cột số, **trộn đều** (seed=42). *(Bản 100k cũ `dataset_100k.csv` + `train_and_compare.ipynb`
được GIỮ làm mốc đối chiếu lịch sử.)*

## 3. Chiến Lược Phân Chia Dữ Liệu
Dữ liệu ~949k dòng chia theo tỉ lệ chuẩn (stratify theo nhãn):
- **Tập Train (70%):** 664.674 mẫu — huấn luyện.
- **Tập Validation (10%):** ~94.954 mẫu — đánh giá nội bộ / tinh chỉnh siêu tham số.
- **Tập Test / Tập Thi (20%):** 189.907 mẫu — đánh giá tổng quát hóa cuối cùng.

Việc giữ Benign ~21% và Attack ~79% là **cố tình** (thiên recall) giúp Cổng ML tập trung nhận
diện bất thường tần suất cao, phản xạ nhanh & dứt khoát; độ chính xác triển khai được kiểm soát
bởi **ngưỡng tin cậy 0.90** của cổng (dưới ngưỡng → escalate LLM).

## 4. Kết Quả Huấn Luyện & So Sánh

File `train_1m.py` huấn luyện 5 thuật toán: `Logistic Regression`, `Decision Tree`,
`Random Forest`, `XGBoost`, `LightGBM` (LightGBM — mô hình thắng — được tinh chỉnh cho quy mô
1M: **400 cây, 127 lá, learning_rate 0.05**). Metrics đầy đủ ở `ml_lab/train_1m_metrics.json`.

Kết quả trên Tập Test (**189.907 dòng**, held-out):

| Model | Test F1 | Precision | Recall | Inference (ms/sample) |
|---|---|---|---|---|
| **LightGBM** (tinh chỉnh) | **0.9635** | 0.9548 | 0.9723 | 0.000875 |
| **XGBoost** | 0.9429 | 0.9500 | 0.9360 | 0.000151 |
| **Decision Tree** | 0.9422 | 0.9411 | 0.9433 | 0.000096 |
| **Random Forest** | 0.9402 | 0.9400 | 0.9403 | 0.000922 |
| **Logistic Regression** | 0.9278 | 0.9125 | 0.9436 | 0.000044 |

Ngoài F1 test held-out, đo thêm hành vi **triển khai thực** của Cổng ML (ngưỡng 0.90) trên
luồng gộp `data/datatest.json` (`experiments/evaluate_ml_gate.py`) và mức giảm tải LLM
(`run_ablation.py --mode mlgate`, Config G):

Benchmark `data/datatest.json` được **cân bằng lại 2026-07-19** thành 2514 mẫu, đủ **15 lớp
tấn công CICIDS đều tay** (70/lớp) + benign + DAPT (day2-5) + zero-day + adversarial — KHÓ hơn
hẳn bản cũ (vốn bị Infiltration/DDoS lấn át) nên số F1 triển khai giảm nhưng **trung thực hơn**.

| Chỉ số triển khai (benchmark 2.5k mới) | Giá trị |
|---|---|
| F1 (Cổng ML, benchmark gộp 15-lớp) | **0.936** |
| Precision / Recall | 0.9746 / 0.9004 |
| Kháng né-tránh (Inf/cực-đoan) | **99.93%** |
| Giảm tải LLM (bypass, Config G, ground_truth 1250) | **85.1%** — F1(bypass) 0.9911 |

**Nhận xét Kết Quả:**

- LightGBM thắng với **F1-Score 96.35%** trên Tập Test 190k held-out (số của MODEL, không đổi).
- Trên **benchmark gộp MỚI (15-lớp cân bằng, khó hơn)**: F1 triển khai **0.936** (P 0.975 / R 0.900).
  Thấp hơn 0.9803 của benchmark cũ (Infiltration-heavy) vì tập mới đa dạng đều tay (gồm Infiltration/
  Bot vốn khó). Khi Cổng ML TỰ QUYẾT (bypass), F1 vẫn **0.9911** — rất chính xác lúc tự tin.
- Tốc độ dự đoán vẫn ở mức vài phần triệu giây/luồng (≤ 0.001 ms/sample) — không ảnh hưởng
  đường đọc Tier-1.

## 5. Kết Luận & Quyết Định Kiến Trúc
Bộ lọc Tier 2 đã được đào tạo cực kì mạnh mẽ để nhận diện các đợt tấn công từ CICIDS2018:
- **Với các cuộc tấn công DDoS/Brute Force:** Tier 2 sẽ tự tin >95% và tự động chặn đứng ngay lập tức (Early Exit `BLOCK_IP`).
- **Lưu ý Kiến trúc Hệ thống:** Model xuất sắc nhất là **LightGBM** (tinh chỉnh cho 1M), file
  mô hình xuất ra dạng Tự Điển (`dict`) gồm `scaler`, `model`, `features`. Lưu ở `tier_2_model.pkl`
  (tên file giữ theo lịch sử; bản cũ backup `tier_2_model_100k.bak.pkl`) và được Cổng ML của
  Tier-1 nạp lúc chạy. Mọi log bị model từ chối do độ tin cậy thấp (< 0.90) hoặc lệch phân bố
  (OOD-abstain) sẽ tự động escalate lên **Tier-2 (LLM Agent)** đánh giá ngữ cảnh.
