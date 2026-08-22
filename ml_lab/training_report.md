# Báo Cáo Huấn Luyện & So Sánh Mô Hình ML (Cổng ML — Tier 1)

Tài liệu này mô tả quá trình chuẩn bị dữ liệu, chiến lược huấn luyện, so sánh và kết luận rút ra
từ các mô hình Machine Learning truyền thống, được dùng làm **Cổng ML** trong SENTINEL.

## 1. Mục Đích

Kiến trúc SENTINEL là **HAI TẦNG**, tối ưu giữa **Tốc độ (Latency)** và **Chiều sâu suy luận
(Reasoning capability)**:

- **Tier 1 — tất định**: Rule Engine + Welford Z-Score + **Cổng ML** (mục tiêu của Lab này).
- **Tier 2 — nhận thức**: LangGraph Agent + LLM (zero-day và ngữ cảnh tinh vi).

**Cổng ML thuộc Tier-1**, chạy sau luật/Welford và TRƯỚC khi escalate lên Tier-2. Đặt ở Tier-1 để
giải quyết Head-of-Line blocking: chặn đứng ngay các cuộc DDoS/Brute-force rõ ràng ở đường đọc,
KHÔNG để nghẽn hàng đợi LLM.

> ⚠️ **Tên tệp `tier_2_model.pkl` là di sản lịch sử, không phải mô tả kiến trúc.** Mô hình này là
> Cổng ML của **Tier-1**. Bản trước của tài liệu này gọi nó là "Tier 2 Filter" ở tiêu đề rồi lại
> gọi là "thuộc Tier-1" ở phần thân — hai câu mâu thuẫn nhau. Cách gọi đúng: **Cổng ML (Tier-1)**.

## 2. Quá Trình Chuẩn Bị Dữ Liệu (bản 1 TRIỆU — 2026-07-18)

Script `build_1m_dataset.py` tổng hợp tập `dataset_1m.csv` gồm **949.535 mẫu** (NetFlow metrics)
từ **CICIDS2018**, tỉ lệ **~79% attack / ~21% benign** (mục tiêu 80/20; sau khử trùng lặp còn):

1. **Benign (Bình thường):** 200.000 mẫu (~21%).
2. **Attack (đa dạng):** 749.535 mẫu (~79%) — BruteForce (FTP/SSH), DoS (Hulk/GoldenEye/
   Slowloris/SlowHTTP), DDoS (HOIC/LOIC-UDP), Botnet, Infiltration, Web (BruteForce/XSS/SQLi).

Đọc **CHUNKED** từ 9 file-ngày CICIDS (bỏ Tuesday-20 do lỗi trích xuất nghiêm trọng), **khử
trùng lặp** (dữ liệu thô ~17% trùng → chống rò rỉ train/test), tách cột định danh (IP/Timestamp),
chỉ giữ 76 cột số, **trộn đều** (seed=42). *(Bản 100k cũ `dataset_100k.csv` + `train_and_compare.py`
được GIỮ làm mốc đối chiếu lịch sử; notebook `train_and_compare.ipynb` đã xoá 21/08/2026 — nó chỉ là
bản xuất của cùng script đó, mọi số đã nằm trong bảng §4 dưới đây.)*

## 3. Chiến Lược Phân Chia Dữ Liệu

Dữ liệu ~949k dòng chia theo tỉ lệ chuẩn (stratify theo nhãn):

- **Tập Train (70%):** 664.674 mẫu — huấn luyện.
- **Tập Validation (10%):** ~94.954 mẫu — đánh giá nội bộ / tinh chỉnh siêu tham số.
- **Tập Test / Tập Thi (20%):** 189.907 mẫu — đánh giá tổng quát hóa cuối cùng.

Việc giữ Benign ~21% và Attack ~79% là **cố tình** (thiên recall) giúp Cổng ML tập trung nhận
diện bất thường tần suất cao, phản xạ nhanh & dứt khoát; độ chính xác triển khai được kiểm soát
bởi **chính sách 4 dải độ-tin-cậy** của cổng: `C≥0.85`→BLOCK · `0.65≤C<0.85`→ESCALATE (LLM) ·
`0.40≤C<0.65`→ALERT (low-priority) · `C<0.40`→PASS/DROP.

## 4. Kết Quả Huấn Luyện & So Sánh

File `train_1m.py` huấn luyện 5 thuật toán: `Logistic Regression`, `Decision Tree`,
`Random Forest`, `XGBoost`, `LightGBM` (LightGBM — mô hình thắng — được tinh chỉnh cho quy mô
1M: **400 cây, 127 lá, learning_rate 0.05**). Metrics đầy đủ ở `ml_lab/train_1m_metrics.json`.

Kết quả trên Tập Test (**189.907 dòng**, held-out):

| Model | Test F1 | Precision | Recall | FPR | Inference (ms/sample) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **LightGBM** (tinh chỉnh) | **0.9635** | 0.9548 | 0.9723 | **0.1724** | 0.00077 |
| XGBoost | 0.9429 | 0.9500 | 0.9360 | 0.1848 | 0.000149 |
| Decision Tree | 0.9422 | 0.9411 | 0.9433 | 0.2211 | 0.000102 |
| Random Forest | 0.9402 | 0.9400 | 0.9403 | 0.2248 | 0.001051 |
| Logistic Regression | 0.9278 | 0.9125 | 0.9436 | 0.3392 | 0.000039 |

> 🔴 **Cột FPR là con số phải tự nêu.** LightGBM có F1 0,9635 nhưng **FPR 17,24%** — hệ quả trực
> tiếp của việc cố ý huấn luyện trên tập 79% attack (thiên recall). Trích F1 mà giấu FPR là trình
> bày một nửa. Chính FPR này là lý do dải auto-BLOCK phải đặt cao ở 0,85 thay vì 0,5.

Ngoài F1 test held-out, đo thêm hành vi **triển khai thực** của Cổng ML trên luồng gộp
`data/datatest.json` (`experiments/evaluate_ml_gate.py`) và mức giảm tải LLM
(`run_ablation.py --mode mlgate`, Config G):

Benchmark `data/datatest.json` = **4.240 mẫu** — `cicids` 1.171 · `cicids_max` 1.169 · **CSIC 2010**
1.036 · `dapt_max` 469 · zero-day real-derived 360 · `dapt` 31 · đối kháng tự soạn 4. Sau
`drop_authored` còn **4.236** ca được chấm. **Chính sách 4 dải** (C≥0.85 BLOCK · 0.65–0.85 ESCALATE ·
0.40–0.65 ALERT · <0.40 PASS). Vì hành động quyết định là **auto-BLOCK**, chỉ số headline là **độ
chính xác auto-BLOCK**.

| Chỉ số triển khai (datatest 4.236, lượt 06/08/2026) | Giá trị |
| :--- | :--- |
| **Auto-BLOCK (C≥0.85) precision** | **100%** — 962 lệnh, **0 FP** (Wilson 99,6–100) |
| Kháng né-tránh — chế độ KHÓ `extreme_broad` | **98,75%** (1.023/1.036 · CI95 97,86–99,27) |
| Giảm tải LLM (bypass, Config G) | **68,19%** — 761/1.116 · F1(bypass) 0.9739 · P 0.9882 |
| MCC trên phần Cổng ML tự quyết | **0.6667** — BalAcc 0.8328, mẫu số **2.534**, không phải 4.236 |
| F1 gộp (tính CẢ dải ALERT-0.40 là "tấn công") | 0.8248 (P 0.909 / R 0.755) — *xem chú thích* |

**Nhận xét Kết Quả:**

- LightGBM thắng với **F1 96,35%** trên Tập Test 190k held-out (số của MODEL, không đổi khi đổi
  benchmark triển khai).
- **Auto-BLOCK sạch trên benchmark này:** ở dải C≥0.85 Cổng ML chặn 962 luồng mà **0 benign bị chặn
  nhầm**. Nhưng lý do là **ngưỡng đặt cao**, không phải mô hình giỏi: cùng lượt đo, dải ALERT chỉ đạt
  precision **0,416** (74 TP / 104 FP). Đây là số của benchmark 4.236 cụ thể, không phải tuyên bố
  tổng quát.
- **Chú thích trung thực về F1 gộp 0.8248:** con số này lấy CẢ dải ALERT (0.40–0.65) làm "dự đoán tấn
  công"; ngưỡng ALERT thấp nên 104 benign low-priority bị cảnh báo → kéo F1 xuống. ALERT là cảnh báo
  **không chặn**, nên chấp nhận được — nhưng phải nói rõ mẫu số.
- **`bypass_rate` 59,82%:** trong 4.236 ca vào, chỉ **2.534** được Cổng ML tự quyết; 1.586 ca bỏ qua vì
  thiếu đặc trưng NetFlow và 116 ca abstain. Trích MCC 0,667 mà ghi mẫu số 4.236 là **sai mẫu số** —
  `audit_metric_denominators.py` gắn cờ đúng chỗ này.
- Tốc độ dự đoán ≤ 0,001 ms/mẫu — không ảnh hưởng đường đọc Tier-1.

## 5. Kết Luận & Quyết Định Kiến Trúc

Cổng ML đã được huấn luyện đủ mạnh để nhận diện các đợt tấn công tần suất cao từ CICIDS2018:

- **Với DDoS/Brute Force:** Cổng ML thường tự tin > 0,85 và tự động chặn ngay (Early Exit `BLOCK_IP`),
  không tốn một token LLM nào.
- **Lưu trữ:** mô hình thắng là **LightGBM** (tinh chỉnh cho 1M), xuất ra `dict` gồm `scaler`, `model`,
  `features`, lưu ở **`ml_lab/tier_2_model.pkl`** (bản cũ backup `tier_2_model_100k.bak.pkl`), do Cổng
  ML của **Tier-1** nạp lúc chạy.
- **Đường thoát lên Tier-2:** log rơi vào dải ESCALATE (0.65 ≤ C < 0.85) hoặc lệch phân bố
  (OOD-abstain / thiếu feature) sẽ escalate lên **Tier-2 (LLM Agent)** đánh giá ngữ cảnh.

> **Giới hạn khái quát hoá phải tự nêu.** Tập train/test chia **ngẫu nhiên**, không chia theo thời
> gian. Nghiên cứu *"The Evaluation Protocol Is the Hidden Variable"* (06/2026) quét đúng LightGBM
> trên đúng họ dữ liệu này và cho thấy macro-F1 tụt từ 0,79–0,82 (chia ngẫu nhiên) xuống **≈0,02**
> khi chia theo thời gian.
