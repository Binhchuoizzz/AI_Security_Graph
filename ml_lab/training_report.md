# Báo Cáo Huấn Luyện & So Sánh Mô Hình ML (Tier 2 Filter)

Tài liệu này mô tả chi tiết quá trình chuẩn bị dữ liệu, chiến lược huấn luyện, so sánh và kết luận rút ra từ các mô hình Machine Learning truyền thống, được sử dụng làm **Tier 2** trong hệ thống Agentic AI (SENTINEL).

## 1. Mục Đích
Kiến trúc SENTINEL phân tầng quy trình phát hiện tấn công để tối ưu hóa giữa **Tốc độ (Latency)** và **Chiều sâu suy luận (Reasoning capability)**:
- **Tier 1**: Welford Rule Engine (Thống kê Z-Score & Luật tĩnh).
- **Tier 2 (Mục tiêu của Lab này)**: Sử dụng các mô hình Machine Learning siêu nhẹ (như XGBoost, Decision Tree) làm bộ lọc Early Exit. Nhiệm vụ là chặn đứng ngay lập tức các cuộc tấn công DDoS/Brute-force rõ ràng (đã biết), tiết kiệm chi phí gọi API LLM.
- **Tier 3**: GenAI / LLM Triage (Xử lý Zero-day và ngữ cảnh tinh vi).

## 2. Quá Trình Chuẩn Bị Dữ Liệu
Script `build_100k_cicids.py` được sử dụng để tổng hợp tập dữ liệu `dataset_100k.csv` bao gồm chính xác 100.000 mẫu (NetFlow metrics) từ hệ dữ liệu **CICIDS2018**:
1. **Benign (Bình thường):** 20.000 mẫu (20%).
2. **Attack (Tấn công đa dạng):** 80.000 mẫu (80%) bao gồm Infiltration, DDoS (LOIC/HOIC), Botnet, DoS, Brute Force, Web Attacks, v.v.

Dữ liệu được trích xuất đều từ 10 ngày thu thập của bộ CICIDS2018. Tất cả dữ liệu này được **trộn đều (Shuffle)** và các cột định danh dạng chữ (như IP, Timestamp) được tách riêng, chỉ giữ lại các cột số (numerical) nhằm tạo ra một tập huấn luyện chuẩn cho ML Tier 2.

## 3. Chiến Lược Phân Chia Dữ Liệu
Dữ liệu tổng hợp (100k dòng) được phân chia theo tỉ lệ chuẩn để đảm bảo tính khái quát của mô hình, mô phỏng như sau:
- **Tập Train (70%):** Dùng để huấn luyện các mô hình.
- **Tập Validation (10%):** Dùng để đánh giá nội bộ và tinh chỉnh siêu tham số.
- **Tập Test / Tập Thi (20%):** Dùng để đánh giá khả năng tổng quát hóa cuối cùng của các mô hình.

Việc giới hạn lượng Benign ở 20% và Attacks ở mức 80% là cố tình giúp hệ thống tập trung nhận diện các dấu hiệu bất thường (anomaly) với tần suất cao, giúp Cổng ML Tier 2 phản xạ nhanh và dứt khoát hơn. Phần dữ liệu không đưa vào train (50.000 dòng cuối của tập dataset) được trích xuất ra thành file `demo_50k_cicids.csv` để mô phỏng một luồng dữ liệu thời gian thực (Online Streaming Demo) đối mặt trực tiếp với các zero-day không xác định.

## 4. Kết Quả Huấn Luyện & So Sánh
File `train_and_compare.py` / `train_and_compare.ipynb` tiến hành huấn luyện 5 thuật toán: `Logistic Regression`, `Decision Tree`, `Random Forest`, `XGBoost`, và `LightGBM`. Toàn bộ quá trình huấn luyện, metrics (F1, Precision, Recall, Inference Time) và mô hình tốt nhất đều được tự động log lên hệ thống **MLflow Tracking** (tại `http://localhost:5001`, experiment: `Sentinel_ML_Tier2_Training`).

Kết quả thu được trên Tập Test (20k dòng):
| Model | Test F1 | Precision | Recall | Inference (ms/sample) |
|---|---|---|---|---|
| **LightGBM** | **0.9666** | 0.9774 | 0.9559 | 0.000467 |
| **XGBoost** | 0.9634 | 0.9873 | 0.9406 | 0.000119 |
| **Decision Tree** | 0.9582 | 0.9683 | 0.9482 | 0.000095 |
| **Random Forest** | 0.9578 | 0.9660 | 0.9497 | 0.001228 |
| **Logistic Regression**| 0.9506 | 0.9529 | 0.9483 | 0.000044 |

**Nhận xét Kết Quả:**
- Tất cả các thuật toán đều đạt độ F1-Score trên **95%**, nhưng LightGBM là thuật toán thể hiện tốt nhất với **F1-Score 96.66%**.
- Tốc độ dự đoán (Inference time) của các thuật toán cực kỳ ấn tượng, chỉ mất vài phần triệu giây (vài microseconds) để phân tích một luồng mạng.

## 5. Kết Luận & Quyết Định Kiến Trúc
Bộ lọc Tier 2 đã được đào tạo cực kì mạnh mẽ để nhận diện các đợt tấn công từ CICIDS2018:
- **Với các cuộc tấn công DDoS/Brute Force:** Tier 2 sẽ tự tin >95% và tự động chặn đứng ngay lập tức (Early Exit `BLOCK_IP`).
- **Lưu ý Kiến trúc Hệ thống:** Vì model xuất sắc nhất là **LightGBM** (hoặc Decision Tree tuỳ lần chạy được pickle), nên file mô hình được xuất ra dưới định dạng Tự Điển (`dict`) bao gồm `scaler`, `model`, và danh sách `features`. File này được lưu ở `tier_2_model.pkl` và được Node ML Triage đọc vào lúc chạy Agent_UI. Mọi log mới nếu bị model từ chối do độ tin cậy thấp sẽ tự động tuồn xuống LLM (Tier-3) đánh giá ngữ cảnh.
