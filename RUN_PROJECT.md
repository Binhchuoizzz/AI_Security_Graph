# Hướng Dẫn Vận Hành Hệ Thống SENTINEL v3 (Cập nhật 22/04)

Tài liệu này không chỉ hướng dẫn chạy code, mà còn **giải thích rõ ràng mạch tư duy bảo vệ luận văn**, trả lời trực tiếp những câu hỏi phản biện hóc búa nhất của Hội đồng.

---

## I. GIẢI NGỐ KIẾN TRÚC: "3 Model của tôi nằm ở đâu?"

Nhiều người nhầm tưởng "Model" cứ phải là một con LLM nặng nề. Trong kiến trúc SENTINEL, chúng ta có 3 "Bộ não" (Models) phối hợp với nhau tạo thành 2 Tier:

1. **Bộ não 1: Rule Engine & Session Baseline (Tier 1)**
   - **Nằm ở đâu:** Chạy trực tiếp trên RAM bằng Python thuần (`src/tier1_filter/rule_engine.py`).
   - **Chức năng:** Không phải AI, mà là một mô hình thuật toán Heuristic. Nó có khả năng cản phá và vứt bỏ (DROP) 99% rác mạng ở tốc độ sấm sét (hàng chục nghìn log/giây).

2. **Bộ não 2: Embedding Model - `all-MiniLM-L6-v2` (Tier 2 - RAG)**
   - **Nằm ở đâu:** Tự động chạy ngầm trong Python (thông qua thư viện `sentence-transformers`).
   - **Chức năng:** Biến các log và text thành các vector toán học để tìm kiếm tri thức từ thư viện MITRE ATT&CK (FAISS Vector DB).

3. **Bộ não 3: Reasoning LLM - `Gemma 9B` (Tier 2 - LangGraph Agent)**
   - **Nằm ở đâu:** Chạy độc lập trên **Oobabooga WebUI** (`http://localhost:5000`).
   - **Chức năng:** Bộ não "to" nhất, đóng vai trò như một chuyên gia an ninh mạng. Chỉ những luồng dữ liệu 1% thoát qua được Tier 1 mới bị gọi lên đây để LLM phân tích sâu.

---

## II. CHIẾN LƯỢC DATASET: "Tại sao lại trích xuất nhỏ lại?"

Hội đồng chắc chắn sẽ hỏi: *"Tại sao không chạy LLM trên toàn bộ 2.8 triệu dòng của bộ dataset CICIDS2017?"*

**Câu trả lời chuẩn xác:**
Chúng ta CHIA dự án làm 2 Pha đánh giá hoàn toàn riêng biệt:

- **Pha 1: Demo "Sát thực tế" (Streaming Pipeline):** Dùng nguyên file dataset khổng lồ (`Demo-Attack.csv` chứa hàng triệu dòng). Ta bắn dữ liệu ồ ạt vào hệ thống để chứng minh **Tier 1 (Bộ não 1)** chịu tải tốt như thế nào, nó drop sạch rác và chỉ nhả những IP độc hại (DDoS) lên cho LLM. Đây là bài toán về **Hiệu năng hệ thống (Throughput)**.
- **Pha 2: Đánh giá Học thuật (Ablation Study):** Dùng tập dataset siêu nhỏ (`ground_truth.json` gồm 101 mẫu). Lý do: LLM chạy mất 15 giây/mẫu. Nếu bắt LLM chạy 2.8 triệu mẫu sẽ mất... hàng tháng trời! Đánh giá độ thông minh (F1-score) của AI trên 100-500 mẫu được gán nhãn kĩ càng là **tiêu chuẩn khoa học thế giới**.

---

## III. TIMELINE CHẠY PROJECT (THỨ TỰ BẬT CÁC TERMINAL)

Để xem **trực tiếp các Node hoạt động như thế nào**, hãy bật lần lượt các Terminal sau:

### Bước 1: Khởi động Hạ tầng
**Terminal 1:** Bật Redis (Nơi hứng log) và MLflow (Nơi vẽ biểu đồ).
```bash
docker-compose up -d redis mlflow
```

### Bước 2: Bật Oobabooga LLM (Bên ngoài dự án này)
Hãy chắc chắn Oobabooga đang chạy ở `http://127.0.0.1:5000` và đã load model Gemma.

### Bước 3: Khởi chạy Trái Tim Hệ Thống (SENTINEL Core)
**Terminal 2:**
```bash
source .venv/bin/activate
python main.py
```
> 💡 **XEM CÁC NODE HOẠT ĐỘNG Ở ĐÂY:** Ngay khi có log tấn công lọt vào, Terminal này sẽ in ra từng bước đi của LangGraph: `--- NODE: RAG CONTEXT ---`, `--- NODE: LLM TRIAGE ---`, v.v.

### Bước 4: Bật Màn Hình Giám Sát (Dashboard SOC)
**Terminal 3:**
```bash
source .venv/bin/activate
streamlit run src/ui/app.py
```
*(Mở trình duyệt: Username `manager` / Password `sentinel_manager_2026`)*

### Bước 5: Bắt đầu cuộc tấn công (Sát thực tế)
**Terminal 4:** Bắn file Dataset khổng lồ vào hệ thống.
```bash
source .venv/bin/activate
python src/streaming/publisher.py
```
> 💡 Lúc này, bạn hãy nhìn sang Terminal 2 để xem Tier 1 gầm rú và ném log lên cho LLM, sau đó nhìn sang trình duyệt (Terminal 3) để thấy các lệnh `BLOCK_IP` xuất hiện đỏ rực!

---

## IV. TIMELINE CHẠY CHẤM ĐIỂM (Dành cho Slide báo cáo)

Đánh giá gồm 2 Pha: **Classification Accuracy** (Toán học) + **Reasoning Quality** (LLM-as-Judge).

### Pha 1: Statistical Evaluation (Gemma 9B loaded)

```bash
# 1. Chạy bài test 101 mẫu (đợi khoảng 15-20 phút cho Oobabooga trả lời hết)
python experiments/run_ablation_study.py

# 2. Sinh ra điểm thống kê P-Value (Chứng minh AI không đoán mò)
python experiments/statistical_tests.py
```

### Pha 2: Reasoning Quality (Chuyển sang Llama 3 8B)

```bash
# 3. Trên Oobabooga: Unload Gemma 9B → Load Llama 3 8B Instruct
# 4. Chạy LLM-as-Judge (Llama 3 chấm điểm Gemma 9B)
python experiments/evaluate_reasoning.py
```

> 💡 **Tại sao cần 2 model?** Gemma 9B không thể tự chấm điểm chính mình (Self-Enhancement Bias — Zheng et al., 2023). Llama 3 (Meta) khác model family với Gemma (Google) → đánh giá khách quan.

Sau đó vào `http://localhost:5001` (MLflow) để chụp ảnh màn hình các thông số dán vào Luận văn!
