# SENTINEL LLM Lab — QLoRA Fine-Tuning & RAFT Architecture

Thư mục `llm_lab` chứa toàn bộ công cụ, dữ liệu và mô hình huấn luyện tinh chỉnh (Fine-Tuning) cho **SENTINEL SOC Agent**.

---

## 📌 Nội dung Thư mục

- **`prepare_raft_dataset.py`**: Trích xuất dữ liệu log từ `experiments/ground_truth.json`, phân chia theo tỷ lệ **80% Train Set (1,400 mẫu)** và **20% Unseen Test Set (350 mẫu)** theo định dạng **RAFT (Retrieval-Augmented Fine-Tuning)**.
- **`train_qlora.py`**: Script huấn luyện QLoRA adapter cho mô hình `Foundation-Sec-8B`.
- **`raft_train.jsonl`**: Tập dữ liệu huấn luyện (1,400 mẫu).
- **`raft_test.jsonl`**: Tập dữ liệu kiểm thử độc lập (350 mẫu, không rò rỉ dữ liệu).

---

## 🛡️ Nguyên tắc Chống Rò rỉ Dữ liệu (Anti-Data Leakage)
1. **Chia 80/20 Cố định:** Mô hình chỉ được nhìn thấy 80% dữ liệu huấn luyện.
2. **Hold-out Test Set:** Mọi chỉ số Benchmark E2E cuối cùng được đo trên 20% Unseen Test Set chưa từng xuất hiện trong quá trình Fine-Tune.
