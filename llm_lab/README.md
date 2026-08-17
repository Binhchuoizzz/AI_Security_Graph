# SENTINEL LLM Lab — QLoRA Fine-Tuning & RAFT

> **TRẠNG THÁI: THỬ NGHIỆM, CHƯA DÙNG ĐƯỢC.** Xem mục "Trạng thái thật" bên dưới trước khi
> trích bất cứ điều gì từ thư mục này vào luận văn.

Thư mục `llm_lab` chứa công cụ và dữ liệu để tinh chỉnh (fine-tune) mô hình suy luận của
SENTINEL bằng QLoRA trên dữ liệu định dạng RAFT.

---

## Trạng thái thật (cập nhật 17/08/2026)

| hạng mục | trạng thái |
| :-- | :-- |
| Dựng tập RAFT | ✅ xong |
| Script huấn luyện | ✅ có |
| **Trọng số adapter** | ❌ **CHƯA CÓ** |
| **Nối vào hệ chạy thật** | ❌ **CHƯA** |
| Ảnh hưởng tới số liệu hiện tại | **KHÔNG có** |

Thư mục `models/foundation_sec_qlora_adapter/` **không tồn tại** — không có `adapter_config.json`,
càng không có tệp trọng số `adapter_model.safetensors`. *(Bản tài liệu 03/08 ghi thư mục này còn
`adapter_config.json` 230 byte; nay cả thư mục đã không còn.)* Và không chỗ nào trong
`src/agent/llm_client.py` hay `docker-compose.yml` nạp adapter: hệ vẫn chạy
**Foundation-Sec-8B-Instruct Q4_K_M gốc** qua llama.cpp.

Hệ quả cho luận văn: đây là **Hướng phát triển**, không phải đóng góp đã kiểm chứng. Mọi con
số hiện có đều đo trên model gốc. Muốn tuyên bố fine-tuning có tác dụng thì cần đủ ba việc:
lưu được trọng số → nạp vào runtime → đo lại trên tập hold-out.

---

## Nội dung

| tệp | mô tả |
| :-- | :-- |
| `prepare_raft_dataset.py` | Dựng tập RAFT từ `experiments/ground_truth.json` + CSIC 2010 |
| `train_qlora.py` | Huấn luyện QLoRA adapter cho `Foundation-Sec-8B` |
| `raft_train.jsonl` | **4.952** mẫu huấn luyện (80,0%) |
| `raft_test.jsonl` | **1.238** mẫu kiểm thử (20,0%) |

> **Hai bộ RAFT song song — dễ nhầm.** `experiments/data/raft_{train,test}.jsonl` là bộ CŨ
> (1.400/350, chỉ ground_truth). Bộ trong `llm_lab/` là bộ HIỆN HÀNH, lớn hơn vì đã nạp thêm
> CSIC 2010. Dùng nhầm bộ cũ thì tưởng dữ liệu ít đi 3,5 lần.

---

## Chống rò rỉ dữ liệu — và giới hạn của cơ chế hiện tại

1. **Chia 80/20 cố định** — model chỉ thấy phần train.
2. **Loại mẫu trùng benchmark** — `prepare_raft_dataset.py` băm mọi log trong
   `experiments/ground_truth.json` rồi loại khỏi tập RAFT, để tập chấm điểm giữ nguyên tính
   chưa-từng-thấy.

> **Nói cho đúng mức: đây là "loại trùng lặp CHÍNH XÁC", không phải "zero-overlap 100%".**
> `_hash_log()` băm MD5 trên chuỗi ghép `uri|payload|message`. Nó bắt được bản sao y hệt từng
> ký tự, nhưng **không** bắt được biến thể gần giống — cùng một đòn tấn công, khác một tham
> số (`?id=1` với `?id=2`) sẽ cho hai mã băm khác nhau và cả hai cùng lọt.
>
> Muốn tuyên bố mạnh hơn thì phải chuẩn hoá trước khi băm (bỏ giá trị tham số, giữ khung URI)
> hoặc dùng độ tương đồng gần đúng (MinHash/SimHash) kèm ngưỡng công bố được.

---

## Chạy

```bash
.venv/bin/python llm_lab/prepare_raft_dataset.py    # dựng lại tập RAFT
.venv/bin/python llm_lab/train_qlora.py             # huấn luyện (cần GPU rảnh)
```

Huấn luyện xong phải kiểm có `adapter_model.safetensors` trong
`models/foundation_sec_qlora_adapter/` — thiếu tệp đó nghĩa là lượt chạy **chưa lưu được
trọng số**, dù log có báo hoàn tất.
