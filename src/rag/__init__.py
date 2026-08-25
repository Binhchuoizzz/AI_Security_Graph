"""Truy xuất lai Dual-RAG trên kho MITRE ATT&CK và NIST SP 800-61r2.

Gồm bốn phần: Embedder dựng chỉ mục FAISS từ kho tri thức; Retriever tìm lai
FAISS + BM25 rồi hợp nhất bằng RRF; SemanticCache dùng lại kết quả nhúng cho
truy vấn trùng; Security làm sạch cấu trúc tài liệu để chống đầu độc RAG.

CHẠY CỤC BỘ THẬT SỰ. `sentence-transformers` mặc định gọi huggingface.co mỗi lần
nạp mô hình để đối chiếu bản mới, kể cả khi tệp đã nằm trong cache. Đo ngày
25/08/2026: một lần `import src` bắn hơn hai mươi request HTTP ra ngoài - đúng thứ
mà tuyên bố air-gapped của luận văn nói là không có. Chốt hai biến này TRƯỚC khi
`sentence_transformers` được nạp thì thư viện chỉ đọc cache, không chạm mạng.

Vẫn để ghi đè được: ai cần tải mô hình mới thì đặt sẵn biến môi trường trước khi
chạy (ví dụ `HF_HUB_OFFLINE=0`), nhánh dưới không đụng vào giá trị đã có.
"""

import os

for _var in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
    os.environ.setdefault(_var, "1")
