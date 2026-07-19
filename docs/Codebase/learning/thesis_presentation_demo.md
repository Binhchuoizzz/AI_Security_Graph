# CHIẾN LƯỢC TRÌNH BÀY & KỊCH BẢN DEMO BẢO VỆ LUẬN VĂN

Tài liệu này hướng dẫn anh cách xây dựng **Slide Thuyết Trình** mang đậm chất Kỹ sư Kiến trúc Hệ thống (System Architect) và **Kịch Bản Bấm Demo** khiến Hội đồng phải thuyết phục hoàn toàn.

---

## PHẦN 1: CẤU TRÚC SLIDE THUYẾT TRÌNH (TỐI ƯU TRONG 15-20 PHÚT)

Đừng đưa quá nhiều code vào Slide. Hội đồng cần nhìn thấy Tư duy giải quyết vấn đề. Dưới đây là sườn Slide chuẩn mực:

**1. Slide 1: Đặt vấn đề (Pain Points của Hệ thống SOC truyền thống)**
- SOC truyền thống bị hội chứng "Alert Fatigue" (Quá tải cảnh báo). Hàng ngàn cảnh báo giả (False Positives) đổ về mỗi ngày khiến chuyên gia bảo mật bỏ sót cảnh báo thật.
- Các bộ lọc tĩnh (Rule-based) hoặc ML truyền thống giải quyết được tốc độ nhưng thiếu khả năng phân tích ngữ cảnh (Contextual Understanding). Kẻ tấn công dễ dàng lẩn tránh (Evasion).

**2. Slide 2: Đề xuất Kiến trúc "SENTINEL: Cognitive Two-Tier SOC"**
- Đưa ra sơ đồ tổng thể kiến trúc: Tier 1 (Nhanh) + Tier 2 (Sâu) + Streaming (Đệm).
- Giải thích triết lý: "Lọc rác bằng công sức máy cày (ML), suy luận tội phạm bằng bộ não thám tử (LLM)".

**3. Slide 3: Tier 1 - Tốc độ & Sự bền bỉ (Machine Learning Gateway)**
- Show sơ đồ LightGBM train trên 1 Triệu logs.
- Nhấn mạnh: Tốc độ < 0.1ms/log.
- Nêu bật tính mới (Novelty): Cơ chế phòng thủ Anti-Evasion (Sanitize NaN, Clamp z-score) để hệ thống ML không bị hacker "đánh lừa".

**4. Slide 4: Tier 2 - Bộ não nhận thức (Cognitive Agent & RAG)**
- Giải thích cách tích hợp LLM (Gemma 9B) ngay tại biên (Local GPU).
- Nêu sự kết hợp giữa **RAG (FAISS) + MITRE ATT&CK** để LLM không bị ảo giác (Hallucination) mà có căn cứ tri thức rõ ràng.
- Giới thiệu Pydantic JSON Output để ép LLM xuất dữ liệu có cấu trúc.

**5. Slide 5: Kỹ nghệ Tối ưu hóa (Engineering Optimizations)**
- Nút thắt cổ chai (Bottleneck) của AI luôn là Tốc độ. Trình bày cách anh phá vỡ nó:
  - **Semantic Cache:** Hash mã độc để gọi LLM ở mức O(1) (từ 3 giây xuống 1ms).
  - **Redis Backpressure:** Dùng Consumer-group lag để hệ thống không sập khi bị DDoS.

**6. Slide 6: Kết quả Thực nghiệm & Đo đạc (Metrics)**
- Vẽ biểu đồ cột: F1 Score đạt 0.9635, Khả năng chống Evasion đạt 99.9%.
- Show khả năng xử lý stream 100,000 logs nhịp nhàng.

---

## PHẦN 2: KỊCH BẢN LIVE DEMO (WHAT TO SHOW & HOW TO TALK)

Khi bắt đầu Demo, đây là thứ tự bấm máy tính và lời thoại anh cần nói:

**Bước 1: Chuẩn bị & Bật Stream**
- Mở Terminal (Chia nửa màn hình) và Dashboard Streamlit (Nửa còn lại).
- Chạy lệnh khởi động Stream 100k logs (`scripts/run_demo.sh`).
- 🗣️ **Lời thoại:** *"Thưa Hội đồng, em xin mô phỏng một cuộc tấn công thực tế cường độ cao. Cửa sổ dòng lệnh bên trái đang chịu áp lực hàng nghìn logs đổ về mỗi giây, được điều áp thông qua hệ thống Redis Streams để tránh tràn RAM (Backpressure)."*

**Bước 2: Khoe Tier 1 (Lọc Thô & Tốc độ)**
- Chỉ tay vào biểu đồ / số lượng bị chặn trên Dashboard tăng lên liên tục.
- 🗣️ **Lời thoại:** *"Thay vì đẩy tất cả vào LLM, Cổng Tier 1 (LightGBM & Rule Engine) đã lập tức chặn đứng hơn 80% các truy cập độc hại phổ thông với tốc độ dưới 1 mili-giây. Điều này giữ cho hệ thống sống sót qua cuộc tấn công."*

**Bước 3: Khoe Tier 2 (LLM & Khả năng giải thích - Explainable AI)**
- Chờ một cảnh báo màu Cam (hoặc loại LLM phân tích) hiện lên trên Dashboard. Bấm vào chi tiết của nó.
- Đọc to phần `Narrative Summary` hoặc `Reasoning` do LLM tạo ra.
- 🗣️ **Lời thoại:** *"Những luồng traffic tinh vi thoát khỏi Tier 1 sẽ bị bắt lại ở Tier 2. Điểm đặc biệt của đồ án là 'Khả năng giải thích'. Thay vì chỉ ra lệnh BLOCK cứng nhắc, LLM Agent đã lập luận chi tiết: Nó đối chiếu hành vi này với kho tri thức MITRE ATT&CK, phát hiện ra kỹ thuật T1110 (Brute Force) và đưa ra quyết định Block rất có cơ sở."*

**Bước 4: Khoe Semantic Cache (Tốc độ LLM)**
- Cuộn xuống các log tấn công giống nhau tiếp theo. Cho hội đồng xem tốc độ xử lý trả về là 1ms.
- 🗣️ **Lời thoại:** *"Hội đồng có thể thấy các đợt tấn công lặp lại sau đó bị hệ thống xử lý chỉ trong 1 mili-giây mà không hề có độ trễ của LLM. Đó là nhờ hệ thống Đệm Ngữ nghĩa (Semantic Cache) em xây dựng để triệt tiêu nút thắt cổ chai."*

---

## PHẦN 3: LƯU Ý SỐNG CÒN (MUST-DO)

1. **QUAY VIDEO BACKUP (FALLBACK):** 100% phải quay lại toàn bộ màn hình kịch bản Demo ở trên thành 1 video mp4 dài 3-5 phút thật mượt mà.
   - *Lý do:* Lúc thuyết trình, RAM máy tính phải chạy PowerPoint, Zoom (nếu online), cộng thêm hồi hộp. Nếu hệ thống sập (Lỗi `database is locked` hoặc OOM), anh lập tức xin phép: *"Do môi trường thực tế có chút biến động tài nguyên, em xin phép bật video Demo mà em đã quay lại trên cùng môi trường này..."*. Hội đồng hoàn toàn chấp nhận việc này.
2. **Không cố thao tác quá nhanh:** Trong lúc hệ thống đang tải nặng, hạn chế bấm F5 (Refresh) liên tục trên Dashboard để tránh lỗi khóa SQLite. Hãy nói chậm, chờ luồng dữ liệu chạy ổn định rồi mới click xem chi tiết cảnh báo.
