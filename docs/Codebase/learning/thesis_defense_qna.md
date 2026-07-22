# CẨM NANG BẢO VỆ LUẬN VĂN: SENTINEL AI SECURITY GRAPH
*(Bản Toàn Diện Bao Quát Mọi Ngóc Ngách Hệ Thống)*

Tài liệu này bao quát **Toàn bộ hệ thống** từ lúc nhận data đến lúc ra quyết định Block. Hãy học thuộc **BẢN CHẤT** thay vì học thuộc lòng code. Nếu Hội đồng hỏi xoáy, hãy bám vào các triết lý thiết kế (Design Philosophy) ở đây.

---

## PHẦN 1: KIẾN TRÚC LUỒNG DỮ LIỆU & BỘ ĐỆM (STREAMING PIPELINE)

**Q1: Tại sao không ném log mạng thẳng vào mô hình AI mà phải qua Redis?**
- **Trả lời:** Chênh lệch tốc độ (Impedance Mismatch). Mạng xả 100,000 logs/giây, nhưng LLM xử lý mất 2-3 giây/log. Nếu bơm trực tiếp, RAM sẽ tràn (OOM) và hệ thống chết đứng. Redis Streams đóng vai trò là "Hồ chứa giảm xóc" (Message Broker) để cân bằng tải.

**Q2: Làm sao hệ thống biết khi nào nó đang bị quá tải (Nghẽn cổ chai)?**
- **Trả lời:** Em không đo độ dài hàng đợi tĩnh (`xlen`), vì nó rất vô nghĩa nếu có nhiều Node cùng xử lý. Em sử dụng cơ chế đo **Consumer-Group Lag** (Độ trễ của luồng xử lý). Đây là chuẩn công nghiệp (Backpressure) giống hệt Kafka, giúp hệ thống tự động điều tiết tốc độ nhả log theo sức chịu đựng của GPU.

---

## PHẦN 2: TIER 1 - BỘ LỌC THÔ (RULE ENGINE & ML GATEWAY)

**Q3: Khâu Rule Engine (Luật tĩnh) của em có bị chậm khi đối chiếu hàng vạn chuỗi tấn công không?**
- **Trả lời:** Không ạ. Tier 1 nằm trên "Hot-path" (luồng chạy nhiều nhất), nên em đã thiết kế tối ưu Big-O:
  - **Dùng Substring thay vì Regex:** Regex rất tốn CPU. Em ép toàn bộ payload về chữ thường và dùng thuật toán tìm kiếm chuỗi con (Toán tử `in`) nhanh hơn gấp nhiều lần.
  - **Set O(1):** Tập các cổng nhạy cảm (sensitive_ports) được ép kiểu Set để tốc độ lookup luôn là O(1) thay vì O(n) của List.

**Q4: Tại sao Tier 1 dùng thuật toán LightGBM (Cây quyết định) mà không dùng Deep Learning (CNN, LSTM) cho "xịn"?**
- **Trả lời:** Dữ liệu bắt được từ luồng mạng (CICIDS) bản chất là dữ liệu dạng bảng (Tabular Data) với các đặc trưng số. LightGBM luôn đánh bại mạng nơ-ron (Deep Learning) trên dữ liệu bảng về cả F1 Score (0.9635) lẫn tốc độ nội suy (chỉ < 0.1ms/log). Deep Learning bị "Overkill" (quá mức cần thiết) và quá chậm để làm lớp Filter.

**Q5: Nếu Hacker cố tình bơm các giá trị cực đoan (Vd: Infinity) để lừa mô hình ML (Evasion Attack) thì sao?**
- **Trả lời:** ML Gate của em có cơ chế **Anti-Evasion (Chống lẩn tránh)** 3 lớp:
  1. *Sanitize:* Đổi NaN/Infinity thành giá trị Trung bình (Mean) để tránh crash.
  2. *Clamp (Kẹp):* Giới hạn z-score ở ngưỡng ±8σ. Một giá trị cực đoan không thể làm lật dự đoán của cả mô hình.
  3. *OOD Abstain:* Nếu có trên 30% feature vượt ngưỡng 6σ, mô hình sẽ không cố đoán bừa. Nó trả về `Abstain` và nhường lại quyền quyết định cho AI LLM ở Tier 2.

---

## PHẦN 3: LỚP TỐI ƯU HÓA (TIER 1.75 - CACHING LAYER)

**Q6: Hệ thống AI của em rất thông minh, nhưng nếu gặp tấn công DDoS hoặc Brute-Force (10,000 request giống nhau) thì LLM có bị treo không?**
- **Trả lời:** Tuyệt đối không. Em đã thiết kế **Semantic Cache (Bộ nhớ đệm ngữ nghĩa)** ở Tier 1.75.
  - Nó băm (MD5 Hash) mã độc/payload của request.
  - Lần đầu LLM tốn 3 giây để ra quyết định Block. Quyết định này được nạp vào Cache.
  - 9,999 request sau (có cùng mã băm), Cache trả kết quả ngay lập tức trong 1 mili-giây mà không hề gọi tới LLM, đập tan nút thắt cổ chai "LLM Bottleneck".

---

## PHẦN 4: TIER 2 - CỔNG PHÂN TÍCH SUY LUẬN (COGNITIVE LLM AGENT)

**Q7: LLM rất hay bị ảo giác (Hallucination) và xuất văn bản tự do. Làm sao ép nó trả về kết quả chuẩn để hệ thống tự động Block IP?**
- **Trả lời:** Em sử dụng **Pydantic** để ép kiểu cấu trúc tĩnh (Structured JSON Output).
  - Trái tim của Tier 2 là Llama.cpp kết hợp Pydantic Validation. Nếu LLM trả sai cấu trúc, hệ thống có Regex (`_salvage_fields`) để tự vớt vát dữ liệu.
  - **Cực kỳ an toàn:** Nếu JSON nát hoàn toàn, hệ thống tự động đẩy cờ `AWAIT_HITL` (Chờ con người duyệt) chứ tuyệt đối không Block nhầm.

**Q8: Mỗi lần gọi LLM mất thời gian đọc lại System Prompt rất tốn kém?**
- **Trả lời:** Em đã cấu trúc lại Prompt để **giữ System Prompt ở trạng thái Tĩnh (Static)**. Các dữ liệu biến động (Feedback, Log) được đẩy vào User Prompt. Kỹ thuật này giúp bộ nhớ GPU lưu lại được **KV-Cache**, giảm thời gian chờ Token đầu tiên (TTFT) xuống mức thấp nhất.

---

## PHẦN 5: RAG & CƠ SỞ TRI THỨC (MITRE ATT&CK)

**Q9: LLM (Gemma 9B) làm sao biết được các chuẩn mã độc mới nhất để gán nhãn MITRE ATT&CK?**
- **Trả lời:** LLM không tự nhớ. Em dùng công nghệ **RAG (Retrieval-Augmented Generation)** với cơ sở dữ liệu Vector FAISS.
  - Khi có hành vi lạ, FAISS sẽ tìm top-3 chiến thuật MITRE giống nhất trong kho tri thức, rồi đính kèm (Few-shot) vào Prompt.
  - LLM chỉ đóng vai trò phân tích đối chiếu, không phải tự tưởng tượng.

**Q10: Mã T1571 (Non-Standard Port) rất chung chung, lỡ nó quét cổng bình thường rồi hệ thống block bừa thì sao?**
- **Trả lời:** Em có **Guardrail (Rào chắn) riêng cho T1571**. Nếu LLM chỉ quy kết được tội T1571, hệ thống sẽ hạ mức tự tin xuống `low_confidence` và ép sang trạng thái `AWAIT_HITL`. Thà bắt nhầm lên giao diện cho người duyệt còn hơn Block nhầm khách hàng thật (Zero False Positive Goal).

---

## PHẦN 6: INFRASTRUCTURE & THREAT MEMORY

**Q11: Danh sách đen (Threat Memory) em lưu ở đâu? Lỡ hệ thống crash có mất không?**
- **Trả lời:** Lưu tĩnh ở đĩa bằng cơ sở dữ liệu SQLite. Điểm đặc biệt:
  - Em đã cố tình **TẮT chế độ WAL (Write-Ahead Logging)** và dùng `synchronous=NORMAL`.
  - Nếu bật WAL, SQLite sẽ tự sinh ra file tạm `-wal` dẫn đến xung đột quyền tài khoản (Cross-UID) làm Crash Docker. Việc tắt WAL đảm bảo tính tương thích và ổn định tuyệt đối trong môi trường ảo hóa.

**Q12: Zero Trust nghĩa là không tin ai cả, vậy một IP bị Block thì sẽ bị khóa vĩnh viễn sao?**
- **Trả lời:** Hệ thống có tính điểm danh tiếng (Reputation Score).
  - Các lỗi nhẹ thì điểm sẽ tự giảm dần theo thời gian (Decay Rate = 0.95) để khoan hồng.
  - Riêng hành vi đặc biệt nguy hiểm (Reputation đạt kịch trần 100), hệ thống sẽ kích hoạt cờ **Permanent Block-on-sight** (Chặn ngay lập tức vĩnh viễn). Tuy nhiên, vì dải IPv4 thường cấp phát động (DHCP), trong thực tế doanh nghiệp ta có thể reset cờ này nếu được admin xác nhận thủ công.

---

## PHẦN 7: CHÍNH SÁCH QUYẾT ĐỊNH & LEO THANG (DECISION POLICY & ESCALATION)

**Q13: Làm sao đảm bảo LLM không "tự tung tự tác" ra lệnh Block sai lệch?**
- **Trả lời:** Cốt lõi của hệ thống nằm ở tệp `decision_policy.py` - đóng vai trò là **Nguồn Chân Lý Duy Nhất (Single Source of Truth)**.
  - Em không cho phép LLM tự chọn hành động. Cả Cổng ML và LLM đều phải tuân theo "Chính sách 4 dải điểm tự tin (Confidence)": `C >= 0.85` (Tự động BLOCK), `0.65 - 0.85` (CẢNH BÁO / ĐẨY LÊN LLM), `0.40 - 0.65` (CẢNH BÁO / CHỜ NGƯỜI DUYỆT), `C < 0.40` (BỎ QUA).
  - Bằng cách ép LLM chấm điểm Confidence của bằng chứng, hệ thống kỹ thuật (Code) sẽ LÁI quyết định cuối cùng, loại trừ hoàn toàn việc AI "tự ái" hay "đoán bừa".

**Q14: Nếu một IP liên tục tấn công nhưng ở mức độ nhẹ (ví dụ như rò quét rải rác) khiến LLM chỉ ném ra ALERT, thì chẳng phải hệ thống cứ để nó tự do sao?**
- **Trả lời:** Dạ không, hệ thống có cơ chế **"Repeat-Offender Escalation" (Leo thang Kẻ tái phạm)**.
  - Hàm `raise_alert` hoạt động như một Choke-point (Nút cổ chai). Khi một IP bị cảnh báo (ALERT) lần đầu, hệ thống lưu vào Threat Memory.
  - Nếu IP đó tái phạm và bị cảnh báo **lần thứ 2**, hệ thống sẽ nhận diện nó là "Kẻ cứng đầu" (Known-bad) và **tự động thăng cấp (Escalate) từ ALERT thành thẳng BLOCK_IP**. Cơ chế này bảo vệ hệ thống khỏi chiến thuật tấn công chậm (Slow & Low Attack) cực kỳ hiệu quả giống hệt các WAF Doanh nghiệp.

---

## PHẦN 8: XỬ LÝ SỰ CỐ & KINH NGHIỆM THỰC TẾ (TROUBLESHOOTING & LESSONS LEARNED)

**Q15: Trong quá trình xây dựng, em từng gặp tình huống LLM gần như không bao giờ phát hiện được các tấn công tầng ứng dụng (SQLi, XSS) chưa? Em đã giải quyết thế nào?**
- **Trả lời:** Dạ đây là một bài học đắt giá về lỗi "Tước bằng chứng". Hệ thống ban đầu khi đóng gói Log gửi lên LLM đã chỉ lấy các thông số mạng tĩnh (Port, Duration...) mà bỏ sót các trường payload (`message`, `uri`, `User-Agent`). Hệ quả là LLM hoàn toàn bị "mù" trước các cuộc tấn công Web.
  - *Khắc phục:* Em đã cấu trúc lại luồng đóng gói `TemplateMiner`, truyền đầy đủ Payload thô vào Prompt cho LLM. Tất nhiên, để chống Prompt Injection (hacker chèn lệnh độc vào payload), em rào chắn kỹ payload bằng thẻ `<<<DATA_BEGIN...>>>` và giới hạn số ký tự. Kết quả là khả năng phát hiện SQLi/XSS của LLM tăng vọt lên 99%.

**Q16: Tại sao đưa thẳng Payload thô vào hệ thống RAG (FAISS) lại khiến việc đối chiếu chiến thuật MITRE ATT&CK bị sai lệch?**
- **Trả lời:** Vì Payload thô chứa rất nhiều "từ nhiễu" làm lệch không gian vector. Ví dụ, một lệnh SQL Injection có chứa từ "password" (`SELECT password FROM users`) sẽ khiến FAISS tưởng nhầm đây là kỹ thuật dò mật khẩu (T1110) thay vì đúng là tấn công Web (T1190).
  - *Khắc phục:* Em đã tinh chỉnh Query của RAG: Chuyển đổi nhãn của Tier-1 thành các **Cụm từ khóa tiếng Anh chuẩn hóa theo MITRE** và đặt lên ĐẦU truy vấn, còn payload thô bị đẩy xuống cuối (và cắt ngắn). Nhờ đó, FAISS bám sát đúng "văn phạm an ninh mạng" mà không bị từ ngữ thông thường làm nhiễu.
