# 🧠 Bản Đồ Quyết Định SENTINEL — Các Tầng Lọc (Tier-1 & Tier-2)

Kiến trúc SENTINEL V2 bao gồm 3 lớp lọc chính, đi từ siêu nhẹ đến suy luận sâu. Bất kỳ IP nào bị đánh dấu "ác ý" ở một tầng sẽ bị xử lý ngay, giảm tải cho các tầng sau.

## 🌟 Tóm Tắt 3 Tầng Quyết Định

| Tầng | Công Nghệ | Vai Trò | Độ Trễ (Latency) |
|---|---|---|---|
| **Tier-1** | Static Rules & Heuristics | Lọc thô, WAF Signatures, chống DDoS, chặn IP khét tiếng. | Rất thấp (~1ms) |
| **Tier-1 · Cổng ML** | LightGBM / Decision Tree | Phát hiện tấn công tinh vi (DAPT) dựa trên Data Drift và Packet Lengths. | Thấp (~10-20ms) |
| **Tier-2 LLM Agent** | Gemma-2 (LangGraph) | Phân tích ngữ cảnh, MITRE ATT&CK, tấn công đa bước & Prompt Injection. | Cao (1-3s) |

---

## 🛡️ 1. TIER-1: Bộ Lọc Cơ Bản (Rule Engine)
**Nhiệm vụ:** Gạt bỏ nhanh các lưu lượng độc hại rõ ràng và giảm tải nhiễu tại cửa ngõ.

### Tiêu chí chấm điểm (Scoring):
Mỗi kiện dữ liệu (Request/Session) sẽ được cộng điểm rủi ro:
1. **WAF Match (+50đ):** Chứa mã độc SQLi, XSS, Command Injection.
2. **Prompt Injection (+50đ):** Chứa từ khóa jailbreak LLM (VD: "ignore previous").
3. **Z-Score Anomaly (+5-40đ):** Sai lệch lưu lượng (bytes/packet) so với hành vi chuẩn đã học.
4. **Static Port (+40đ/30đ):** Truy cập cổng nhạy cảm (22, 3389) hoặc số gói tin quá lớn.
5. **Session Baseline:** Tần suất truy cập dị thường của chính IP đó trong quá khứ.

### Quyết định (Action):
- `WHITELIST`: IP nằm trong Whitelist (Cho qua mọi rào cản, ưu tiên tuyệt đối).
- `BLOCK_IP`: IP có Reputation xấu (từng bị chặn), dính WAF/Brute-force, hoặc đã có luật ở Tier-1.
- `AWAIT_HITL`: Truy cập port lạ không xác định (cần L3 Manager phân tích).
- `ESCALATE`: Nghi ngờ Prompt Injection hoặc điểm rủi ro ≥ 50 nhưng không rõ loại -> Đẩy lên Tier-2.

---

## ⚡ 2. TIER-1.5 CỔNG ML: Lớp Lọc Máy Học Siêu Nhẹ
**Nhiệm vụ:** Phễu lọc trung gian (Middle-box), phát hiện các mẫu tấn công mạng phức tạp mà Tier-1 (Luật tĩnh) bỏ sót, bảo vệ LLM khỏi bị quá tải (Giảm tải nhiễu).

### Điều kiện lọc:
- Trích xuất hàng chục đặc trưng (features) từ Network Flow (độ dài gói tin, thời gian ngắt quãng, tỉ lệ cờ TCP...).
- Đưa qua mô hình học máy dạng cây (LightGBM/Decision Tree) siêu nhẹ.

### Quyết định (Action):
- **Phát hiện Malign (Độc hại):** Ra lệnh `BLOCK_IP` ngay lập tức, tự động ghi chú "Phát hiện tấn công bởi Cổng ML Tier-1".
- **Phát hiện Benign (Bình thường) / Cần ngữ cảnh:** Nếu Cổng ML không chắc chắn nhưng Tier-1 đã chấm điểm cao -> Đẩy (`ESCALATE`) lên LLM Agent phân tích tiếp.

---

## 🧠 3. TIER-2 LLM AGENT: Tác Tử Suy Luận Sâu
**Nhiệm vụ:** Trọng tài cuối cùng (Deep Reasoning), phân tích ngữ cảnh của các ca khó và ánh xạ chính xác kỹ thuật tấn công (MITRE ATT&CK).

### Điều kiện lọc (Agentic Reasoning):
- Gom **10 log liên tiếp** của cùng 1 IP (Batching) để nhìn nhận bức tranh toàn cảnh thay vì từng gói tin đơn lẻ.
- Truy xuất RAG Context: So khớp với tri thức tấn công (MITRE) và Cẩm nang ứng phó (NIST).
- LLM đánh giá các Payload/Header để tìm dấu hiệu khai thác lỗ hổng (Exploit), C&C, hoặc thao túng (Social Engineering).

### Quyết định (Action):
- `BLOCK_IP`: Khẳng định là tấn công rõ ràng / tấn công đa bước.
- `ALERT`: Bất thường nhẹ, cần SOC theo dõi thêm.
- `AWAIT_HITL`: Tình huống mơ hồ, mục tiêu VIP, hoặc xung đột với kết luận của Tier-1 -> Yêu cầu con người phê duyệt.
- `LOG`: Hoàn toàn bình thường (Benign), khép lại cảnh báo.

---

## 🔄 Cơ Chế Học Tập (Feedback Loop & Manual Override)
Sentinel không chỉ là màng lọc 1 chiều mà là một vòng lặp liên tục cải thiện hiệu suất:

1. **Can Thiệp Thủ Công (Manual Override):** Con người (L3 Manager) bấm chặn/whitelist IP trên UI. Quyết định thủ công được duyệt ngay lập tức (Trạng thái: ACTIVE) và áp đặt thẳng xuống Firewall.
2. **Chờ Duyệt (Pending Rules):** Khi Cổng ML (Tier-1) hoặc LLM (Tier-2) chặn 1 IP, hệ thống sẽ đề xuất tạo luật PENDING ở tab Phê duyệt.
3. **ML/LLM Dạy Tier-1:** Sau khi một luật PENDING được con người duyệt thành ACTIVE, Tier-1 cập nhật bộ nhớ. Lần sau IP đó quay lại, Tier-1 sẽ **tự động chặn ở rìa mạng** mà không tốn công gọi ML/LLM nữa, giúp tiết kiệm tài nguyên khổng lồ.
4. **Loại Trừ Xung Đột:** Nếu một IP đang bị chặn (Block) nhưng con người cho vào Whitelist, luật chặn sẽ bị vô hiệu hóa (Rejected) tự động để nhường quyền ưu tiên tuyệt đối cho Whitelist.
