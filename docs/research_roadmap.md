# Lộ Trình Nghiên Cứu (Research Roadmap)

Dự án SENTINEL hiện đang trong quá trình chuẩn bị bảo vệ Luận văn Thạc sĩ. Dưới đây là lộ trình phát triển tương lai.

## 1. Trạng Thái Hiện Tại (Current Status)
- ✅ Hoàn thiện **Tier 1 (Rule-based Filter)** với khả năng chặn nhiễu.
- ✅ Tích hợp **Tier 2 (LLM Agent)** sử dụng LangGraph.
- ✅ Áp dụng cơ chế **Dual-RAG** (MITRE Enterprise & NIST SP 800-61r2).
- ✅ Thiết kế kiến trúc **Short-term Memory** (Redis) và **Vulnerability Graph** (Neo4j).
- ✅ Đánh giá hiệu năng với bộ dữ liệu CSE-CIC-IDS2018 (E2E Ablation Study).

## 2. Kế Hoạch Các Cột Mốc (Next Milestones)

### Giai đoạn 3 tháng (Short-term)
- Triển khai **Mã nguồn thực tế cho Vulnerability Pipeline** (Tích hợp Trivy Scanner trực tiếp qua Python SDK thay vì bash).
- Tối ưu hóa **Guardrails** để giảm thiểu độ trễ xử lý (Latency) xuống dưới 1 giây.
- Deploy hệ thống lên môi trường Docker Swarm.

### Giai đoạn 6 tháng (Mid-term)
- Thử nghiệm với các Local Model nhỏ nhưng chuyên dụng cho an ninh mạng (như **CyberLlama** hoặc các model Finetuned từ Llama-3 8B).
- Triển khai tính năng **Tự động đóng băng tài khoản (Account Freeze)** tương tác với Active Directory khi có rủi ro Insider Threat.

### Giai đoạn 12 tháng (Long-term)
- Chuyển đổi toàn bộ Long-term Memory sang **Vector Database chuyên dụng (Milvus)** để phục vụ quy mô Data Center.
- Đưa hệ thống lên môi trường Hybrid Cloud (AWS + On-Premise).

## 3. Câu Hỏi Nghiên Cứu Mở (Open Research Questions)
1. **Explainability (Khả năng Giải thích):** Làm sao để định lượng độ tin cậy của Agent khi nó quyết định BLOCK_IP dựa trên "cảm nhận" của RAG thay vì Rules cứng?
2. **Adversarial AI:** Nếu hacker sử dụng LLM để tự động thay đổi cấu trúc mã độc liên tục (Polymorphic AI Malware), RAG Database cập nhật mỗi 24h có đủ sức chống đỡ?
3. **Data Privacy:** Xử lý thế nào nếu PII (Thông tin cá nhân) vô tình lọt vào Payload log và bị đẩy cho Agent đọc?
