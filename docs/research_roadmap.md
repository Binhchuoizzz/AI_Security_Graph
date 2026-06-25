# Lộ Trình Nghiên Cứu (Research Roadmap)

Dự án SENTINEL hiện đang trong quá trình chuẩn bị bảo vệ Luận văn Thạc sĩ. Dưới đây là lộ trình phát triển tương lai.

## 1. Trạng Thái Hiện Tại (Current Status)

- ✅ Hoàn thiện **Tier 1 Filter**: Tích hợp Rule Engine (Stateless/Stateful) kết hợp với thuật toán **Welford** online để phát hiện **Unsupervised Outlier (Zero-day attacks)** thời gian thực dựa trên Z-Score lưu lượng.
- ✅ Tích hợp **Tier 2 (LLM Agent)**: Phát triển luồng suy luận bằng LangGraph sử dụng mô hình `Gemma-2-9B-IT`, tích hợp **Few-shot Active Learning** tự động lấy ví dụ dynamic rules được duyệt/từ chối từ Human-in-the-loop để cải thiện prompt.
- ✅ Áp dụng cơ chế **Dual-RAG** (MITRE Enterprise & NIST SP 800-61r2) và bộ đệm ngữ cảnh **Semantic Cache**.
- ✅ Thiết kế kiến trúc **Short-term Memory** (Redis), **Long-term Threat Memory** (SQLite để lưu vết APT/DAPT2020) và **Vulnerability Graph** (Neo4j).
- ✅ Thiết lập khung đánh giá **5D Evaluation Framework** (Classification, Operational, Robustness, Context Quality, Explainability) + đánh giá Zero-day riêng và tự động quản lý thí nghiệm qua **MLflow**.
- ✅ Tích hợp tiện ích **Docker Model Switcher** (`switch_model.sh`) hỗ trợ hot-swap mô hình LLM trọng tài và tác tử.
- ✅ **Độ bền & quan sát LLM (2026-06):** suy luận tất định (`seed=42`), **suy biến an toàn** khi LLM chết → `AWAIT_HITL` (đồ thị không vỡ), và **quan sát ngân sách ngữ cảnh** (`token_monitor` → `config/llm_token_stats.json`, KPI Context Utilization trên Dashboard).
- ✅ **Nâng độ chặt chẽ thực nghiệm (rebut hội đồng):** độ nhạy ngưỡng Welford, zero-day phân cấp (đường cong k·σ), đối chứng âm APT + Wilson 95% CI, ablation B–E + cân bằng 150/150, stress ngữ cảnh — tất cả chạy thật, tất định khi không cần LLM.

## 2. Kế Hoạch Các Cột Mốc (Next Milestones)

### Giai đoạn 3 tháng (Short-term)
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

