# Chính Sách Bảo Mật (SECURITY)

## 1. Báo Cáo Lỗ Hổng (Vulnerability Disclosure Policy)
Chúng tôi khuyến khích mọi cá nhân và tổ chức đánh giá an toàn thông tin (Pentest) dự án này một cách có trách nhiệm.
- **Phạm vi (Scope):** `src/`, `scripts/`, `docker-compose.yml`, và mô hình AI.
- **Ngoại trừ:** Không tấn công hệ thống Redis, MLflow, Neo4j nếu chúng đang chạy trên mạng nội bộ sản xuất (Production).
- **Cách báo cáo:** Vui lòng tạo một Issue trên GitHub với thẻ `[SECURITY]` và gửi kèm Proof of Concept (PoC). Không công khai mã khai thác trước khi chúng tôi ra bản vá (Patch).

## 2. Thông Tin Nhạy Cảm (Sensitive Information)
Dự án cấm tuyệt đối việc commit các tệp tin sau vào Git:
- `.env`
- Các tệp `.pem`, `.key`
- Trọng số mô hình tĩnh `.gguf`, `.safetensors`
- Tệp SQLite chứa dữ liệu thực tế: `mlflow.db`

Nếu bạn phát hiện tệp tin nào bị rò rỉ, vui lòng liên hệ ngay với Maintainer.

## 3. Hardening Checklist cho Deployment
Trước khi đưa hệ thống SENTINEL ra môi trường thực tế (Production), cần rà soát các bước sau:

*   [ ] **Docker Security:** 
    * Chạy Container ở chế độ Rootless.
    * Đảm bảo cờ `no-new-privileges:true` đang được bật trong `docker-compose.yml`.
    * Volume mount mã nguồn chính ở chế độ Read-Only (`:ro`).
*   [ ] **Network & Ports:** 
    * Redis chỉ lắng nghe trên `127.0.0.1`.
    * Neo4j phải được đổi mật khẩu mặc định ngay sau khi khởi tạo.
*   [ ] **API & Auth:** 
    * `LLM_API_KEY` phải là chuỗi ngẫu nhiên dài (e.g., UUID) để tránh bị gọi trộm API từ trong nội bộ mạng.
    * Giao diện Streamlit Dashboard (`port 8501`) phải được bọc đằng sau một Reverse Proxy (như Nginx) cấu hình HTTPS và xác thực cơ bản (Basic Auth).

---
*Xem thêm: [Hướng dẫn Đóng góp](CONTRIBUTING.md) | [Mô hình Đe dọa](docs/threat_model.md)*
