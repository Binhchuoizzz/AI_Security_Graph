# Chính sách Bảo mật & Sử dụng (Security Policy)

Dự án **AI Security Agent (IDS/SOAR)** này là kết quả nghiên cứu cấp Thạc sĩ (AI Security Engineering). Hệ thống được thiết kế với mục đích tự động hóa luồng phân tích SOC và phòng thủ chủ động cấu trúc Trí tuệ Nhân tạo trước các cuộc tấn công mạng, đặc biệt là các cuộc tấn công tiêm mã lệnh nhắm vào LLM (Adversarial AI Attacks - Prompt Injection).

## Thông số Phiên bản (Supported Versions)

Hiện tại, nhánh `main` là luồng phát triển duy nhất và tích cực nhận các bản cập nhật liên quan tới nâng cấp kiến trúc LangGraph và Guardrails.

| Phiên bản               | Trạng thái Hỗ trợ             |
| ----------------------- | ----------------------------- |
| Tích hợp Local LLM (v1) | :white_check_mark: Đang hỗ trợ |
| Triển khai Lab Test     | :warning: Benchmark |

## Cảnh báo An ninh Tích hợp (Critical Warning for Environments)

1. **Về Mã độc (Adversarial Logs):** Trong quá trình vận hành, hệ thống sẽ chứa/tiếp nhận các log payload thật do quá trình mô phỏng giả lập tấn công (từ CICIDS2017 hoặc Adversarial Testing). Tuyệt đối **KHÔNG** đưa các file log thực nghiệm này tải ngược lên các hệ thống Production hoặc SIEM thật của doanh nghiệp mà không làm sạch.
2. **Local Model Only:** Dự án sử dụng mô hình LLM nội bộ (Local Deployment). Vui lòng cấu hình ACL (Access Control List) hoặc Docker network blocks sao cho toàn bộ port API LLM không mở công khai (Public Network) để chống rò rỉ dữ liệu từ bên ngoài.

## Thông báo Lỗ hổng (Reporting a Vulnerability)

Mục tiêu lớn nhất của việc tạo Guardrails là ngăn chặn AI bị rò rỉ hoặc bị qua mặt (Bypassed) từ chính file log rác. Do đó, việc tìm ra lỗ hổng của Agent là một thành công về mặt nghiên cứu.

- Bạn KHÔNG cần thiết xin phép mà có thể thẳng thắn public Issue để chèn Proof-of-concept (PoC) về việc búng mã độc qua mặt Guardrails.
- Mọi đóng góp PoC bypass thành công các luồng suy luận LangGraph đều được ghi nhận là đóng góp trực tiếp cho luận văn Master Thesis này.
