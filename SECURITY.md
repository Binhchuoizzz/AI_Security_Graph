# 🛡️ Chính Sách Bảo Mật (Security Policy)

[![Security Policy: Active](https://img.shields.io/badge/Security%20Policy-Active-brightgreen.svg?style=flat-square)](#1-báo-cáo-lỗ-hổng-vulnerability-disclosure-policy)
[![Audit Status: Passed](https://img.shields.io/badge/Audit%20Status-8%20Layers%20Clean-059669.svg?style=flat-square)](#4-bản-vá-bảo-mật-gần-đây-audit-2026-06)
[![Responsible Disclosure](https://img.shields.io/badge/Disclosure-Coordinated-blue.svg?style=flat-square)](#1-báo-cáo-lỗ-hổng-vulnerability-disclosure-policy)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)

Dự án **SENTINEL** cam kết bảo vệ an toàn thông tin và áp dụng các nguyên tắc phòng thủ đa tầng (Defense-in-Depth) xuyên suốt toàn bộ mã nguồn, cấu hình hạ tầng và luồng suy luận của Tác tử AI.

---

## 📑 Mục Lục

1. [Chính Sách Báo Cáo Lỗ Hổng (Vulnerability Disclosure Policy)](#1-báo-cáo-lỗ-hổng-vulnerability-disclosure-policy)
2. [Quản Lý Thông Tin Nhạy Cảm (Sensitive Information)](#2-thông-tin-nhạy-cảm-sensitive-information)
3. [Danh Mục Kiểm Tra Tăng Cường Bảo Mật (Hardening Checklist)](#3-hardening-checklist-cho-deployment)
4. [Lịch Sử Bản Vá Bảo Mật (Security Audit Log)](#4-bản-vá-bảo-mật-gần-đây-audit-2026-06)

---

## 1. Báo Cáo Lỗ Hổng (Vulnerability Disclosure Policy)

Chúng tôi đặc biệt khuyến khích các nhà nghiên cứu an toàn thông tin, chuyên gia pentest và cộng đồng đánh giá bảo mật dự án này theo nguyên tắc **Tiết lộ có trách nhiệm (Coordinated Disclosure)**:

- **Phạm vi (In-Scope):** Mã nguồn trong `src/`, các kịch bản `scripts/`, cấu hình `docker-compose.yml`, các cơ chế Guardrails, bộ phân lớp LightGBM và mô hình AI.
- **Ngoại trừ (Out-of-Scope):** Không tấn công từ chối dịch vụ (DoS/DDoS) hạ tầng Redis, MLflow, Neo4j nếu chúng đang chạy trên mạng nội bộ sản xuất (Production).
- **Cách thức báo cáo:** Vui lòng tạo một Issue bảo mật trên GitHub với nhãn `[SECURITY]` hoặc liên hệ trực tiếp Maintainer kèm theo **Proof of Concept (PoC)**. Vui lòng **không công khai** mã khai thác cho đến khi bản vá chính thức được phát hành.

---

## 2. Thông Tin Nhạy Cảm (Sensitive Information)

> [!CAUTION]
> **Các Tệp Tuyệt Đối Cấm Commit Vào Kho Mã Nguồn Git:**
>
> - File cấu hình chứa khóa bí mật: `.env`
> - Các chứng chỉ và khóa mật mã: `*.pem`, `*.key`, `*.pfx`
> - Trọng số mô hình AI tĩnh có dung lượng lớn: `*.gguf`, `*.safetensors`, `*.bin`
> - Tệp cơ sở dữ liệu SQLite chứa log thực tế hoặc telemetry: `mlflow.db`, `audit_trail.db`

Nếu bạn phát hiện bất kỳ tệp tin nhạy cảm nào bị vô tình đưa lên Git, vui lòng thông báo khẩn cấp cho Maintainer để tiến hành thu hồi và xoay vòng khóa bí mật (Secret Rotation).

---

## 3. Hardening Checklist cho Deployment

Trước khi đưa hệ thống SENTINEL ra môi trường thực tế (Production / Air-gapped SOC), cần rà soát kỹ lưỡng danh mục sau:

### A. Docker & Container Isolation

- [ ] ✅ Chạy toàn bộ Container ở chế độ **Rootless**.
- [ ] ✅ Đảm bảo cờ `no-new-privileges: true` được kích hoạt trong `docker-compose.yml`.
- [ ] ✅ Volume mount mã nguồn chính của ứng dụng ở chế độ chỉ đọc (**Read-Only** `:ro`).

### B. Network & Ports

- [ ] ✅ Cấu hình Redis chỉ lắng nghe cục bộ trên `127.0.0.1` hoặc trong Docker Internal Bridge Network.
- [ ] ✅ Thay đổi toàn bộ mật khẩu mặc định của cơ sở dữ liệu (Neo4j, Redis, MLflow) ngay sau khi khởi tạo.

### C. API & Authentication

- [ ] ✅ Biến `LLM_API_KEY` phải là chuỗi ngẫu nhiên dài (UUID v4 / Token 256-bit) để ngăn chặn truy cập trái phép.
- [ ] ✅ Giao diện SOC Dashboard (Streamlit `port 8501`) phải được đặt phía sau **Reverse Proxy (Nginx / Caddy)** cấu hình HTTPS (TLS 1.3) và xác thực Basic Auth / OAuth2.

---

## 4. Bản Vá Bảo Mật Gần Đây (Audit 2026-06)

Đã rà soát độc lập **8 lớp vector tấn công** (*Secrets, SQL Injection, Command Injection, Deserialization, Path Traversal, SSRF, Cryptography, Third-party Dependencies*). Toàn bộ 8 lớp đã được gia cố vững chắc:

- 🔐 **Authentication (CWE-798 / CWE-259):** `src/ui/auth.py` — **Loại bỏ hoàn toàn mật khẩu dạng rõ (Plaintext) khỏi mã nguồn**, thay thế bằng thuật toán băm chuẩn **PBKDF2-HMAC-SHA256 (100.000 vòng lặp)**. Cơ chế tự động cảnh báo `fail-loud` khi phát hiện salt/hash demo. Mật khẩu demo được lưu riêng trong tài liệu `RUN_PROJECT.md`.
- 🛡️ **Anti-Self-DoS Shield:** `DecisionValidator` đã được tinh chỉnh từ `trusted_internal_subnets` (toàn dải RFC 1918 — quá rộng, khiến không chặn được attacker nội bộ/lateral movement) sang **`critical_infrastructure_subnets` thu hẹp có chủ đích** (chỉ bảo vệ Loopback và IP máy chủ hạ tầng cốt lõi `10.0.0.99`).
- 📦 **CVE Dependency Pinning:** Tệp `requirements.txt` ghim cứng phiên bản an toàn tối thiểu cho các thư viện trung gian có CVE (*`aiohttp >= 3.14.0`*, *`authlib >= 1.6.12`*, *`gitpython >= 3.1.50`*, *`pyjwt >= 2.13.0`*, *`langchain-core >= 1.3.3`*); `torch CVE-2025-3000` được ghi nhận theo diện rủi ro chấp nhận được (accepted-risk) trong môi trường local air-gapped.
- 🧹 **Resource Leak (CWE-404):** Đã rà soát và bọc toàn bộ 10 vị trí mở file bằng cú pháp ngữ cảnh chuẩn `with open(...) as f:` đảm bảo tự động đóng file descriptor.

> [!NOTE]
> **Lưu ý về cơ chế thực thi chặn:**
> Hàm `block_ip()` trong `src/response/executor.py` hiện tại là **`[FIREWALL MOCK]`** (thực hiện ghi vết kiểm toán HMAC-SHA256 an toàn, không trực tiếp can thiệp `iptables` hệ điều hành). Cơ chế chặn thực tế diễn ra ở vành ngoài Tier-1 sau khi quyết định được duyệt qua quy trình HITL. Trong môi trường Production thực tế, mock này sẽ được thay thế bằng API của Firewall / WAF phần cứng.

---

*Xem thêm tài liệu liên quan: [Hướng Dẫn Đóng Góp (CONTRIBUTING.md)](CONTRIBUTING.md) | [Hướng Dẫn Chạy & Demo Dự Án (RUN_PROJECT.md)](docs/Codebase/guides/RUN_PROJECT.md)*
