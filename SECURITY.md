# Chính sách Bảo mật & Sử dụng (Security Policy)

> **SENTINEL** — Autonomous AI Security Agent (IDS/SOAR)
> Dự án nghiên cứu cấp Thạc sĩ — AI Security Engineering

---

## Phiên bản được Hỗ trợ (Supported Versions)

| Phiên bản | Trạng thái |
| --- | --- |
| `main` branch (v1.0.0) | ✅ Đang hỗ trợ & cập nhật |
| Các nhánh `dependabot/*` | ⚠️ Tự động tạo — chỉ merge khi CI xanh |

---

## Kiến trúc Bảo mật 7 Lớp (Defense-in-Depth)

SENTINEL được thiết kế theo nguyên tắc **Defense-in-Depth**: Mỗi tầng trong hệ thống đều có lớp phòng thủ riêng.

### Lớp 1: Infrastructure Security (Hạ tầng)

| Thành phần | Biện pháp | File cấu hình |
| --- | --- | --- |
| Redis | Bind `127.0.0.1` only, `requirepass`, disable `FLUSHALL/CONFIG` | `docker-compose.yml` |
| Docker | Non-root user `sentinel`, `no-new-privileges`, resource limits | `Dockerfile` |
| Network | `sentinel_net` bridge isolation, read-only mount volumes | `docker-compose.yml` |
| Secrets | `.env` file gitignored, `.env.example` chỉ chứa placeholder | `.gitignore`, `.env.example` |

### Lớp 2: Tier 1 — Rule Engine (Tầng Tốc Độ)

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| Static Rules | Kiểm tra Port/IP/Threshold tĩnh từ YAML | `config/system_settings.yaml` |
| Dynamic Rules | Luật do LLM sinh ra phải qua HITL Quarantine | `src/tier1_filter/feedback_listener.py` |
| Session Baseline | Z-score Behavioral Baselining với TTL eviction | `src/tier1_filter/rule_engine.py` |
| Whitelist | IP đặc cách (Pentest/Internal) bypass Tier 1 | `config/system_settings.yaml` |

### Lớp 3: Guardrails — Prompt Injection Defense

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| Template Mining | Drain3 nén log (giảm token budget, loại noise) | `src/guardrails/template_miner.py` |
| Encoding Neutralization | Decode Base64/Hex/Unicode trước khi gửi LLM | `src/guardrails/prompt_filter.py` |
| Dynamic Delimiters | `secrets.token_hex()` tạo delimiter mới mỗi request | `src/guardrails/prompt_filter.py` |
| Data Validation | Kiểm tra cấu trúc, loại bỏ trường rác | `src/guardrails/data_validator.py` |

### Lớp 4: RAG Security (Tri thức)

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| Knowledge Base | Read-only mount (`chmod 555` trong Docker) | `Dockerfile` |
| RAG Poisoning Defense | Structural sanitization + provenance checking | `src/rag/security.py` |
| Semantic Cache | Tránh gọi LLM lặp lại cho cùng một query | `src/rag/retriever.py` |

### Lớp 5: LLM Agent Security

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| Local Deployment | LLM chạy nội bộ, không gửi dữ liệu ra Internet | Oobabooga (`localhost:5000`) |
| Structured Output | Ép JSON schema cho LLM response, reject malformed | `src/agent/nodes.py` |
| Rate Limiting | Exponential backoff khi model bận | `src/agent/llm_client.py` |

### Lớp 6: HITL Dashboard Security

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| RBAC | L1 (view-only), L3 (approve/reject/whitelist) | `src/ui/app.py` |
| Authentication | SHA-256 password hashing via `streamlit-authenticator` | `config/system_settings.yaml` |
| Audit Trail | Mọi hành động ghi vào SQLite (không thể xóa từ UI) | `src/response/executor.py` |
| Quarantine | Rule mới phải được L3_Manager approve trước khi active | `src/tier1_filter/feedback_listener.py` |

### Lớp 7: CI/CD & Supply Chain Security

| Thành phần | Biện pháp | File |
| --- | --- | --- |
| CI Pipeline | Auto-run 80 Pytest trên mỗi Push/PR | `.github/workflows/ci.yml` |
| Security Audit | pip-audit + Safety CVE scan hàng tuần | `.github/workflows/security.yml` |
| Secret Scanning | TruffleHog quét toàn bộ commit history | `.github/workflows/security.yml` |
| Dependabot | Auto-PR khi phát hiện CVE trong dependencies | `.github/dependabot.yml` |
| CODEOWNERS | Bắt buộc `@Binhchuoizzz` review trước khi merge | `.github/CODEOWNERS` |
| Pinned Dependencies | Tất cả package ghim phiên bản chính xác (`==`) | `requirements.txt` |

---

## Cảnh báo An ninh (Security Warnings)

1. **Về Mã độc (Adversarial Logs):** Trong quá trình vận hành, hệ thống sẽ tiếp nhận các log payload tấn công (từ CICIDS2017 hoặc Adversarial Testing). **KHÔNG** đưa các file log thực nghiệm lên hệ thống Production hoặc SIEM thật mà chưa làm sạch.

2. **Local Model Only:** Dự án sử dụng LLM nội bộ. Cấu hình ACL hoặc Docker network blocks sao cho port API LLM (`5000`) không mở công khai để chống rò rỉ dữ liệu.

3. **Redis Password:** Luôn thay đổi mật khẩu Redis mặc định trong file `.env` trước khi triển khai.

---

## Thông báo Lỗ hổng (Reporting a Vulnerability)

Mục tiêu lớn nhất của việc tạo Guardrails là ngăn chặn AI bị rò rỉ hoặc bị qua mặt (Bypassed). Việc tìm ra lỗ hổng của Agent là một thành công nghiên cứu.

- Bạn **KHÔNG** cần xin phép mà có thể trực tiếp tạo Issue kèm Proof-of-Concept (PoC) bypass Guardrails.
- Mọi đóng góp PoC bypass đều được ghi nhận là đóng góp trực tiếp cho luận văn.
- Với lỗ hổng bảo mật nghiêm trọng (credential leak, RCE), vui lòng email riêng trước khi public.
