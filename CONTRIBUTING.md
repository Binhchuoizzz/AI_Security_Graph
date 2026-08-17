# 🛠️ Hướng Dẫn Đóng Góp (Contributing Guidelines)

[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square)](https://github.com/Binhchuoizzz/AI_Security_Graph/pulls)
[![Branching: Feature Workflow](https://img.shields.io/badge/Workflow-Feature%20Branch-blue.svg?style=flat-square)](#1-branching-strategy-chiến-lược-rẽ-nhánh)
[![Commits: Conventional](https://img.shields.io/badge/Commits-Conventional-orange.svg?style=flat-square)](#2-commit-convention-quy-ước-commit)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff%20%2F%20PEP8-black.svg?style=flat-square)](https://github.com/astral-sh/ruff)

Cám ơn bạn đã quan tâm đến việc đóng góp mã nguồn và nghiên cứu cho dự án **SENTINEL: Cognitive Two-Tier SOC Architecture**. Dưới đây là các tiêu chuẩn kỹ thuật và quy trình chuẩn cần tuân thủ khi cộng tác.

---

## 📑 Mục Lục

1. [Chiến Lược Rẽ Nhánh (Branching Strategy)](#1-branching-strategy-chiến-lược-rẽ-nhánh)
2. [Quy Ước Commit (Commit Convention)](#2-commit-convention-quy-ước-commit)
3. [Cách Thêm Detection Module Mới](#3-cách-thêm-một-detection-module-mới-module-mở-rộng)
4. [Quy Trình Kiểm Thử & Chạy Test](#4-quy-trình-kiểm-thử--chạy-test)
5. [Pull Request Checklist](#5-pull-request-checklist-kiểm-tra-trước-khi-nộp-pr)

---

## 1. Branching Strategy (Chiến Lược Rẽ Nhánh)

Dự án áp dụng mô hình **Feature Branch Workflow**:

| Nhánh (Branch) | Mục Đích Sử Dụng | Quyền Hạn Merge |
| :--- | :--- | :--- |
| `main` | Production-ready & Bản nộp Luận văn chuẩn | Chỉ nhận merge từ các PR đã pass 100% CI & Review |
| `feature/<tên>` | Phát triển tính năng mới (VD: `feature/trivy-scanner`) | PR thẳng vào `main` |
| `fix/<tên>` | Sửa lỗi (VD: `fix/redis-timeout`) | PR thẳng vào `main` |
| `perf/<tên>` | Tối ưu hiệu năng (VD: `perf/parallel-agent-workers`) | PR thẳng vào `main` |

> [!NOTE]
> Kho này **không có nhánh `develop`**. Mọi nhánh làm việc rẽ từ `main` và PR ngược về `main`;
> tiền tố nhánh dùng đúng bộ `type` của Conventional Commits ở mục 2 để tên nhánh và tên commit
> nói cùng một thứ.

---

## 2. Commit Convention (Quy Ước Commit)

Tuân thủ chuẩn **Conventional Commits** để chuẩn hóa lịch sử Git và tự động hóa việc sinh Changelog:

```text
<type>(<scope>): <mô tả ngắn gọn về thay đổi>
```

| Type | Ý Nghĩa & Mục Đích | Ví Dụ Cụ Thể |
| :--- | :--- | :--- |
| `feat` | Thêm tính năng hoặc module mới | `feat(rag): add BM25 reciprocal rank fusion indexer` |
| `fix` | Sửa lỗi trong mã nguồn hoặc logic | `fix(tier1): handle Redis connection timeout gracefully` |
| `docs` | Cập nhật tài liệu, README, hướng dẫn | `docs(readme): update 5D benchmark results table` |
| `style` | Cải thiện giao diện, màu sắc, format | `style(slides): enhance high-contrast color scheme` |
| `refactor` | Tái cấu trúc mã nguồn, không đổi logic | `refactor(agent): split decision validator into helper classes` |
| `perf` | Tối ưu hiệu năng, giảm độ trễ, giảm tải GPU | `perf(slides): replace 3D transforms with 2D micro-lifts` |
| `test` | Thêm mới hoặc cập nhật Unit/Integration test | `test(offline): add offline validation for slide deck assets` |

---

## 3. Cách Thêm Một Detection Module Mới (Module Mở Rộng)

Nếu bạn muốn đóng góp một Rule mới cho Tier 1 hoặc một Node mới cho Agent Tier 2:

### A. Với Tier 1 (Rule Engine & Lọc Nhanh $\mathcal{O}(1)$)

SENTINEL **không** sử dụng hệ plugin `BaseRule`. Có 2 cách thêm luật:

1. **Khai báo (khuyến nghị):** Thêm vào `static_rules` / `dynamic_rules` trong `config/system_settings.yaml` — `RuleEngine` **hot-reload mỗi 5 giây**, không cần khởi động lại dịch vụ. Luật động qua Dashboard còn được kiểm duyệt bởi `FeedbackValidator` (Zero-Trust) + HITL.
2. **Bằng code:** Mở rộng phương thức `evaluate()` trong `src/tier1_filter/rule_engine.py` (trả về một action hợp lệ: `DROP` / `LOG` / `ALERT` / `BLOCK_IP` / `AWAIT_HITL` / `ESCALATE`), kèm Unit Test tương ứng trong `tests/unit/`.

### B. Với Tier 2 (LangGraph Cognitive Multi-Agent)

SENTINEL sử dụng **LangGraph `StateGraph`**, **không** dùng `@tool` của LangChain:

1. Viết một hàm node chuẩn: `node_<tên>(state: SentinelState) -> Dict[str, Any]` trong `src/agent/nodes.py`.
2. Đăng ký node vào đồ thị bằng `workflow.add_node(...)` và nối các cạnh điều kiện (conditional edges) trong `src/agent/workflow.py`.
3. Mọi quyết định phát ra từ LLM bắt buộc phải đi qua `DecisionValidator` + `enforce_tier_consensus` trước khi kích hoạt hành động phản hồi.

---

## 4. Quy Trình Kiểm Thử & Chạy Test

> [!IMPORTANT]
> **Biến Môi Trường Bắt Buộc:**
> Khi chạy pytest, **luôn luôn** đặt `SENTINEL_FREEZE_DYNAMIC_RULES=1` để tránh việc quá trình test tự động ghi đè ~1.400 luật học được vào file `config/system_settings.yaml`.

```bash
# 1. Kích hoạt môi trường ảo
source .venv/bin/activate

# 2. Kiểm tra định dạng mã nguồn (Ruff)
ruff check src/ tests/
ruff format --check src/ tests/

# 3. Chạy toàn bộ bộ test: 613 ca thu thập -> 609 pass, 4 skip khi không có Redis
SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest tests/ --tb=short

# 4. Chạy kiểm toán đối chiếu số liệu
python scripts/audit_thesis_numbers.py
```

---

## 5. Pull Request Checklist (Kiểm Tra Trước Khi Nộp PR)

Trước khi nhấn nút **Create Pull Request**, hãy tự rà soát danh sách kiểm tra sau:

- [ ] ✅ **Unit Tests:** Mã nguồn mới đã có Unit Test đi kèm với độ bao phủ (Coverage) cao.
- [ ] ✅ **Xanh Toàn Bộ Tests:** Lệnh `SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest` chạy thành công (609 passed, 4 skipped).
- [ ] ✅ **Code Quality:** Tuân thủ chuẩn PEP 8 và đã chạy qua linter `ruff`.
- [ ] ✅ **Tài Liệu:** Đã cập nhật tài liệu Markdown (`README.md`, `RUN_PROJECT.md`) nếu có thay đổi kiến trúc/API.
- [ ] ✅ **Bảo Mật:** Tuyệt đối không commit tệp nhạy cảm (token, mật khẩu, file `.env`, database `.db`).

> [!TIP]
> Mọi Pull Request sẽ được Maintainer xem xét, đánh giá và phản hồi trong vòng **3–5 ngày làm việc**. Cảm ơn sự đồng hành và đóng góp chất lượng của bạn!
