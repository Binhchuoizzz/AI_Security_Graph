# Hướng Dẫn Đóng Góp (Contributing)

Cám ơn bạn đã quan tâm đến việc đóng góp mã nguồn cho dự án **SENTINEL**. Dưới đây là các tiêu chuẩn và quy trình bạn cần tuân thủ.

## 1. Branching Strategy (Chiến Lược Rẽ Nhánh)
Dự án áp dụng mô hình Feature Branch Workflow:
- `main`: Nhánh production-ready, chỉ nhận merge từ các PR đã được test đầy đủ.
- `develop`: Nhánh chứa các tính năng đang phát triển.
- `feature/<tên-tính-năng>`: Nhánh cá nhân để bạn làm việc (VD: `feature/trivy-scanner`).
- `bugfix/<tên-lỗi>`: Nhánh để sửa lỗi khẩn cấp (VD: `bugfix/redis-timeout`).

## 2. Commit Convention (Quy Ước Commit)
Tuân thủ Conventional Commits để tự động hóa việc sinh Changelog:
- `feat:` Thêm tính năng mới (VD: `feat: add Neo4j graph builder module`)
- `fix:` Sửa lỗi (VD: `fix: handle Redis connection timeout gracefully`)
- `docs:` Cập nhật tài liệu (VD: `docs: update architecture diagram`)
- `refactor:` Tái cấu trúc mã nhưng không đổi logic (VD: `refactor: move llm_client to core folder`)
- `test:` Thêm hoặc sửa Unit Test.

## 3. Cách Thêm Một Detection Module Mới (Module Mở Rộng)
Nếu bạn muốn đóng góp một Rule mới cho Tier 1 hoặc một Node mới cho Agent Tier 2 (khớp kiến trúc thực tế ở HEAD):
1. **Với Tier 1 (Rules):** SENTINEL KHÔNG dùng hệ plugin `BaseRule`. Có 2 cách thêm luật:
   - **Khai báo (khuyến nghị):** thêm vào `static_rules`/`dynamic_rules` trong `config/system_settings.yaml` — `RuleEngine` **hot-reload** mỗi 5s, không cần sửa code. Luật động qua Dashboard còn được kiểm duyệt bởi `FeedbackValidator` (Zero-Trust) + HITL.
   - **Bằng code:** mở rộng phương thức `evaluate()` trong `src/tier1_filter/rule_engine.py` (trả về một action hợp lệ: `DROP`/`LOG`/`ALERT`/`BLOCK_IP`/`AWAIT_HITL`/`ESCALATE`), kèm Unit Test trong `tests/`.
2. **Với Tier 2 (Agent Node):** SENTINEL dùng **LangGraph `StateGraph`**, KHÔNG dùng `@tool` của LangChain. Viết một hàm node `node_<tên>(state: SentinelState)` trong `src/agent/nodes.py`, rồi đăng ký bằng `workflow.add_node(...)` + nối edge/conditional-edge trong `src/agent/workflow.py`. Mọi quyết định LLM phải đi qua `DecisionValidator` + `enforce_tier_consensus` trước khi thực thi.

## 4. Pull Request Checklist (Kiểm Tra Trước Khi Nộp PR)
Trước khi nhấn nút Create Pull Request, hãy tự rà soát:
- [ ] Code mới đã được viết Unit Test (Coverage > 80%).
- [ ] Lệnh `pytest tests/ --tb=short` chạy thành công (Xanh toàn bộ).
- [ ] Code tuân thủ chuẩn PEP 8 (khuyến khích dùng `ruff` cho linting và formatting).
- [ ] Tài liệu Markdown liên quan đã được cập nhật (nếu kiến trúc bị thay đổi).
- [ ] Không rò rỉ bất kỳ thông tin nhạy cảm nào (Token, Mật khẩu) trong file diff.

Mọi PR sẽ được Reviewer đọc và đánh giá trong vòng 3-5 ngày làm việc. Cám ơn sự hỗ trợ của bạn!
