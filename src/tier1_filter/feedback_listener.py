"""
Tier 1: Feedback Listener (Dynamic Rule Update Receiver)

Module này lắng nghe lệnh từ LangGraph Agent (Tier 2) khi Agent phát hiện
được một mẫu tấn công mới (Zero-day / APT). Agent sẽ tự động sinh ra
Signature/Regex và đẩy ngược về đây để cập nhật luật chặn Tier-1 ngay lập tức.

Luồng hoạt động:
  1. LangGraph Agent xác nhận mẫu tấn công mới
  2. Agent gọi add_dynamic_rule() trên RuleEngine
  3. FeedbackListener persist rule mới vào config/system_settings.yaml
  4. Tier-1 tự động áp dụng rule mới trong lần evaluate() tiếp theo

Đây là cơ chế "Feedback Loop" giúp hệ thống tự tiến hóa:
  Tier 1 (lọc) → Tier 2 (phân tích) → Feedback Loop → Tier 1 (cập nhật luật mới)

*Conscious Design Decision:*
- State Machine chỉ có 1 chiều: PENDING_APPROVAL -> ACTIVE hoặc REJECTED.
- Các rule bị REJECTED sẽ không được re-submit trong cùng phiên làm việc để tránh spam L3 Manager.
- Hiện tại các ACTIVE rules không có TTL (sống mãi mãi trong file cấu hình) nhằm phục vụ demo tính ổn định. Trong môi trường production thực tế, một eviction policy (LRU hoặc Fixed TTL 24h) phải được áp dụng để đảm bảo RuleEngine không bị tràn bộ nhớ.
"""

import logging
import os
import tempfile
from datetime import datetime

import yaml  # type: ignore
from filelock import FileLock  # type: ignore

from src.guardrails import FeedbackValidator

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")
LOCK_PATH = CONFIG_PATH + ".lock"
_lock = FileLock(LOCK_PATH)

logger = logging.getLogger(__name__)


def _save_config_atomically(config: dict):
    """Ghi đè file cấu hình một cách nguyên tử (Atomic Write) chống lỗi đọc dở file."""
    dir_name = os.path.dirname(CONFIG_PATH)
    fd, temp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with open(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        # mkstemp tạo file mode 0600 -> os.replace giữ nguyên khiến container (user khác
        # uid) KHÔNG đọc được config. Đặt 0644 để các tiến trình khác (Dashboard trong
        # Docker, RuleEngine) vẫn đọc được dynamic_rules/whitelist sau khi Agent lưu rule.
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, CONFIG_PATH)
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise e


class FeedbackListener:
    """
    Nhận và xử lý feedback từ LangGraph Agent.
    Persist các dynamic rules mới vào YAML config.
    """

    def __init__(self):
        self.feedback_log = []  # Lịch sử feedback để audit

    def receive_new_rule(
        self,
        field: str,
        pattern: str,
        score: int = 50,
        source: str = "langgraph_agent",
        reason: str = "",
    ) -> dict:
        """
        Nhận luật mới từ Agent và persist vào config.

        Args:
            field: Tên trường trong log (ví dụ: 'Source IP', 'URI', 'User-Agent')
            pattern: Chuỗi pattern cần match (regex hoặc substring)
            score: Điểm risk score cộng thêm khi match (mặc định 50)
            source: Nguồn sinh rule (để audit trail)
            reason: Lý do tạo rule (LLM reasoning)

        Returns:
            dict chứa thông tin rule + status
        """
        # Validate dynamic rule using FeedbackValidator
        validator = FeedbackValidator()
        is_valid, errors = validator.validate_rule(field, pattern, score)
        if not is_valid:
            logger.error(f"[Feedback] Rejected dynamic rule registration: {errors}")
            return {
                "status": "REJECTED",
                "errors": errors,
                "rule": {
                    "field": field,
                    "pattern": pattern,
                    "score": score,
                    "source": source,
                    "reason": reason,
                },
            }

        new_rule = {
            "field": field,
            "pattern": pattern,
            "score": score,
            # Dùng giờ CỤC BỘ (naive) để KHỚP với timestamp audit_trail do executor ghi
            # (cùng tiến trình subscriber) — tránh lệch 7h giữa "Tạo lúc" (HITL) và giờ cảnh báo.
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "source": source,
            "reason": reason,
            "status": "PENDING_APPROVAL",  # Trạng thái chờ kiểm duyệt
        }

        # Persist vào YAML
        try:
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)

                if "tier1" not in config:
                    config["tier1"] = {}
                if "dynamic_rules" not in config["tier1"]:
                    config["tier1"]["dynamic_rules"] = []

                # Kiểm tra trùng lặp trước khi thêm (check cả field và pattern)
                existing_rules = {
                    (r.get("field"), r.get("pattern")) for r in config["tier1"]["dynamic_rules"]
                }
                if (field, pattern) in existing_rules:
                    logger.warning(
                        f"[Feedback] Duplicate rule skipped: {field} contains '{pattern}'"
                    )
                    return {
                        "status": "SKIPPED",
                        "reason": "Duplicate pattern for field",
                        "rule": new_rule,
                    }

                config["tier1"]["dynamic_rules"].append(new_rule)
                _save_config_atomically(config)

            logger.info(f"[Feedback] New dynamic rule persisted: {field} contains '{pattern}'")

            # Ghi vào feedback log
            self.feedback_log.append(new_rule)

            return {"status": "APPLIED", "rule": new_rule}

        except Exception as e:
            logger.error(f"[Feedback] Failed to persist rule: {e}")
            return {"status": "FAILED", "error": str(e), "rule": new_rule}

    def get_feedback_history(self) -> list:
        """Trả về lịch sử tất cả feedback đã nhận trong session này."""
        return self.feedback_log

    def get_active_dynamic_rules(self) -> list:
        """Đọc danh sách dynamic rules hiện đang ACTIVE từ config."""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            rules = config.get("tier1", {}).get("dynamic_rules", [])
            return [r for r in rules if r.get("status", "ACTIVE") == "ACTIVE"]
        except Exception:
            return []

    def get_pending_rules(self) -> list:
        """Lấy danh sách các rule đang chờ phê duyệt."""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            rules = config.get("tier1", {}).get("dynamic_rules", [])
            return [r for r in rules if r.get("status") == "PENDING_APPROVAL"]
        except Exception:
            return []

    def update_rule_status(self, pattern: str, new_status: str, field: str | None = None) -> bool:
        """Cập nhật trạng thái của rule (ACTIVE hoặc REJECTED)."""
        try:
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)

                rules = config.get("tier1", {}).get("dynamic_rules", [])
                updated = False
                for rule in rules:
                    match = rule.get("pattern") == pattern
                    if field is not None:
                        match = match and rule.get("field") == field
                    if match:
                        rule["status"] = new_status
                        updated = True

                if updated:
                    _save_config_atomically(config)
                    logger.info(
                        f"[Feedback] Rule '{pattern}' (field={field}) updated to {new_status}"
                    )
            return updated
        except Exception as e:
            logger.error(f"[Feedback] Failed to update rule status: {e}")
            return False

    def approve_rule(self, pattern: str, field: str | None = None) -> bool:
        return self.update_rule_status(pattern, "ACTIVE", field)

    def reject_rule(self, pattern: str, field: str | None = None) -> bool:
        return self.update_rule_status(pattern, "REJECTED", field)

    def clear_all_dynamic_rules(self):
        """Reset toàn bộ dynamic rules (dùng khi chạy experiment mới)."""
        try:
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)
                config["tier1"]["dynamic_rules"] = []
                _save_config_atomically(config)
            self.feedback_log = []
            logger.info("[Feedback] All dynamic rules cleared.")
        except Exception as e:
            logger.error(f"[Feedback] Failed to clear rules: {e}")

    def add_to_whitelist(self, ip: str) -> bool:
        """Thêm một IP vào whitelist trong config (Dùng cho luồng phê duyệt Pentest/Internal)."""
        validator = FeedbackValidator()
        is_valid, errors = validator.validate_whitelist_ip(ip)
        if not is_valid:
            logger.error(f"[Feedback] Whitelist IP '{ip}' validation failed: {errors}")
            return False

        try:
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)

                if "tier1" not in config:
                    config["tier1"] = {}
                if "whitelist_ips" not in config["tier1"]:
                    config["tier1"]["whitelist_ips"] = []

                if ip not in config["tier1"]["whitelist_ips"]:
                    config["tier1"]["whitelist_ips"].append(ip)
                    _save_config_atomically(config)
                    logger.info(f"[Feedback] IP {ip} has been added to Whitelist.")
            return True
        except Exception as e:
            logger.error(f"[Feedback] Failed to add {ip} to whitelist: {e}")
            return False

    def remove_from_whitelist(self, ip: str) -> bool:
        """Gỡ một IP khỏi whitelist."""
        try:
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)

                whitelist = config.get("tier1", {}).get("whitelist_ips", [])
                if ip in whitelist:
                    whitelist.remove(ip)
                    _save_config_atomically(config)
                    logger.info(f"[Feedback] IP {ip} has been removed from Whitelist.")
                    return True
            return False
        except Exception as e:
            logger.error(f"[Feedback] Failed to remove {ip} from whitelist: {e}")
            return False

    def get_whitelisted_ips(self) -> list:
        """Lấy danh sách các IP đang được Whitelist."""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            return config.get("tier1", {}).get("whitelist_ips", [])
        except Exception:
            return []

    def get_all_dynamic_rules(self) -> list:
        """Đọc toàn bộ danh sách dynamic rules từ config (gồm cả ACTIVE, PENDING_APPROVAL, REJECTED)."""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            return config.get("tier1", {}).get("dynamic_rules", [])
        except Exception:
            return []
