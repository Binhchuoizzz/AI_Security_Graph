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
# Whitelist mặc định khi reset demo (loopback + scanner nội bộ + gateway).
DEFAULT_WHITELIST_IPS = ["127.0.0.1", "10.0.0.99", "192.168.1.254"]


def _ensure_lock_writable():
    """Đảm bảo file .lock GHI được bởi cả host (uid 1000) lẫn container (uid 999).

    Docker mount config/ chung: nếu file lock cũ do UID KHÁC tạo (mode 0644) thì bên còn
    lại KHÔNG mở ghi được -> FileLock ném Permission denied (bug reset_all không xoá nổi
    luật động). Thư mục config/ thuộc host nên ta XOÁ lock cũ rồi tạo lại 0666. Bọc lỗi để
    KHÔNG BAO GIỜ làm hỏng luồng import.
    """
    try:
        if os.path.exists(LOCK_PATH) and not os.access(LOCK_PATH, os.W_OK):
            os.remove(LOCK_PATH)  # dir config/ host-owned -> xoá được dù file thuộc uid khác
        if not os.path.exists(LOCK_PATH):
            fd = os.open(LOCK_PATH, os.O_CREAT | os.O_WRONLY, 0o666)
            os.close(fd)
        os.chmod(LOCK_PATH, 0o666)  # noqa: S103  (cross-UID: có thể fail nếu thuộc uid khác -> nuốt)
    except Exception:
        pass


_ensure_lock_writable()
_lock = FileLock(LOCK_PATH)

logger = logging.getLogger(__name__)


def _save_config_atomically(config: dict):
    """Ghi đè file cấu hình một cách nguyên tử (Atomic Write) chống lỗi đọc dở file."""
    dir_name = os.path.dirname(CONFIG_PATH)
    fd, temp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with open(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        # mkstemp tạo file mode 0600 -> os.replace giữ nguyên khiến tiến trình UID khác
        # KHÔNG dùng được config. Docker mount config/ chung cho Dashboard (container uid
        # 999) VÀ subscriber/reset (host uid 1000): hai bên luân phiên GHI cùng file. Đặt
        # 0666 để bên nào cũng ghi ĐÈ in-place được (nếu 0644 thì chỉ owner ghi -> bên kia
        # bị Permission denied, vd reset_all không xoá nổi luật động). os.replace đổi chủ sở
        # hữu mỗi lần ghi nên phải 0666 để tự chữa lành cross-UID.
        os.chmod(temp_path, 0o666)  # noqa: S103  (cross-UID Docker: host↔container cùng ghi)
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
        ok = self.update_rule_status(pattern, "ACTIVE", field)
        # ĐỒNG BỘ block ↔ whitelist (LOẠI TRỪ LẪN NHAU · "hành động sau cùng thắng"):
        # kích hoạt CHẶN một Source IP thì phải GỠ nó khỏi whitelist. Nếu không, whitelist
        # (ưu tiên CAO NHẤT ở Tier-1) sẽ khiến luật chặn vừa duyệt trở nên VÔ HIỆU — IP nằm
        # cả 2 danh sách nên Tier-1 vẫn cho qua. Đây là việc của HỆ THỐNG, không phụ thuộc UI.
        if ok and field == "Source IP" and pattern in self.get_whitelisted_ips():
            self.remove_from_whitelist(pattern)
            logger.info(
                f"[Feedback] IP {pattern} đã GỠ khỏi whitelist do chuyển sang CHẶN "
                "(block ↔ whitelist loại trừ lẫn nhau)."
            )
        return ok

    def reject_rule(self, pattern: str, field: str | None = None) -> bool:
        return self.update_rule_status(pattern, "REJECTED", field)

    def clear_all_dynamic_rules(self) -> bool:
        """Reset toàn bộ dynamic rules (dùng khi chạy experiment mới). Trả True nếu thành công."""
        try:
            _ensure_lock_writable()  # phòng lock cũ do UID khác chiếm (Docker cross-UID)
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)
                config["tier1"]["dynamic_rules"] = []
                _save_config_atomically(config)
            self.feedback_log = []
            logger.info("[Feedback] All dynamic rules cleared.")
            return True
        except Exception as e:
            logger.error(f"[Feedback] Failed to clear rules: {e}")
            return False

    def reset_whitelist_to_defaults(self) -> bool:
        """Đặt whitelist về mặc định (dùng khi reset demo). Trả True nếu thành công.

        Whitelist là trạng thái do HỆ THỐNG quản lý -> mọi nơi (UI Reset, reset_all) gọi
        method này thay vì tự sửa YAML, để đồng bộ & bền với cross-UID (0666 + lock).
        """
        try:
            _ensure_lock_writable()
            with _lock:
                with open(CONFIG_PATH) as f:
                    config = yaml.safe_load(f)
                config.setdefault("tier1", {})["whitelist_ips"] = list(DEFAULT_WHITELIST_IPS)
                _save_config_atomically(config)
            logger.info("[Feedback] Whitelist reset to defaults.")
            return True
        except Exception as e:
            logger.error(f"[Feedback] Failed to reset whitelist: {e}")
            return False

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

                # Hủy bỏ luật chặn động (dynamic rules) nếu có
                rules = config["tier1"].get("dynamic_rules", [])
                updated_rules = False
                for rule in rules:
                    if rule.get("pattern") == ip and rule.get("status") == "ACTIVE":
                        rule["status"] = "REJECTED"
                        updated_rules = True

                _save_config_atomically(config)
                logger.info(f"[Feedback] IP {ip} has been added to Whitelist.")
                if updated_rules:
                    logger.info(
                        f"[Feedback] IP {ip} has been REJECTED from dynamic_rules because it was added to whitelist."
                    )
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
