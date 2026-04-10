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
"""
import yaml
import os
import json
import logging
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'system_settings.yaml')

logger = logging.getLogger(__name__)


class FeedbackListener:
    """
    Nhận và xử lý feedback từ LangGraph Agent.
    Persist các dynamic rules mới vào YAML config.
    """
    def __init__(self):
        self.feedback_log = []  # Lịch sử feedback để audit

    def receive_new_rule(self, field: str, pattern: str, score: int = 50,
                          source: str = "langgraph_agent", reason: str = "") -> dict:
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
        new_rule = {
            "field": field,
            "pattern": pattern,
            "score": score,
            "created_at": datetime.utcnow().isoformat(),
            "source": source,
            "reason": reason
        }

        # Persist vào YAML
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)

            if 'tier1' not in config:
                config['tier1'] = {}
            if 'dynamic_rules' not in config['tier1']:
                config['tier1']['dynamic_rules'] = []

            # Kiểm tra trùng lặp trước khi thêm
            existing_patterns = [r.get('pattern') for r in config['tier1']['dynamic_rules']]
            if pattern in existing_patterns:
                logger.warning(f"[Feedback] Duplicate rule skipped: {pattern}")
                return {"status": "SKIPPED", "reason": "Duplicate pattern", "rule": new_rule}

            config['tier1']['dynamic_rules'].append(new_rule)

            with open(CONFIG_PATH, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

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
        """Đọc danh sách dynamic rules hiện đang active từ config."""
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)
            return config.get('tier1', {}).get('dynamic_rules', [])
        except Exception:
            return []

    def clear_all_dynamic_rules(self):
        """Reset toàn bộ dynamic rules (dùng khi chạy experiment mới)."""
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)
            config['tier1']['dynamic_rules'] = []
            with open(CONFIG_PATH, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            self.feedback_log = []
            logger.info("[Feedback] All dynamic rules cleared.")
        except Exception as e:
            logger.error(f"[Feedback] Failed to clear rules: {e}")
