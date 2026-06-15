"""
Guardrails: State Monitor
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

import yaml  # type: ignore

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")

# Khóa luồng (thread lock) bảo vệ ghi DB đồng thời
_db_lock = threading.Lock()


def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
                if cfg:
                    return cfg
    except Exception:
        pass
    return {
        "llm": {"max_context_tokens": 8192},
        "guardrails": {"token_budget": 4000},
        "logging": {"audit_db_path": "logs/guardrails_audit.db"},
    }


class ContextOverflowGuard:
    """
    Kiểm soát kích thước Context Window.
    Nếu prompt + log data vượt quá ngân sách token tối đa -> cắt bớt.
    """

    def __init__(self):
        config = load_config()
        self.max_tokens = int(config.get("llm", {}).get("max_context_tokens", 8192))
        self.log_budget = int(config.get("guardrails", {}).get("token_budget", 4000))

    def check(self, prompt_tokens: int, log_tokens: int) -> dict:
        total = prompt_tokens + log_tokens
        is_overflow = total > self.max_tokens
        return {
            "total_tokens": total,
            "max_allowed": self.max_tokens,
            "is_overflow": is_overflow,
            "action": "TRUNCATE_LOGS" if is_overflow else "PASS",
        }


class LoopDetector:
    """
    Phát hiện LangGraph bị mắc kẹt trong vòng lặp vô hạn.
    Nếu cùng một Node được gọi > max_iterations lần -> Force Stop.
    """

    def __init__(self, max_iterations: int = 10):
        self.max_iterations = max_iterations
        self.node_counter = {}

    def record_visit(self, node_name: str) -> dict:
        self.node_counter[node_name] = self.node_counter.get(node_name, 0) + 1
        count = self.node_counter[node_name]

        if count > self.max_iterations:
            return {
                "node": node_name,
                "visits": count,
                "action": "FORCE_STOP",
                "reason": (f"Infinite loop detected: Node '{node_name}' visited {count} times"),
            }
        return {"node": node_name, "visits": count, "action": "CONTINUE"}

    def reset(self):
        self.node_counter = {}


class AuditLogger:
    """
    Ghi lại toàn bộ quyết định của Agent vào SQLite DB (guardrails_audit.db).

    LƯU Ý: DB này (metadata nghiên cứu, bảng `audit_log`) tách biệt với
    `config/audit_trail.db` (chuỗi HMAC pháp lý, bảng `audit_trail`) của
    response/executor.py — tên file khác nhau để tránh nhầm lẫn.
    """

    def __init__(self):
        config = load_config()
        self.db_path = str(
            config.get("logging", {}).get("audit_db_path", "logs/guardrails_audit.db")
        )
        self._init_db()

    def _init_db(self):
        with _db_lock:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        source_ip TEXT,
                        tier1_score INTEGER,
                        tier1_action TEXT,
                        guardrail_injected BOOLEAN,
                        agent_decision TEXT,
                        agent_reasoning TEXT,
                        mitre_technique TEXT,
                        nist_control TEXT,
                        hitl_approved BOOLEAN,
                        latency_ms REAL,
                        metadata TEXT
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def log_event(self, event: dict):
        """
        Ghi sự kiện vào audit trail DB có sử dụng thread lock và try/finally
        để bảo đảm đóng kết nối chống rò rỉ (connection leaks).
        """
        with _db_lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_log (
                        timestamp, event_type, source_ip, tier1_score,
                        tier1_action, guardrail_injected, agent_decision,
                        agent_reasoning, mitre_technique, nist_control,
                        hitl_approved, latency_ms, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        datetime.now(timezone.utc).isoformat(),
                        event.get("event_type", "UNKNOWN"),
                        event.get("source_ip"),
                        event.get("tier1_score"),
                        event.get("tier1_action"),
                        event.get("guardrail_injected", False),
                        event.get("agent_decision"),
                        event.get("agent_reasoning"),
                        event.get("mitre_technique"),
                        event.get("nist_control"),
                        event.get("hitl_approved"),
                        event.get("latency_ms"),
                        json.dumps(event.get("metadata", {})),
                    ),
                )
                conn.commit()
            finally:
                conn.close()


# Khởi tạo singletons
loop_detector = LoopDetector()
context_overflow_guard = ContextOverflowGuard()
audit_logger = AuditLogger()
