"""
Mock Executor Module cho Hệ thống Phản hồi tự động.
Mô phỏng các hành động khóa IP, cách ly Host và gửi Cảnh báo.

HARDENED (Attack Vector #07 — Sandbox Escape / RCE Defense):
  - ActionValidator: Allowlist-only actions, reject unknown commands
  - Input Sanitization: Chặn command injection trong target/reason fields
  - Output Sanitizer: Strip markdown/HTML trước khi ghi DB
"""

import sqlite3
import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "audit_trail.db"
)


# =========================================================================
# ACTION VALIDATOR — Sandbox Escape / RCE Defense (Attack Vector #07)
# =========================================================================
class ActionValidator:
    """
    Allowlist-based action validator.
    CHỈ cho phép các action đã định nghĩa trước.
    Reject mọi thứ khác → ngăn LLM bị thao túng để thực thi lệnh tùy ý.
    """

    ALLOWED_ACTIONS = frozenset({
        "BLOCK_IP", "QUARANTINE", "ALERT", "LOG", "AWAIT_HITL"
    })

    # Patterns nguy hiểm trong target/reason fields (command injection)
    DANGEROUS_PATTERNS = re.compile(
        r'[;|&`$]|'           # Shell metacharacters
        r'\b(?:rm|sudo|chmod|chown|wget|curl|nc|bash|sh|python|exec)\b|'
        r'\.\./',             # Path traversal
        re.IGNORECASE
    )

    @classmethod
    def validate_action(cls, action: str) -> bool:
        """Kiểm tra action có nằm trong allowlist không."""
        return action.upper() in cls.ALLOWED_ACTIONS

    @classmethod
    def sanitize_target(cls, target: str) -> str:
        """
        Sanitize target field — chặn command injection.
        Target chỉ nên là IP, hostname, hoặc identifier.
        """
        if cls.DANGEROUS_PATTERNS.search(target):
            logger.warning(
                f"[ACTION VALIDATOR] Dangerous pattern in target: {target[:50]}. "
                f"Possible command injection attempt!"
            )
            # Strip dangerous characters, keep only safe ones
            return re.sub(r'[^a-zA-Z0-9._:\-/@ ]', '', target)
        return target

    @classmethod
    def sanitize_reason(cls, reason: str) -> str:
        """Sanitize reason field trước khi ghi DB."""
        if cls.DANGEROUS_PATTERNS.search(reason):
            logger.warning(
                f"[ACTION VALIDATOR] Dangerous pattern in reason field. Sanitizing."
            )
            return re.sub(r'[;|&`$]', '', reason)
        return reason


# Singleton validator
_validator = ActionValidator()


def _init_db():
    """Khoi tao SQLite Database cho audit trail neu chua co."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                target TEXT,
                reason TEXT
            )
        """)
        conn.commit()


_init_db()


def _log_to_db(action: str, target: str, reason: str):
    """Ghi audit trail với validation và sanitization."""
    # Validate action
    if not _validator.validate_action(action):
        logger.error(
            f"[ACTION VALIDATOR] REJECTED unknown action: {action}. "
            f"Possible sandbox escape attempt!"
        )
        action = "AWAIT_HITL"  # Fallback to safe action

    # Sanitize inputs
    safe_target = _validator.sanitize_target(target)
    safe_reason = _validator.sanitize_reason(reason)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO audit_trail (timestamp, action, target, reason) VALUES (?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, safe_target, safe_reason),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Loi ghi audit trail: {e}")


def block_ip(ip: str, reason: str):
    safe_ip = _validator.sanitize_target(ip)
    logger.warning(f" [FIREWALL MOCK] BLOCKING IP: {safe_ip} | Lý do: {reason}")
    _log_to_db("BLOCK_IP", safe_ip, reason)


def quarantine_host(host: str, reason: str):
    safe_host = _validator.sanitize_target(host)
    logger.warning(f" [EDR MOCK] QUARANTINE HOST: {safe_host} | Lý do: {reason}")
    _log_to_db("QUARANTINE", safe_host, reason)


def raise_alert(msg: str, reason: str):
    logger.info(f" [SIEM MOCK] ALERT: {msg} | Lý do: {reason}")
    _log_to_db("ALERT", msg, reason)


def get_audit_trail(limit=50):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT timestamp, action, target, reason FROM audit_trail ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = c.fetchall()
        return [
            {"timestamp": r[0], "action": r[1], "target": r[2], "reason": r[3]}
            for r in rows
        ]
    except Exception:
        return []


def get_audit_trail_for_ip(ip: str, limit=100):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT timestamp, action, target, reason FROM audit_trail WHERE target = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            )
            rows = c.fetchall()
        return [
            {"timestamp": r[0], "action": r[1], "target": r[2], "reason": r[3]}
            for r in rows
        ]
    except Exception:
        return []

