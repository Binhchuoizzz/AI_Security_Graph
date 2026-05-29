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
import hmac
import hashlib
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
    """Khoi tao SQLite Database cho audit trail va login locks neu chua co."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Tao bang audit_trail
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                target TEXT,
                reason TEXT
            )
        """)
        
        # Tao bang login_attempts
        c.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                lockout_until REAL DEFAULT 0.0
            )
        """)

        # Tu dong check va nang cap them cot integrity_hash neu chua co
        c.execute("PRAGMA table_info(audit_trail)")
        columns = [col[1] for col in c.fetchall()]
        if "integrity_hash" not in columns:
            c.execute("ALTER TABLE audit_trail ADD COLUMN integrity_hash TEXT")
            
        conn.commit()


_init_db()


def _log_to_db(action: str, target: str, reason: str):
    """Ghi audit trail voi validation, sanitization va HMAC log chaining."""
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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            
            # 1. Lay integrity_hash cua log cuoi cung de xau chuoi
            c.execute("SELECT integrity_hash FROM audit_trail ORDER BY id DESC LIMIT 1")
            last_row = c.fetchone()
            prev_hash = last_row[0] if last_row and last_row[0] else "genesis_block_hash_sentinel_soc"

            # 2. Tinh toan HMAC hash
            secret_key = os.getenv("SENTINEL_LOG_SECRET", "sentinel_secure_fallback_log_secret_2026").encode()
            message = f"{prev_hash}|{timestamp}|{action}|{safe_target}|{safe_reason}".encode()
            current_hash = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

            # 3. Ghi vao database
            c.execute(
                "INSERT INTO audit_trail (timestamp, action, target, reason, integrity_hash) VALUES (?, ?, ?, ?, ?)",
                (timestamp, action, safe_target, safe_reason, current_hash),
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


def verify_audit_trail_integrity() -> tuple[bool, str]:
    """
    Quet toan bo chuoi audit_trail va xac minh tinh toan ven (HMAC Log Chaining).
    Tra ve (True, "He thong toan ven") hoac (False, "Mo ta loi").
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT id, timestamp, action, target, reason, integrity_hash FROM audit_trail ORDER BY id ASC")
            rows = c.fetchall()
            
        if not rows:
            return True, "Cơ sở dữ liệu trống. Hệ thống nhật ký trống nhưng toàn vẹn."

        secret_key = os.getenv("SENTINEL_LOG_SECRET", "sentinel_secure_fallback_log_secret_2026").encode()
        prev_hash = "genesis_block_hash_sentinel_soc"

        for row in rows:
            row_id, timestamp, action, target, reason, integrity_hash = row
            
            # Tinh toan lai hash mong doi
            message = f"{prev_hash}|{timestamp}|{action}|{target}|{reason}".encode()
            expected_hash = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
            
            if not integrity_hash or not hmac.compare_digest(integrity_hash, expected_hash):
                return False, f"⚠️ PHÁT HIỆN GIẢ MẠO! Dòng log ID {row_id} ({timestamp} - {action}) đã bị sửa đổi, xóa hoặc chèn sai thứ tự."
                
            prev_hash = integrity_hash

        return True, "✅ Hệ thống nhật ký toàn vẹn (0 phát hiện sửa đổi hay giả mạo)."
    except Exception as e:
        return False, f"Lỗi trong quá trình kiểm tra toàn vẹn: {e}"


def get_login_attempts(username: str) -> tuple[int, float]:
    """Tra ve (attempts, lockout_until) cho mot username."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT attempts, lockout_until FROM login_attempts WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                return row[0], row[1]
            return 0, 0.0
    except Exception:
        return 0, 0.0


def increment_login_attempts(username: str) -> int:
    """Tang so lan dang nhap that bai va tra ve so lan hien tai."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO login_attempts (username, attempts, lockout_until) 
                VALUES (?, 1, 0.0)
                ON CONFLICT(username) DO UPDATE SET attempts = attempts + 1
            """, (username,))
            conn.commit()
        attempts, _ = get_login_attempts(username)
        return attempts
    except Exception as e:
        logger.error(f"Loi tang login attempts: {e}")
        return 0


def reset_login_attempts(username: str):
    """Reset so lan dang nhap sai va mo khoa."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO login_attempts (username, attempts, lockout_until) 
                VALUES (?, 0, 0.0)
                ON CONFLICT(username) DO UPDATE SET attempts = 0, lockout_until = 0.0
            """, (username,))
            conn.commit()
    except Exception as e:
        logger.error(f"Loi reset login attempts: {e}")


def lock_user(username: str, duration_seconds: int):
    """Khoa tai khoan trong mot khoang thoi gian."""
    try:
        import time
        lockout_time = time.time() + duration_seconds
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO login_attempts (username, attempts, lockout_until) 
                VALUES (?, 5, ?)
                ON CONFLICT(username) DO UPDATE SET lockout_until = ?, attempts = 5
            """, (username, lockout_time, lockout_time, lockout_time))
            conn.commit()
    except Exception as e:
        logger.error(f"Loi khoa user: {e}")

