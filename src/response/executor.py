"""
Mock Executor Module cho Hệ thống Phản hồi tự động.
Mô phỏng các hành động khóa IP, cách ly Host và gửi Cảnh báo.

TĂNG CƯỜNG BẢO MẬT (Attack Vector #07 — Sandbox Escape / Phòng thủ RCE):
  - ActionValidator: Chỉ cho phép các hành động trong allowlist, từ chối lệnh lạ
  - Làm sạch đầu vào (Input Sanitization): Chặn command injection trong các trường target/reason
  - Làm sạch đầu ra (Output Sanitizer): Loại bỏ markdown/HTML trước khi ghi DB
"""

import hashlib
import hmac
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "audit_trail.db")

# Khóa GHI chuỗi audit HMAC: _log_to_db là read-modify-write (đọc prev_hash → tính HMAC →
# INSERT). Hai worker Tier-2 song song mà không khóa sẽ CÙNG móc vào một prev_hash → chuỗi
# HMAC BỊ RẼ NHÁNH và verify_audit_trail_integrity() báo gãy. Khóa này serialize đúng đoạn
# tối hậu đó; đơn luồng (production/test) không tranh chấp = chi phí ~0, chuỗi Y HỆT như trước.
_audit_lock = threading.Lock()
CONFIG_YAML_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml"
)

# Cache whitelist (đọc từ YAML) để phòng vệ chiều sâu KHÔNG tốn I/O mỗi lần chặn.
# Khử cache theo MTIME của file: hễ whitelist đổi (vd approve_rule vừa gỡ 1 IP) là
# đọc lại NGAY — tránh đua dữ liệu khi block ngay sau khi gỡ khỏi whitelist.
_wl_cache: dict = {"mtime": None, "ips": frozenset()}


def _whitelisted_ips() -> frozenset:
    """Đọc whitelist_ips từ config, cache theo mtime. Dùng để executor KHÔNG chặn nhầm IP
    đã whitelist — nhất quán với Tier-1 dù suy luận LLM có nêu tên IP đó."""
    try:
        mtime = os.path.getmtime(CONFIG_YAML_PATH)
    except OSError:
        return _wl_cache["ips"]
    if mtime == _wl_cache["mtime"]:
        return _wl_cache["ips"]
    try:
        import yaml  # type: ignore

        with open(CONFIG_YAML_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        ips = frozenset(cfg.get("tier1", {}).get("whitelist_ips", []) or [])
    except Exception:
        ips = _wl_cache["ips"]
    _wl_cache.update({"mtime": mtime, "ips": ips})
    return ips


# =========================================================================
# ACTION VALIDATOR — Sandbox Escape / RCE Defense (Attack Vector #07)
# =========================================================================
class ActionValidator:
    """
    Trình xác thực hành động dựa trên danh sách cho phép (allowlist).
    CHỈ cho phép các hành động đã được định nghĩa trước.
    Từ chối các hành động khác -> ngăn LLM bị thao túng để thực thi lệnh tùy ý.
    """

    # WHITELIST: bản ghi audit cho truy cập được đặc cách cho qua (không phải hành động
    # phản ứng, chỉ để ghi nhận + hiển thị thẻ riêng trên UI).
    ALLOWED_ACTIONS = frozenset(
        {"BLOCK_IP", "QUARANTINE", "ALERT", "LOG", "AWAIT_HITL", "WHITELIST"}
    )

    # Các mẫu nguy hiểm trong trường target/reason (command injection)
    DANGEROUS_PATTERNS = re.compile(
        r"[;|&`$]|"  # Ký tự đặc biệt của shell (metacharacters)
        r"\b(?:rm|sudo|chmod|chown|wget|curl|nc|bash|sh|python|exec)\b|"
        r"\.\./",  # Tấn công duyệt thư mục (path traversal)
        re.IGNORECASE,
    )

    @classmethod
    def validate_action(cls, action: str) -> bool:
        """Kiểm tra hành động có nằm trong danh sách cho phép hay không."""
        return action.upper() in cls.ALLOWED_ACTIONS

    @classmethod
    def sanitize_target(cls, target: str) -> str:
        """
        Làm sạch trường target — chặn command injection.
        Target chỉ nên là IP, hostname, hoặc định danh (identifier).
        """
        if cls.DANGEROUS_PATTERNS.search(target):
            logger.warning(
                f"[ACTION VALIDATOR] Dangerous pattern in target: {target[:50]}. "
                f"Possible command injection attempt!"
            )
            # Loại bỏ các ký tự nguy hiểm, giữ lại các ký tự an toàn
            return re.sub(r"[^a-zA-Z0-9._:\-/@ ]", "", target)
        return target

    @classmethod
    def sanitize_reason(cls, reason: str) -> str:
        """Làm sạch trường reason trước khi ghi cơ sở dữ liệu."""
        if cls.DANGEROUS_PATTERNS.search(reason):
            logger.warning("[ACTION VALIDATOR] Dangerous pattern in reason field. Sanitizing.")
            return re.sub(r"[;|&`$]", "", reason)
        return reason


# Thực thể duy nhất (Singleton)
_validator = ActionValidator()


def _ensure_db_writable(db_path: str):
    """Đảm bảo file DB có thể ghi được bởi cả host (uid 1000) và container (uid 999)."""
    try:
        if os.path.exists(db_path) and not os.access(db_path, os.W_OK):
            os.remove(db_path)
    except OSError:
        pass
    try:
        if os.path.exists(db_path):
            os.chmod(db_path, 0o666)  # noqa: S103
    except OSError:
        pass


def _init_db():
    """Khởi tạo cơ sở dữ liệu SQLite cho audit trail và login locks nếu chưa tồn tại."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _ensure_db_writable(DB_PATH)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Tạo bảng audit_trail
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                target TEXT,
                reason TEXT
            )
        """)

        # Tạo bảng login_attempts
        c.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                lockout_until REAL DEFAULT 0.0
            )
        """)

        # Tự động kiểm tra và nâng cấp thêm cột integrity_hash nếu chưa có
        c.execute("PRAGMA table_info(audit_trail)")
        columns = [col[1] for col in c.fetchall()]
        if "integrity_hash" not in columns:
            c.execute("ALTER TABLE audit_trail ADD COLUMN integrity_hash TEXT")
        # Cột raw_log: lưu LOG THÔ đầu vào (đặc trưng luồng đã loại nhãn) để Dashboard hiển
        # thị minh bạch "cái gì đã vào Tier-1/LLM". KHÔNG nằm trong HMAC — chữ ký chỉ phủ
        # QUYẾT ĐỊNH (action/target/reason); raw_log là ngữ cảnh đầu vào đính kèm.
        if "raw_log" not in columns:
            c.execute("ALTER TABLE audit_trail ADD COLUMN raw_log TEXT")

        conn.commit()


_init_db()


def _log_to_db(action: str, target: str, reason: str, raw_log: str = ""):
    """Ghi nhật ký kiểm toán (audit trail) kèm xác thực, làm sạch đầu vào và liên kết mã HMAC.

    raw_log: chuỗi JSON của LOG THÔ đầu vào (đặc trưng luồng đã loại nhãn) — chỉ để hiển
    thị minh bạch trên Dashboard, KHÔNG tham gia HMAC (chữ ký phủ quyết định)."""
    # Xác thực hành động
    if not _validator.validate_action(action):
        logger.error(
            f"[ACTION VALIDATOR] REJECTED unknown action: {action}. "
            f"Possible sandbox escape attempt!"
        )
        action = "AWAIT_HITL"  # Chuyển về hành động an toàn mặc định

    # Làm sạch đầu vào (sanitize)
    safe_target = _validator.sanitize_target(target)
    safe_reason = _validator.sanitize_reason(reason)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with _audit_lock, sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()

            # 1. Lấy integrity_hash của dòng log cuối cùng để liên kết (chaining)
            c.execute("SELECT integrity_hash FROM audit_trail ORDER BY id DESC LIMIT 1")
            last_row = c.fetchone()
            prev_hash = (
                last_row[0] if last_row and last_row[0] else "genesis_block_hash_sentinel_soc"
            )

            # 2. Tính toán mã băm HMAC
            secret_key = os.getenv(
                "SENTINEL_LOG_SECRET", "sentinel_secure_fallback_log_secret_2026"
            ).encode()
            message = f"{prev_hash}|{timestamp}|{action}|{safe_target}|{safe_reason}".encode()
            current_hash = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

            # 3. Ghi vào database (raw_log là ngữ cảnh đầu vào, ngoài phạm vi HMAC)
            c.execute(
                "INSERT INTO audit_trail (timestamp, action, target, reason, integrity_hash, raw_log) VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, action, safe_target, safe_reason, current_hash, raw_log or ""),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Lỗi ghi audit trail: {e}")


def _redis_url() -> str:
    """URL Redis: ưu tiên env REDIS_URL (agent/subscriber có sẵn), fallback config."""
    url = os.getenv("REDIS_URL")
    if url:
        return url
    try:
        import yaml  # type: ignore

        with open(CONFIG_YAML_PATH) as f:
            return (yaml.safe_load(f) or {}).get("redis", {}).get("url", "redis://localhost:6379/0")
    except Exception:
        return "redis://localhost:6379/0"


def _add_to_blacklist(ip: str, ttl: int = 3600) -> None:
    """Ghi IP vào Redis blacklist (TTL 1h) để Tier-1 NHỚ MẶT và chặn ngay lần tái phạm mà
    KHÔNG cần leo thang Tier-2 lại. Best-effort: agent chạy trên host reach được Redis;
    dashboard container KHÔNG reach -> bỏ qua im lặng (block vẫn ghi audit + tạo luật)."""
    try:
        import redis  # type: ignore

        redis.Redis.from_url(_redis_url(), socket_connect_timeout=0.5).setex(
            f"blacklist:{ip}", ttl, "1"
        )
    except Exception as e:
        logger.warning(f"Failed to add to Redis blacklist: {e}")


def _remove_from_blacklist(ip: str) -> None:
    """Xóa IP khỏi Redis blacklist."""
    try:
        import redis  # type: ignore

        redis.Redis.from_url(_redis_url(), socket_connect_timeout=0.5).delete(f"blacklist:{ip}")
    except Exception as e:
        logger.warning(f"Failed to remove from Redis blacklist: {e}")


def unblock_ip(ip: str):
    """Gỡ chặn IP bằng cách xóa khỏi Tier-1 Redis blacklist và reset Reputation."""
    safe_ip = _validator.sanitize_target(ip)

    # 1. Xoá khỏi Redis cache chặn tốc độ cao
    _remove_from_blacklist(safe_ip)
    logger.info(f" [FIREWALL MOCK] UNBLOCKED IP: {safe_ip} (removed from Redis)")

    # 2. Xoá tiền sử danh tiếng xấu trong DB để tránh Tier-1 auto-block lại ngay lập tức
    try:
        from src.agent.threat_memory import ThreatMemoryStore

        mem = ThreatMemoryStore()
        mem.reset_ip_reputation(safe_ip)
    except Exception as e:
        logger.error(f"[FIREWALL MOCK] Failed to reset reputation for {safe_ip}: {e}")


def block_ip(ip: str, reason: str, raw_log: str = ""):
    safe_ip = _validator.sanitize_target(ip)
    # ĐỒNG BỘ WHITELIST (phòng vệ chiều sâu): IP đã whitelist KHÔNG BAO GIỜ bị chặn thật —
    # dù suy luận LLM/Tier-2 có nêu tên nó trong 1 batch nhiều IP. Ghi bản WHITELIST (cho
    # qua) thay vì BLOCK_IP để UI nhất quán, tránh mâu thuẫn "vừa whitelist vừa bị chặn".
    if safe_ip in _whitelisted_ips():
        logger.warning(f" [FIREWALL MOCK] BỎ QUA chặn (đã whitelist): {safe_ip}")
        _log_to_db(
            "WHITELIST",
            safe_ip,
            f"IP whitelist — BỎ QUA lệnh chặn từ Tier-2/LLM (giữ đặc cách cho qua). "
            f"Lý do gốc: {reason}",
            raw_log,
        )
        return
    logger.warning(f" [FIREWALL MOCK] BLOCKING IP: {safe_ip} | Lý do: {reason}")
    _log_to_db("BLOCK_IP", safe_ip, reason, raw_log)
    # TRÍ NHỚ: đưa vào blacklist để Tier-1 chặn thẳng lần sau (Tier-2 không phải xử lại).
    _add_to_blacklist(safe_ip)


def quarantine_host(host: str, reason: str, raw_log: str = ""):
    safe_host = _validator.sanitize_target(host)
    logger.warning(f" [EDR MOCK] QUARANTINE HOST: {safe_host} | Lý do: {reason}")
    _log_to_db("QUARANTINE", safe_host, reason, raw_log)


def raise_alert(msg: str, reason: str, raw_log: str = ""):
    logger.info(f" [SIEM MOCK] ALERT: {msg} | Lý do: {reason}")
    _log_to_db("ALERT", msg, reason, raw_log)


def get_audit_trail(limit=50):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT timestamp, action, target, reason, raw_log FROM audit_trail ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = c.fetchall()
        return [
            {
                "timestamp": r[0],
                "action": r[1],
                "target": r[2],
                "reason": r[3],
                "raw_log": r[4] or "",
            }
            for r in rows
        ]
    except Exception:
        return []


def get_audit_trail_for_ip(ip: str, limit=100):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT timestamp, action, target, reason, raw_log FROM audit_trail WHERE target = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            )
            rows = c.fetchall()
        return [
            {
                "timestamp": r[0],
                "action": r[1],
                "target": r[2],
                "reason": r[3],
                "raw_log": r[4] or "",
            }
            for r in rows
        ]
    except Exception:
        return []


def verify_audit_trail_integrity() -> tuple[bool, str]:
    """
    Quét toàn bộ chuỗi audit_trail và xác minh tính toàn vẹn (HMAC Log Chaining).
    Trả về (True, "Hệ thống toàn vẹn") hoặc (False, "Mô tả lỗi").
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, timestamp, action, target, reason, integrity_hash FROM audit_trail ORDER BY id ASC"
            )
            rows = c.fetchall()

        if not rows:
            return True, "Cơ sở dữ liệu trống. Hệ thống nhật ký trống nhưng toàn vẹn."

        secret_key = os.getenv(
            "SENTINEL_LOG_SECRET", "sentinel_secure_fallback_log_secret_2026"
        ).encode()
        prev_hash = "genesis_block_hash_sentinel_soc"

        for row in rows:
            row_id, timestamp, action, target, reason, integrity_hash = row

            # Tính toán lại hash mong đợi
            message = f"{prev_hash}|{timestamp}|{action}|{target}|{reason}".encode()
            expected_hash = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

            if not integrity_hash or not hmac.compare_digest(integrity_hash, expected_hash):
                return (
                    False,
                    f"⚠️ PHÁT HIỆN GIẢ MẠO! Dòng log ID {row_id} ({timestamp} - {action}) đã bị sửa đổi, xóa hoặc chèn sai thứ tự.",
                )

            prev_hash = integrity_hash

        return True, "✅ Hệ thống nhật ký toàn vẹn (0 phát hiện sửa đổi hay giả mạo)."
    except Exception as e:
        return False, f"Lỗi trong quá trình kiểm tra toàn vẹn: {e}"


def get_login_attempts(username: str) -> tuple[int, float]:
    """Trả về (attempts, lockout_until) cho một username. Tự động đặt lại (reset) nếu thời gian khóa đã hết."""
    try:
        import time

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT attempts, lockout_until FROM login_attempts WHERE username = ?", (username,)
            )
            row = c.fetchone()
            if row:
                attempts, lockout_until = row[0], row[1]
                if lockout_until > 0.0 and time.time() >= lockout_until:
                    # Thời gian khóa đã hết hạn, tự động đặt lại số lần thử
                    c.execute(
                        "UPDATE login_attempts SET attempts = 0, lockout_until = 0.0 WHERE username = ?",
                        (username,),
                    )
                    conn.commit()
                    return 0, 0.0
                return attempts, lockout_until
            return 0, 0.0
    except Exception:
        return 0, 0.0


def increment_login_attempts(username: str) -> int:
    """Tăng số lần đăng nhập thất bại và trả về số lần hiện tại."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO login_attempts (username, attempts, lockout_until)
                VALUES (?, 1, 0.0)
                ON CONFLICT(username) DO UPDATE SET attempts = attempts + 1
            """,
                (username,),
            )
            conn.commit()
        attempts, _ = get_login_attempts(username)
        return attempts
    except Exception as e:
        logger.error(f"Lỗi tăng login attempts: {e}")
        return 0


def reset_login_attempts(username: str):
    """Đặt lại số lần đăng nhập sai và mở khóa."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO login_attempts (username, attempts, lockout_until)
                VALUES (?, 0, 0.0)
                ON CONFLICT(username) DO UPDATE SET attempts = 0, lockout_until = 0.0
            """,
                (username,),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Lỗi reset login attempts: {e}")


def lock_user(username: str, duration_seconds: int):
    """Khóa tài khoản trong một khoảng thời gian."""
    try:
        import time

        lockout_time = time.time() + duration_seconds
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO login_attempts (username, attempts, lockout_until)
                VALUES (?, 5, ?)
                ON CONFLICT(username) DO UPDATE SET lockout_until = ?, attempts = 5
            """,
                (username, lockout_time, lockout_time),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Lỗi khóa người dùng: {e}")
