"""
Guardrails: State Monitor
"""

import atexit
import json
import os
import sqlite3
import threading
import time
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
        "llm": {"max_context_tokens": 16384},
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
        self.max_tokens = int(config.get("llm", {}).get("max_context_tokens", 16384))
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
        # node_counter là THREAD-LOCAL: mỗi luồng worker Tier-2 giữ bộ đếm riêng, để nhiều
        # lần agent_app.invoke() chạy SONG SONG (nhiều slot LLM) KHÔNG lẫn trạng thái vòng
        # lặp của nhau. Đơn luồng (production/test) hành vi Y HỆT như trước.
        self._local = threading.local()

    @property
    def node_counter(self) -> dict:
        nc = getattr(self._local, "node_counter", None)
        if nc is None:
            nc = {}
            self._local.node_counter = nc
        return nc

    def record_visit(self, node_name: str) -> dict:
        nc = self.node_counter
        nc[node_name] = nc.get(node_name, 0) + 1
        count = nc[node_name]

        if count > self.max_iterations:
            return {
                "node": node_name,
                "visits": count,
                "action": "FORCE_STOP",
                "reason": (f"Infinite loop detected: Node '{node_name}' visited {count} times"),
            }
        return {"node": node_name, "visits": count, "action": "CONTINUE"}

    def reset(self):
        self._local.node_counter = {}


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
        self._buf: list[tuple] = []
        self._c: sqlite3.Connection | None = None
        self._last_flush: float = time.time()
        self._init_db()
        # Chốt chặn cuối: thoát bình thường thì KHÔNG được mất phần đuôi trong bộ đệm.
        atexit.register(self.flush)

    def _init_db(self):
        with _db_lock:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                # synchronous=NORMAL: bỏ 1 fsync/commit -> ghi nhanh hơn khi nhiều worker
                # Tier-2 log song song (serialize qua _db_lock). Mức KẾT NỐI (không ghi file
                # header) nên AN TOÀN cả khi DB mở read-only (container). KHÔNG bật WAL: WAL
                # đổi header + bắt reader ghi -shm -> crash cross-UID Docker (container uid 999
                # không ghi được logs/guardrails_audit.db).
                cursor.execute("PRAGMA synchronous=NORMAL")
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

    # Gom nhiều bản ghi vào MỘT giao dịch thay vì mở/đóng kết nối cho từng sự kiện.
    #
    # LÝ DO HIỆU NĂNG, KHÔNG ĐÁNH ĐỔI TOÀN VẸN. Bảng `audit_log` này là nhật ký VẬN HÀNH —
    # nó KHÔNG mang chuỗi băm HMAC. Sổ cái pháp y có chuỗi nằm ở bảng `audit_trail` khác
    # (`src/response/executor.py::_log_to_db`) và không bị đụng tới ở đây. Vì vậy gom giao
    # dịch không làm yếu bất kỳ bảo chứng chống giả mạo nào; đổi lại, một lần sập tiến trình
    # đột ngột có thể mất phần đuôi chưa đổ (tối đa `_FLUSH_EVERY` bản ghi hoặc `_FLUSH_SEC`).
    #
    # Đo được: 15,195 ms/lượt gọi khi mỗi lượt tự mở kết nối + commit riêng. Cổng ML ghi một
    # bản ghi cho MỖI ca nó tự quyết, tức ~42,5% luồng — riêng khoản này là **53 phút** cho
    # lượt chạy 496.885 sự kiện, và nó chính là thứ ghìm subscriber ở 133–190 sự kiện/giây
    # trong khi CPU chỉ 18%: tiến trình đứng chờ đĩa chứ không tính toán gì.
    _FLUSH_EVERY = 200
    _FLUSH_SEC = 2.0

    def _conn(self):
        if self._c is None:
            self._c = sqlite3.connect(self.db_path, check_same_thread=False)
            self._c.execute("PRAGMA synchronous=NORMAL")  # mức kết nối, không WAL (xem _init_db)
        return self._c

    def flush(self) -> int:
        """Đổ bộ đệm xuống đĩa. Gọi được từ ngoài (nhịp dọn định kỳ / lúc tắt máy)."""
        with _db_lock:
            return self._flush_locked()

    def _flush_locked(self) -> int:
        if not self._buf:
            return 0
        rows, self._buf = self._buf, []
        try:
            conn = self._conn()
            conn.executemany(
                "INSERT INTO audit_log (timestamp, event_type, source_ip, tier1_score, "
                "tier1_action, guardrail_injected, agent_decision, agent_reasoning, "
                "mitre_technique, nist_control, hitl_approved, latency_ms, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            conn.commit()
        except Exception:
            # Đóng kết nối hỏng để lượt sau mở lại; KHÔNG ném ra đường nóng.
            try:
                if self._c is not None:
                    self._c.close()
            except Exception:
                pass
            self._c = None
            return 0
        self._last_flush = time.time()
        return len(rows)

    def log_event(self, event: dict):
        """Xếp sự kiện vào bộ đệm audit; tự đổ theo số lượng hoặc theo thời gian."""
        row = (
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
        )
        with _db_lock:
            self._buf.append(row)
            if (
                len(self._buf) >= self._FLUSH_EVERY
                or (time.time() - self._last_flush) >= self._FLUSH_SEC
            ):
                self._flush_locked()


# Khởi tạo singletons
loop_detector = LoopDetector()
context_overflow_guard = ContextOverflowGuard()
audit_logger = AuditLogger()
