"""
Exact-Match Response Cache cho Tier-2 (LLM).

TRUNG THỰC VỀ THUẬT NGỮ: đây KHÔNG phải "semantic cache" (không có embedding/độ tương
đồng vector như GPTCache). Đây là cache KHỚP-CHÍNH-XÁC theo dấu vân (fingerprint) MD5 của
chuỗi batch ĐÃ MÃ HOÁ: chỉ HIT khi log mới băm ra CÙNG hash với log đã phân tích trước đó
(tức nội dung đưa vào LLM giống hệt sau khi Guardrails nén/che biến). Mục tiêu: các đợt
DDoS/Brute-force sinh nhiều log gần như trùng lặp -> bỏ qua lần gọi LLM lặp lại (2-3s -> <1ms).

An toàn đa luồng: subscriber chạy nhiều agent worker song song cùng đọc/ghi cache này, nên
mọi thao tác get/set/evict được bọc trong một threading.Lock (tránh 'dictionary changed size
during iteration' khi một luồng evict trong lúc luồng khác chèn).
"""

import hashlib
import logging
import threading
import time

logger = logging.getLogger(__name__)


class ExactMatchResponseCache:
    def __init__(self, max_size=10000, ttl_seconds=3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()

    def _hash_payload(self, batch_encapsulated: str) -> str:
        """Dấu vân MD5 cho chuỗi dữ liệu (đã bọc tags). MD5 CHỈ dùng làm khoá cache —
        KHÔNG dùng cho mục đích bảo mật (nên đặt usedforsecurity=False)."""
        return hashlib.md5(batch_encapsulated.encode("utf-8"), usedforsecurity=False).hexdigest()

    def get(self, batch_encapsulated: str) -> dict | None:
        """Lấy kết quả từ cache. Trả về None nếu miss hoặc hết hạn."""
        if not batch_encapsulated:
            return None

        key = self._hash_payload(batch_encapsulated)
        with self._lock:
            entry = self.cache.get(key)
            if entry is None:
                return None
            if time.time() - entry["ts"] < self.ttl_seconds:
                logger.info(f"[ResponseCache] HIT - Bypassing LLM cho dấu vân {key[:8]}...")
                return entry["result"]
            # Hết hạn -> loại bỏ
            self.cache.pop(key, None)
            return None

    def set(self, batch_encapsulated: str, llm_decision: dict):
        """Lưu kết quả từ LLM vào Cache."""
        if not batch_encapsulated or not llm_decision:
            return

        key = self._hash_payload(batch_encapsulated)
        with self._lock:
            # LRU eviction đơn giản nếu đầy: xoá 20% cũ nhất (thao tác nằm TRONG lock để
            # snapshot keys không bị luồng khác sửa giữa chừng).
            if len(self.cache) >= self.max_size and key not in self.cache:
                sorted_keys = sorted(self.cache, key=lambda k: self.cache[k]["ts"])
                for k in sorted_keys[: max(1, int(self.max_size * 0.2))]:
                    self.cache.pop(k, None)
            self.cache[key] = {"ts": time.time(), "result": llm_decision}
            logger.debug(f"[ResponseCache] SET - Lưu kết quả cho dấu vân {key[:8]}")

    # ── LỚP 2: Cache theo ĐẶC TRƯNG (feature fingerprint) ────────────────────────
    # Exact-match ở trên chỉ HIT khi chuỗi log GIỐNG HỆT. Nhưng luồng gộp có RẤT NHIỀU
    # log gần-trùng về BẢN CHẤT (vd ~400 DAPT nền benign: cùng cổng 443, không payload,
    # khác mỗi IP/timestamp) — exact-match bỏ lỡ hết -> mỗi cái tốn 1 lần gọi LLM (5.7s),
    # phình backlog. Lớp này băm theo ĐẶC TRƯNG NỔI BẬT (service/cổng/protocol/tier1/dấu
    # vân payload) — KHÔNG gồm IP/timestamp — nên flow cùng bản chất GỘP về 1 lần gọi LLM.
    # An toàn IP: mục tiêu THỰC THI (block) LUÔN lấy từ Source IP của batch hiện tại trong
    # node_llm_triage, KHÔNG từ verdict cache -> gộp không gây chặn nhầm IP.
    _WELL_KNOWN_PORTS = frozenset({21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080})

    def _port_token(self, val) -> str:
        """Cổng well-known -> giữ nguyên số (định danh dịch vụ); cổng ephemeral cao -> gộp
        về 'hi' (mọi cổng lạ đều 'phi chuẩn' như nhau); còn lại -> '0'."""
        try:
            p = int(float(val or 0))
        except (TypeError, ValueError):
            p = 0
        if p in self._WELL_KNOWN_PORTS:
            return str(p)
        return "hi" if p >= 1024 else "0"

    def feature_fingerprint(self, log: dict) -> str:
        """Chuỗi đặc trưng chuẩn hoá cho một log escalate (nền của khoá cache lớp-2)."""
        reasons = log.get("tier1_reasons") or []
        if isinstance(reasons, list):
            reasons = "|".join(sorted(str(r) for r in reasons))
        else:
            reasons = str(reasons)
        app = (
            (str(log.get("message", "")) + str(log.get("payload", "")) + str(log.get("uri", "")))
            .strip()
            .lower()
        )
        app_fp = (
            hashlib.md5(app.encode("utf-8"), usedforsecurity=False).hexdigest()[:12] if app else ""
        )
        parts = [
            str(log.get("service") or log.get("Service") or ""),
            self._port_token(log.get("Destination Port") or log.get("dst_port")),
            str(log.get("Protocol") or log.get("protocol") or ""),
            str(log.get("tier1_action") or ""),
            reasons,
            app_fp,
        ]
        return "ftr:" + "§".join(parts)

    def get_by_features(self, log: dict) -> dict | None:
        """Tra cache theo đặc trưng (dùng lại LRU/TTL của get())."""
        if not log:
            return None
        return self.get(self.feature_fingerprint(log))

    def set_by_features(self, log: dict, llm_decision: dict):
        """Lưu verdict theo đặc trưng (dùng lại eviction/TTL của set())."""
        if not log or not llm_decision:
            return
        self.set(self.feature_fingerprint(log), llm_decision)


# Singleton instance
response_cache = ExactMatchResponseCache()
