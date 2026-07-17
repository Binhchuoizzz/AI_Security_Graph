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


# Singleton instance
response_cache = ExactMatchResponseCache()
