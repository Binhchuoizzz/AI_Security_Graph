"""
Semantic Caching Layer for Tier 2 Agent (LLM)
- Giúp bỏ qua bước gọi LLM nếu payload/log data giống hệt log đã từng phân tích.
- Tăng tốc độ phản hồi từ 2-3s xuống < 1ms cho các đợt DDoS/Brute-force.
"""

import hashlib
import logging
import time

logger = logging.getLogger(__name__)


class SemanticCache:
    def __init__(self, max_size=10000, ttl_seconds=3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds

    def _hash_payload(self, batch_encapsulated: str) -> str:
        """Tạo mã băm MD5 cho chuỗi dữ liệu (đã bọc tags)."""
        return hashlib.md5(batch_encapsulated.encode("utf-8")).hexdigest()

    def get(self, batch_encapsulated: str) -> dict | None:
        """Lấy kết quả từ cache. Trả về None nếu miss hoặc hết hạn."""
        if not batch_encapsulated:
            return None

        key = self._hash_payload(batch_encapsulated)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry["ts"] < self.ttl_seconds:
                logger.info(f"[SemanticCache] HIT - Bypassing LLM cho chuỗi hash {key[:8]}...")
                return entry["result"]
            else:
                # Expired
                del self.cache[key]

        return None

    def set(self, batch_encapsulated: str, llm_decision: dict):
        """Lưu kết quả từ LLM vào Cache."""
        if not batch_encapsulated or not llm_decision:
            return

        # LRU eviction đơn giản nếu đầy
        if len(self.cache) >= self.max_size:
            # Xóa 20% cũ nhất
            sorted_keys = sorted(self.cache.keys(), key=lambda k: self.cache[k]["ts"])
            for k in sorted_keys[: int(self.max_size * 0.2)]:
                del self.cache[k]

        key = self._hash_payload(batch_encapsulated)
        self.cache[key] = {"ts": time.time(), "result": llm_decision}
        logger.debug(f"[SemanticCache] SET - Lưu kết quả cho chuỗi hash {key[:8]}")


# Singleton instance
semantic_cache = SemanticCache()
