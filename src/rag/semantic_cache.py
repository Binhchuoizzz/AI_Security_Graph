"""
RAG: Semantic Cache (Embedding Latency Optimization)

VẤN ĐỀ:
  Mỗi sự kiện escalate đều phải: embed log → query FAISS → trả context.
  Embedding realtime tốn khoảng 50-200ms/query trên CPU.
  Với 100+ events/batch, nút thắt cổ chai này sẽ làm sai lệch
  Reasoning Latency ở RQ1.

GIẢI PHÁP: Semantic Cache
  Cache các vector query đã từng xử lý (key = template pattern).
  Khi gặp log có cùng attack pattern (cùng template), trả kết quả
  từ cache thay vì embed + search lại.

  Cache hit rate dự kiến:
  - DDoS: >90% (hàng nghìn log cùng pattern)
  - Brute Force: >80% (cùng port + method)
  - Mixed attacks: 40-60%

  Điều này cũng chứng minh thêm giá trị của Template Mining:
  Template Mining không chỉ nén volume, mà còn tạo ra cache key
  chất lượng cao cho Semantic Cache.
"""
import hashlib
import time
from collections import OrderedDict


class SemanticCache:
    """
    LRU Cache cho RAG query results.
    Key: hash của query template (từ LogTemplateMiner output)
    Value: FAISS search results (MITRE + ISO contexts)

    Dùng OrderedDict để implement LRU eviction khi cache đầy.
    TTL đảm bảo cache không bị stale.
    """
    def __init__(self, max_size: int = 500, ttl_seconds: int = 1800):
        self.cache = OrderedDict()  # {hash_key: {"result": ..., "timestamp": ...}}
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # Metrics cho MLflow tracking
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
        }

    def _make_key(self, query_text: str) -> str:
        """
        Tạo cache key từ query text.
        Dùng MD5 hash (nhanh, không cần crypto security ở đây).
        """
        return hashlib.md5(query_text.encode()).hexdigest()

    def _evict_expired(self):
        """Xóa entries quá TTL."""
        now = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if (now - entry['timestamp']) > self.ttl_seconds
        ]
        for key in expired_keys:
            del self.cache[key]
            self.stats['evictions'] += 1

    def get(self, query_text: str) -> dict:
        """
        Tra cứu cache.
        Returns: {"hit": True, "result": ...} hoặc {"hit": False}
        """
        key = self._make_key(query_text)

        if key in self.cache:
            entry = self.cache[key]
            # Kiểm tra TTL
            if (time.time() - entry['timestamp']) <= self.ttl_seconds:
                # Move to end (LRU: most recently used)
                self.cache.move_to_end(key)
                self.stats['hits'] += 1
                return {"hit": True, "result": entry['result']}
            else:
                # Expired
                del self.cache[key]
                self.stats['evictions'] += 1

        self.stats['misses'] += 1
        return {"hit": False}

    def put(self, query_text: str, result: dict):
        """
        Lưu kết quả RAG search vào cache.
        LRU eviction khi cache đầy.
        """
        key = self._make_key(query_text)

        # Nếu key đã tồn tại, update
        if key in self.cache:
            self.cache.move_to_end(key)
            self.cache[key] = {
                'result': result,
                'timestamp': time.time()
            }
            return

        # Evict LRU nếu cache đầy
        while len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)  # Remove oldest
            self.stats['evictions'] += 1

        self.cache[key] = {
            'result': result,
            'timestamp': time.time()
        }

    def get_hit_rate(self) -> float:
        """Tính cache hit rate (metric cho MLflow)."""
        total = self.stats['hits'] + self.stats['misses']
        if total == 0:
            return 0.0
        return self.stats['hits'] / total

    def get_stats(self) -> dict:
        """Trả về toàn bộ stats cho MLflow logging."""
        return {
            **self.stats,
            'hit_rate': self.get_hit_rate(),
            'cache_size': len(self.cache),
            'max_size': self.max_size
        }

    def clear(self):
        """Reset cache. Dùng khi chạy experiment mới."""
        self.cache.clear()
        self.stats = {'hits': 0, 'misses': 0, 'evictions': 0}
