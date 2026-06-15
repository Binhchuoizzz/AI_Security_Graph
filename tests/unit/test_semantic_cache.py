"""
Unit tests cho SemanticCache (LRU + TTL) — tầng tối ưu độ trễ RAG.

Cache key = SHA-256 của query template; hit rate là metric MLflow nên
hành vi hit/miss/eviction phải chính xác tuyệt đối.
"""

import pytest  # type: ignore

from src.rag.semantic_cache import SemanticCache


@pytest.fixture
def cache():
    return SemanticCache(max_size=3, ttl_seconds=60)


class TestHitMiss:
    def test_miss_then_put_then_hit(self, cache):
        assert cache.get("port scan T1046")["hit"] is False
        cache.put("port scan T1046", {"mitre": "T1046-context"})
        res = cache.get("port scan T1046")
        assert res["hit"] is True
        assert res["result"] == {"mitre": "T1046-context"}

    def test_different_query_is_miss(self, cache):
        cache.put("brute force ssh", {"x": 1})
        assert cache.get("brute force ftp")["hit"] is False

    def test_hit_rate_metric(self, cache):
        cache.put("q", {"r": 1})
        cache.get("q")  # hit
        cache.get("khác")  # miss (chưa put)
        stats = cache.get_stats()
        assert stats["hits"] == 1 and stats["misses"] >= 1
        assert 0.0 < stats["hit_rate"] <= 0.5 + 1e-9


class TestTTL:
    def test_expired_entry_is_miss_and_evicted(self, cache):
        cache.put("stale query", {"r": "old"})
        key = cache._make_key("stale query")
        # Giả lập entry đã quá TTL (không sleep — test tất định)
        cache.cache[key]["timestamp"] -= cache.ttl_seconds + 1
        res = cache.get("stale query")
        assert res["hit"] is False
        assert key not in cache.cache
        assert cache.stats["evictions"] >= 1


class TestLRU:
    def test_eviction_when_full_removes_oldest(self, cache):
        for i in range(3):
            cache.put(f"q{i}", {"i": i})
        cache.get("q0")  # q0 thành mới nhất (LRU move_to_end)
        cache.put("q3", {"i": 3})  # đầy -> evict cũ nhất = q1
        assert cache.get("q1")["hit"] is False
        assert cache.get("q0")["hit"] is True
        assert cache.get("q3")["hit"] is True

    def test_update_existing_key_does_not_evict(self, cache):
        for i in range(3):
            cache.put(f"q{i}", {"i": i})
        cache.put("q1", {"i": "updated"})  # update, KHÔNG phải insert mới
        assert len(cache.cache) == 3
        assert cache.get("q1")["result"] == {"i": "updated"}


def test_clear_resets_everything(cache):
    cache.put("q", {"r": 1})
    cache.get("q")
    cache.clear()
    assert len(cache.cache) == 0
    assert cache.get_stats()["hits"] == 0
    assert cache.get_hit_rate() == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
