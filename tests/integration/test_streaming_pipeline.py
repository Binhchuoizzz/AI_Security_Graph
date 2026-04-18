"""
Integration Tests: Streaming Pipeline (Publisher → Redis → Subscriber → RuleEngine)
Kiểm thử end-to-end luồng dữ liệu từ Redis queue tới Tier 1 filter.
"""
import sys
import os
import json
import pytest
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


class TestMultiSourceRouting:
    """Test Multi-source Log Correlation routing logic."""

    def test_firewall_routing(self):
        from scripts.simulate_traffic import determine_queue
        log = {"Destination Port": 22, "payload": ""}
        assert determine_queue(log) == "queue_firewall"

    def test_waf_routing(self):
        from scripts.simulate_traffic import determine_queue
        log = {"Destination Port": 80, "payload": "GET /admin"}
        assert determine_queue(log) == "queue_waf"

    def test_sysmon_routing(self):
        from scripts.simulate_traffic import determine_queue
        log = {"Destination Port": 9999, "payload": ""}
        assert determine_queue(log) == "queue_sysmon"

    def test_rdp_goes_to_firewall(self):
        from scripts.simulate_traffic import determine_queue
        log = {"Destination Port": 3389, "payload": ""}
        assert determine_queue(log) == "queue_firewall"

    def test_https_goes_to_waf(self):
        from scripts.simulate_traffic import determine_queue
        log = {"Destination Port": 443, "payload": ""}
        assert determine_queue(log) == "queue_waf"


class TestRuleEngineIntegration:
    """Test RuleEngine processes logs with provenance tags correctly."""

    def test_provenance_tag_preserved(self):
        from src.tier1_filter.rule_engine import RuleEngine
        engine = RuleEngine()
        log = {
            "Source IP": "10.0.0.1",
            "Destination Port": 22,
            "Total Fwd Packets": 100,
            "log_source": "queue_firewall"
        }
        result = engine.evaluate(log)
        assert result.get("log_source") == "queue_firewall"

    def test_multi_source_batch_processing(self):
        """Simulate a batch of logs from different sources."""
        from src.tier1_filter.rule_engine import RuleEngine
        engine = RuleEngine()
        
        batch = [
            {"Source IP": "10.0.0.1", "Destination Port": 22, "Total Fwd Packets": 5000, "log_source": "queue_firewall"},
            {"Source IP": "10.0.0.2", "Destination Port": 80, "Total Fwd Packets": 10, "log_source": "queue_waf"},
            {"Source IP": "10.0.0.3", "Destination Port": 8080, "Total Fwd Packets": 3, "log_source": "queue_sysmon"},
        ]
        
        results = [engine.evaluate(log) for log in batch]
        
        # SSH with high packets should escalate
        assert results[0]["tier1_action"] == "ESCALATE"
        # Normal HTTP should drop
        assert results[1]["tier1_action"] == "DROP"


class TestRedisConnectivity:
    """Test Redis connection and queue operations."""

    @pytest.fixture
    def redis_client(self):
        import redis
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            r = redis.Redis.from_url(url, decode_responses=True)
            r.ping()
            return r
        except Exception:
            pytest.skip("Redis not available")

    def test_redis_ping(self, redis_client):
        assert redis_client.ping() is True

    def test_queue_push_pop(self, redis_client):
        test_queue = "test_sentinel_queue"
        test_data = json.dumps({"Source IP": "1.1.1.1", "test": True})
        
        redis_client.rpush(test_queue, test_data)
        result = redis_client.lpop(test_queue)
        
        parsed = json.loads(result)
        assert parsed["Source IP"] == "1.1.1.1"
        assert parsed["test"] is True

    def test_multi_queue_blpop(self, redis_client):
        """Test BLPOP across multiple queues (core SIEM mechanism)."""
        queues = ["test_q_fw", "test_q_waf", "test_q_sys"]
        
        # Clean up
        for q in queues:
            redis_client.delete(q)
        
        # Push to WAF queue
        redis_client.rpush("test_q_waf", json.dumps({"event": "sql_injection"}))
        
        # BLPOP should pick from WAF
        result = redis_client.blpop(queues, timeout=1)
        assert result is not None
        assert result[0] == "test_q_waf"
        
        # Clean up
        for q in queues:
            redis_client.delete(q)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
