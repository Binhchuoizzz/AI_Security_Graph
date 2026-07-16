"""
Integration Tests: Streaming Pipeline (Publisher → Redis → Subscriber → RuleEngine)
Kiểm thử end-to-end luồng dữ liệu từ Redis queue tới Tier 1 filter.
"""

import json
import os
import sys

import pytest  # type: ignore

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # type: ignore

load_dotenv()


class TestMultiSourceRouting:
    """Test Multi-source Log Correlation routing logic."""

    def test_firewall_routing(self):
        from experiments.unified_dataset import determine_queue

        log = {"Destination Port": 22, "payload": ""}
        assert determine_queue(log) == "queue_firewall"

    def test_waf_routing(self):
        from experiments.unified_dataset import determine_queue

        log = {"Destination Port": 80, "payload": "GET /admin"}
        assert determine_queue(log) == "queue_waf"

    def test_unrecognized_port_goes_to_firewall(self):
        from experiments.unified_dataset import determine_queue

        log = {"Destination Port": 9999, "payload": ""}
        assert determine_queue(log) == "queue_firewall"

    def test_rdp_goes_to_firewall(self):
        from experiments.unified_dataset import determine_queue

        log = {"Destination Port": 3389, "payload": ""}
        assert determine_queue(log) == "queue_firewall"

    def test_https_goes_to_waf(self):
        from experiments.unified_dataset import determine_queue

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
            "log_source": "queue_firewall",
        }
        result = engine.evaluate(log)
        assert result.get("log_source") == "queue_firewall"

    def test_multi_source_batch_processing(self):
        """Simulate a batch of logs from different sources."""
        from src.tier1_filter.rule_engine import RuleEngine

        engine = RuleEngine()

        batch = [
            {
                "Source IP": "10.0.0.1",
                "Destination Port": 22,
                "Total Fwd Packets": 5000,
                "log_source": "queue_firewall",
            },
            {
                "Source IP": "10.0.0.2",
                "Destination Port": 80,
                "Total Fwd Packets": 10,
                "log_source": "queue_waf",
            },
            {
                "Source IP": "10.0.0.3",
                "Destination Port": 8080,
                "Total Fwd Packets": 3,
                "log_source": "queue_sysmon",
            },
        ]

        results = [engine.evaluate(log) for log in batch]

        # SSH với nhiều gói tin (volumetric) sẽ bị ALERT
        assert results[0]["tier1_action"] == "ALERT"
        # Port 80 with low packets -> DROP (since port 80 is not in sensitive_ports)
        assert results[1]["tier1_action"] == "DROP"
        # Port 8080 with low packets -> DROP
        assert results[2]["tier1_action"] == "DROP"


class TestRedisConnectivity:
    """Test Redis connection and stream operations (xadd/xreadgroup/xack)."""

    TEST_STREAM = "test_sentinel_stream"
    TEST_GROUP = "test_group"
    TEST_CONSUMER = "test_consumer"

    @pytest.fixture
    def redis_client(self):
        import redis  # type: ignore

        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            r = redis.Redis.from_url(url, decode_responses=True)
            r.ping()
            return r
        except Exception:
            pytest.skip("Redis not available")

    @pytest.fixture(autouse=True)
    def cleanup_streams(self, redis_client):
        """Clean up test streams before and after each test."""
        streams = [self.TEST_STREAM, "test_s_fw", "test_s_waf", "test_s_sys"]
        for s in streams:
            redis_client.delete(s)
        yield
        for s in streams:
            redis_client.delete(s)

    def test_redis_ping(self, redis_client):
        assert redis_client.ping() is True

    def test_stream_xadd_and_xreadgroup(self, redis_client):
        """Test xadd → xreadgroup → xack round-trip (core streaming mechanism)."""
        test_data = json.dumps({"Source IP": "1.1.1.1", "test": True})

        # Create consumer group
        redis_client.xgroup_create(self.TEST_STREAM, self.TEST_GROUP, id="0", mkstream=True)

        # Publish via xadd
        msg_id = redis_client.xadd(self.TEST_STREAM, {"log": test_data})
        assert msg_id is not None

        # Consume via xreadgroup
        response = redis_client.xreadgroup(
            self.TEST_GROUP,
            self.TEST_CONSUMER,
            {self.TEST_STREAM: ">"},
            count=1,
            block=1000,
        )
        assert response is not None
        assert len(response) == 1

        stream_name, messages = response[0]
        assert stream_name == self.TEST_STREAM
        assert len(messages) == 1

        received_id, data = messages[0]
        parsed = json.loads(data["log"])
        assert parsed["Source IP"] == "1.1.1.1"
        assert parsed["test"] is True

        # Acknowledge
        ack_count = redis_client.xack(self.TEST_STREAM, self.TEST_GROUP, received_id)
        assert ack_count == 1

    def test_multi_stream_consumer_group(self, redis_client):
        """Test xreadgroup across multiple streams (multi-source SIEM)."""
        streams = ["test_s_fw", "test_s_waf", "test_s_sys"]
        group = "test_multi_group"
        consumer = "test_multi_consumer"

        # Create consumer groups
        for s in streams:
            redis_client.xgroup_create(s, group, id="0", mkstream=True)

        # Publish to WAF stream only
        redis_client.xadd("test_s_waf", {"log": json.dumps({"event": "sql_injection"})})

        # xreadgroup must consume from WAF stream
        streams_dict = {s: ">" for s in streams}
        response = redis_client.xreadgroup(group, consumer, streams_dict, count=10, block=1000)
        assert response is not None
        assert len(response) == 1

        stream_name, messages = response[0]
        assert stream_name == "test_s_waf"
        assert len(messages) == 1

        # Verify data integrity
        _, data = messages[0]
        parsed = json.loads(data["log"])
        assert parsed["event"] == "sql_injection"

    def test_stream_xlen_backpressure(self, redis_client):
        """Test xlen reports accurate stream length for backpressure control."""
        assert redis_client.xlen(self.TEST_STREAM) == 0

        # Publish 5 messages
        for i in range(5):
            redis_client.xadd(self.TEST_STREAM, {"log": json.dumps({"idx": i})})

        assert redis_client.xlen(self.TEST_STREAM) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
