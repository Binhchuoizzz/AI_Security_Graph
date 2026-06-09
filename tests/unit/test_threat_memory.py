"""
Tests for Long-Term Threat Memory Store (APT Detection + Organizational Context)
"""
import pytest  # type: ignore
from src.agent.threat_memory import ThreatMemoryStore


@pytest.fixture
def memory_store(tmp_path):
    """Tạo memory store tạm cho testing."""
    db_path = str(tmp_path / "test_threat_memory.db")
    store = ThreatMemoryStore(db_path=db_path)
    return store


class TestIPReputation:
    """Test IP Reputation Tracking."""

    def test_record_single_incident(self, memory_store):
        memory_store.record_incident("192.168.1.100", "ALERT", "T1110")
        rep = memory_store.get_ip_reputation("192.168.1.100")
        assert rep is not None
        assert rep["total_incidents"] == 1
        assert rep["total_alerts"] == 1
        assert rep["reputation_score"] == 10.0
        assert rep["last_mitre_technique"] == "T1110"

    def test_record_multiple_incidents(self, memory_store):
        memory_store.record_incident("10.0.0.5", "ALERT")
        memory_store.record_incident("10.0.0.5", "BLOCK_IP")
        memory_store.record_incident("10.0.0.5", "ALERT")
        rep = memory_store.get_ip_reputation("10.0.0.5")
        assert rep["total_incidents"] == 3
        assert rep["total_blocks"] == 1
        assert rep["total_alerts"] == 2
        assert rep["reputation_score"] == 50.0  # 10 + 30 + 10

    def test_reputation_score_capped_at_100(self, memory_store):
        for _ in range(10):
            memory_store.record_incident("1.2.3.4", "BLOCK_IP")
        rep = memory_store.get_ip_reputation("1.2.3.4")
        assert rep["reputation_score"] <= 100.0

    def test_unknown_ip_returns_none(self, memory_store):
        assert memory_store.get_ip_reputation("255.255.255.255") is None

    def test_get_high_risk_ips(self, memory_store):
        # Low risk
        memory_store.record_incident("10.0.0.1", "LOG")
        # High risk
        for _ in range(5):
            memory_store.record_incident("10.0.0.2", "BLOCK_IP")

        high_risk = memory_store.get_high_risk_ips(min_score=50.0)
        assert len(high_risk) >= 1
        assert high_risk[0]["ip"] == "10.0.0.2"


class TestOrganizationalContext:
    """Test Known Entities (internal tools, pentest IPs)."""

    def test_add_known_entity(self, memory_store):
        memory_store.add_known_entity(
            "scanner", "10.10.10.5", "Nessus Vulnerability Scanner", "admin"
        )
        entity = memory_store.is_known_entity("10.10.10.5")
        assert entity is not None
        assert entity["entity_type"] == "scanner"
        assert entity["description"] == "Nessus Vulnerability Scanner"

    def test_unknown_entity_returns_none(self, memory_store):
        assert memory_store.is_known_entity("1.2.3.4") is None

    def test_remove_known_entity(self, memory_store):
        memory_store.add_known_entity(
            "pentest_ip", "192.168.50.10", "Pentest VM"
        )
        memory_store.remove_known_entity("192.168.50.10")
        assert memory_store.is_known_entity("192.168.50.10") is None

    def test_get_all_entities(self, memory_store):
        import sqlite3
        with sqlite3.connect(memory_store.db_path) as conn:
            conn.execute("DELETE FROM known_entities")
            conn.commit()
        memory_store.add_known_entity("scanner", "10.0.0.1", "Scanner A")
        memory_store.add_known_entity("admin_tool", "10.0.0.2", "Admin Panel")
        entities = memory_store.get_all_known_entities()
        assert len(entities) == 2


class TestAPTCorrelation:
    """Test APT Detection Logic."""

    def test_no_apt_for_new_ip(self, memory_store):
        memory_store.record_incident("10.0.0.50", "ALERT")
        apt = memory_store.check_apt_pattern("10.0.0.50")
        assert apt is None  # Not enough incidents

    def test_apt_detection_threshold(self, memory_store):
        # Simulate many incidents
        for _ in range(10):
            memory_store.record_incident("172.16.0.100", "ALERT")
        # Won't trigger APT because threshold_days requires first_seen to be old enough
        apt = memory_store.check_apt_pattern(
            "172.16.0.100", threshold_incidents=5, threshold_days=0
        )
        assert apt is not None
        assert apt["is_apt_candidate"] is True
        assert apt["total_incidents"] == 10

    def test_record_apt_indicator(self, memory_store):
        memory_store.record_apt_indicator(
            "persistent_ip", "172.16.0.100", 0.85,
            related_ips="172.16.0.100", mitre_chain="T1110→T1078"
        )
        # Record again — should increment
        memory_store.record_apt_indicator(
            "persistent_ip", "172.16.0.100", 0.90,
            related_ips="172.16.0.100", mitre_chain="T1110→T1078→T1059"
        )
        stats = memory_store.get_stats()
        assert stats["apt_indicators"] >= 1

    def test_check_apt_chain_multi_day(self, memory_store):
        # Sự kiện 1 ngày -> không phải APT
        memory_store.record_apt_event("10.0.0.1", apt_phase="recon", apt_day=1)
        result = memory_store.check_apt_chain("10.0.0.1")
        assert result["is_apt"] is False

        # Sự kiện 2 ngày khác nhau -> APT
        memory_store.record_apt_event("10.0.0.1", apt_phase="lateral", apt_day=2)
        result = memory_store.check_apt_chain("10.0.0.1")
        assert result["is_apt"] is True
        assert result["chain_length"] == 2  # 2 ngày distinct


class TestPromptContextGeneration:
    """Test context generation for LLM prompt injection."""

    def test_empty_context_for_unknown_ip(self, memory_store):
        ctx = memory_store.get_context_for_prompt("255.255.255.0")
        assert ctx == ""

    def test_context_includes_reputation(self, memory_store):
        memory_store.record_incident("10.0.0.99", "BLOCK_IP", "T1595")
        ctx = memory_store.get_context_for_prompt("10.0.0.99")
        assert "10.0.0.99" in ctx
        assert "1 incidents" in ctx or "incidents" in ctx

    def test_context_includes_known_entity(self, memory_store):
        memory_store.add_known_entity("scanner", "10.0.0.99", "Qualys Scanner")
        memory_store.record_incident("10.0.0.99", "ALERT")
        ctx = memory_store.get_context_for_prompt("10.0.0.99")
        assert "KNOWN INTERNAL ENTITY" in ctx
        assert "Qualys Scanner" in ctx


class TestStats:
    """Test dashboard statistics."""

    def test_initial_stats(self, memory_store):
        import sqlite3
        with sqlite3.connect(memory_store.db_path) as conn:
            conn.execute("DELETE FROM known_entities")
            conn.commit()
        stats = memory_store.get_stats()
        assert stats["total_tracked_ips"] == 0
        assert stats["high_risk_ips"] == 0
        assert stats["known_entities"] == 0
        assert stats["apt_indicators"] == 0

    def test_stats_after_operations(self, memory_store):
        import sqlite3
        with sqlite3.connect(memory_store.db_path) as conn:
            conn.execute("DELETE FROM known_entities")
            conn.commit()
        memory_store.record_incident("1.1.1.1", "ALERT")
        memory_store.add_known_entity("scanner", "2.2.2.2", "Test")
        stats = memory_store.get_stats()
        assert stats["total_tracked_ips"] == 1
        assert stats["known_entities"] == 1


class TestReputationDecay:
    """Test reputation decay mechanism."""

    def test_decay_does_not_crash(self, memory_store):
        memory_store.record_incident("10.0.0.1", "BLOCK_IP")
        # Should not raise
        memory_store.decay_reputation(decay_rate=0.5, inactive_days=0)


class TestMemoryPoisoningProtection:
    """Test làm sạch dữ liệu đầu vào chống Memory Poisoning."""

    def test_record_incident_sanitization(self, memory_store):
        # Truyền payload XSS/HTML/Markdown
        malicious_mitre = "T1110 <script>xss()</script> ![evil](http://evil.com)"
        memory_store.record_incident("1.2.3.4", "ALERT", malicious_mitre)

        rep = memory_store.get_ip_reputation("1.2.3.4")
        assert rep is not None
        assert "evil.com" not in rep["last_mitre_technique"]
        assert "<script>" not in rep["last_mitre_technique"]
        assert "[IMG_STRIPPED]" in rep["last_mitre_technique"]
        assert "[SCRIPT_STRIPPED]" in rep["last_mitre_technique"]

    def test_add_known_entity_sanitization(self, memory_store):
        memory_store.add_known_entity(
            "scanner <script>alert(1)</script>",
            "10.0.0.1",
            "Nessus Scanner ![leak](http://leak.com)"
        )
        entity = memory_store.is_known_entity("10.0.0.1")
        assert entity is not None
        assert "<script>" not in entity["entity_type"]
        assert "leak.com" not in entity["description"]
        assert "[IMG_STRIPPED]" in entity["description"]

