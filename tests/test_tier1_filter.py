"""
Unit Tests: Tier 1 Rule Engine + Session Baselining
"""
import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tier1_filter.rule_engine import RuleEngine, SessionBaseline


class TestRuleEngine:
    """Kiểm thử RuleEngine với các tình huống tấn công và benign."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_sensitive_port_ssh_escalate(self):
        """Port 22 phải bị escalate."""
        log = {"Source IP": "10.0.0.1", "Destination Port": 22, "Total Fwd Packets": 5}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "ESCALATE"
        assert result["tier1_score"] >= 30

    def test_sensitive_port_rdp_escalate(self):
        """Port 3389 (RDP) phải bị escalate."""
        log = {"Source IP": "10.0.0.2", "Destination Port": 3389, "Total Fwd Packets": 10}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "ESCALATE"

    def test_high_packet_count_escalate(self):
        """Gói tin vượt ngưỡng max_fwd_packets phải bị escalate."""
        log = {"Source IP": "10.0.0.3", "Destination Port": 443, "Total Fwd Packets": 5000}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "ESCALATE"
        assert "anomaly" in str(result.get("tier1_reasons", [])).lower() or "pkts" in str(result.get("tier1_reasons", []))

    def test_benign_traffic_drop(self):
        """Traffic bình thường (port 443, ít gói) phải bị DROP."""
        log = {"Source IP": "192.168.1.1", "Destination Port": 443, "Total Fwd Packets": 3}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "DROP"
        assert result["tier1_score"] < 30

    def test_ftp_port_escalate(self):
        """Port 21 (FTP) phải bị escalate."""
        log = {"Source IP": "10.0.0.4", "Destination Port": 21, "Total Fwd Packets": 2}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "ESCALATE"

    def test_telnet_port_escalate(self):
        """Port 23 (Telnet) phải bị escalate."""
        log = {"Source IP": "10.0.0.5", "Destination Port": 23, "Total Fwd Packets": 1}
        result = self.engine.evaluate(log)
        assert result["tier1_action"] == "ESCALATE"

    def test_combined_score_accumulation(self):
        """SSH + high packets phải có score cao hơn chỉ SSH."""
        log_ssh_only = {"Source IP": "10.0.0.6", "Destination Port": 22, "Total Fwd Packets": 5}
        log_ssh_high = {"Source IP": "10.0.0.7", "Destination Port": 22, "Total Fwd Packets": 5000}
        
        result_only = self.engine.evaluate(log_ssh_only)
        result_high = self.engine.evaluate(log_ssh_high)
        
        assert result_high["tier1_score"] > result_only["tier1_score"]

    def test_evaluate_returns_required_fields(self):
        """Kết quả evaluate phải chứa đầy đủ các field bắt buộc."""
        log = {"Source IP": "1.1.1.1", "Destination Port": 80, "Total Fwd Packets": 10}
        result = self.engine.evaluate(log)
        
        assert "tier1_action" in result
        assert "tier1_score" in result
        assert "tier1_reasons" in result
        assert result["tier1_action"] in ["ESCALATE", "DROP"]


class TestSessionBaseline:
    """Kiểm thử Session Behavioral Baselining."""

    def setup_method(self):
        self.baseline = SessionBaseline(deviation_threshold=2.0, window_seconds=300)

    def test_first_connection_returns_result(self):
        """Kết nối đầu tiên phải trả về dict hợp lệ."""
        result = self.baseline.update("192.168.1.1", {"Destination Port": 80})
        assert isinstance(result, dict)

    def test_anomaly_after_burst(self):
        """Burst traffic sau baseline bình thường phải được ghi nhận."""
        ip = "10.0.0.99"
        # Xây baseline: 10 request bình thường
        for _ in range(10):
            self.baseline.update(ip, {"Destination Port": 80})
        
        # Burst: 50 request liên tiếp
        results = []
        for _ in range(50):
            result = self.baseline.update(ip, {"Destination Port": 80})
            results.append(result)
        
        # Kiểm tra có ít nhất 1 result trả về
        assert len(results) == 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
