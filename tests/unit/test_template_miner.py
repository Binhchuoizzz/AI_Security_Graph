"""
Unit Test cho module LogTemplateMiner (src/guardrails/template_miner.py).

Kiểm tra khả năng gom nhóm log, nén volume và format output cho LLM.
"""

from src.guardrails.template_miner import LogTemplateMiner, TokenBudgetManager


class TestLogTemplateMiner:
    """Bộ kiểm thử cho LogTemplateMiner."""

    def setup_method(self):
        self.miner = LogTemplateMiner(max_samples=3)

    def test_add_single_log(self):
        """Thêm 1 log phải tạo ra đúng 1 template."""
        self.miner.add_log("GET /index.html HTTP/1.1 200")
        assert len(self.miner.templates) == 1
        assert self.miner.total_logs_processed == 1

    def test_identical_logs_grouped(self):
        """Nhiều log giống hệt nhau phải gom vào 1 template duy nhất."""
        for _ in range(100):
            self.miner.add_log("GET /index.html HTTP/1.1 200")
        assert len(self.miner.templates) == 1
        summary = self.miner.get_summary()
        assert summary[0]["count"] == 100

    def test_ip_generalization(self):
        """Địa chỉ IP phải được thay thế bằng <IP> placeholder."""
        self.miner.add_log("Failed login from 192.168.1.1")
        self.miner.add_log("Failed login from 10.0.0.5")
        assert len(self.miner.templates) == 1

    def test_numeric_generalization(self):
        """Giá trị số phải được thay thế bằng <NUM> placeholder."""
        self.miner.add_log("Connection timeout after 5000 ms")
        self.miner.add_log("Connection timeout after 3000 ms")
        assert len(self.miner.templates) == 1

    def test_max_samples_limit(self):
        """Số lượng samples được giữ lại không vượt quá max_samples."""
        for i in range(50):
            self.miner.add_log(f"Error code {i}")
        summary = self.miner.get_summary()
        assert len(summary[0]["samples"]) == 3

    def test_compression_ratio(self):
        """Tỷ lệ nén phải chính xác."""
        for _ in range(100):
            self.miner.add_log("Repeated log entry")
        ratio = self.miner.get_compression_ratio()
        assert ratio == 100.0

    def test_different_structures_separate_templates(self):
        """Log có cấu trúc khác nhau phải tạo template riêng biệt."""
        self.miner.add_log("GET /api/users HTTP/1.1")
        self.miner.add_log("POST /api/login HTTP/1.1")
        assert len(self.miner.templates) == 2

    def test_format_for_llm(self):
        """Output cho LLM phải chứa thông tin template và thống kê."""
        self.miner.add_log("Test log entry")
        output = self.miner.format_for_llm()
        assert "[Template 1]" in output
        assert "[Stats]" in output
        assert "Compression:" in output

    def test_add_log_dict(self):
        """Thêm log dạng dict phải hoạt động đúng."""
        log_dict = {
            "Source IP": "192.168.1.1",
            "Destination Port": 22,
            "Protocol": 6,
            "Total Fwd Packets": 100,
        }
        self.miner.add_log_dict(log_dict)
        assert self.miner.total_logs_processed == 1

    def test_reset(self):
        """Hàm reset phải xóa sạch tất cả dữ liệu."""
        self.miner.add_log("Test log")
        self.miner.reset()
        assert len(self.miner.templates) == 0
        assert self.miner.total_logs_processed == 0

    def test_timestamp_tracking(self):
        """Time range phải được theo dõi đúng."""
        self.miner.add_log("Event", timestamp=1.0)
        self.miner.add_log("Event", timestamp=5.0)
        summary = self.miner.get_summary()
        assert summary[0]["time_range"][0] == 1.0
        assert summary[0]["time_range"][1] == 5.0


class TestTokenBudgetManager:
    """Bộ kiểm thử cho TokenBudgetManager."""

    def setup_method(self):
        self.manager = TokenBudgetManager(budget=100)

    def test_estimate_tokens(self):
        """Ước lượng token phải xấp xỉ len/4."""
        text = "a" * 400
        assert self.manager.estimate_tokens(text) == 100

    def test_fit_to_budget_no_overflow(self):
        """Khi chưa vượt ngân sách, toàn bộ nội dung phải được giữ lại."""
        short_text = "Line 1\nLine 2\nLine 3"
        result = self.manager.fit_to_budget(short_text)
        assert "TRUNCATED" not in result
        assert "Token usage" in result

    def test_fit_to_budget_overflow(self):
        """Khi vượt ngân sách, nội dung phải bị cắt và ghi chú TRUNCATED."""
        long_text = "\n".join([f"Long log line number {i} " * 10 for i in range(100)])
        result = self.manager.fit_to_budget(long_text)
        assert "TRUNCATED" in result


class TestTemplateMinerEntropyScorer:
    """Kiểm tra EntropyScorer tích hợp với TemplateMiner."""

    def test_default_threshold_value(self):
        from src.guardrails.template_miner import EntropyScorer

        scorer = EntropyScorer()  # Ngưỡng mặc định 4.5
        assert scorer.threshold == 4.5

        # Dữ liệu entropy thấp (< 4.5)
        low_entropy_log = "GET /index.html HTTP/1.1 200 OK"
        assert scorer.is_high_entropy(low_entropy_log) is False

        # Dữ liệu entropy cao (>= 4.5) do chứa nhiều ký tự ngẫu nhiên hoặc payload độc hại dài
        high_entropy_log = "SELECT * FROM users WHERE id=1 OR 1=1 UNION SELECT username,password FROM admin -- aAbBcCdD"
        assert scorer.is_high_entropy(high_entropy_log) is True
