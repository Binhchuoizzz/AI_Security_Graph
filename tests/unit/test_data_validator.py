"""
Unit Test cho module DataValidator (src/guardrails/data_validator.py).

Kiểm tra khả năng validate schema, ép kiểu và xử lý null/NaN.
"""

import pytest
import math
from src.guardrails.data_validator import DataValidator


class TestDataValidator:
    """Bộ kiểm thử cho DataValidator."""

    def setup_method(self):
        self.validator = DataValidator()

    def test_valid_log_entry(self):
        """Log hợp lệ phải pass validation không có lỗi."""
        log = {
            "Source IP": "192.168.1.1",
            "Destination Port": 22,
            "Protocol": 6,
            "Total Fwd Packets": 100,
        }
        result = self.validator.validate(log)
        assert result["_is_valid"] is True
        assert len(result["_validation_errors"]) == 0

    def test_missing_required_field(self):
        """Log thiếu trường bắt buộc phải báo lỗi."""
        log = {
            "Source IP": "10.0.0.1",
            # Thiếu "Destination Port" và "Protocol"
        }
        result = self.validator.validate(log)
        assert result["_is_valid"] is False
        assert any("Destination Port" in e for e in result["_validation_errors"])
        assert any("Protocol" in e for e in result["_validation_errors"])

    def test_type_coercion_string_to_float(self):
        """Trường số dạng string phải được ép kiểu thành float."""
        log = {
            "Source IP": "10.0.0.1",
            "Destination Port": "443",
            "Protocol": 6,
            "Total Fwd Packets": "250",
        }
        result = self.validator.validate(log)
        assert result["Destination Port"] == 443.0
        assert result["Total Fwd Packets"] == 250.0

    def test_type_coercion_invalid_value(self):
        """Giá trị không thể ép kiểu phải mặc định về 0 và ghi lỗi."""
        log = {
            "Source IP": "10.0.0.1",
            "Destination Port": "abc_invalid",
            "Protocol": 6,
        }
        result = self.validator.validate(log)
        assert result["Destination Port"] == 0
        assert any("Invalid numeric" in e for e in result["_validation_errors"])

    def test_null_handling(self):
        """Giá trị None phải được thay bằng chuỗi rỗng."""
        log = {
            "Source IP": "10.0.0.1",
            "Destination Port": 80,
            "Protocol": None,
        }
        result = self.validator.validate(log)
        assert result["Protocol"] == ""

    def test_nan_handling(self):
        """Giá trị NaN phải được thay bằng chuỗi rỗng."""
        log = {
            "Source IP": "10.0.0.1",
            "Destination Port": 80,
            "Protocol": 6,
            "Flow Duration": float("nan"),
        }
        result = self.validator.validate(log)
        assert result["Flow Duration"] == ""

    def test_custom_required_fields(self):
        """Validator với danh sách trường tùy chỉnh phải hoạt động đúng."""
        custom_validator = DataValidator(required_fields=["timestamp", "src_ip"])
        log = {"timestamp": "2026-01-01", "src_ip": "1.2.3.4"}
        result = custom_validator.validate(log)
        assert result["_is_valid"] is True
