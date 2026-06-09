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

    def test_invalid_ip_format(self):
        """Địa chỉ IP không đúng định dạng phải bị reject."""
        log = {
            "Source IP": "999.999.999.999",
            "Destination Port": 80,
            "Protocol": 6
        }
        result = self.validator.validate(log)
        assert result["_is_valid"] is False
        assert any("Invalid IP address format" in e for e in result["_validation_errors"])

    def test_port_out_of_range(self):
        """Cổng đích ngoài dải [0, 65535] phải bị reject."""
        log = {
            "Source IP": "1.2.3.4",
            "Destination Port": 99999,
            "Protocol": 6
        }
        result = self.validator.validate(log)
        assert result["_is_valid"] is False
        assert any("out of bounds" in e for e in result["_validation_errors"])

    def test_validate_batch_filter(self):
        """Kiểm tra chức năng xử lý batch log, lọc bỏ các dòng lỗi hoặc quăng lỗi."""
        batch = [
            {"Source IP": "1.2.3.4", "Destination Port": 80, "Protocol": 6},  # Valid
            {"Source IP": "invalid_ip", "Destination Port": 80, "Protocol": 6},  # Invalid IP
            {"Source IP": "5.6.7.8", "Destination Port": 99999, "Protocol": 6},  # Invalid Port
        ]
        
        # Test 1: Mặc định giữ tất cả nhưng đánh dấu _is_valid = False
        res_default = self.validator.validate_batch(batch)
        assert len(res_default) == 3
        assert res_default[0]["_is_valid"] is True
        assert res_default[1]["_is_valid"] is False
        
        # Test 2: Lọc bỏ dòng lỗi
        res_filter = self.validator.validate_batch(batch, filter_invalid=True)
        assert len(res_filter) == 1
        assert res_filter[0]["Source IP"] == "1.2.3.4"
        
        # Test 3: Quăng lỗi khi raise_on_error = True
        with pytest.raises(ValueError) as excinfo:
            self.validator.validate_batch(batch, raise_on_error=True)
        assert "Validation failed at batch index 1" in str(excinfo.value)

