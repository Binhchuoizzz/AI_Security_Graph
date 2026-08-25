"""Kiểm tính toàn vẹn log trước khi đưa vào đồ thị LangGraph."""

import ipaddress
import logging

from src.guardrails.constants import KEY_ALIASES, normalize_log_keys

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["Source IP", "Destination Port", "Protocol"]


class DataValidator:
    """Kiểm tra tính toàn vẹn dữ liệu trước khi đưa vào pipeline LangGraph."""

    def __init__(self, required_fields: list | None = None):
        fields = required_fields or REQUIRED_FIELDS
        # Chuẩn hoá danh sách trường bắt buộc theo bảng ánh xạ
        self.required_fields = []
        for f in fields:
            norm_f = KEY_ALIASES.get(f.lower(), f)
            self.required_fields.append(norm_f)

    def validate(self, log_entry: dict) -> dict:
        """Kiểm tra và làm sạch log entry đơn lẻ."""
        errors = []

        # Chuẩn hoá khoá trước, rồi mới soi tới giá trị.
        clean_log = normalize_log_keys(log_entry)

        # NaN/None quy về chuỗi rỗng: các assertion cũ so sánh với "", không phải None.
        for key, value in list(clean_log.items()):
            if key.startswith("_"):
                continue
            if value is None or (isinstance(value, float) and value != value):
                clean_log[key] = ""

        for field in self.required_fields:
            if field not in clean_log or clean_log[field] == "":
                errors.append(f"Missing required field: {field}")

        # Ép kiểu số: hỏng thì về 0 và ghi lỗi, không ném ngoại lệ ra ngoài.
        numeric_fields = ["Destination Port", "Total Fwd Packets", "Flow Duration", "Protocol"]
        for field in numeric_fields:
            if field in clean_log and clean_log[field] != "":
                val = clean_log[field]
                try:
                    if field in ["Destination Port", "Protocol"]:
                        clean_log[field] = int(float(val))
                    else:
                        clean_log[field] = float(val)
                except (ValueError, TypeError):
                    clean_log[field] = 0
                    errors.append(f"Invalid numeric value for '{field}', defaulted to 0")

        for ip_field in ["Source IP", "Destination IP"]:
            if ip_field in clean_log and clean_log[ip_field] != "":
                ip_str = str(clean_log[ip_field]).strip()
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    errors.append(f"Invalid IP address format in '{ip_field}': {ip_str}")

        if (
            "Destination Port" in clean_log
            and clean_log["Destination Port"] != ""
            and isinstance(clean_log["Destination Port"], int)
        ):
            port = clean_log["Destination Port"]
            if not (0 <= port <= 65535):
                errors.append(f"Destination Port {port} is out of bounds [0, 65535]")

        if (
            "Protocol" in clean_log
            and clean_log["Protocol"] != ""
            and isinstance(clean_log["Protocol"], int)
        ):
            proto = clean_log["Protocol"]
            if not (0 <= proto <= 255):
                errors.append(f"Protocol {proto} is out of bounds [0, 255]")

        clean_log["_validation_errors"] = errors
        clean_log["_is_valid"] = len(errors) == 0

        return clean_log

    def validate_batch(
        self, batch: list[dict], filter_invalid: bool = False, raise_on_error: bool = False
    ) -> list[dict]:
        """Xác thực lô dữ liệu log (batch)."""
        validated_batch = []
        for i, log in enumerate(batch):
            validated_log = self.validate(log)
            if not validated_log["_is_valid"]:
                msg = f"Validation failed at batch index {i}: {validated_log['_validation_errors']}"
                if raise_on_error:
                    raise ValueError(msg)
                logger.warning(msg)

                if filter_invalid:
                    continue

            validated_batch.append(validated_log)

        return validated_batch
