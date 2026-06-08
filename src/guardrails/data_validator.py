"""
Guardrails: Data Validator
"""

import logging
import ipaddress
from typing import Optional, List
from src.guardrails.constants import normalize_log_keys, KEY_ALIASES

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["Source IP", "Destination Port", "Protocol"]


class DataValidator:
    """
    Kiểm tra tính toàn vẹn dữ liệu trước khi đưa vào pipeline LangGraph.
    """

    def __init__(self, required_fields: Optional[list] = None):
        fields = required_fields or REQUIRED_FIELDS
        # Normalize the required fields list using canonical mapping
        self.required_fields = []
        for f in fields:
            norm_f = KEY_ALIASES.get(f.lower(), f)
            self.required_fields.append(norm_f)

    def validate(self, log_entry: dict) -> dict:
        """
        Kiểm tra và làm sạch log entry đơn lẻ.
        """
        errors = []

        # 1. Chuẩn hóa log keys trước
        clean_log = normalize_log_keys(log_entry)

        # 2. Xử lý giá trị Null/NaN thành "" trước để phù hợp với các test assertion cũ
        for key, value in list(clean_log.items()):
            if key.startswith("_"):
                continue
            if value is None or (isinstance(value, float) and value != value):
                clean_log[key] = ""

        # 3. Kiểm tra các trường bắt buộc (Schema Check)
        for field in self.required_fields:
            if field not in clean_log or clean_log[field] == "":
                # Nếu trường rỗng hoặc không tồn tại, báo lỗi thiếu trường
                errors.append(f"Missing required field: {field}")

        # 4. Ép kiểu an toàn cho các trường số và kiểm tra dải giá trị
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

        # 5. Xác thực địa chỉ IP cụ thể (IPv4/IPv6 syntax validation)
        for ip_field in ["Source IP", "Destination IP"]:
            if ip_field in clean_log and clean_log[ip_field] != "":
                ip_str = str(clean_log[ip_field]).strip()
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    errors.append(f"Invalid IP address format in '{ip_field}': {ip_str}")

        # 6. Xác thực dải Port cụ thể (Port range validation [0, 65535])
        if "Destination Port" in clean_log and clean_log["Destination Port"] != "" and isinstance(clean_log["Destination Port"], int):
            port = clean_log["Destination Port"]
            if not (0 <= port <= 65535):
                errors.append(f"Destination Port {port} is out of bounds [0, 65535]")

        # 7. Xác thực dải Protocol cụ thể (Protocol validation [0, 255])
        if "Protocol" in clean_log and clean_log["Protocol"] != "" and isinstance(clean_log["Protocol"], int):
            proto = clean_log["Protocol"]
            if not (0 <= proto <= 255):
                errors.append(f"Protocol {proto} is out of bounds [0, 255]")

        clean_log["_validation_errors"] = errors
        clean_log["_is_valid"] = len(errors) == 0

        return clean_log

    def validate_batch(self, batch: List[dict], filter_invalid: bool = False, raise_on_error: bool = False) -> List[dict]:
        """
        Xác thực lô dữ liệu log (batch).
        """
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
