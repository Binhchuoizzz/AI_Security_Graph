"""
Guardrails: Data Validator

Kiểm tra tính toàn vẹn dữ liệu trước khi đưa vào pipeline LangGraph.
  - Schema Validation: Đảm bảo log có đúng các trường bắt buộc.
  - Type Coercion: Ép kiểu an toàn cho các trường số (tránh crash runtime).
  - Null/NaN Handling: Làm sạch giá trị rỗng.
"""

REQUIRED_FIELDS = ['Source IP', 'Destination Port', 'Protocol']

class DataValidator:
    def __init__(self, required_fields: list = None):
        self.required_fields = required_fields or REQUIRED_FIELDS

    def validate(self, log_entry: dict) -> dict:
        """
        Kiểm tra và làm sạch log entry.
        Trả về log đã sạch + flag validation status.
        """
        errors = []

        # Schema check
        for field in self.required_fields:
            if field not in log_entry:
                errors.append(f"Missing required field: {field}")

        # Type coercion cho các trường số
        numeric_fields = ['Destination Port', 'Total Fwd Packets', 'Flow Duration']
        for field in numeric_fields:
            if field in log_entry:
                try:
                    log_entry[field] = float(log_entry[field])
                except (ValueError, TypeError):
                    log_entry[field] = 0
                    errors.append(f"Invalid numeric value for '{field}', defaulted to 0")

        # Null/NaN handling
        for key, value in log_entry.items():
            if value is None or (isinstance(value, float) and value != value):  # NaN check
                log_entry[key] = ""

        log_entry['_validation_errors'] = errors
        log_entry['_is_valid'] = len(errors) == 0

        return log_entry
