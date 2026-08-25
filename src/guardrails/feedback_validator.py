"""Kiểm luật động trước khi nhận: zero-trust cho mẫu luật và địa chỉ IP."""

import ipaddress
import logging
import re

from src.guardrails.constants import KEY_ALIASES
from src.guardrails.prompt_filter import load_config

logger = logging.getLogger(__name__)


class FeedbackValidator:
    """
    Xác thực các quy tắc động (dynamic rules) và whitelist được đẩy về Tier-1.
    Chống bypass bằng wildcard và chặn/cho phép sai IP (Zero-Trust Principle).
    """

    def __init__(self):
        config = load_config()
        subnets = config.get("guardrails", {}).get(
            "trusted_internal_subnets",
            ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        )
        self.trusted_subnets = subnets
        self.allowed_fields = ["Source IP", "Destination Port", "Protocol", "URI", "User-Agent"]

    def validate_rule(self, field: str, pattern: str, score: int) -> tuple[bool, list[str]]:
        """
        Xác thực cấu trúc và logic an toàn của một rule mới.
        Trả về (is_valid, list_of_errors).
        """
        errors = []

        norm_field = KEY_ALIASES.get(field.lower(), field)
        if norm_field not in self.get_allowed_fields():
            errors.append(
                f"Field '{field}' is not allowed for dynamic rules. "
                f"Allowed fields: {self.allowed_fields}"
            )

        pattern_str = pattern.strip()
        if not pattern_str:
            errors.append("Rule pattern cannot be empty")
            return False, errors

        # Luật quét sạch Internet thì vô dụng mà lại chặn luôn chính mình.
        if pattern_str in ["0.0.0.0/0", "*", "any", "all", "::/0"]:
            errors.append(
                "Wildcard rules targeting the entire internet "
                "(e.g. '0.0.0.0/0' or '*') are forbidden"
            )

        if norm_field == "Source IP":
            if pattern_str in ["127.0.0.1", "::1", "10.0.0.99", "localhost"]:
                errors.append(
                    f"Forbidden to create rules affecting critical infrastructure IP: {pattern_str}"
                )
            else:
                try:
                    if "/" in pattern_str:
                        net = ipaddress.ip_network(pattern_str, strict=False)
                        # /8 trở lên là hàng triệu địa chỉ - quá rộng cho một luật tự sinh.
                        if net.prefixlen < 8:
                            errors.append(
                                f"CIDR prefix /{net.prefixlen} is too broad (must be >= /8)"
                            )
                    else:
                        ip = ipaddress.ip_address(pattern_str)
                        for subnet_str in self.trusted_subnets:
                            network = ipaddress.ip_network(subnet_str, strict=False)
                            # Địa chỉ mạng = chặn cả subnet nội bộ chứ không phải một máy.
                            if ip == network.network_address:
                                errors.append(f"Forbidden to match network address: {pattern_str}")
                except ValueError:
                    # Không phải IP thì là regex/chữ ký, để nhánh dưới kiểm cú pháp.
                    pass

        # Kiểm cú pháp regex cho trường không phải IP
        if norm_field in ["URI", "User-Agent"]:
            try:
                re.compile(pattern_str)
            except re.error as e:
                errors.append(f"Invalid regex syntax in pattern: {e}")

        if not (0 <= score <= 100):
            errors.append(f"Rule score {score} must be clamped between 0 and 100")

        return len(errors) == 0, errors

    def validate_whitelist_ip(self, ip_str: str) -> tuple[bool, list[str]]:
        """Xác thực IP whitelist mới.

        Analyst được whitelist một HOST cụ thể ở bất kỳ dải nào (nội bộ, TEST-NET, hay
        public như DAPT) - đây là quyết định có chủ đích cho mọi luồng demo/vận hành.
        Chỉ cấm thứ thực sự nguy hiểm (Zero-Trust): wildcard toàn Internet và dải CIDR quá
        lớn (nuốt cả vùng địa chỉ). Whitelist host cụ thể là hợp lệ; whitelist cả dải thì không.
        """
        errors = []
        ip_str = ip_str.strip()

        if ip_str in ["0.0.0.0", "0.0.0.0/0", "*", "any", "all", "::/0"]:
            errors.append("Cannot whitelist wildcard internet ranges")
            return False, errors

        try:
            if "/" in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                # Cấm dải quá lớn: prefix < /16 (IPv4) nghĩa là > 65k host -> quá rộng để tin.
                min_prefix = 16 if net.version == 4 else 64
                if net.prefixlen < min_prefix:
                    errors.append(
                        f"CIDR {ip_str} quá rộng để whitelist (yêu cầu /{min_prefix} trở lên); "
                        "chỉ whitelist host cụ thể hoặc dải nhỏ."
                    )
            else:
                ipaddress.ip_address(ip_str)  # host cụ thể: chỉ cần hợp lệ là whitelist được
        except ValueError:
            errors.append(f"Invalid IP address or CIDR format: {ip_str}")

        return len(errors) == 0, errors

    def get_allowed_fields(self) -> list[str]:
        return self.allowed_fields
