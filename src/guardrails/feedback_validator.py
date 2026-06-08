"""
Guardrails: Configurable Feedback Loop Validator (Zero-Trust Rules & IP Checks)
"""

import re
import logging
import ipaddress
from typing import Tuple, List
from src.guardrails.prompt_filter import load_config
from src.guardrails.constants import KEY_ALIASES

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
            ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        )
        self.trusted_subnets = subnets
        self.allowed_fields = [
            "Source IP", "Destination Port", "Protocol", "URI", "User-Agent"
        ]

    def validate_rule(self, field: str, pattern: str, score: int) -> Tuple[bool, List[str]]:
        """
        Xác thực cấu trúc và logic an toàn của một rule mới.
        Trả về (is_valid, list_of_errors).
        """
        errors = []

        # 1. Chuẩn hóa và kiểm tra tên trường (Field Validation)
        norm_field = KEY_ALIASES.get(field.lower(), field)
        if norm_field not in self.get_allowed_fields():
            errors.append(
                f"Field '{field}' is not allowed for dynamic rules. "
                f"Allowed fields: {self.allowed_fields}"
            )

        # 2. Kiểm tra tính hợp lệ của Pattern
        pattern_str = pattern.strip()
        if not pattern_str:
            errors.append("Rule pattern cannot be empty")
            return False, errors

        # 3. Kiểm tra Wildcard & Bypasses (Zero-Trust)
        if pattern_str in ["0.0.0.0/0", "*", "any", "all", "::/0"]:
            errors.append(
                "Wildcard rules targeting the entire internet "
                "(e.g. '0.0.0.0/0' or '*') are forbidden"
            )

        # 4. Kiểm tra an toàn cho IP và hạ tầng nếu trường liên quan đến Source IP
        if norm_field == "Source IP":
            # Chặn hành vi chặn IP hạ tầng quan trọng (Self-DoS prevention)
            if pattern_str in ["127.0.0.1", "::1", "10.0.0.99", "localhost"]:
                errors.append(
                    f"Forbidden to create rules affecting critical "
                    f"infrastructure IP: {pattern_str}"
                )
            else:
                try:
                    # Thử phân tích IP hoặc Subnet
                    if "/" in pattern_str:
                        # Dạng CIDR
                        net = ipaddress.ip_network(pattern_str, strict=False)
                        # Tránh dải quá rộng (bảo vệ zero-trust)
                        if net.prefixlen < 8:
                            errors.append(
                                f"CIDR prefix /{net.prefixlen} is too broad "
                                f"(must be >= /8)"
                            )
                    else:
                        ip = ipaddress.ip_address(pattern_str)
                        # Kiểm tra xem có trùng với hạ tầng quan trọng
                        for subnet_str in self.trusted_subnets:
                            network = ipaddress.ip_network(subnet_str, strict=False)
                            # Không cho chặn toàn bộ subnet nội bộ
                            if ip == network.network_address:
                                errors.append(
                                    f"Forbidden to match network address: "
                                    f"{pattern_str}"
                                )
                except ValueError:
                    # Nếu là regex hoặc signature khác, cho phép qua
                    pass

        # Validate regex syntax cho non-IP fields
        if norm_field in ["URI", "User-Agent"]:
            try:
                re.compile(pattern_str)
            except re.error as e:
                errors.append(f"Invalid regex syntax in pattern: {e}")

        # 5. Kiểm tra Score
        if not (0 <= score <= 100):
            errors.append(
                f"Rule score {score} must be clamped between 0 and 100"
            )

        return len(errors) == 0, errors

    def validate_whitelist_ip(self, ip_str: str) -> Tuple[bool, List[str]]:
        """
        Xác thực IP whitelist mới: Chỉ cho phép whitelist
        các dải nội bộ/tin cậy.
        Không cho phép whitelist IP công cộng ngoài Internet.
        """
        errors = []
        ip_str = ip_str.strip()

        if ip_str in ["0.0.0.0", "0.0.0.0/0", "*", "::/0"]:
            errors.append("Cannot whitelist wildcard internet ranges")
            return False, errors

        try:
            if "/" in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                # Phải nằm trong các subnet nội bộ tin cậy
                is_within = False
                for subnet_str in self.trusted_subnets:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                    if (
                        net.network_address in network
                        and net.broadcast_address in network
                    ):
                        is_within = True
                        break
                if not is_within:
                    errors.append(
                        f"IP range {ip_str} is outside the trusted "
                        f"internal subnets"
                    )
            else:
                ip = ipaddress.ip_address(ip_str)
                is_within = False
                for subnet_str in self.trusted_subnets:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                    if ip in network:
                        is_within = True
                        break
                if not is_within:
                    errors.append(
                        f"IP {ip_str} is outside the trusted "
                        f"internal subnets"
                    )
        except ValueError:
            errors.append(f"Invalid IP address or CIDR format: {ip_str}")

        return len(errors) == 0, errors

    def get_allowed_fields(self) -> List[str]:
        return self.allowed_fields
