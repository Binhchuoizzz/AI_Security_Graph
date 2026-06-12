"""
Guardrails: LLM Decision Validator (Action Enum, Anti-DoS Shield, Confidence Gate, Reasoning Sanitization)
"""

import logging
import ipaddress
from src.guardrails.output_sanitizer import output_sanitizer
from src.guardrails.prompt_filter import load_config

logger = logging.getLogger(__name__)


class DecisionValidator:
    """
    Xác thực và chuẩn hóa quyết định của LLM trước khi thực thi.
    Giảm cấp các hành động không hợp lệ hoặc có mức độ rủi ro tự từ chối dịch vụ (Self-DoS).
    """

    def __init__(self):
        config = load_config()
        # Lá chắn chống TỰ CHẶN HẠ TẦNG (Anti-Self-DoS): CHỈ bảo vệ các IP/dải HẠ TẦNG
        # TRỌNG YẾU cụ thể (loopback, gateway, DNS, DC, host giám sát) khỏi bị BLOCK_IP.
        # KHÔNG dùng `trusted_internal_subnets` (toàn bộ RFC1918) ở đây — nếu coi cả 10/8,
        # 172.16/12, 192.168/16 là "không được chặn" thì hệ thống KHÔNG THỂ cô lập kẻ tấn
        # công nội bộ (lateral movement / insider / host bị chiếm), và luồng HITL sinh-luật
        # (chỉ kích hoạt khi BLOCK_IP) sẽ không bao giờ chạy. Dải này phải HẸP và tường minh.
        self.critical_infra_subnets = config.get("guardrails", {}).get("critical_infrastructure_subnets", [
            "127.0.0.0/8", "10.0.0.99/32", "192.168.1.254/32"
        ])
        self.allowed_actions = ["BLOCK_IP", "ALERT", "AWAIT_HITL", "LOG", "DROP"]

    def validate_decision(self, decision: dict) -> dict:
        """
        Xác thực và giảm cấp hành động nếu vi phạm các chính sách an toàn.
        """
        validated = dict(decision)

        # 1. Ép buộc Action Enum hợp lệ
        action = validated.get("action", "AWAIT_HITL")
        if action not in self.allowed_actions:
            logger.warning(f"[DecisionValidator] Invalid action '{action}' overridden to AWAIT_HITL")
            validated["action"] = "AWAIT_HITL"
            action = "AWAIT_HITL"

        # 2. Kiểm tra mức độ tin cậy (Confidence Gate)
        try:
            confidence = float(validated.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0
        validated["confidence"] = confidence

        if action == "BLOCK_IP" and confidence < 0.5:
            logger.warning(
                f"[DecisionValidator] BLOCK_IP downgraded to AWAIT_HITL due to low confidence ({confidence})"
            )
            validated["action"] = "AWAIT_HITL"
            action = "AWAIT_HITL"

        # 3. Lá chắn chống tự chặn hạ tầng (Anti-DoS Shield)
        target = str(validated.get("target", "UNKNOWN")).strip()
        if action == "BLOCK_IP":
            is_critical = False

            # Hàm phụ trợ parse IP/CIDR linh hoạt chống bypass
            def parse_ip_or_network(addr_str: str):
                addr_str = addr_str.strip()
                # Thử parse trực tiếp IPAddress
                try:
                    return ipaddress.ip_address(addr_str)
                except ValueError:
                    pass

                # Thử parse trực tiếp IPNetwork (CIDR)
                try:
                    return ipaddress.ip_network(addr_str, strict=False)
                except ValueError:
                    pass

                # Thử chuyển đổi định dạng Hex/Octal/Integer
                try:
                    # Hex address (0x...)
                    if addr_str.lower().startswith("0x"):
                        val = int(addr_str, 16)
                        if 0 <= val <= 4294967295:
                            return ipaddress.ip_address(val)
                    # Octal address (bắt đầu bằng 0, dài > 1 và toàn số 0-7)
                    elif (
                        addr_str.startswith("0")
                        and len(addr_str) > 1
                        and all(c in "01234567" for c in addr_str)
                    ):
                        val = int(addr_str, 8)
                        if 0 <= val <= 4294967295:
                            return ipaddress.ip_address(val)
                    # Integer address (Decimal)
                    elif addr_str.isdigit():
                        val = int(addr_str)
                        if 0 <= val <= 4294967295:
                            return ipaddress.ip_address(val)
                except Exception:
                    pass
                return None

            parsed_obj = parse_ip_or_network(target)

            if parsed_obj:
                for subnet_str in self.critical_infra_subnets:
                    try:
                        network = ipaddress.ip_network(subnet_str, strict=False)
                        if isinstance(parsed_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                            if parsed_obj in network:
                                is_critical = True
                                break
                        elif isinstance(parsed_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                            if parsed_obj.overlaps(network):
                                is_critical = True
                                break
                    except ValueError:
                        pass
            else:
                # Nếu không thể parse, kiểm tra chuỗi tĩnh thông dụng
                if target.lower() in ["localhost", "127.0.0.1", "::1", "10.0.0.99"]:
                    is_critical = True

            if is_critical or target in ["127.0.0.1", "::1", "10.0.0.99", "localhost"]:
                logger.warning(
                    f"[DecisionValidator] BLOCK_IP on critical asset '{target}' "
                    f"downgraded to ALERT"
                )
                validated["action"] = "ALERT"
                action = "ALERT"

        # 4. Làm sạch trường giải trình và thông tin (Reasoning Sanitization)
        # Ngăn chặn các cuộc tấn công tiêm nhiễm hiển thị (XSS/SSRF qua UI)
        if "reasoning" in validated:
            validated["reasoning"] = output_sanitizer.sanitize(str(validated["reasoning"]))
        if "mitre_technique" in validated:
            validated["mitre_technique"] = output_sanitizer.sanitize(str(validated["mitre_technique"]))
        if "nist_control" in validated:
            validated["nist_control"] = output_sanitizer.sanitize(str(validated["nist_control"]))

        return validated

    def enforce_tier_consensus(self, validated: dict, tier1_flagged_attack: bool) -> dict:
        """
        Lá chắn chống Social-Engineering ngữ nghĩa (Tier-1/Tier-2 Consensus Guard).

        Tier-1 (rule engine xác định) KHÔNG thể bị thao túng bằng ngôn ngữ thuyết phục.
        Nếu Tier-1 đã đánh giá luồng này là TẤN CÔNG nhưng LLM (có thể bị giả mạo thẩm
        quyền/ngữ cảnh) lại HẠ CẤP xuống LOG/DROP (bỏ qua), KHÔNG tin LLM — buộc chuyển
        AWAIT_HITL để con người xác minh. Đây là hiện thực hóa defense-in-depth: tầng
        deterministic làm trọng tài kiểm tra tầng có thể bị thao túng.
        """
        action = str(validated.get("action", "AWAIT_HITL"))
        if tier1_flagged_attack and action in ("LOG", "DROP"):
            logger.warning(
                "[DecisionValidator] Tier-1/Tier-2 DISAGREEMENT: Tier-1 flagged attack but "
                f"LLM downgraded to {action}. Possible semantic social-engineering — overriding to AWAIT_HITL."
            )
            validated["action"] = "AWAIT_HITL"
            validated["_tier_consensus_override"] = True
            note = (
                "[GIÁM SÁT BẤT ĐỒNG TIER-1/TIER-2] Tier-1 (luật xác định) đánh giá đây là "
                "tấn công nhưng LLM hạ cấp xuống bỏ qua — nghi ngờ bị thao túng ngữ nghĩa "
                "(giả mạo thẩm quyền/ngữ cảnh). Chuyển con người kiểm duyệt."
            )
            validated["reasoning"] = note + " | " + str(validated.get("reasoning", ""))
        return validated
