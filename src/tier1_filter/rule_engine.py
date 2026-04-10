"""
Tier 1 Filter: Rule-based Engine with Dynamic Rules & Feedback Loop

Hoạt động như một Firewall cực nhẹ, chấm điểm sơ bộ (Risk Score) các gói tin
từ luồng phân tích. Dựa trên heuristic, các gói tin "sạch" sẽ bị gạt bỏ mà
không cần tiêu tốn tài nguyên của LangGraph AI.

Nâng cấp:
  - Random Sampling: Đẩy ngẫu nhiên 1-5% clean traffic vào Tier 2 để phát hiện Zero-day.
  - Dynamic Rule Update: Nhận rule mới từ LangGraph Agent để chặn APT ngay tại cửa ngõ.
"""
import json
import random
import yaml
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'system_settings.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


class RuleEngine:
    def __init__(self):
        config = load_config()
        tier1_config = config.get('tier1', {})

        self.risk_threshold = tier1_config.get('risk_threshold', 30)
        self.sensitive_ports = tier1_config.get('sensitive_ports', [21, 22, 23, 3389])
        self.max_fwd_packets = tier1_config.get('max_fwd_packets', 1000)
        self.sample_rate = tier1_config.get('clean_traffic_sample_rate', 0.02)
        self.dynamic_rules = tier1_config.get('dynamic_rules', [])

    def evaluate(self, log_entry: dict) -> dict:
        """
        Phân tách JSON log và trả về bản thân log đính kèm theo điểm dị thường (anomaly score).
        Tối ưu tốc độ cao nhất có thể. (O(1) dictionary lookups)
        """
        score = 0
        reasons = []

        # --- Static Rules ---
        dest_port = log_entry.get('Destination Port', -1)
        fwd_packets = log_entry.get('Total Fwd Packets', 0)

        # Rule 1: Quét truy cập trái phép vào các Port nhạy cảm
        try:
            if int(dest_port) in self.sensitive_ports:
                score += 40
                reasons.append(f"Truy cập cổng quản trị rủi ro cao (Port {dest_port})")
        except (ValueError, TypeError):
            pass

        # Rule 2: Thể tích packet bất thường (Dấu hiệu Volumetric Attack / DDoS)
        try:
            if float(fwd_packets) > self.max_fwd_packets:
                score += 30
                reasons.append(f"Mật độ gói tin FWD tăng đột biến ({fwd_packets} pkts)")
        except (ValueError, TypeError):
            pass

        # --- Dynamic Rules (Từ Feedback Loop của LangGraph) ---
        for rule in self.dynamic_rules:
            rule_field = rule.get('field')
            rule_pattern = rule.get('pattern')
            rule_score = rule.get('score', 50)
            if rule_field and rule_pattern:
                field_value = str(log_entry.get(rule_field, ''))
                if rule_pattern in field_value:
                    score += rule_score
                    reasons.append(f"Dynamic Rule matched: {rule_field} contains '{rule_pattern}'")

        # --- Quyết định ---
        log_entry['tier1_score'] = score
        log_entry['tier1_reasons'] = reasons

        if score >= self.risk_threshold:
            log_entry['tier1_action'] = "ESCALATE"
        else:
            # Random Sampling: Ngẫu nhiên đẩy 1-5% clean traffic vào Tier 2
            # để Agent "khám sức khỏe" traffic -> phát hiện Zero-day
            if random.random() < self.sample_rate:
                log_entry['tier1_action'] = "SAMPLE"
                log_entry['tier1_reasons'].append(
                    f"Random sampling ({self.sample_rate*100:.0f}% clean traffic -> Tier 2 health check)"
                )
            else:
                log_entry['tier1_action'] = "DROP"

        return log_entry

    def add_dynamic_rule(self, field: str, pattern: str, score: int = 50):
        """
        Được gọi bởi LangGraph Agent khi phát hiện mẫu tấn công mới.
        Rule mới sẽ được append vào config/system_settings.yaml.
        """
        new_rule = {"field": field, "pattern": pattern, "score": score}
        self.dynamic_rules.append(new_rule)

        # Persist rule vào YAML config
        try:
            config = load_config()
            config['tier1']['dynamic_rules'].append(new_rule)
            with open(CONFIG_PATH, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            print(f"[+] Dynamic Rule persisted: {new_rule}")
        except Exception as e:
            print(f"[!] Failed to persist dynamic rule: {e}")
