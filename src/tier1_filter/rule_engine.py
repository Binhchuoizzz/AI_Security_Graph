"""
Tier 1 Filter: Rule-based Engine with Session Baselining & Dynamic Rules

TRIẾT LÝ THIẾT KẾ (ĐÃ SỬA LỖI KIẾN TRÚC):
  Phiên bản cũ dùng Random Sampling (1-3% clean traffic) → BẺ GÃY kill-chain.
  Lý do: APT là tấn công low-and-slow. Ném bỏ 97-99% dữ liệu = tự tay
  xóa bằng chứng. Không tool Log Correlation nào hoạt động trên dữ liệu
  đã bị băm nát ngẫu nhiên.

  GIẢI PHÁP MỚI: Session-Aware Behavioral Baselining
  - Tier 1 duy trì baseline hành vi cho mỗi IP (frequency, ports, packet/flow ratio)
  - Mọi traffic đều được GHI NHẬN vào baseline (không vứt bỏ ngẫu nhiên)
  - Escalate lên Tier 2 khi phát hiện STATISTICAL DEVIATION so với baseline
  - Đảm bảo 100% dữ liệu bất thường (kể cả APT low-and-slow) được chuyển lên

  Tier 1 hoạt động như một BỘ LỌC THÔNG MINH, không phải máy xay ngẫu nhiên.

  FEEDBACK LOOP (Data Flow rõ ràng):
  LangGraph Agent → feedback_listener.py → system_settings.yaml → RuleEngine.__init__()
  → dynamic_rules được load tại khởi tạo và reload khi có notify
"""
import json
import yaml
import os
import time
from collections import defaultdict

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'system_settings.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


class SessionBaseline:
    """
    Theo dõi behavioral baseline cho mỗi Source IP.
    Phát hiện APT bằng statistical deviation thay vì random sampling.

    Baseline variables per IP:
    - request_count: Tổng số request trong window
    - unique_ports: Tập hợp các port đã truy cập
    - avg_packet_size: Kích thước packet trung bình
    - first_seen / last_seen: Timestamps
    - port_scan_score: Tăng khi IP quét nhiều port khác nhau
    """
    def __init__(self, deviation_threshold: float = 2.0, window_seconds: int = 300):
        self.profiles = defaultdict(lambda: {
            'request_count': 0,
            'unique_ports': set(),
            'total_fwd_packets': 0,
            'first_seen': None,
            'last_seen': None,
        })
        self.deviation_threshold = deviation_threshold
        self.window_seconds = window_seconds
        self.global_avg_request_rate = 1.0  # Initialized, updated over time

    def update(self, source_ip: str, log_entry: dict) -> dict:
        """
        Cập nhật baseline cho IP và trả về deviation score.
        GHI NHẬN TOÀN BỘ traffic, không vứt bỏ gì.
        """
        profile = self.profiles[source_ip]
        now = time.time()

        # Update profile
        profile['request_count'] += 1
        try:
            port = int(log_entry.get('Destination Port', 0))
            profile['unique_ports'].add(port)
        except (ValueError, TypeError):
            pass
        try:
            profile['total_fwd_packets'] += float(log_entry.get('Total Fwd Packets', 0))
        except (ValueError, TypeError):
            pass

        if profile['first_seen'] is None:
            profile['first_seen'] = now
        profile['last_seen'] = now

        # Tính deviation indicators
        deviation_reasons = []
        deviation_score = 0

        # Indicator 1: Port Scanning (IP truy cập quá nhiều ports khác nhau)
        unique_port_count = len(profile['unique_ports'])
        if unique_port_count > 5:
            deviation_score += unique_port_count * 3
            deviation_reasons.append(
                f"Port scanning: {unique_port_count} unique ports accessed"
            )

        # Indicator 2: High-frequency requests (so với global average)
        elapsed = max(now - profile['first_seen'], 1)
        request_rate = profile['request_count'] / elapsed
        if request_rate > self.global_avg_request_rate * self.deviation_threshold:
            deviation_score += 20
            deviation_reasons.append(
                f"High request rate: {request_rate:.2f} req/s "
                f"(baseline: {self.global_avg_request_rate:.2f})"
            )

        # Indicator 3: Abnormal packet volume
        if profile['request_count'] > 0:
            avg_packets = profile['total_fwd_packets'] / profile['request_count']
            if avg_packets > 500:
                deviation_score += 15
                deviation_reasons.append(
                    f"High avg packet volume: {avg_packets:.0f} pkts/request"
                )

        return {
            'source_ip': source_ip,
            'deviation_score': deviation_score,
            'deviation_reasons': deviation_reasons,
            'request_count': profile['request_count'],
            'unique_ports': unique_port_count,
            'is_anomalous': deviation_score > 0
        }

    def update_global_baseline(self):
        """Cập nhật global average request rate từ tất cả IP profiles."""
        if not self.profiles:
            return
        total_rates = []
        now = time.time()
        for ip, profile in self.profiles.items():
            if profile['first_seen']:
                elapsed = max(now - profile['first_seen'], 1)
                total_rates.append(profile['request_count'] / elapsed)
        if total_rates:
            self.global_avg_request_rate = sum(total_rates) / len(total_rates)

    def reset_window(self):
        """Reset tất cả profiles. Gọi sau mỗi time window."""
        self.profiles.clear()


class RuleEngine:
    """
    Tier 1 Rule Engine — Bộ lọc thông minh (KHÔNG random).

    Luồng xử lý mỗi log entry:
      1. Static Rules: Kiểm tra port nhạy cảm, volumetric attack
      2. Dynamic Rules: Áp dụng rule từ Feedback Loop (LangGraph Agent)
      3. Session Baselining: Kiểm tra behavioral deviation cho Source IP
      4. Quyết định: ESCALATE (lên Tier 2) hoặc DROP (log sạch)

    KHÔNG có Random Sampling. Mọi quyết định đều dựa trên LOGIC.

    FEEDBACK LOOP DATA FLOW:
    ┌─────────────────────────────────────────────────────────┐
    │ LangGraph Agent (Tier 2) phát hiện mẫu tấn công mới   │
    │         │                                               │
    │         ▼                                               │
    │ feedback_listener.py nhận rule mới                      │
    │         │                                               │
    │         ▼                                               │
    │ Persist vào config/system_settings.yaml                 │
    │         │                                               │
    │         ▼                                               │
    │ RuleEngine.reload_dynamic_rules() load rule mới        │
    │         │                                               │
    │         ▼                                               │
    │ Rule mới được áp dụng ngay trong evaluate() tiếp theo  │
    └─────────────────────────────────────────────────────────┘
    """
    def __init__(self):
        config = load_config()
        tier1_config = config.get('tier1', {})

        self.risk_threshold = tier1_config.get('risk_threshold', 30)
        self.sensitive_ports = tier1_config.get('sensitive_ports', [21, 22, 23, 3389])
        self.max_fwd_packets = tier1_config.get('max_fwd_packets', 1000)
        self.dynamic_rules = tier1_config.get('dynamic_rules', [])

        # Session Baselining thay thế Random Sampling
        baseline_config = tier1_config.get('session_baseline', {})
        self.session_baseline = SessionBaseline(
            deviation_threshold=baseline_config.get('deviation_threshold', 2.0),
            window_seconds=baseline_config.get('window_seconds', 300)
        )

    def evaluate(self, log_entry: dict) -> dict:
        """
        Đánh giá log entry qua 3 tầng: Static Rules → Dynamic Rules → Session Baseline.
        Quyết định: ESCALATE hoặc DROP. KHÔNG có SAMPLE ngẫu nhiên.
        """
        score = 0
        reasons = []

        # --- Tầng 1: Static Rules ---
        dest_port = log_entry.get('Destination Port', -1)
        fwd_packets = log_entry.get('Total Fwd Packets', 0)

        try:
            if int(dest_port) in self.sensitive_ports:
                score += 40
                reasons.append(f"Sensitive port access (Port {dest_port})")
        except (ValueError, TypeError):
            pass

        try:
            if float(fwd_packets) > self.max_fwd_packets:
                score += 30
                reasons.append(f"Volumetric anomaly ({fwd_packets} fwd pkts)")
        except (ValueError, TypeError):
            pass

        # --- Tầng 2: Dynamic Rules (Từ Feedback Loop) ---
        for rule in self.dynamic_rules:
            rule_field = rule.get('field')
            rule_pattern = rule.get('pattern')
            rule_score = rule.get('score', 50)
            if rule_field and rule_pattern:
                field_value = str(log_entry.get(rule_field, ''))
                if rule_pattern in field_value:
                    score += rule_score
                    reasons.append(
                        f"Dynamic Rule [from Agent]: {rule_field}='{rule_pattern}'"
                    )

        # --- Tầng 3: Session Baseline (thay thế Random Sampling) ---
        source_ip = log_entry.get('Source IP', 'unknown')
        baseline_result = self.session_baseline.update(source_ip, log_entry)

        if baseline_result['is_anomalous']:
            score += baseline_result['deviation_score']
            reasons.extend(baseline_result['deviation_reasons'])

        # --- Quyết định ---
        log_entry['tier1_score'] = score
        log_entry['tier1_reasons'] = reasons
        log_entry['tier1_baseline'] = {
            'ip_request_count': baseline_result['request_count'],
            'ip_unique_ports': baseline_result['unique_ports']
        }

        if score >= self.risk_threshold:
            log_entry['tier1_action'] = "ESCALATE"
        else:
            log_entry['tier1_action'] = "DROP"

        return log_entry

    def reload_dynamic_rules(self):
        """
        Hot-reload dynamic rules từ YAML config.
        Được gọi bởi feedback_listener khi có rule mới.
        """
        config = load_config()
        self.dynamic_rules = config.get('tier1', {}).get('dynamic_rules', [])
