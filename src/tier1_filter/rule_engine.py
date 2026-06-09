"""
Tier 1 Filter: Rule-based Engine with Session Baselining & Dynamic Rules

TRIẾT LÝ THIẾT KẾ:
  Session-Aware Behavioral Baselining
  - Tier 1 duy trì baseline hành vi cho mỗi IP (frequency, ports, packet/flow ratio)
  - Mọi traffic đều được GHI NHẬN vào baseline (không vứt bỏ ngẫu nhiên)
  - Escalate lên Tier 2 khi phát hiện STATISTICAL DEVIATION so với baseline
  - Đảm bảo 100% dữ liệu bất thường (kể cả APT low-and-slow) được chuyển lên

  FEEDBACK LOOP (Data Flow rõ ràng):
  LangGraph Agent → feedback_listener.py → system_settings.yaml → RuleEngine.__init__()
  → dynamic_rules được load tại khởi tạo và reload khi có notify
"""

import json
import yaml  # type: ignore
import os
import time
import math
import re
from collections import defaultdict
from typing import TypedDict, Optional, Set, Dict, List, Any

class IPProfile(TypedDict):
    request_count: int
    unique_ports: Set[int]
    total_fwd_packets: float
    first_seen: Optional[float]
    last_seen: Optional[float]


class RunningStats:
    """
    Duy trì Trung bình và Phương sai chạy trực tuyến dùng thuật toán Welford.
    Độ phức tạp: O(1) thời gian, O(1) không gian. Tránh memory leak/OOM trên data lớn.
    """
    def __init__(self):
        self.n = 0
        self.old_m = 0.0
        self.new_m = 0.0
        self.old_s = 0.0
        self.new_s = 0.0

    def push(self, x: float):
        self.n += 1
        if self.n == 1:
            self.old_m = self.new_m = x
            self.old_s = 0.0
        else:
            self.new_m = self.old_m + (x - self.old_m) / self.n
            self.new_s = self.old_s + (x - self.old_m) * (x - self.new_m)
            self.old_m = self.new_m
            self.old_s = self.new_s

    def mean(self) -> float:
        return self.new_m if self.n > 0 else 0.0

    def variance(self) -> float:
        return self.new_s / (self.n - 1) if self.n > 1 else 0.0

    def std_dev(self) -> float:
        return math.sqrt(self.variance()) if self.n > 1 else 0.0


CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml"
)

# Chuan hoa key: ho tro ca CICIDS CSV format va normalized JSON format
_KEY_ALIASES = {
    "dst_port": "Destination Port",
    "src_port": "Source Port",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "fwd_packets": "Total Fwd Packets",
    "bwd_packets": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
    "flow_duration_us": "Flow Duration",
    "flow_duration_ms": "Flow Duration",
    "protocol": "Protocol",
}

# Ánh xạ các trường mạng thô sang các nhóm tính năng phục vụ Z-score tracking
_RAW_TO_CANONICAL = {
    "Flow Duration": ["Flow Duration", "flow_duration_us", "flow_duration_ms"],
    "Total Fwd Packets": ["Total Fwd Packets", "fwd_packets"],
    "Total Length of Fwd Packets": ["Total Length of Fwd Packets", "fwd_bytes", "Total Fwd Bytes"],
    "Total Backward Packets": ["Total Backward Packets", "bwd_packets", "Total Bwd Packets"],
    "Total Length of Bwd Packets": ["Total Length of Bwd Packets", "bwd_bytes", "Total Bwd Bytes"],
    "Fwd Seg Size Min": ["Fwd Seg Size Min", "fwd_seg_size_min"],
    "Init Fwd Win Byts": ["Init Fwd Win Byts", "init_fwd_win_byts"],
    "Init Bwd Win Byts": ["Init Bwd Win Byts", "init_bwd_win_byts"],
    "Bwd Pkt Len Min": ["Bwd Pkt Len Min", "bwd_pkt_len_min"],
    "PSH Flag Cnt": ["PSH Flag Cnt", "psh_flag_cnt"],
    "Flow Pkts/s": ["Flow Pkts/s", "Flow Packets/s", "flow_pkts_s"]
}


def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


class SessionBaseline:
    """
    Theo dõi behavioral baseline cho mỗi Source IP.
    Phát hiện APT bằng statistical deviation thay vì random sampling.

    CHỐNG REDIS/RAM OOM:
      Cơ chế Sliding Window TTL: IP sessions inactive quá ttl_seconds
      sẽ tự động bị evict. Đảm bảo RAM không cạn kiệt khi chạy.
    """

    def __init__(
        self,
        deviation_threshold: float = 2.0,
        window_seconds: int = 300,
        ttl_seconds: int = 600,
        max_profiles: int = 10000,
        eviction_interval: int = 100,
    ):
        self.profiles: Dict[str, IPProfile] = defaultdict(
            lambda: {
                "request_count": 0,
                "unique_ports": set(),
                "total_fwd_packets": 0.0,
                "first_seen": None,
                "last_seen": None,
            }
        )
        self.deviation_threshold = deviation_threshold
        self.window_seconds = window_seconds
        self.ttl_seconds = ttl_seconds  # IP inactive > TTL → evict
        self.max_profiles = max_profiles
        self.eviction_interval = eviction_interval
        self.global_avg_request_rate = 1.0
        self._update_counter = 0  # Đếm để trigger eviction định kỳ

    def _evict_stale_profiles(self):
        """
        Dọn dẹp IP profiles đã inactive vượt TTL.
        Chạy mỗi eviction_interval updates để không ảnh hưởng performance.
        Đây là cơ chế chống RAM OOM khi xử lý dataset lớn.
        """
        now = time.time()
        stale_ips = [
            ip
            for ip, profile in self.profiles.items()
            if profile["last_seen"] and (now - profile["last_seen"]) > self.ttl_seconds
        ]
        for ip in stale_ips:
            if ip in self.profiles:
                del self.profiles[ip]
        # Recalibrate global baseline request rate sau mỗi chu kỳ dọn dẹp
        self.update_global_baseline()

    def update(self, source_ip: str, log_entry: dict) -> dict:
        """
        Cập nhật baseline cho IP và trả về deviation score.
        GHI NHẬN TOÀN BỘ traffic, evict stale profiles định kỳ.
        """
        # Kiểm soát kích thước cache để chống tấn công cạn kiệt trạng thái (State Exhaustion)
        if source_ip not in self.profiles and len(self.profiles) >= self.max_profiles:
            self._evict_stale_profiles()
            # Nếu vẫn vượt ngưỡng sau khi dọn dẹp stale profiles, tiến hành xoá 10% profiles cũ nhất (FIFO/LRU-style)
            if len(self.profiles) >= self.max_profiles:
                sorted_ips = sorted(
                    self.profiles.keys(),
                    key=lambda ip: self.profiles[ip]["last_seen"] or 0
                )
                num_to_evict = max(1, int(self.max_profiles * 0.1))
                for ip_to_evict in sorted_ips[:num_to_evict]:
                    if ip_to_evict in self.profiles:
                        del self.profiles[ip_to_evict]

        # Eviction check mỗi eviction_interval updates
        self._update_counter += 1
        if self._update_counter % self.eviction_interval == 0:
            self._evict_stale_profiles()

        profile = self.profiles[source_ip]
        now = time.time()

        # Update profile
        profile["request_count"] += 1
        try:
            port = int(log_entry.get("Destination Port", 0))
            profile["unique_ports"].add(port)
        except (ValueError, TypeError):
            pass
        try:
            profile["total_fwd_packets"] += float(log_entry.get("Total Fwd Packets", 0))
        except (ValueError, TypeError):
            pass

        if profile["first_seen"] is None:
            profile["first_seen"] = now
        profile["last_seen"] = now

        # Tính deviation indicators
        deviation_reasons = []
        deviation_score = 0

        # Indicator 1: Port Scanning (Loại trừ HTTP/HTTPS traffic thông thường của client)
        non_http_ports = profile["unique_ports"] - {80, 443, 8080, 8443}
        non_http_port_count = len(non_http_ports)
        if non_http_port_count > 10:
            deviation_score += non_http_port_count * 3
            deviation_reasons.append(
                f"Quét cổng (Port scan): đã truy cập {non_http_port_count} cổng non-HTTP khác nhau"
            )

        # Indicator 2: High-frequency requests (so với global average)
        elapsed = max(now - profile["first_seen"], 1)
        request_rate = profile["request_count"] / elapsed
        if request_rate > self.global_avg_request_rate * self.deviation_threshold:
            deviation_score += 20
            deviation_reasons.append(
                f"Tần suất gửi yêu cầu cao: {request_rate:.2f} req/s "
                f"(ngưỡng bình thường: {self.global_avg_request_rate:.2f})"
            )

        # Indicator 3: Abnormal packet volume
        if profile["request_count"] > 0:
            avg_packets = profile["total_fwd_packets"] / profile["request_count"]
            if avg_packets > 500:
                deviation_score += 15
                deviation_reasons.append(
                    f"Số lượng gói tin trung bình cao: {avg_packets:.0f} gói/yêu cầu"
                )

        return {
            "source_ip": source_ip,
            "deviation_score": deviation_score,
            "deviation_reasons": deviation_reasons,
            "request_count": profile["request_count"],
            "unique_ports": len(profile["unique_ports"]),
            "is_anomalous": deviation_score > 0,
            "active_profiles": len(self.profiles),  # Metric cho monitoring
        }

    def update_global_baseline(self):
        """Cập nhật global average request rate từ tất cả IP profiles."""
        if not self.profiles:
            return
        total_rates = []
        now = time.time()
        for ip, profile in self.profiles.items():
            if profile["first_seen"]:
                elapsed = max(now - profile["first_seen"], 1)
                total_rates.append(profile["request_count"] / elapsed)
        if total_rates:
            self.global_avg_request_rate = sum(total_rates) / len(total_rates)

    def reset_window(self):
        """Reset tất cả profiles. Gọi sau mỗi time window."""
        self.profiles.clear()
        self._update_counter = 0


class RuleEngine:
    """
    Tier 1 Rule Engine — Bộ lọc thông minh (KHÔNG random).

    Luồng xử lý mỗi log entry:
      1. Static Rules: Kiểm tra port nhạy cảm, volumetric attack
      2. Dynamic Rules: Áp dụng rule từ Feedback Loop (LangGraph Agent)
      3. Session Baselining: Kiểm tra behavioral deviation cho Source IP
      4. Quyết định hành động chi tiết (Action Differentiation): ESCALATE / BLOCK_IP / ALERT / AWAIT_HITL / LOG / DROP
    """

    def __init__(self):
        config = load_config()
        tier1_config = config.get("tier1", {})

        self.risk_threshold = tier1_config.get("risk_threshold", 30)
        self.sensitive_ports = tier1_config.get("sensitive_ports", [21, 22, 23, 3389])
        self.max_fwd_packets = tier1_config.get("max_fwd_packets", 1000)
        
        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_rules = [r for r in all_rules if r.get("status", "ACTIVE") == "ACTIVE"]
        self.whitelist_ips = tier1_config.get("whitelist_ips", [])

        # Theo dõi file modification time để hot-reload
        self.last_config_mtime = os.path.getmtime(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else 0
        self.last_config_check_time = time.time()  # Chống I/O bottleneck

        # Session Baselining thay thế Random Sampling
        baseline_config = tier1_config.get("session_baseline", {})
        self.session_baseline = SessionBaseline(
            deviation_threshold=baseline_config.get("deviation_threshold", 2.0),
            window_seconds=baseline_config.get("window_seconds", 300),
            ttl_seconds=baseline_config.get("ttl_seconds", 600),
            max_profiles=baseline_config.get("max_profiles", 10000),
            eviction_interval=baseline_config.get("eviction_interval", 100),
        )

        # Compile prompt injection & jailbreak patterns từ config
        self.config = config
        guardrails_config = config.get("guardrails", {})
        injection_pats = guardrails_config.get("injection_patterns", [])
        jailbreak_pats = guardrails_config.get("jailbreak_patterns", [])
        self.injection_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in injection_pats]
        self.jailbreak_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in jailbreak_pats]

        # Unsupervised Anomaly Detection (Zero-Day statistical profiling trên các core features có corr cao)
        self.global_stats: Dict[str, RunningStats] = {
            "Flow Duration": RunningStats(),
            "Total Fwd Packets": RunningStats(),
            "Total Length of Fwd Packets": RunningStats(),
            "Total Backward Packets": RunningStats(),
            "Total Length of Bwd Packets": RunningStats(),
            "Fwd Seg Size Min": RunningStats(),
            "Init Fwd Win Byts": RunningStats(),
            "Init Bwd Win Byts": RunningStats(),
            "Bwd Pkt Len Min": RunningStats(),
            "PSH Flag Cnt": RunningStats(),
            "Flow Pkts/s": RunningStats()
        }
        # Cần 100 mẫu sạch để khởi tạo baseline tin cậy trước khi tính Z-score
        self.warmup_count = 100
        self.total_processed_logs = 0

    def _check_waf_signatures(self, log_entry: dict) -> Optional[str]:
        """
        Bộ lọc Signature WAF siêu nhẹ để phát hiện nhanh các dấu hiệu SQLi, XSS, Path Traversal
        ngay tại Tier-1 nhằm bảo vệ Tier-2 khỏi bị nghẽn (Resource Starvation).
        """
        waf_patterns = {
            "SQL Injection (SQLi)": re.compile(
                r"(?i)(union\s+select|select\s+.*?\s+from|insert\s+into|update\s+.*?set|delete\s+from|drop\s+table|information_schema|or\s+['\"]\d+['\"]s*=\s*['\"]\d+)"
            ),
            "Cross-Site Scripting (XSS)": re.compile(
                r"(?i)(<script.*?>|javascript:|onload\s*=|onerror\s*=|<img\s+.*?onerror|<svg.*?onload)"
            ),
            "Path Traversal / LFI": re.compile(
                r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini)"
            ),
            "Command Injection": re.compile(
                r"(?i)(;\s*(cat|ls|pwd|whoami|id|netstat|ping|sh|bash|powershell|cmd)\b|`.*?`|\$\(.*?\))"
            )
        }
        target_fields = ["payload", "uri", "user_agent", "User-Agent", "headers", "message", "command", "process"]
        for field in target_fields:
            val = log_entry.get(field) or log_entry.get(field.lower())
            if val and isinstance(val, str):
                for attack_type, pattern in waf_patterns.items():
                    if pattern.search(val):
                        return f"WAF: Phát hiện {attack_type} trong '{field}'"
        return None

    def _check_injection_signatures(self, log_entry: dict) -> Optional[str]:
        """
        Kiểm tra các mẫu Prompt Injection và Jailbreak từ config hệ thống ngay tại Tier-1.
        """
        target_fields = ["payload", "uri", "user_agent", "User-Agent", "headers", "message", "command", "process"]
        for field in target_fields:
            val = log_entry.get(field) or log_entry.get(field.lower())
            if val and isinstance(val, str):
                # 1. Prompt Injection Patterns
                for pattern in self.injection_patterns:
                    if pattern.search(val):
                        return f"Prompt Injection Pattern: Phát hiện '{pattern.pattern}' trong '{field}'"
                # 2. Jailbreak Patterns
                for pattern in self.jailbreak_patterns:
                    if pattern.search(val):
                        return f"Jailbreak Pattern: Phát hiện '{pattern.pattern}' trong '{field}'"
        return None

    def evaluate(self, log_entry: dict) -> dict:
        """
        Đánh giá log entry qua các tầng: Whitelist -> Static/Dynamic Rules -> Session Baseline -> Action.
        """
        # Tự động reload configurations nếu file system_settings.yaml bị sửa đổi (đã gộp & bảo vệ I/O bằng cách hạn chế tần suất check)
        now_time = time.time()
        if now_time - self.last_config_check_time > 5.0:
            self.last_config_check_time = now_time
            try:
                if os.path.exists(CONFIG_PATH):
                    current_mtime = os.path.getmtime(CONFIG_PATH)
                    if current_mtime > self.last_config_mtime:
                        self.reload_dynamic_rules()
                        self.last_config_mtime = current_mtime
            except (yaml.YAMLError, FileNotFoundError) as e:
                print(f"[!] Config reload failed: {e}. Using cached configurations.")
            except Exception as e:
                print(f"[!] Unexpected error during config reload: {e}")

        score = 0
        reasons = []

        # Chuan hoa key: ho tro ca CICIDS CSV format va normalized JSON format
        for alias, canonical in _KEY_ALIASES.items():
            if alias in log_entry and canonical not in log_entry:
                log_entry[canonical] = log_entry[alias]

        # --- Tầng 0: Whitelist Check ---
        source_ip = log_entry.get("Source IP", "unknown")
        if source_ip in self.whitelist_ips:
            log_entry["tier1_score"] = 0
            log_entry["tier1_reasons"] = ["IP nằm trong Whitelist (An toàn)"]
            log_entry["tier1_action"] = "DROP"
            log_entry["tier1_baseline"] = {"ip_request_count": 0, "ip_unique_ports": 0}
            return log_entry

        # --- Tầng 0.1: WAF Signature Check (Chống LLM Starvation) ---
        waf_reason = self._check_waf_signatures(log_entry)
        if waf_reason:
            score += 50
            reasons.append(waf_reason)

        # --- Tầng 0.2: Prompt Injection / Jailbreak Signature Check ---
        injection_reason = self._check_injection_signatures(log_entry)
        if injection_reason:
            score += 50
            reasons.append(injection_reason)

        # --- Tầng 0.5: Kiểm tra Unsupervised Statistical Anomaly ---
        self.total_processed_logs += 1
        
        # Ánh xạ các trường mạng thô sang các nhóm tính năng
        current_values = {}
        for key, aliases in _RAW_TO_CANONICAL.items():
            val = None
            for alias in aliases:
                if alias in log_entry:
                    try:
                        val = float(log_entry[alias])
                        break
                    except (ValueError, TypeError):
                        pass
            if val is not None:
                current_values[key] = val
                
        # Chỉ kích hoạt cảnh báo sau giai đoạn warmup cho từng key cụ thể (dựa trên số lượng mẫu benign của key đó)
        max_z_score = 0.0
        z_anomaly_reasons = []
        z_anomaly_score = 0
        
        for key, val in current_values.items():
            stats = self.global_stats[key]
            if stats.n >= self.warmup_count:
                mean_val = stats.mean()
                std_val = stats.std_dev()
                
                # Bỏ qua nếu dữ liệu không biến động (std quá bé)
                if std_val > 0.01:
                    z_score = abs(val - mean_val) / std_val
                    max_z_score = max(max_z_score, z_score)
                    if z_score > 3.5:
                        # Điểm phạt tăng dần theo độ lệch, cap ở 40
                        penalty = min(int(z_score * 5), 40)
                        z_anomaly_score += penalty
                        z_anomaly_reasons.append(
                            f"Phát hiện dị biệt thống kê Zero-day [{key}]: Giá trị {val:.1f} lệch {z_score:.2f} lần độ lệch chuẩn (Z-Score > 3.5)"
                        )
                        
        if z_anomaly_reasons:
            score += z_anomaly_score
            reasons.extend(z_anomaly_reasons)

        # --- Tầng 1: Static Rules ---
        dest_port = log_entry.get("Destination Port", -1)
        fwd_packets = log_entry.get("Total Fwd Packets", 0)

        try:
            if int(dest_port) in self.sensitive_ports:
                score += 40
                reasons.append(f"Truy cập cổng nhạy cảm (Cổng {dest_port})")
        except (ValueError, TypeError):
            pass

        try:
            if float(fwd_packets) > self.max_fwd_packets:
                score += 30
                reasons.append(f"Bất thường về dung lượng ({fwd_packets} gói tin chiều đi)")
        except (ValueError, TypeError):
            pass

        # --- Tầng 2: Dynamic Rules (Từ Feedback Loop) ---
        for rule in self.dynamic_rules:
            rule_field = rule.get("field")
            rule_pattern = rule.get("pattern")
            rule_score = rule.get("score", 50)
            if rule_field and rule_pattern:
                field_value = str(log_entry.get(rule_field, ""))
                if rule_pattern in field_value:
                    score += rule_score
                    reasons.append(
                        f"Luật động [từ Tác tử]: {rule_field}='{rule_pattern}'"
                    )

        # --- Tầng 3: Session Baseline ---
        source_ip = log_entry.get("Source IP", "unknown")
        baseline_result = self.session_baseline.update(source_ip, log_entry)

        if baseline_result["is_anomalous"]:
            score += baseline_result["deviation_score"]
            reasons.extend(baseline_result["deviation_reasons"])

        # --- Đánh giá & Phân luồng Action (Tier 1 Action Differentiation) ---
        log_entry["tier1_score"] = score
        log_entry["tier1_reasons"] = reasons
        log_entry["tier1_z_score"] = max_z_score
        log_entry["tier1_baseline"] = {
            "ip_request_count": baseline_result["request_count"],
            "ip_unique_ports": baseline_result["unique_ports"],
        }

        if score >= self.risk_threshold:
            dest_port_val = 0
            try:
                dest_port_val = int(dest_port)
            except (ValueError, TypeError):
                pass
            
            fwd_pkts_val = 0.0
            try:
                fwd_pkts_val = float(fwd_packets)
            except (ValueError, TypeError):
                pass

            # Phát hiện tấn công web rõ ràng (SQLi/XSS/Command Inj) -> Chặn luôn để bảo vệ LLM
            has_waf_match = any("WAF:" in r for r in reasons)
            has_injection_match = any("Prompt Injection Pattern:" in r or "Jailbreak Pattern:" in r for r in reasons)

            if has_waf_match:
                log_entry["tier1_action"] = "BLOCK_IP"
            elif has_injection_match:
                # Prompt Injection / Jailbreak: gửi lên Tier-2 xử lý
                log_entry["tier1_action"] = "ESCALATE"
            elif dest_port_val in self.sensitive_ports and fwd_pkts_val < 200:
                # BruteForce: port nhạy cảm, packet count trung bình → block IP
                log_entry["tier1_action"] = "BLOCK_IP"
            elif fwd_pkts_val > self.max_fwd_packets:
                # DoS/DDoS: volumetric → alert không block (có thể distributed)
                log_entry["tier1_action"] = "ALERT"
            elif dest_port_val not in self.sensitive_ports and dest_port_val not in [80, 443, 8080]:
                # Lateral movement / Infiltration: unusual port, moderate score → HITL
                log_entry["tier1_action"] = "AWAIT_HITL"
            else:
                log_entry["tier1_action"] = "ESCALATE"
        else:
            log_entry["tier1_action"] = "DROP" if not reasons else "LOG"

        # --- Tầng 0.6: Cập nhật RunningStats CHỈ với dữ liệu được coi là benign (DROP hoặc LOG) ---
        # Điều này chống Baseline Poisoning (tấn công Slow-Rate baseline drift)
        if log_entry["tier1_action"] in ("DROP", "LOG"):
            for key, val in current_values.items():
                if key in self.global_stats:
                    self.global_stats[key].push(val)

        return log_entry

    def reload_dynamic_rules(self):
        """
        Hot-reload dynamic rules, whitelists, thresholds, and configurations từ YAML config.
        Chỉ tải các luật đã phê duyệt (status == 'ACTIVE').
        """
        config = load_config()
        tier1_config = config.get("tier1", {})
        
        self.risk_threshold = tier1_config.get("risk_threshold", self.risk_threshold)
        self.sensitive_ports = tier1_config.get("sensitive_ports", self.sensitive_ports)
        self.max_fwd_packets = tier1_config.get("max_fwd_packets", self.max_fwd_packets)
        self.whitelist_ips = tier1_config.get("whitelist_ips", self.whitelist_ips)
        
        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_rules = [r for r in all_rules if r.get("status", "ACTIVE") == "ACTIVE"]

        # Hot-reload injection & jailbreak patterns
        self.config = config
        guardrails_config = config.get("guardrails", {})
        injection_pats = guardrails_config.get("injection_patterns", [])
        jailbreak_pats = guardrails_config.get("jailbreak_patterns", [])
        self.injection_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in injection_pats]
        self.jailbreak_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in jailbreak_pats]

        # Hot-reload SessionBaseline parameters without wiping profiles cache
        baseline_config = tier1_config.get("session_baseline", {})
        self.session_baseline.deviation_threshold = baseline_config.get("deviation_threshold", self.session_baseline.deviation_threshold)
        self.session_baseline.window_seconds = baseline_config.get("window_seconds", self.session_baseline.window_seconds)
        self.session_baseline.ttl_seconds = baseline_config.get("ttl_seconds", self.session_baseline.ttl_seconds)
        self.session_baseline.max_profiles = baseline_config.get("max_profiles", self.session_baseline.max_profiles)
        self.session_baseline.eviction_interval = baseline_config.get("eviction_interval", self.session_baseline.eviction_interval)
