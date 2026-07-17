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
import math
import os
import re
import time
from collections import defaultdict
from typing import Any, TypedDict

import yaml  # type: ignore


class IPProfile(TypedDict):
    request_count: int
    unique_ports: set[int]
    total_fwd_packets: float
    first_seen: float | None
    last_seen: float | None


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

    def seed(self, n: int, mean: float, m2: float) -> None:
        """Nạp sẵn trạng thái Welford (n, mean, M2) từ một hồ sơ baseline 'golden'
        tính offline trên lưu lượng benign đã kiểm định. Sau khi seed, push() tiếp tục
        cập nhật đúng theo công thức Welford incremental từ điểm khởi tạo này."""
        if n < 1:
            return
        self.n = n
        self.old_m = self.new_m = mean
        self.old_s = self.new_s = m2

    def as_state(self) -> dict[str, float]:
        """Trạng thái Welford thô (n, mean, M2) để lưu vào hồ sơ golden baseline."""
        return {"n": self.n, "mean": self.new_m, "m2": self.new_s}


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")

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
    # Trường lớp-ứng-dụng (WAF/HTTP) — cần cho luật HÀNH VI do Agent học ngược
    # (User-Agent/URI signature). Đồng bộ với KEY_ALIASES của Guardrails (G1) để
    # luật động khớp bất kể log nguồn viết hoa/thường.
    "user_agent": "User-Agent",
    "user-agent": "User-Agent",
    "uri": "URI",
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
    "Flow Pkts/s": ["Flow Pkts/s", "Flow Packets/s", "flow_pkts_s"],
}


_WAF_PATTERNS = {
    "SQL Injection (SQLi)": re.compile(
        r"(?i)(union\s+select|select\s+.*?\s+from|insert\s+into|update\s+.*?set|delete\s+from|drop\s+table|information_schema|or\s+['\"]\d+['\"]s*=\s*['\"]\d+)"
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(?i)(<script\b|javascript:|onload\s*=|onerror\s*=|<img\b|<svg\b)"
    ),
    "Path Traversal / LFI": re.compile(
        r"(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|boot\.ini)"
    ),
    "Command Injection": re.compile(
        r"(?i)(;\s*(cat|ls|pwd|whoami|id|netstat|ping|sh|bash|powershell|cmd)\b|`.*?`|\$\(.*?\))"
    ),
}


def load_config() -> dict[str, Any]:
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
                if cfg and isinstance(cfg, dict):
                    return cfg
    except Exception as e:
        print(
            f"[!] Warning: Failed to load config from {CONFIG_PATH}: {e}. Using default configuration."
        )
    return {
        "tier1": {
            # Fallback PHẢI là bản sao trung thực của config production (fail-safe không
            # được yếu hơn): khớp system_settings.yaml (risk_threshold=15, đủ 7 cổng nhạy cảm).
            "risk_threshold": 15,
            "sensitive_ports": [21, 22, 23, 3389, 445, 1433, 3306],
            "max_fwd_packets": 1000,
            "z_threshold": 3.5,
            "dynamic_rules": [],
            "whitelist_ips": [],
            "session_baseline": {
                "deviation_threshold": 2.0,
                "window_seconds": 300,
                "ttl_seconds": 600,
                "max_profiles": 10000,
                "eviction_interval": 100,
            },
        },
        "guardrails": {
            "injection_patterns": [
                "ignore previous instructions",
                "you are now",
                "system prompt",
                "disregard",
                "<script>",
                "DROP TABLE",
                "UNION SELECT",
                "; exec",
                "forget everything",
                "act as",
                "new instructions",
                "override your instructions",
                "bypass safety",
                "pretend you are",
            ],
            "jailbreak_patterns": [
                "DAN mode",
                "Do Anything Now",
                "Developer Mode",
                "jailbroken",
                "ignore all previous",
            ],
        },
    }


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
        self.profiles: dict[str, IPProfile] = defaultdict(
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
                    self.profiles.keys(), key=lambda ip: self.profiles[ip]["last_seen"] or 0
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
        for _ip, profile in self.profiles.items():
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

        self.risk_threshold = tier1_config.get("risk_threshold", 15)
        self.sensitive_ports = tier1_config.get(
            "sensitive_ports", [21, 22, 23, 3389, 445, 1433, 3306]
        )
        self.max_fwd_packets = tier1_config.get("max_fwd_packets", 1000)
        # Ngưỡng Z-score cho phát hiện dị biệt thống kê Welford (zero-day). Mặc định
        # 3.5σ; cấu hình được để phục vụ phân tích độ nhạy (sensitivity analysis).
        self.z_threshold = tier1_config.get("z_threshold", 3.5)

        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_ip_blocks = set()
        self.dynamic_behavioral_rules = []
        for r in all_rules:
            if r.get("status", "ACTIVE") == "ACTIVE":
                field = r.get("field")
                pattern = r.get("pattern")
                if field == "Source IP" and pattern:
                    self.dynamic_ip_blocks.add(str(pattern))
                else:
                    self.dynamic_behavioral_rules.append((field, pattern, r.get("score", 50)))

        self.whitelist_ips = set(tier1_config.get("whitelist_ips", []))

        # --- Reputation-based enforcement (tiền sử IP từ Threat Memory) ---
        # IP đã có "hồ sơ đen": điểm danh tiếng >= block_threshold -> Tier-1 CHẶN NGAY
        # (không tốn LLM); >= hitl_threshold -> AWAIT_HITL (đưa lên analyst) DÙ gói hiện
        # tại trông lành. Đây là "known-bad short-circuit": kẻ đã bị chứng minh xấu không
        # cần escalate lại. Có thể TẮT bằng reputation_enforcement=false.
        self.reputation_enforcement = tier1_config.get("reputation_enforcement", True)
        self.reputation_block_threshold = tier1_config.get("reputation_block_threshold", 70)
        self.reputation_hitl_threshold = tier1_config.get("reputation_hitl_threshold", 50)
        # Cache reputation trong RAM (TTL ngắn) để GIỮ Tier-1 ở tốc độ đường truyền —
        # tránh truy vấn SQLite cho MỖI log; IP lặp lại chỉ tốn O(1) trong burst.
        self._rep_cache: dict[str, tuple[float, float]] = {}
        self._rep_cache_ttl = tier1_config.get("reputation_cache_ttl", 5.0)

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
        self.global_stats: dict[str, RunningStats] = {
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
            "Flow Pkts/s": RunningStats(),
        }
        # Cần 100 mẫu sạch để khởi tạo baseline tin cậy trước khi tính Z-score
        self.warmup_count = 100
        self.total_processed_logs = 0

        # Seed baseline từ hồ sơ 'golden' (benign đã kiểm định) nếu bật trong config;
        # sau đó baseline vẫn cập nhật online CÓ ĐIỀU KIỆN (chỉ DROP/LOG) như bình thường.
        self._seed_golden_baseline(tier1_config)

    def _seed_golden_baseline(self, tier1_config: dict) -> None:
        """Nạp golden baseline (trạng thái Welford của lưu lượng benign đã kiểm định)
        vào global_stats nếu được bật trong config. Mặc định TẮT để tương thích ngược.
        Sau khi seed, baseline vẫn cập nhật online CÓ ĐIỀU KIỆN (chỉ DROP/LOG)."""
        gb = tier1_config.get("golden_baseline", {}) if isinstance(tier1_config, dict) else {}
        if not (isinstance(gb, dict) and gb.get("enabled")):
            return
        path = str(gb.get("path", "")).strip()
        if not path:
            return
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(__file__), "..", "..", path)
        if not os.path.exists(path):
            print(
                f"[Tier-1] Golden baseline bật nhưng thiếu file: {path} (bỏ qua, dùng warmup online)."
            )
            return
        try:
            with open(path, encoding="utf-8") as f:
                profile = json.load(f)
        except (OSError, ValueError) as exc:
            print(f"[Tier-1] Không đọc được golden baseline ({exc}); bỏ qua.")
            return
        features = profile.get("features", {}) if isinstance(profile, dict) else {}
        seeded = 0
        for key, st in features.items():
            if key in self.global_stats and isinstance(st, dict):
                n = st.get("n", 0)
                if isinstance(n, (int, float)) and n >= 2:
                    self.global_stats[key].seed(
                        int(n), float(st.get("mean", 0.0)), float(st.get("m2", 0.0))
                    )
                    seeded += 1
        if seeded:
            print(
                f"[Tier-1] Seed golden baseline: {seeded}/{len(self.global_stats)} feature "
                f"(nguồn: {os.path.basename(path)}); cập nhật online có điều kiện tiếp tục như thường."
            )

    def learn_baseline(self, log_entry: dict) -> None:
        """Cập nhật baseline Welford KHÔNG điều kiện từ một bản ghi benign đã kiểm định.
        Dùng OFFLINE để dựng golden baseline (mọi mẫu đều đã biết là sạch), khác với
        đường runtime vốn chỉ cập nhật với phán quyết DROP/LOG."""
        for key, aliases in _RAW_TO_CANONICAL.items():
            if key not in self.global_stats:
                continue
            for alias in aliases:
                if alias in log_entry:
                    try:
                        self.global_stats[key].push(float(log_entry[alias]))
                        break
                    except (ValueError, TypeError):
                        pass

    def _check_waf_signatures(self, log_entry: dict) -> str | None:
        """
        Bộ lọc Signature WAF siêu nhẹ để phát hiện nhanh các dấu hiệu SQLi, XSS, Path Traversal
        ngay tại Tier-1 nhằm bảo vệ Tier-2 khỏi bị nghẽn (Resource Starvation).
        """
        # _WAF_PATTERNS is compiled at module level for ultra-fast matching
        target_fields = [
            "payload",
            "uri",
            "user_agent",
            "User-Agent",
            "headers",
            "message",
            "command",
            "process",
        ]
        for field in target_fields:
            val = log_entry.get(field) or log_entry.get(field.lower())
            if val and isinstance(val, str):
                for attack_type, pattern in _WAF_PATTERNS.items():
                    if pattern.search(val):
                        return f"WAF: Phát hiện {attack_type} trong '{field}'"
        return None

    def _check_injection_signatures(self, log_entry: dict) -> str | None:
        """
        Kiểm tra các mẫu Prompt Injection và Jailbreak từ config hệ thống ngay tại Tier-1.
        """
        target_fields = [
            "payload",
            "uri",
            "user_agent",
            "User-Agent",
            "headers",
            "message",
            "command",
            "process",
        ]
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

    def _get_reputation_score(self, ip: str) -> float:
        """Lấy điểm danh tiếng của IP từ Threat Memory (có cache TTL để giữ Tier-1 nhanh).

        AN TOÀN TUYỆT ĐỐI: mọi lỗi truy vấn/DB chưa sẵn sàng -> trả 0.0. Tier-1 KHÔNG
        BAO GIỜ được sập chỉ vì tra cứu bộ nhớ dài hạn.
        """
        if not ip or ip == "unknown":
            return 0.0
        now = time.time()
        cached = self._rep_cache.get(ip)
        if cached and cached[1] > now:
            return cached[0]
        score = 0.0
        try:
            from src.agent.threat_memory import threat_memory

            rep = threat_memory.get_ip_reputation(ip)
            if rep:
                score = float(rep.get("reputation_score", 0.0) or 0.0)
        except Exception:
            score = 0.0
        self._rep_cache[ip] = (score, now + self._rep_cache_ttl)
        return score

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

        # --- Tầng 0: Whitelist Check (ĐÁNH DẤU — KHÔNG return sớm) ---
        # IP whitelist VẪN được phân tích ĐẦY ĐỦ ở Tier-1 (chữ ký WAF/injection, Z-score,
        # luật tĩnh/động, baseline...) để analyst QUAN SÁT hành vi — nhưng hành động cuối
        # LUÔN bị ép về WHITELIST_DROP: CHO QUA, KHÔNG chặn / không escalate / không HITL /
        # miễn trừ reputation. Nhờ vậy lần chạy thứ 2 vẫn hiện "kiểu tấn công + suy luận"
        # như log thường (chỉ khác: không bị chặn) thay vì bị nuốt lặng ở Tầng 0.
        source_ip = log_entry.get("Source IP", "unknown")
        is_whitelisted = source_ip in self.whitelist_ips
        log_entry["is_whitelisted"] = is_whitelisted

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
                        parsed = float(log_entry[alias])
                        if not math.isinf(parsed) and not math.isnan(parsed):
                            val = parsed
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
                    if z_score > self.z_threshold:
                        # Điểm phạt tăng dần theo độ lệch, cap ở 40
                        penalty = min(int(z_score * 5), 40)
                        z_anomaly_score += penalty
                        z_anomaly_reasons.append(
                            f"Phát hiện dị biệt thống kê Zero-day [{key}]: Giá trị {val:.1f} lệch {z_score:.2f} lần độ lệch chuẩn (Z-Score > {self.z_threshold:.1f})"
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
        # dynamic_ip_block: luật Source-IP ĐÃ được Analyst DUYỆT (HITL) khớp CHÍNH XÁC ->
        # Tier-1 TỰ CHẶN ngay lần tái phạm, KHÔNG cần leo thang Tier-2 (đây là "Tier-1 học được").
        dynamic_ip_block = False

        # O(1) lookup cho luật chặn IP
        if source_ip in self.dynamic_ip_blocks:
            dynamic_ip_block = True
            reasons.append(f"Luật động [từ Tác tử]: Source IP='{source_ip}'")
            score += 100

        # Kiểm tra luật hành vi
        for rule_field, rule_pattern, rule_score in self.dynamic_behavioral_rules:
            if rule_field and rule_pattern:
                field_value = str(log_entry.get(rule_field, ""))
                if rule_pattern in field_value:
                    score += rule_score
                    reasons.append(f"Luật động [từ Tác tử]: {rule_field}='{rule_pattern}'")

        # --- Tầng 3: Session Baseline ---
        source_ip = log_entry.get("Source IP", "unknown")
        baseline_result = self.session_baseline.update(source_ip, log_entry)

        if baseline_result["is_anomalous"]:
            score += baseline_result["deviation_score"]
            reasons.extend(baseline_result["deviation_reasons"])

        # --- Tầng 3.5: Reputation Enforcement (tiền sử IP) ---
        # Kẻ ĐÃ bị chứng minh xấu không cần escalate lại: chặn/HITL ngay theo hồ sơ danh
        # tiếng, ĐỘC LẬP với điểm gói hiện tại (gói lành từ IP xấu vẫn bị nâng cấp).
        rep_action = None
        if self.reputation_enforcement and not is_whitelisted:
            rep_score = self._get_reputation_score(source_ip)
            if rep_score >= self.reputation_block_threshold:
                rep_action = "BLOCK_IP"
                reasons.append(
                    f"IP có tiền sử NGUY HIỂM (điểm danh tiếng {rep_score:.0f} ≥ "
                    f"{self.reputation_block_threshold}) → chặn tự động"
                )
            elif rep_score >= self.reputation_hitl_threshold:
                rep_action = "ESCALATE"
                reasons.append(
                    f"IP có tiền sử đáng ngờ (điểm danh tiếng {rep_score:.0f} ≥ "
                    f"{self.reputation_hitl_threshold}) → đẩy lên Cổng ML (Tier-1) / LLM (Tier-2)"
                )

        # --- Đánh giá & Phân luồng Action (Tier 1 Action Differentiation) ---
        log_entry["tier1_score"] = score
        log_entry["tier1_reasons"] = reasons
        log_entry["tier1_z_score"] = max_z_score
        log_entry["tier1_baseline"] = {
            "ip_request_count": baseline_result["request_count"],
            "ip_unique_ports": baseline_result["unique_ports"],
        }

        if is_whitelisted:
            # IP whitelist: ĐÃ phân tích đầy đủ ở trên (score + reasons giữ nguyên để
            # analyst quan sát) nhưng LUÔN cho qua — ưu tiên CAO NHẤT, đè mọi nhánh chặn.
            log_entry["tier1_action"] = "WHITELIST_DROP"
        elif rep_action == "BLOCK_IP":
            # Tiền sử NGUY HIỂM (reputation >= ngưỡng block): CHẶN NGAY, ĐỘC LẬP với điểm
            # gói hiện tại — kẻ đã bị chứng minh xấu không cần escalate lại, không tốn LLM.
            log_entry["tier1_action"] = "BLOCK_IP"
        elif score >= self.risk_threshold:
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
            has_injection_match = any(
                "Prompt Injection Pattern:" in r or "Jailbreak Pattern:" in r for r in reasons
            )

            if dynamic_ip_block:
                # IP đã được Analyst DUYỆT chặn (HITL -> luật ACTIVE): Tier-1 TỰ CHẶN ngay,
                # KHÔNG tốn LLM. Ưu tiên CAO NHẤT — kẻ tái phạm không cần leo thang lại.
                log_entry["tier1_action"] = "BLOCK_IP"
            elif has_waf_match:
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
                # Lateral movement / Infiltration: unusual port, moderate score → ESCALATE
                log_entry["tier1_action"] = "ESCALATE"
            else:
                log_entry["tier1_action"] = "ESCALATE"
        else:
            log_entry["tier1_action"] = "DROP" if not reasons else "LOG"

        # Sàn Escalate theo tiền sử: IP đáng ngờ (reputation >= ngưỡng HITL) mà gói hiện tại
        # chưa đủ mạnh -> NÂNG lên ESCALATE cho Tier-2 xem, thay vì lặng lẽ DROP/LOG.
        if rep_action == "ESCALATE" and log_entry["tier1_action"] in ("DROP", "LOG"):
            log_entry["tier1_action"] = "ESCALATE"

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
        self.whitelist_ips = set(tier1_config.get("whitelist_ips", []))
        self.reputation_enforcement = tier1_config.get(
            "reputation_enforcement", self.reputation_enforcement
        )
        self.reputation_block_threshold = tier1_config.get(
            "reputation_block_threshold", self.reputation_block_threshold
        )
        self.reputation_hitl_threshold = tier1_config.get(
            "reputation_hitl_threshold", self.reputation_hitl_threshold
        )

        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_ip_blocks = set()
        self.dynamic_behavioral_rules = []
        for r in all_rules:
            if r.get("status", "ACTIVE") == "ACTIVE":
                field = r.get("field")
                pattern = r.get("pattern")
                if field == "Source IP" and pattern:
                    self.dynamic_ip_blocks.add(str(pattern))
                else:
                    self.dynamic_behavioral_rules.append((field, pattern, r.get("score", 50)))

        # Hot-reload injection & jailbreak patterns
        self.config = config
        guardrails_config = config.get("guardrails", {})
        injection_pats = guardrails_config.get("injection_patterns", [])
        jailbreak_pats = guardrails_config.get("jailbreak_patterns", [])
        self.injection_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in injection_pats]
        self.jailbreak_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in jailbreak_pats]

        # Hot-reload SessionBaseline parameters without wiping profiles cache
        baseline_config = tier1_config.get("session_baseline", {})
        self.session_baseline.deviation_threshold = baseline_config.get(
            "deviation_threshold", self.session_baseline.deviation_threshold
        )
        self.session_baseline.window_seconds = baseline_config.get(
            "window_seconds", self.session_baseline.window_seconds
        )
        self.session_baseline.ttl_seconds = baseline_config.get(
            "ttl_seconds", self.session_baseline.ttl_seconds
        )
        self.session_baseline.max_profiles = baseline_config.get(
            "max_profiles", self.session_baseline.max_profiles
        )
        self.session_baseline.eviction_interval = baseline_config.get(
            "eviction_interval", self.session_baseline.eviction_interval
        )
