"""
Guardrails: Log Template Miner (Volume Compression Engine using Drain3)
"""

import math
import logging
from collections import Counter
from typing import Optional

from drain3.template_miner_config import TemplateMinerConfig  # type: ignore
from drain3 import TemplateMiner  # type: ignore
from drain3.masking import MaskingInstruction  # type: ignore

from src.guardrails.constants import normalize_log_keys

logger = logging.getLogger(__name__)


# Lazy config loader to avoid circular dependency
def load_config():
    from src.guardrails.prompt_filter import load_config as pf_load_config
    return pf_load_config()


class LogTemplateMiner:
    """
    Thuật toán nén log sử dụng thư viện Drain3 chính thức từ IBM.
    GOM NHÓM các dòng log có cùng cấu trúc tĩnh -> 1 Template + freq + samples.
    """

    def __init__(self, max_samples: int = 3):
        config = load_config()
        guardrails_cfg = config.get("guardrails", {})
        if not isinstance(guardrails_cfg, dict):
            guardrails_cfg = {}
        drain_config = guardrails_cfg.get("drain3", {})
        if not isinstance(drain_config, dict):
            drain_config = {}
        max_samples_val = drain_config.get("max_samples_per_template", max_samples)
        max_samples = int(max_samples_val) if isinstance(max_samples_val, (int, float, str)) else max_samples

        # Cấu hình TemplateMinerConfig từ config dict để tránh lỗi
        # không tìm thấy drain3.ini
        cfg = TemplateMinerConfig()
        cfg.drain_depth = drain_config.get("depth", 4)
        cfg.drain_sim_th = drain_config.get("similarity_threshold", 0.4)
        cfg.drain_max_children = drain_config.get("max_children", 100)
        cfg.drain_max_clusters = drain_config.get("max_clusters", 1000)

        # Cấu hình luật mặt nạ (Masking Instructions)
        cfg.masking_instructions = [
            MaskingInstruction(
                pattern=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                mask_with="IP"
            ),
            MaskingInstruction(pattern=r"^[a-f0-9]{8,}$", mask_with="HASH"),
            MaskingInstruction(pattern=r"^\d+$", mask_with="NUM")
        ]

        self.miner = TemplateMiner(config=cfg)
        self.max_samples = max_samples
        self.samples = {}       # cluster_id -> list of raw logs
        self.time_ranges = {}   # cluster_id -> [min_time, max_time]
        self.total_logs_processed = 0

    @property
    def templates(self) -> dict:
        """
        Bảo toàn tính tương thích ngược (backward compatibility)
        cho các unit test suite cũ.
        Trả về dictionary map từ template_key đến thông tin chi tiết
        của template đó.
        """
        res = {}
        clusters = list(self.miner.drain.clusters)
        for c in clusters:
            cid = c.cluster_id
            template_key = c.get_template()
            default_tr = [float("inf"), float("-inf")]
            res[template_key] = {
                "template": template_key,
                "count": c.size,
                "samples": self.samples.get(cid, []),
                "time_range": self.time_ranges.get(cid, default_tr),
            }
        return res

    def add_log(self, log_str: str, timestamp: Optional[float] = None):
        """Thêm log vào bộ template sử dụng drain3.add_log_message."""
        self.total_logs_processed += 1

        # Đưa log message vào Drain3
        res = self.miner.add_log_message(log_str)
        cluster_id = res["cluster_id"]

        # Giữ mẫu log gốc cho từng cluster
        if cluster_id not in self.samples:
            self.samples[cluster_id] = []
        if len(self.samples[cluster_id]) < self.max_samples:
            self.samples[cluster_id].append(log_str)

        # Cập nhật time range
        if timestamp is not None:
            if cluster_id not in self.time_ranges:
                self.time_ranges[cluster_id] = [float("inf"), float("-inf")]
            self.time_ranges[cluster_id][0] = min(
                self.time_ranges[cluster_id][0], timestamp
            )
            self.time_ranges[cluster_id][1] = max(
                self.time_ranges[cluster_id][1], timestamp
            )

    def add_log_dict(self, log_entry: dict):
        """Thêm log dạng dict, chuẩn hóa keys trước khi trích xuất."""
        normalized = normalize_log_keys(log_entry)

        key_fields = [
            "Source IP",
            "Destination Port",
            "Protocol",
            "Total Fwd Packets",
            "Flow Duration",
        ]
        parts = [
            f"{f}={normalized.get(f)}"
            for f in key_fields
            if normalized.get(f) is not None
        ]
        log_str = " ".join(parts) if parts else str(normalized)

        timestamp = normalized.get(
            "Timestamp", normalized.get("Flow Duration")
        )
        try:
            timestamp = float(timestamp) if timestamp else None
        except (ValueError, TypeError):
            timestamp = None
        self.add_log(log_str, timestamp)

    def get_summary(self) -> list:
        """Trả về danh sách templates sắp xếp theo size giảm dần."""
        summary = []
        clusters = list(self.miner.drain.clusters)

        for c in clusters:
            cid = c.cluster_id
            default_tr = [float("inf"), float("-inf")]
            summary.append({
                "template": c.get_template(),
                "count": c.size,
                "samples": self.samples.get(cid, []),
                "time_range": self.time_ranges.get(cid, default_tr),
            })

        return sorted(summary, key=lambda x: x["count"], reverse=True)

    def get_compression_ratio(self) -> float:
        cluster_count = len(self.miner.drain.clusters)
        if self.total_logs_processed == 0:
            return 0.0
        return self.total_logs_processed / max(cluster_count, 1)

    def format_for_llm(self) -> str:
        """Format output cho LLM."""
        lines = []
        for i, tmpl in enumerate(self.get_summary(), 1):
            time_str = ""
            if tmpl["time_range"][0] != float("inf"):
                time_str = (
                    f", Time: {tmpl['time_range'][0]:.1f}s"
                    f"-{tmpl['time_range'][1]:.1f}s"
                )
            lines.append(
                f"[Template {i}] {tmpl['template']} "
                f"(Count: {tmpl['count']}{time_str})"
            )
            for sample in tmpl["samples"]:
                lines.append(f"  Sample: {sample}")
        lines.append(
            f"\n[Stats] Total: {self.total_logs_processed} logs → "
            f"{len(self.miner.drain.clusters)} templates "
            f"(Compression: {self.get_compression_ratio():.0f}x)"
        )
        return "\n".join(lines)

    def reset(self):
        """Reset sau mỗi time window."""
        self.miner = TemplateMiner(config=self.miner.config)
        self.samples.clear()
        self.time_ranges.clear()
        self.total_logs_processed = 0


class EntropyScorer:
    """
    Shannon Entropy scorer cho log strings.
    """

    def __init__(self, threshold: Optional[float] = None):
        if threshold is not None:
            self.threshold = threshold
        else:
            config = load_config()
            val = config.get("guardrails", {}).get("entropy_threshold", 4.5)
            self.threshold = float(val) if isinstance(val, (int, float)) else 4.5

    @staticmethod
    def calculate(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum(
            (c / length) * math.log2(c / length) for c in freq.values()
        )

    def is_high_entropy(self, log_str: str) -> bool:
        return self.calculate(log_str) > self.threshold

    def score(self, log_str: str) -> dict:
        entropy = self.calculate(log_str)
        return {
            "entropy": round(entropy, 3),
            "is_high_entropy": entropy > self.threshold,
            "priority": "HIGH" if entropy > self.threshold else "NORMAL",
        }


class TokenBudgetManager:
    """
    Quản lý ngân sách token.
    """

    def __init__(self, budget: Optional[int] = None):
        # Tham số tường minh được ưu tiên hơn config; config chỉ là mặc định
        # khi caller không truyền budget (vd: GuardrailsPipeline.process_batch).
        if budget is not None:
            self.budget = budget
            return
        config = load_config()
        guardrails_cfg = config.get("guardrails", {})
        if not isinstance(guardrails_cfg, dict):
            guardrails_cfg = {}
        budget_val = guardrails_cfg.get("token_budget", 4000)
        if isinstance(budget_val, (int, float, str)):
            try:
                self.budget = int(budget_val)
            except ValueError:
                self.budget = 4000
        else:
            self.budget = 4000

    @staticmethod
    def estimate_tokens(text: str) -> int:
        return len(text) // 4

    def fit_to_budget(
        self, template_text: str, high_entropy_logs: Optional[list] = None
    ) -> str:
        output_lines = []
        current_tokens = 0

        # Priority 1: High-entropy logs (40% budget)
        if high_entropy_logs:
            output_lines.append(
                "--- HIGH-PRIORITY LOGS (anomalous entropy) ---"
            )
            for log in high_entropy_logs:
                line = f"  {log}"
                t = self.estimate_tokens(line)
                if current_tokens + t > self.budget * 0.4:
                    break
                output_lines.append(line)
                current_tokens += t

        # Priority 2: Template summaries (remaining 60%)
        output_lines.append("--- COMPRESSED TEMPLATES ---")
        for line in template_text.split("\n"):
            t = self.estimate_tokens(line)
            if current_tokens + t > self.budget:
                output_lines.append("[TRUNCATED due to token budget]")
                break
            output_lines.append(line)
            current_tokens += t

        output_lines.append(
            f"--- Token usage: ~{current_tokens}/{self.budget} ---"
        )
        return "\n".join(output_lines)
