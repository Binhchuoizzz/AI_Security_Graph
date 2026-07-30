"""
Prometheus Telemetry & SOC Observability Exporter
=================================================
Cung cấp các số liệu đo lường theo thời gian thực (Real-time Metrics)
cho SOC Dashboard & Grafana:
  - Latency Histograms (P50/P95/P99)
  - Decision Counters per Tier (Tier 1, Semantic Cache, Tier 2 LLM)
  - Token Usage Counters
  - Red Teaming Deflection Stats
"""

import logging

from prometheus_client import Counter, Histogram, generate_latest

logger = logging.getLogger(__name__)

# Metrics Definitions
SENTINEL_DECISIONS_TOTAL = Counter(
    "sentinel_decisions_total",
    "Tổng số phán quyết an ninh được xử lý",
    ["tier", "action"],
)

SENTINEL_LATENCY_SECONDS = Histogram(
    "sentinel_latency_seconds",
    "Độ trễ xử lý phán quyết phân tầng (giây)",
    ["tier"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0),
)

SENTINEL_LLM_TOKENS_TOTAL = Counter(
    "sentinel_llm_tokens_total",
    "Tổng số token LLM tiêu thụ",
    ["type"],  # 'prompt', 'completion'
)

SENTINEL_REDTEAM_DEFLECTIONS_TOTAL = Counter(
    "sentinel_redteam_deflections_total",
    "Số lần vô hiệu hóa tấn công Prompt Injection / Evasion thành công",
    ["attack_type"],
)


class MetricsManager:
    """Quản lý ghi nhận chỉ số vận hành SOC."""

    @staticmethod
    def record_decision(tier: str, action: str):
        """Ghi nhận phán quyết từ Tier 1 / Cache / Tier 2."""
        SENTINEL_DECISIONS_TOTAL.labels(tier=tier, action=action).inc()

    @staticmethod
    def record_latency(tier: str, duration_sec: float):
        """Ghi nhận độ trễ xử lý."""
        SENTINEL_LATENCY_SECONDS.labels(tier=tier).observe(duration_sec)

    @staticmethod
    def record_tokens(prompt_tokens: int, completion_tokens: int):
        """Ghi nhận số token LLM."""
        SENTINEL_LLM_TOKENS_TOTAL.labels(type="prompt").inc(prompt_tokens)
        SENTINEL_LLM_TOKENS_TOTAL.labels(type="completion").inc(completion_tokens)

    @staticmethod
    def record_deflection(attack_type: str):
        """Ghi nhận vô hiệu hóa tấn công."""
        SENTINEL_REDTEAM_DEFLECTIONS_TOTAL.labels(attack_type=attack_type).inc()


def get_metrics_snapshot() -> str:
    """Xuất snapshot dữ liệu metrics dưới dạng định dạng chuẩn Prometheus text."""
    return generate_latest().decode("utf-8")
