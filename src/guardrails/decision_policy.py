"""
Guardrails: Chính sách Độ-tin-cậy THỐNG NHẤT (Unified Confidence Policy)

MỘT nguồn sự thật cho ngưỡng quyết định của cả Cổng ML (Tier-1) và LLM Agent (Tier-2).
Hai tầng DÙNG CHUNG thang điểm độ-tin-cậy tấn công C ∈ [0,1], chỉ khác tập HÀNH ĐỘNG
đầu-cuối mà mỗi tầng được phép ra.

── Cổng ML (Tier-1) — 4 dải (theo yêu cầu):
    C >= 0.85            -> BLOCK    (chặn ngay)
    0.65 <= C < 0.85     -> ESCALATE (đưa lên LLM phân tích sâu)
    0.40 <= C < 0.65     -> ALERT    (low-priority; IP tái phạm -> tự BLOCK)
    C < 0.40             -> PASS/DROP (audit log, dừng ở Tier-1)

── LLM (Tier-2) — tầng phán quyết cuối (KHÔNG escalate tiếp; vùng mơ hồ -> người):
    C >= 0.85            -> BLOCK
    0.65 <= C < 0.85     -> ALERT    (IP tái phạm -> tự BLOCK)
    C < 0.65             -> AWAIT_HITL (không đủ chắc -> chuyển người)
    LLM phán log SẠCH    -> DROP     (bất kể C)

Mặc định nằm TRONG code (checkout sạch vẫn chạy); có thể override tuỳ chọn qua khối
`decision_policy:` trong config/system_settings.yaml (KHÔNG commit file config đó).
"""

from __future__ import annotations

import logging
import os

import yaml  # type: ignore

logger = logging.getLogger(__name__)

# ── Cổng ML (Tier-1) — 4 dải ─────────────────────────────────────────────────
ML_BLOCK_CONF: float = 0.85  # >= -> BLOCK
ML_ESCALATE_CONF: float = 0.65  # [0.65, 0.85) -> ESCALATE (LLM)
ML_ALERT_CONF: float = 0.40  # [0.40, 0.65) -> ALERT ; < 0.40 -> PASS/DROP

# ── LLM (Tier-2) — chốt BLOCK trùng ML để nhất quán ──────────────────────────
LLM_BLOCK_CONF: float = 0.85  # >= -> BLOCK
LLM_ALERT_CONF: float = 0.65  # [0.65, 0.85) -> ALERT ; < 0.65 -> AWAIT_HITL

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")


def _load_overrides() -> None:
    """Nạp override tuỳ chọn từ config (nếu có). Sai/khuyết -> giữ mặc định code."""
    global ML_BLOCK_CONF, ML_ESCALATE_CONF, ML_ALERT_CONF, LLM_BLOCK_CONF, LLM_ALERT_CONF
    try:
        if not os.path.exists(_CONFIG_PATH):
            return
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        pol = (cfg.get("decision_policy") or {}) if isinstance(cfg, dict) else {}
        ML_BLOCK_CONF = float(pol.get("ml_block_conf", ML_BLOCK_CONF))
        ML_ESCALATE_CONF = float(pol.get("ml_escalate_conf", ML_ESCALATE_CONF))
        ML_ALERT_CONF = float(pol.get("ml_alert_conf", ML_ALERT_CONF))
        LLM_BLOCK_CONF = float(pol.get("llm_block_conf", LLM_BLOCK_CONF))
        LLM_ALERT_CONF = float(pol.get("llm_alert_conf", LLM_ALERT_CONF))
        # Bất biến an toàn: alert <= escalate <= block; nếu lệch -> kẹp lại.
        ML_ESCALATE_CONF = min(ML_ESCALATE_CONF, ML_BLOCK_CONF)
        ML_ALERT_CONF = min(ML_ALERT_CONF, ML_ESCALATE_CONF)
        LLM_ALERT_CONF = min(LLM_ALERT_CONF, LLM_BLOCK_CONF)
    except Exception as e:  # pragma: no cover - phòng thủ, không chặn khởi động
        logger.warning(f"[decision_policy] Bỏ override cấu hình (dùng mặc định): {e}")


_load_overrides()


def classify_ml(p_attack: float) -> str:
    """Cổng ML: độ tin cậy tấn công C -> BLOCK_IP | ESCALATE | ALERT | DROP.

    ESCALATE = ML đủ ngờ nhưng chưa chắc -> đẩy LLM (caller ánh xạ về action=None).
    DROP = C < 0.40 (PASS/audit log), dừng ở Tier-1."""
    if p_attack >= ML_BLOCK_CONF:
        return "BLOCK_IP"
    if p_attack >= ML_ESCALATE_CONF:
        return "ESCALATE"
    if p_attack >= ML_ALERT_CONF:
        return "ALERT"
    return "DROP"


def classify_llm(is_threat: bool, confidence: float) -> str:
    """LLM: (có phải đe doạ?, độ tin cậy) -> BLOCK_IP | ALERT | AWAIT_HITL | DROP.

    - is_threat=False (LLM phán log sạch) -> DROP bất kể confidence.
    - is_threat=True -> confidence LÁI action: >=0.85 BLOCK · 0.65–0.85 ALERT ·
      < 0.65 AWAIT_HITL (không đủ chắc -> người)."""
    if not is_threat:
        return "DROP"
    if confidence >= LLM_BLOCK_CONF:
        return "BLOCK_IP"
    if confidence >= LLM_ALERT_CONF:
        return "ALERT"
    return "AWAIT_HITL"
