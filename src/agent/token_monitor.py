"""
Theo dõi Token & Ngân sách Ngữ cảnh LLM (Context Budget Observability)
=====================================================================
Trả lời câu hỏi vận hành: "Khi log quá dài / quá nhiều, làm sao BIẾT prompt đang
cách trần ngữ cảnh bao xa để tinh chỉnh?".

  - record_usage(usage): ghi lại token THẬT do server trả về (`response.usage`)
    sau mỗi call -> mean / p95 / max / utilization% so với n_ctx.
  - preflight_check(messages, max_output): ƯỚC LƯỢNG token input TRƯỚC khi gọi;
    nếu vượt ngưỡng cảnh báo -> log WARNING + đếm (degrade có quan sát, không âm thầm).
  - get_stats(): cho dashboard đọc để hiển thị KPI "Context Utilization".

Số liệu bền vững ở config/llm_token_stats.json. Nhẹ, thread-safe, không bao giờ
làm hỏng luồng LLM (mọi lỗi ghi file đều nuốt êm).
"""

import json
import logging
import os
import threading

import yaml  # type: ignore

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(__file__)
STATS_PATH = os.path.join(_HERE, "..", "..", "config", "llm_token_stats.json")
_CONFIG_PATH = os.path.join(_HERE, "..", "..", "config", "system_settings.yaml")

try:
    with open(_CONFIG_PATH) as _f:
        _cfg = yaml.safe_load(_f) or {}
except Exception:
    _cfg = {}

# n_ctx mục tiêu của app (server llama.cpp đặt 16384 nên còn headroom an toàn).
N_CTX = int(_cfg.get("llm", {}).get("max_context_tokens", 8192))
WARN_RATIO = 0.90  # cảnh báo khi prompt vượt 90% ngân sách input
_CHARS_PER_TOKEN = 3.5  # ước lượng bảo thủ (Gemma/Llama ~3.5–4 char/token)

_lock = threading.Lock()
_state = {
    "calls": 0,
    "prompt_sum": 0,
    "prompt_max": 0,
    "completion_sum": 0,
    "overflow_warnings": 0,
    "recent_prompt": [],  # giữ tối đa 500 mẫu gần nhất để tính p95
}


def estimate_tokens(messages) -> int:
    """Ước lượng số token của list messages (chars / 3.5)."""
    chars = sum(len(str(m.get("content", ""))) for m in messages)
    return int(chars / _CHARS_PER_TOKEN)


def preflight_check(messages, max_output_tokens: int) -> int:
    """Kiểm tra TRƯỚC khi gọi LLM. Trả về ước lượng token input; log WARNING nếu sát trần."""
    est = estimate_tokens(messages)
    input_budget = max(N_CTX - max_output_tokens, 1)
    if est > WARN_RATIO * input_budget:
        with _lock:
            _state["overflow_warnings"] += 1
        logger.warning(
            f"[CONTEXT GUARD] Prompt ước lượng ~{est} token > {int(WARN_RATIO * 100)}% ngân sách "
            f"input ({input_budget}/{N_CTX}). Nguy cơ cắt ngữ cảnh — nên nén template mạnh hơn "
            f"hoặc giảm RAG/memory budget."
        )
        _persist()
    return est


def record_usage(usage) -> None:
    """Ghi token THẬT từ response.usage (prompt_tokens / completion_tokens)."""
    if usage is None:
        return
    pt = int(getattr(usage, "prompt_tokens", 0) or 0)
    ct = int(getattr(usage, "completion_tokens", 0) or 0)
    if pt == 0 and ct == 0:
        return
    with _lock:
        _state["calls"] += 1
        _state["prompt_sum"] += pt
        _state["completion_sum"] += ct
        _state["prompt_max"] = max(_state["prompt_max"], pt)
        _state["recent_prompt"].append(pt)
        if len(_state["recent_prompt"]) > 500:
            _state["recent_prompt"] = _state["recent_prompt"][-500:]
        _persist()


def _persist() -> None:
    rp = sorted(_state["recent_prompt"])
    p95 = rp[min(int(0.95 * len(rp)), len(rp) - 1)] if rp else 0
    calls = _state["calls"]
    out = {
        "n_ctx": N_CTX,
        "calls": calls,
        "prompt_tokens_mean": round(_state["prompt_sum"] / calls, 1) if calls else 0,
        "prompt_tokens_p95": p95,
        "prompt_tokens_max": _state["prompt_max"],
        "completion_tokens_mean": round(_state["completion_sum"] / calls, 1) if calls else 0,
        "overflow_warnings": _state["overflow_warnings"],
        "utilization_pct_p95": round(100 * p95 / N_CTX, 1) if N_CTX else 0.0,
        "utilization_pct_max": round(100 * _state["prompt_max"] / N_CTX, 1) if N_CTX else 0.0,
    }
    try:
        with open(STATS_PATH, "w") as f:
            json.dump(out, f, indent=2)
    except Exception:
        pass  # quan sát không được phép làm hỏng luồng LLM


def get_stats():
    """Đọc số liệu đã bền vững (cho dashboard)."""
    try:
        with open(STATS_PATH) as f:
            return json.load(f)
    except Exception:
        return None
