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
# Ước lượng KHỞI ĐIỂM khi chưa có số đo thật. 3.5 char/token quá bảo thủ với nội dung
# thật của SENTINEL (log/JSON nhiều chữ số + dấu câu): đo trên demo 100k cho thấy tỉ lệ
# thật > 4.2 -> ước lượng thổi phồng > 21%, khiến CONTEXT GUARD báo động GIẢ gần như mọi
# call (33/34) dù prompt thật (max 5.909) chưa bao giờ chạm ngưỡng 6.923. Nay chỉ dùng
# hằng này lúc chưa có mẫu, sau đó TỰ HIỆU CHUẨN theo prompt_tokens THẬT (xem _ratio()).
_CHARS_PER_TOKEN = 4.0
_MIN_CALIB_SAMPLES = 20  # đủ mẫu mới tin tỉ lệ đo được

_lock = threading.Lock()


def _new_state() -> dict:
    """Trạng thái rỗng — NGUỒN DUY NHẤT của schema `_state`.

    Test cũng phải dùng hàm này để reset (thay vì chép tay dict): trước đây fixture
    chép cứng các khoá nên mỗi lần thêm khoá mới là test vỡ hàng loạt bằng KeyError.
    """
    return {
        "calls": 0,
        "prompt_sum": 0,
        "prompt_max": 0,
        "completion_sum": 0,
        "overflow_warnings": 0,
        "recent_prompt": [],  # giữ tối đa 500 mẫu gần nhất để tính p95
        # Hiệu chuẩn: tổng ký tự đã gửi và tổng token THẬT tương ứng.
        "calib_chars": 0,
        "calib_tokens": 0,
    }


_state = _new_state()


def _ratio() -> float:
    """Số ký tự trên mỗi token — ĐO THẬT nếu đủ mẫu, nếu chưa thì dùng hằng khởi điểm.

    Tự hiệu chuẩn để CONTEXT GUARD phản ánh đúng tokenizer đang chạy (Gemma vs Llama
    cho tỉ lệ khác nhau), thay vì báo động giả bằng một hằng số đoán trước.
    """
    tok = _state["calib_tokens"]
    if tok >= _MIN_CALIB_SAMPLES and _state["calib_chars"] > 0:
        return max(1.0, _state["calib_chars"] / tok)
    return _CHARS_PER_TOKEN


def estimate_tokens(messages) -> int:
    """Ước lượng số token của list messages (chars / tỉ lệ đã hiệu chuẩn)."""
    chars = sum(len(str(m.get("content", ""))) for m in messages)
    return int(chars / _ratio())


def preflight_check(messages, max_output_tokens: int) -> int:
    """Kiểm tra TRƯỚC khi gọi LLM. Trả về ước lượng token input; log WARNING nếu sát trần."""
    chars = sum(len(str(m.get("content", ""))) for m in messages)
    est = int(chars / _ratio())
    input_budget = max(N_CTX - max_output_tokens, 1)
    # Góp mẫu hiệu chuẩn: mỗi preflight_check ứng với ĐÚNG một record_usage sau đó, nên
    # tỉ lệ giữa TỔNG ký tự và TỔNG token thật hội tụ đúng dù không ghép được từng cặp
    # (nhiều worker chạy song song).
    with _lock:
        _state["calib_chars"] += chars
    if est > WARN_RATIO * input_budget:
        # _persist() PHẢI nằm trong lock: record_usage() ở worker khác cũng persist()
        # dưới lock — nếu preflight persist NGOÀI lock thì hai thread cùng ghi STATS_PATH
        # -> JSON hỏng. Gộp vào lock để ghi file được serialize.
        with _lock:
            _state["overflow_warnings"] += 1
            _persist()
        logger.warning(
            f"[CONTEXT GUARD] Prompt ước lượng ~{est} token > {int(WARN_RATIO * 100)}% ngân sách "
            f"input ({input_budget}/{N_CTX}). Nguy cơ cắt ngữ cảnh — nên nén template mạnh hơn "
            f"hoặc giảm RAG/memory budget."
        )
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
        _state["calib_tokens"] += pt  # mẫu THẬT để _ratio() tự hiệu chuẩn
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
        # Tỉ lệ ký tự/token ĐANG dùng cho CONTEXT GUARD: đo thật khi đủ mẫu, nếu không
        # thì là hằng khởi điểm. Phơi ra để kiểm chứng được cảnh báo có chính xác không.
        "chars_per_token": round(_ratio(), 2),
        "chars_per_token_calibrated": _state["calib_tokens"] >= _MIN_CALIB_SAMPLES,
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
