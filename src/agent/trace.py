"""
Tier-2 Execution Tracer — BẬT THEO YÊU CẦU (opt-in), mặc định TẮT.

VÌ SAO CÓ FILE NÀY. Một lượt chạy Tier-2 TÍNH RỒI VỨT gần hết bằng chứng trung gian: cờ
injection/jailbreak theo từng log, hai truy vấn RAG, top-k tài liệu truy xuất, prompt ĐẦY
ĐỦ, câu trả lời THÔ của LLM, và ba lớp kiểm duyệt hạ cấp quyết định (cổng confidence · lá
chắn hạ tầng · consensus Tier-1/Tier-2). Sau lượt chạy KHÔNG có cách nào dựng lại "vì sao
lô này ra verdict đó": `logs/guardrails_audit.db` chỉ giữ verdict GIỮA CHỪNG, còn
`node_attack_mapper` chạy SAU khi dòng audit đã ghi nên không bao giờ vào DB đó.

BỐN RÀNG BUỘC CỨNG:
  1. TẮT mặc định — mỗi điểm cắm tốn ĐÚNG một phép đọc bool (`trace.enabled()`): không dựng
     dict, không format chuỗi, không I/O.
  2. MỘT dòng JSON cho MỖI `agent_app.invoke()`, kể cả khi đồ thị NÉM LỖI (lô lỗi là lô cần
     audit nhất).
  3. Bản ghi sống trong `contextvars.ContextVar` — KHÔNG phải `threading.local` — vì
     LangGraph `copy_context()` khi đẩy task sang executor thread. ContextVar đi theo
     context nên node chạy ở luồng nào cũng bồi đúng bản ghi của lô mình, mà các worker
     Tier-2 vẫn cô lập tuyệt đối (mỗi thread khởi đầu bằng context RỖNG). `add()` chỉ SỬA
     TẠI CHỖ dict, KHÔNG BAO GIỜ `.set()` lại — nhờ vậy bản context đã copy vẫn trỏ chung
     một đối tượng.
  4. KHÔNG BAO GIỜ ném lỗi ra ngoài. Sink hỏng -> tự tắt vĩnh viễn.

KHÔNG đụng `SentinelState`: dataclass đó không có reducer, node sau sẽ ghi đè node trước.

ENV:
  SENTINEL_TRACE=1              bật (mặc định tắt)
  SENTINEL_TRACE_FILE=...       mặc định logs/tier2_trace.jsonl
  SENTINEL_TRACE_MAX_CHARS=N    cắt MỌI chuỗi dài quá N (mặc định 12000; 0 = KHÔNG cắt —
                                dùng khi cần soi rò rỉ nhãn trên prompt ĐẦY ĐỦ)

CẢNH BÁO BẢO MẬT: file trace chứa payload thô của kẻ tấn công và toàn văn system prompt.
`logs/` đã nằm trong .gitignore. Đừng render `llm.prompt` / `llm.raw_response` ra HTML mà
không qua `output_sanitizer`.
"""

import contextvars
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_PATH = "logs/tier2_trace.jsonl"
DEFAULT_MAX_CHARS = 12000
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_MAX_IDS = 50  # trần số IP/gt_id ghi lại (lô thường 10 log)
_CLIP_MAX_DEPTH = 6  # trần đệ quy khi cắt chuỗi

# ── Cấu hình + sink dùng chung toàn tiến trình ────────────────────────────────
_enabled: bool = False
_path: str = DEFAULT_PATH
_max_chars: int = DEFAULT_MAX_CHARS
_write_lock = threading.Lock()
_fh: Any = None  # mở LƯỜI: chỉ tạo file khi có bản ghi ĐẦU TIÊN
_sink_broken: bool = False  # hỏng -> tắt vĩnh viễn, không spam log, không ném lỗi

_record: contextvars.ContextVar = contextvars.ContextVar(
    "sentinel_tier2_trace_record", default=None
)


# ==============================================================================
# API CÔNG KHAI
# ==============================================================================
def configure() -> None:
    """Nạp lại cấu hình từ env và đóng sink cũ. Dùng ở entrypoint/test — KHÔNG ở hot-path."""
    global _enabled, _path, _max_chars, _fh, _sink_broken
    with _write_lock:
        if _fh is not None:
            try:
                _fh.close()
            except Exception:
                pass
            _fh = None
        _sink_broken = False
        _enabled = str(os.getenv("SENTINEL_TRACE", "")).strip().lower() in _TRUTHY
        _path = os.getenv("SENTINEL_TRACE_FILE", DEFAULT_PATH)
        try:
            _max_chars = max(0, int(os.getenv("SENTINEL_TRACE_MAX_CHARS", str(DEFAULT_MAX_CHARS))))
        except ValueError:
            _max_chars = DEFAULT_MAX_CHARS


def enabled() -> bool:
    """Cổng DUY NHẤT ở mọi điểm cắm. False ngay khi sink hỏng -> tự vô hiệu hoá."""
    return _enabled and not _sink_broken


def begin(state: Any = None, **meta: Any) -> None:
    """Mở bản ghi cho MỘT lần invoke. Gọi ở proxy `_TracedGraph.invoke` (workflow.py)."""
    if not enabled():
        return
    try:
        stale = _record.get()
        if stale is not None:
            # Lần invoke trước không flush được -> KHÔNG nuốt bản ghi cũ, ghi ra rồi mở mới.
            _emit(stale, status="abandoned")
        logs = _batch_logs(state)
        now = time.time()
        rec: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "trace_id": "t2-"
            + time.strftime("%Y%m%dT%H%M%S", time.gmtime(now))
            + "-"
            + uuid.uuid4().hex[:8],
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
            "ts_start": _iso(now),
            "ts_start_local": _local(now),  # khớp định dạng của config/audit_trail.db
            "ts_start_epoch": round(now, 6),
            "batch": _batch_meta(logs),
            "nodes": {},
        }
        if meta:
            rec["meta"] = dict(meta)
        _record.set(rec)
    except Exception:  # tracer KHÔNG BAO GIỜ được làm vỡ pipeline
        pass


def add(section: str, **fields: Any) -> None:
    """Bồi dữ liệu vào bản ghi hiện tại. CHỈ gọi bên trong `if trace.enabled():`.

    Gộp theo khoá (`dict.update`) và CHỈ sửa TẠI CHỖ — không bao giờ `_record.set()` — để
    context đã copy sang thread khác vẫn bồi vào ĐÚNG một đối tượng.
    """
    if not enabled():
        return
    try:
        rec = _record.get()
        if rec is None:
            return  # gọi node trực tiếp (test/eval) mà không begin() -> no-op êm
        sec = rec.get(section)
        if not isinstance(sec, dict):
            sec = {}
            rec[section] = sec
        sec.update(fields)
    except Exception:
        pass


def flush(status: str = "ok", error: BaseException | None = None, final_state: Any = None) -> None:
    """Đóng bản ghi và ghi ĐÚNG MỘT dòng JSON. Gọi thừa (không có bản ghi) -> no-op."""
    if not enabled():
        return
    rec = None
    try:
        rec = _record.get()
        _record.set(None)
        if rec is None:
            return
        if error is not None:
            rec["error"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        if final_state is not None:
            rec["final"] = _final_meta(final_state)
    except Exception:
        pass
    if rec is not None:
        _emit(rec, status=status)


# ==============================================================================
# NỘI BỘ
# ==============================================================================
def _emit(rec: dict, status: str) -> None:
    global _sink_broken
    try:
        now = time.time()
        rec["status"] = status
        rec["ts_end"] = _iso(now)
        rec["ts_end_local"] = _local(now)
        rec["duration_ms"] = round((now - float(rec.get("ts_start_epoch") or now)) * 1000, 2)
        # Tuần tự hoá NGOÀI lock: giữ vùng tới hạn chỉ còn một lệnh write.
        line = json.dumps(_clip(rec, _max_chars), ensure_ascii=False, default=str)
    except Exception as e:
        logger.warning(f"[TRACE] Không tuần tự hoá được bản ghi: {e}")
        return
    try:
        with _write_lock:  # NỐI TIẾP mọi luồng: một dòng không bao giờ xen vào dòng khác
            _sink().write(line + "\n")
    except Exception as e:
        _sink_broken = True
        logger.error(f"[TRACE] Sink {_path!r} hỏng ({e}) — TẮT tracer cho phần còn lại.")


def _sink():
    """Mở lười, append, line-buffered (mỗi bản ghi chạm OS ngay). Gọi TRONG _write_lock."""
    global _fh
    if _fh is None:
        d = os.path.dirname(_path)
        if d:
            os.makedirs(d, exist_ok=True)
        _fh = open(_path, "a", encoding="utf-8", buffering=1)
    return _fh


def _clip(obj: Any, cap: int, depth: int = 0) -> Any:
    """Cắt MỌI chuỗi dài quá `cap` (cap<=0 -> không cắt), có ghi rõ đã cắt bao nhiêu."""
    if cap <= 0 or depth > _CLIP_MAX_DEPTH:
        return obj
    if isinstance(obj, str):
        if len(obj) <= cap:
            return obj
        return obj[:cap] + f"…[TRUNCATED {len(obj) - cap} of {len(obj)} chars]"
    if isinstance(obj, dict):
        return {k: _clip(v, cap, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clip(v, cap, depth + 1) for v in obj]
    return obj


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _local(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def _batch_logs(state: Any) -> list:
    """Nhận cả SentinelState (dataclass) lẫn dict — mọi nơi gọi invoke đều truyền 1 trong 2."""
    if state is None:
        return []
    logs = getattr(state, "current_batch_logs", None)
    if logs is None and isinstance(state, dict):
        logs = state.get("current_batch_logs")
    return list(logs or [])


def _batch_meta(logs: list) -> dict:
    """Khoá NỐI về Tier-1.

    `gt_id` là khoá MẠNH NHẤT: nó sống sót `_strip_dataset_labels` (xem
    `subscriber._LABEL_KEY_ALLOW`), nên nối chuẩn hơn hẳn cách 'IP + gần nhau về thời gian'
    — vốn là cách DUY NHẤT có thể làm trước khi có tracer, vì hệ không có ID tương quan nào.
    """
    ips: list[str] = []
    gts: list[str] = []
    actions: list[str] = []
    scores: list[float] = []
    for lg in logs:
        if not isinstance(lg, dict):
            continue
        ip = lg.get("Source IP") or lg.get("src_ip")
        if ip:
            ips.append(str(ip))
        if lg.get("gt_id"):
            gts.append(str(lg["gt_id"]))
        if lg.get("tier1_action"):
            actions.append(str(lg["tier1_action"]))
        try:
            scores.append(float(lg.get("tier1_score") or 0))
        except (TypeError, ValueError):
            pass
    return {
        "size": len(logs),
        "source_ips": list(dict.fromkeys(ips))[:_MAX_IDS],
        "gt_ids": list(dict.fromkeys(gts))[:_MAX_IDS],
        "tier1_actions": sorted(set(actions)),
        "tier1_score_max": max(scores) if scores else 0.0,
    }


def _final_meta(final_state: Any) -> dict:
    """`decisions` bị THAY THẾ (state không có reducer) nên phần tử cuối là bản giàu nhất."""
    decisions = (
        final_state.get("decisions")
        if isinstance(final_state, dict)
        else getattr(final_state, "decisions", None)
    )
    d = decisions[-1] if decisions else {}
    if not isinstance(d, dict):
        return {}
    return {
        "action": d.get("action", ""),
        "target": d.get("target", ""),
        "confidence": d.get("confidence"),
        "mitre_technique": d.get("mitre_technique", ""),
        "mitre_technique_id": d.get("mitre_technique_id", ""),
        "mapping_status": d.get("mapping_status", ""),
        # Mã lý do chuyển người xử lý — để hậu kiểm thống kê được "hàng đợi HITL gồm gì"
        # mà không phải khớp chuỗi tiếng Việt trong `reasoning`.
        "hitl_reason": d.get("hitl_reason", ""),
        "reasoning": d.get("reasoning", ""),
        "reasoning_chars": len(str(d.get("reasoning", ""))),
    }


configure()  # đọc env một lần lúc import
