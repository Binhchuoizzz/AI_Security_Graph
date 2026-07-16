"""Cách ly script ĐO khỏi trạng thái PRODUCTION (snapshot → chạy → khôi phục).

VÌ SAO CẦN (sự cố 2026-07-15): chạy `agent_app.invoke()` trong một script eval KHÔNG
phải là thao tác chỉ-đọc. `node_action_executor` ghi vào 4 kho trạng thái:

  - `block_ip()`                        -> config/audit_trail.db + Redis `blacklist:*`
  - `FeedbackListener.receive_new_rule()` -> luật động trong config/system_settings.yaml
  - `threat_memory.record_incident()`   -> config/threat_memory.db (ip_reputation)
  - `raise_alert()`                     -> config/audit_trail.db

Cả 4 đều QUAY LẠI NUÔI Tier-1 (L2 luật động, Tầng 3.5 uy tín IP, blacklist). Nghĩa là
phép đo TỰ LÀM NHIỄM chính nó: chạy eval xong, lần đo SAU sẽ escalate ít hơn vì Tier-1
đã "nhớ mặt" các IP do chính lần đo trước tạo ra. Đo được trực tiếp: `collect_escalated()`
ra 651 ca (14/07, có luật tích luỹ) so với 823 ca (15/07, sau reset_all) trên CÙNG dữ liệu.

CÁCH TIẾP CẬN: snapshot 4 kho trước khi chạy, khôi phục nguyên trạng sau khi chạy. Ưu
điểm so với việc vô hiệu hoá (no-op) các side effect: eval vẫn chạy ĐÚNG code path thật
— tức vẫn đo cái thật — chỉ là không để lại dấu vết.

LƯU Ý VỀ TÁI LẬP: cách ly chỉ đảm bảo eval không làm bẩn hệ thống. Muốn số liệu TÁI LẬP
được thì còn phải chạy từ trạng thái SẠCH đã biết -> chạy `scripts/reset_all.py` trước.

Dùng:
    from experiments._eval_isolation import isolated_state
    with isolated_state():
        run_benchmark()
"""

import os
import shutil
import sys
from contextlib import contextmanager

from dotenv import load_dotenv  # type: ignore

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.threat_memory import MEMORY_DB_PATH  # noqa: E402
from src.response.executor import DB_PATH as AUDIT_DB_PATH  # noqa: E402

# Secret chỉ sống trong .env — nạp trước khi đọc REDIS_URL (module dùng standalone).
load_dotenv()

_HERE = os.path.dirname(os.path.abspath(__file__))
SETTINGS_PATH = os.path.join(_HERE, "..", "config", "system_settings.yaml")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Các file bị side effect của agent ghi vào. Dùng chính hằng của module nguồn để không
# bao giờ lệch đường dẫn khi code đổi.
_TRACKED_FILES = (AUDIT_DB_PATH, MEMORY_DB_PATH, SETTINGS_PATH)


def _snapshot_files(tmpdir: str) -> dict[str, str]:
    """Copy các file trạng thái vào tmpdir. Trả map {gốc: bản sao}."""
    saved = {}
    for i, path in enumerate(_TRACKED_FILES):
        if os.path.exists(path):
            dest = os.path.join(tmpdir, f"{i}_{os.path.basename(path)}")
            shutil.copy2(path, dest)
            saved[path] = dest
    return saved


def _restore_files(saved: dict[str, str]) -> None:
    for path, backup in saved.items():
        try:
            shutil.copy2(backup, path)
        except Exception as exc:  # noqa: BLE001 — khôi phục best-effort, báo to để biết
            print(f"[!] CÁCH LY: không khôi phục được {path}: {exc}")


def _snapshot_blacklist() -> set[str] | None:
    """Trả tập key blacklist:* hiện có. None = không nối được Redis (bỏ qua êm)."""
    try:
        import redis  # type: ignore

        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        return set(r.keys("blacklist:*"))  # type: ignore[arg-type]
    except Exception:
        return None


def _restore_blacklist(before: set[str] | None) -> None:
    """Xoá đúng các key blacklist mà eval vừa TẠO THÊM (không đụng key có sẵn)."""
    if before is None:
        return
    try:
        import redis  # type: ignore

        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        now = set(r.keys("blacklist:*"))  # type: ignore[arg-type]
        added = now - before
        if added:
            r.delete(*added)
            print(f"[*] CÁCH LY: đã gỡ {len(added)} key blacklist do eval tạo.")
    except Exception as exc:  # noqa: BLE001
        print(f"[!] CÁCH LY: không dọn được blacklist: {exc}")


@contextmanager
def isolated_state(enabled: bool = True):
    """Chạy khối lệnh mà KHÔNG để lại thay đổi ở audit_trail / threat_memory / luật động
    / Redis blacklist.

    enabled=False -> không làm gì (khi cố ý muốn giữ side effect, vd chạy demo thật).
    """
    if not enabled:
        yield
        return

    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="sentinel_eval_isolation_")
    saved = _snapshot_files(tmpdir)
    bl_before = _snapshot_blacklist()
    print(
        f"[*] CÁCH LY BẬT: snapshot {len(saved)} file trạng thái"
        f"{f' + {len(bl_before)} key blacklist' if bl_before is not None else ''}."
        " Hệ thống sẽ được khôi phục nguyên trạng sau khi đo."
    )
    try:
        yield
    finally:
        _restore_files(saved)
        _restore_blacklist(bl_before)
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("[*] CÁCH LY: đã khôi phục trạng thái production về trước khi đo.")
