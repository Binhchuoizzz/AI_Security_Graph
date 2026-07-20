import json
import os
import re
import sys
import time

import redis  # type: ignore
from dotenv import load_dotenv

load_dotenv()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# determine_queue dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import determine_queue  # noqa: E402

DATA_FILE = os.path.join(ROOT, "data", "demo.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
# Giới hạn số event đẩy (demo NGẮN để soi UI). 0 = đẩy hết (mặc định, giữ nguyên hành vi cũ).
STREAM_LIMIT = int(os.getenv("UNIFIED_STREAM_LIMIT", "0"))
MAX_QUEUE_SIZE = 10_000
# Backpressure: các stream subscriber đang đọc + file thống kê THẬT (subscriber ghi).
QUEUES = ("queue_firewall", "queue_waf", "queue_sysmon")
GROUP_NAME = "sentinel_group"  # PHẢI khớp subscriber.py (đo lag của đúng consumer-group này)
STATS_PATH = os.path.join(ROOT, "config", "pipeline_stats.json")
# Trần backlog LLM (hàng đợi Tier-2 trong RAM). Vượt -> tạm dừng đẩy để không phình RAM.
MAX_LLM_BACKLOG = int(os.getenv("UNIFIED_STREAM_MAX_LLM_BACKLOG", "2000"))
# Trần độ trễ consumer-group (số entry CHƯA được subscriber nhận). Đo bằng lag của
# consumer-group, KHÔNG bằng xlen — xlen KHÔNG giảm khi dùng xreadgroup+xack nên sẽ
# "kẹt" ở mức cao dù subscriber đã xử lý xong (gây dừng OAN, đúng lỗi đã gặp).
STREAM_LAG_MAX = int(os.getenv("UNIFIED_STREAM_MAX_LAG", "5000"))


def _redact_redis_url(url: str) -> str:
    """Ẩn mật khẩu trong REDIS_URL trước khi in/log (redis://:pass@host -> redis://:***@host).

    Mật khẩu Redis CHỈ được sống trong .env — không bao giờ để rò ra stdout/journald.
    """
    return re.sub(r"(://[^:/@]*:)[^@/]*@", r"\1***@", url)


def _consumer_lag(redis_client) -> int:
    """Độ trễ THẬT của consumer-group `sentinel_group`: số entry đã vào stream nhưng
    subscriber CHƯA nhận (lag).

    TẠI SAO KHÔNG DÙNG xlen: subscriber tiêu thụ bằng xreadgroup + xack, thao tác này
    KHÔNG xoá entry khỏi stream nên `xlen` giữ nguyên (~maxlen) dù đã xử lý xong hết →
    backpressure theo xlen sẽ dừng OAN vĩnh viễn. `lag` (Redis 7+) mới phản ánh đúng
    'consumer tụt lại bao nhiêu'. Bọc lỗi để thiếu stream/redis chỉ coi như không tụt hậu."""
    total = 0
    for q in QUEUES:
        try:
            groups = redis_client.xinfo_groups(q)
        except Exception:
            continue  # stream chưa tồn tại / lỗi -> bỏ qua queue này
        for g in groups:
            if g.get("name") != GROUP_NAME:
                continue
            lag = g.get("lag")
            if lag is None:
                # Redis cũ / lag không xác định -> fallback: số entry đang chờ ack (pending).
                try:
                    lag = int((redis_client.xpending(q, GROUP_NAME) or {}).get("pending", 0))
                except Exception:
                    lag = 0
            total += int(lag or 0)
    return total


def _wait_for_capacity(redis_client) -> None:
    """BACKPRESSURE — cho phép đẩy 'vô số' log AN TOÀN: producer TỰ chậm lại theo năng lực
    consumer, thay vì tràn Redis stream / phình RAM hàng đợi LLM.

    Tạm dừng khi: độ trễ consumer-group (lag) vượt STREAM_LAG_MAX HOẶC backlog LLM
    (pending_llm_queue do subscriber ghi vào config/pipeline_stats.json) vượt MAX_LLM_BACKLOG.
    Bọc lỗi toàn bộ để KHÔNG bao giờ làm hỏng luồng đẩy (thiếu file/redis coi như 'còn chỗ')."""
    warned = False
    for _ in range(3000):  # trần chờ ~10 phút/batch (đủ để Tier-2 tiêu hoá backlog)
        lag = _consumer_lag(redis_client)
        backlog = 0
        try:
            with open(STATS_PATH) as f:
                backlog = int(json.load(f).get("pending_llm_queue", 0))
        except Exception:
            backlog = 0
        if lag < STREAM_LAG_MAX and backlog < MAX_LLM_BACKLOG:
            return
        if not warned:
            print(
                f"\n[~] Backpressure: consumer lag={lag}, LLM backlog={backlog} "
                f"— chờ consumer bắt kịp (đẩy tiếp khi có chỗ)…"
            )
            warned = True
        time.sleep(0.2)


def main():
    if not os.path.exists(DATA_FILE):
        print(f"[-] Data file not found: {DATA_FILE}")
        print("[*] Please run `python scripts/build_demo.py` first.")
        sys.exit(1)

    with open(DATA_FILE) as f:
        events = json.load(f)

    if STREAM_LIMIT > 0:
        events = events[:STREAM_LIMIT]
        print(
            f"[*] UNIFIED_STREAM_LIMIT={STREAM_LIMIT} -> demo NGẮN, chỉ đẩy {len(events)} event đầu."
        )

    print(f"[*] Loaded {len(events)} events from {DATA_FILE}")

    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        redis_client.ping()
    except redis.exceptions.ConnectionError:  # type: ignore[attr-defined]
        print(
            f"[-] Failed to connect to Redis at {_redact_redis_url(REDIS_URL)}. Please start Redis."
        )
        sys.exit(1)

    print(f"[*] Connected to Redis. Starting push (Batch: {BATCH_SIZE}, Delay: {BATCH_DELAY}s)...")

    total_pushed = 0
    for i in range(0, len(events), BATCH_SIZE):
        _wait_for_capacity(redis_client)  # backpressure: chờ nếu consumer sau lưng
        batch = events[i : i + BATCH_SIZE]
        pipe = redis_client.pipeline()
        for ev in batch:
            q_name = determine_queue(ev)
            # Dữ liệu đã được enrich sẵn trong JSON, chỉ việc đẩy thẳng lên
            pipe.xadd(q_name, {"log": json.dumps(ev)}, maxlen=MAX_QUEUE_SIZE)

        pipe.execute()
        total_pushed += len(batch)
        print(f"  -> Pushed {total_pushed}/{len(events)} events...", end="\r")
        time.sleep(BATCH_DELAY)

    print(f"\n[+] Finished streaming {total_pushed} events to Redis.")


if __name__ == "__main__":
    main()
