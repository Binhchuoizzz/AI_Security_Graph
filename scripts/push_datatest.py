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

DATA_FILE = os.path.join(ROOT, "data", "datatest.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
MAX_QUEUE_SIZE = 10_000
QUEUES = ("queue_firewall", "queue_waf", "queue_sysmon")
GROUP_NAME = "sentinel_group"  # PHẢI khớp subscriber.py (đo lag đúng consumer-group)
STATS_PATH = os.path.join(ROOT, "config", "pipeline_stats.json")
MAX_LLM_BACKLOG = int(os.getenv("UNIFIED_STREAM_MAX_LLM_BACKLOG", "2000"))
# Trần độ trễ consumer-group (đo bằng lag, KHÔNG bằng xlen — xlen không giảm khi xack).
STREAM_LAG_MAX = int(os.getenv("UNIFIED_STREAM_MAX_LAG", "5000"))


def _redact_redis_url(url: str) -> str:
    """Ẩn mật khẩu trong REDIS_URL trước khi in/log (redis://:pass@host -> redis://:***@host).

    Mật khẩu Redis CHỈ được sống trong .env — không bao giờ để rò ra stdout/journald.
    """
    return re.sub(r"(://[^:/@]*:)[^@/]*@", r"\1***@", url)


def _consumer_lag(redis_client) -> int:
    """Độ trễ THẬT của consumer-group `sentinel_group` (lag) — xem chú thích ở scripts/demo.py.
    KHÔNG dùng xlen: xreadgroup+xack không xoá entry nên xlen kẹt cao → dừng OAN."""
    total = 0
    for q in QUEUES:
        try:
            groups = redis_client.xinfo_groups(q)
        except Exception:
            continue
        for g in groups:
            if g.get("name") != GROUP_NAME:
                continue
            lag = g.get("lag")
            if lag is None:
                try:
                    lag = int((redis_client.xpending(q, GROUP_NAME) or {}).get("pending", 0))
                except Exception:
                    lag = 0
            total += int(lag or 0)
    return total


def _wait_for_capacity(redis_client) -> None:
    """BACKPRESSURE — producer tự chậm lại theo năng lực consumer (xem scripts/demo.py):
    dừng khi độ trễ consumer-group (lag) vượt STREAM_LAG_MAX HOẶC backlog LLM
    (pipeline_stats.json) vượt trần. Bọc lỗi toàn bộ để KHÔNG làm hỏng luồng đẩy."""
    warned = False
    for _ in range(3000):
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
            print(f"\n[~] Backpressure: consumer lag={lag}, LLM backlog={backlog} — chờ consumer…")
            warned = True
        time.sleep(0.2)


def main():
    if not os.path.exists(DATA_FILE):
        print(f"[-] Data file not found: {DATA_FILE}")
        print("[*] Please run `python scripts/build_datatest.py` first.")
        sys.exit(1)

    with open(DATA_FILE) as f:
        events = json.load(f)

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
