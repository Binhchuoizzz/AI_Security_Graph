import json
import os
import sys
import time

import redis  # type: ignore
from dotenv import load_dotenv

load_dotenv()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# determine_queue dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import determine_queue  # noqa: E402

DATA_FILE = os.path.join(ROOT, "data", "demo_10k.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
MAX_QUEUE_SIZE = 10_000


def main():
    if not os.path.exists(DATA_FILE):
        print(f"[-] Data file not found: {DATA_FILE}")
        print("[*] Please run `python scripts/build_demo.py` first.")
        sys.exit(1)

    with open(DATA_FILE) as f:
        events = json.load(f)

    print(f"[*] Loaded {len(events)} events from {DATA_FILE}")

    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        redis_client.ping()
    except redis.exceptions.ConnectionError:  # type: ignore[attr-defined]
        print(f"[-] Failed to connect to Redis at {REDIS_URL}. Please start Redis.")
        sys.exit(1)

    print(f"[*] Connected to Redis. Starting push (Batch: {BATCH_SIZE}, Delay: {BATCH_DELAY}s)...")

    total_pushed = 0
    for i in range(0, len(events), BATCH_SIZE):
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
