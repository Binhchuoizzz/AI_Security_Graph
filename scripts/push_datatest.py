import os
import sys
import json
import time
import redis
from dotenv import load_dotenv

load_dotenv()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(ROOT, "data", "datatest.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
MAX_QUEUE_SIZE = 10_000

FIREWALL_PORTS = {21, 22, 23, 53, 139, 445, 3389}
WAF_PORTS = {80, 443, 8080}

def determine_queue(log: dict) -> str:
    """Port-based → payload/UA → default firewall."""
    try:
        port = int(log.get("Destination Port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if port in FIREWALL_PORTS:
        return "queue_firewall"
    if port in WAF_PORTS:
        return "queue_waf"
    if log.get("payload") or log.get("user_agent"):
        return "queue_waf"
    return "queue_firewall"

def main():
    if not os.path.exists(DATA_FILE):
        print(f"[-] Data file not found: {DATA_FILE}")
        print("[*] Please run `python scripts/build_demo_test.py` first.")
        sys.exit(1)

    with open(DATA_FILE, "r") as f:
        events = json.load(f)

    print(f"[*] Loaded {len(events)} events from {DATA_FILE}")
    
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        redis_client.ping()
    except redis.exceptions.ConnectionError:
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
