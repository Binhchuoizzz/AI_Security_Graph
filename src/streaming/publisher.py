import redis
import json
import time
import os
import hashlib
import random
import numpy as np
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
QUEUE_NAME = "queue_waf"  # Default to WAF queue for CSV-based ingestion
BATCH_DELAY_SECONDS = 0.5  # Throttle delay between batches
MAX_QUEUE_SIZE = 10000  # Backpressure queue limit to prevent Redis OOM

# Standard column mapping to align different datasets (CSE-CIC-IDS2018 & DAPT2020)
COLUMN_MAPPING = {
    "src_ip": "Source IP",
    "Src IP": "Source IP",
    "Source IP": "Source IP",
    "dst_ip": "Destination IP",
    "Dst IP": "Destination IP",
    "Destination IP": "Destination IP",
    "src_port": "Source Port",
    "Src Port": "Source Port",
    "Source Port": "Source Port",
    "dst_port": "Destination Port",
    "Dst Port": "Destination Port",
    "Destination Port": "Destination Port",
    "protocol": "Protocol",
    "Protocol": "Protocol",
    "flow_duration": "Flow Duration",
    "Flow Duration": "Flow Duration",
    "flow_duration_us": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Fwd Packets": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Bwd Packets",
    "Total Bwd packets": "Total Bwd Packets",
    "Total Bwd Packets": "Total Bwd Packets",
    "Label": "Label",
    "label": "Label",
    "Stage": "Stage",
    "stage": "Stage",
    "Timestamp": "timestamp",
    "timestamp": "timestamp",
}


def _clean_val(v):
    """Clean NaN and Inf values to safe representations for JSON parsing."""
    if pd.isna(v):
        return 0
    if isinstance(v, float) and np.isinf(v):
        return 0.0
    return v


def _inject_ips(entry: dict, idx: int):
    """Dynamically generate deterministic IPs based on label and index to prevent blacklist saturation."""
    if "Source IP" not in entry and "src_ip" not in entry:
        label = entry.get("Label", "BENIGN")
        rng = random.Random(hashlib.sha256(f"{label}_{idx}".encode()).digest())
        if str(label).upper() not in ("BENIGN", "NORMAL"):
            # Simulated attacker range
            entry["Source IP"] = f"10.200.{rng.randint(1, 20)}.{rng.randint(2, 254)}"
        else:
            # Simulated benign corporate subnet range
            entry["Source IP"] = f"192.168.100.{rng.randint(2, 254)}"
        entry["Destination IP"] = f"192.168.100.{rng.randint(10, 50)}"


def stream_logs_to_redis(csv_path: str):
    """
    Simulate Data Engineering Pipeline (Streaming Ingestion):
    Read attack logs from CSV and push continuously into Redis List (using rpush).
    Uses a consumer queue pattern (blpop on the subscriber side) to guarantee delivery.
    
    Includes backpressure control and batch-level throttling to prevent Redis OOM crashes.
    """
    print(f"[*] Connecting to Redis: {REDIS_URL}")
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        print("[+] Redis connection successful.")
    except Exception as e:
        print(f"[!] Failed to connect to Redis: {e}")
        return

    if not os.path.exists(csv_path):
        print(f"[!] CSV path not found: {csv_path}.")
        print("    Please place a sample CSV file in this directory.")
        return

    print(
        f"[*] Ingesting logs from {csv_path} in batches with {BATCH_DELAY_SECONDS}s delay..."
    )
    
    total_published = 0
    try:
        # chunksize=500 is optimal for balancing performance and memory overhead
        for chunk_idx, chunk in enumerate(pd.read_csv(csv_path, chunksize=500)):
            for index, row in chunk.iterrows():
                log_entry = row.to_dict()

                # Clean invalid values (NaN -> 0, Inf -> 0.0)
                clean_entry = {
                    k: _clean_val(v) for k, v in log_entry.items()
                }

                # Normalize keys to standard expected format (CIC-IDS2018 headers)
                normalized_entry = {}
                for k, v in clean_entry.items():
                    key_stripped = k.strip()
                    target_key = COLUMN_MAPPING.get(key_stripped, key_stripped)
                    normalized_entry[target_key] = v

                # Auto-generate simulated IPs deterministically if missing
                _inject_ips(normalized_entry, index)

                while r.llen(QUEUE_NAME) > MAX_QUEUE_SIZE:  # type: ignore
                    time.sleep(0.1)

                # Push to Redis List
                r.rpush(QUEUE_NAME, json.dumps(normalized_entry))
                total_published += 1

            print(f"[>] Published chunk {chunk_idx + 1} (Total logs sent: {total_published}) -> Queue: {QUEUE_NAME}")
            
            # Throttle ingestion per-chunk (not per-row) to prevent bottlenecks
            time.sleep(BATCH_DELAY_SECONDS)

        print(f"[+] Finished streaming! Total published logs: {total_published}")

    except KeyboardInterrupt:
        print("\n[*] Stopped manually by Admin.")
    except Exception as e:
        print(f"[!] Streaming failed: {e}")


if __name__ == "__main__":
    MOCK_CSV = "data/raw/Demo-Attack.csv"
    stream_logs_to_redis(MOCK_CSV)
