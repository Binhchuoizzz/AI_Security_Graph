import redis
import json
import time
import os
import pandas as pd

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
QUEUE_NAME = "security_logs_stream"
BATCH_DELAY_SECONDS = 0.5  # Simulate processing interval

def stream_logs_to_redis(csv_path: str):
    """
    Giả lập Data Engineering Pipeline (Streaming): 
    Đọc dữ liệu tấn công từ CSV và push liên tục vào Redis Queue (rpush).
    Điều này giải quyết tính Real-time (Thời gian thực) của một SOC hiện đại.
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
        print("    Vui lòng copy file sample từ CICIDS2017 vào đường dẫn này.")
        return

    print(f"[*] Throttling ingestion from {csv_path} with {BATCH_DELAY_SECONDS}s delay...")
    try:
        # Dùng chunksize để tránh load toàn bộ file GB vào RAM gây sập (Best Practice DE)
        for chunk in pd.read_csv(csv_path, chunksize=10):
            for index, row in chunk.iterrows():
                log_entry = row.to_dict()
                
                # Làm sạch NaN value do Pandas
                clean_entry = {k: ("" if pd.isna(v) else v) for k, v in log_entry.items()}
                
                r.rpush(QUEUE_NAME, json.dumps(clean_entry))
                print(f"[>] Published row {index} -> Redis Queue: {QUEUE_NAME}")
                
                time.sleep(BATCH_DELAY_SECONDS)
                
    except KeyboardInterrupt:
        print("\n[*] Stopped manually by Admin.")
    except Exception as e:
        print(f"[!] Streaming failed: {e}")

if __name__ == "__main__":
    MOCK_CSV = "data/raw/sample_logs.csv"
    # Bạn sẽ tạo một sample_logs.csv giả lập hoặc trích từ CICIDS2017
    stream_logs_to_redis(MOCK_CSV)
