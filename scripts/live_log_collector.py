import json
import os
import re
import time
import redis
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "system_settings.yaml")
try:
    with open(CONFIG_PATH) as f:
        _config = yaml.safe_load(f)
except Exception:
    _config = {}

REDIS_URL = os.getenv("REDIS_URL", _config.get("redis", {}).get("url", "redis://localhost:6379/0"))
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# File log cần giám sát (Ví dụ mặc định của Ubuntu/Debian)
AUTH_LOG_PATH = "/var/log/auth.log"

# Regex để parse SSH auth log thất bại
SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2"
)

def follow_file(filepath):
    """Realtime file tailer (tương đương tail -f)"""
    if not os.path.exists(filepath):
        # Tạo file trống nếu chưa tồn tại
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write("")
            
    with open(filepath, "r") as f:
        # Di chuyển con trỏ tới cuối file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def push_to_redis(queue_name, log_entry):
    payload = {"log": json.dumps(log_entry)}
    r.xadd(queue_name, payload, maxlen=10000, approximate=True)
    print(f"[+] Pushed to Redis [{queue_name}]: {log_entry['Source IP']} -> {log_entry.get('message') or log_entry.get('payload')}")

def monitor_ssh():
    print(f"[*] Monitoring SSH logs in {AUTH_LOG_PATH}...")
    for line in follow_file(AUTH_LOG_PATH):
        match = SSH_FAILED_PATTERN.search(line)
        if match:
            ip = match.group("ip")
            user = match.group("user")
            port = int(match.group("port"))
            
            # Map sang schema mà SENTINEL expects
            log_entry = {
                "Source IP": ip,
                "Destination IP": "127.0.0.1",
                "Source Port": port,
                "Destination Port": 22,
                "Protocol": 6,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "Flow Duration": 1000,
                "Total Fwd Packets": 1,
                "Total Bwd Packets": 0,
                "service": "SSH",
                "message": f"Failed password for user {user}",
                "dataset_source": "live_pentest"
            }
            push_to_redis("queue_firewall", log_entry)

if __name__ == "__main__":
    try:
        monitor_ssh()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
