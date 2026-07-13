import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import redis  # type: ignore
import yaml  # type: ignore

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


def follow_file(filepath):
    """Realtime file tailer (tương đương tail -f)"""
    if not os.path.exists(filepath):
        # Tạo file trống nếu chưa tồn tại
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write("")

    with open(filepath) as f:
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
    r.xadd(queue_name, payload, maxlen=10000, approximate=True)  # pyright: ignore[reportArgumentType]
    print(
        f"[+] Pushed to Redis [{queue_name}]: {log_entry['Source IP']} -> {log_entry.get('message') or log_entry.get('payload')}"
    )


def parse_ssh_line(line):
    """Parse SSH failures from auth.log for both password and publickey auth mechanisms."""
    # Pattern 1: Failed password
    m1 = re.search(r"Failed password for (\S+) from (\S+) port (\d+)", line)
    if m1:
        return m1.group(1), m1.group(2), int(m1.group(3))
    # Pattern 2: Invalid user
    m2 = re.search(r"Invalid user (\S+) from (\S+) port (\d+)", line)
    if m2:
        return m2.group(1), m2.group(2), int(m2.group(3))
    # Pattern 3: Connection closed by authenticating/invalid user
    m3 = re.search(
        r"Connection closed by (?:authenticating|invalid) user (\S+) (\S+) port (\d+)", line
    )
    if m3:
        return m3.group(1), m3.group(2), int(m3.group(3))
    return None


def monitor_ssh():
    print(f"[*] Monitoring SSH logs in {AUTH_LOG_PATH}...")
    for line in follow_file(AUTH_LOG_PATH):
        parsed = parse_ssh_line(line)
        if parsed:
            user, ip, port = parsed

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
                "message": f"Failed SSH connection attempt for user {user}",
                "dataset_source": "live_pentest",
            }
            push_to_redis("queue_firewall", log_entry)


class DecoyWAFHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Mute default logging to console to keep output clean
        pass

    def do_GET(self):
        # Parse query params
        parsed_url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_url.query)
        input_payload = params.get("input", [""])[0]

        # Log entry for Sentinel WAF
        log_entry = {
            "Source IP": self.client_address[0],
            "Destination IP": "127.0.0.1",
            "Source Port": self.client_address[1],
            "Destination Port": 8000,
            "Protocol": 6,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "Flow Duration": 500,
            "Total Fwd Packets": 1,
            "Total Bwd Packets": 1,
            "service": "HTTP",
            "message": f"GET {self.path}",
            "payload": input_payload,
            "user_agent": self.headers.get("User-Agent", ""),
            "dataset_source": "live_pentest",
        }

        push_to_redis("queue_waf", log_entry)

        # Send response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        response = {"status": "ok", "message": "Request processed by decoy WAF"}
        self.wfile.write(json.dumps(response).encode("utf-8"))


def start_decoy_web_server():
    server_address = ("", 8000)
    httpd = HTTPServer(server_address, DecoyWAFHandler)
    print("[*] Starting decoy WAF server on port 8000...")
    httpd.serve_forever()


if __name__ == "__main__":
    # Start decoy web server in a daemon thread
    web_thread = threading.Thread(target=start_decoy_web_server, daemon=True)
    web_thread.start()

    try:
        monitor_ssh()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
