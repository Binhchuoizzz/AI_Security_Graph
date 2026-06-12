"""
Data Publisher — stream CSV THÔ lên Redis (production-scale ingestion).

Vai trò trong bộ BA PUBLISHER (không trùng nhau):
  - src/streaming/publisher.py (file này): đọc CSV thô CHUNKED (chunksize=500,
    file hàng triệu dòng/GB không nạp hết RAM), backpressure + chống Redis OOM.
    Dùng cho LOAD TEST / chứng minh tầng ingestion; KHÔNG mang nhãn ground-truth
    hay metadata APT.
  - scripts/simulate_traffic.py: replay ground_truth.json (có nhãn, demo dashboard).
  - experiments/stream_unified_online.py: phát LUỒNG GỘP CICIDS+DAPT+zero-day kèm
    metadata APT (demo end-to-end APT emergent — khuyến nghị cho demo luồng gộp).
"""
import redis  # type: ignore
import json
import time
import os
import hashlib
import random
import numpy as np  # type: ignore
import pandas as pd  # type: ignore
from dotenv import load_dotenv  # type: ignore

import yaml  # type: ignore

load_dotenv()

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml"
)
try:
    with open(CONFIG_PATH, "r") as f:
        _config = yaml.safe_load(f)
except Exception:
    _config = {}

REDIS_URL = os.getenv("REDIS_URL", _config.get("redis", {}).get("url", "redis://localhost:6379/0"))
QUEUE_NAME = _config.get("redis", {}).get("queue_name", "queue_waf")
BATCH_DELAY_SECONDS = float(_config.get("redis", {}).get("publisher_delay_seconds", 0.5))
MAX_QUEUE_SIZE = 10000  # Giới hạn hàng đợi để chống nghẽn và ngăn Redis OOM

# Ánh xạ cột tiêu chuẩn để đồng bộ các tập dữ liệu khác nhau (CSE-CIC-IDS2018 & DAPT2020)
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
    """Làm sạch các giá trị sentinel NaN, Inf, và -1 thành dạng an toàn cho việc phân tích cú pháp JSON."""
    if pd.isna(v):
        return 0
    if isinstance(v, float) and np.isinf(v):
        return 0.0
    if v == -1:
        return 0
    return v


def _inject_ips(entry: dict, idx: int):
    """Tạo địa chỉ IP động dựa trên nhãn và chỉ số để tránh làm bão hòa danh sách đen."""
    if "Source IP" not in entry and "src_ip" not in entry:
        label = entry.get("Label", "BENIGN")
        rng = random.Random(hashlib.sha256(f"{label}_{idx}".encode()).digest())
        if str(label).upper() not in ("BENIGN", "NORMAL"):
            # Dải mạng giả lập của kẻ tấn công
            entry["Source IP"] = f"10.200.{rng.randint(1, 20)}.{rng.randint(2, 254)}"
        else:
            # Dải mạng nội bộ an toàn giả lập
            entry["Source IP"] = f"192.168.100.{rng.randint(2, 254)}"
        entry["Destination IP"] = f"192.168.100.{rng.randint(10, 50)}"


def stream_logs_to_redis(csv_path: str):
    """
    Mô phỏng đường ống kỹ thuật dữ liệu (Streaming Ingestion):
    Đọc log tấn công từ tệp CSV và đẩy liên tục vào Redis Stream (dùng xadd).
    Sử dụng mô hình nhóm tiêu thụ (xreadgroup ở phía subscriber) để đảm bảo phân phối log ít nhất một lần.
    
    Bao gồm kiểm soát nghẽn (backpressure) và giới hạn băng thông ở mức batch để tránh crash do Redis OOM.
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
        # chunksize=500 là tối ưu để cân bằng giữa hiệu suất và chi phí bộ nhớ
        for chunk_idx, chunk in enumerate(pd.read_csv(csv_path, chunksize=500)):
            # Kiểm soát nghẽn: Kiểm tra kích thước hàng đợi trước khi xử lý chunk để tránh gọi Redis ở mỗi dòng
            wait_count = 0
            backpressure_threshold = int(MAX_QUEUE_SIZE * 0.9)
            while r.xlen(QUEUE_NAME) > backpressure_threshold:  # type: ignore
                time.sleep(0.1)
                wait_count += 1
                if wait_count % 100 == 0:  # Mỗi 10 giây (100 * 0.1s)
                    print(
                        f"[!] Backpressure: stream={r.xlen(QUEUE_NAME)} exceeds threshold {backpressure_threshold}. Consumer offline or slow?"
                    )

            for index, row in chunk.iterrows():
                log_entry = row.to_dict()

                # Làm sạch các giá trị không hợp lệ (NaN -> 0, Inf -> 0.0, -1 -> 0)
                clean_entry = {
                    k: _clean_val(v) for k, v in log_entry.items()
                }

                # Chuẩn hóa các trường khóa về định dạng tiêu chuẩn (tiêu đề CIC-IDS2018)
                normalized_entry = {}
                for k, v in clean_entry.items():
                    key_stripped = k.strip()
                    target_key = COLUMN_MAPPING.get(key_stripped, key_stripped)
                    normalized_entry[target_key] = v

                # Tự động sinh IP giả lập một cách xác định nếu thiếu
                _inject_ips(normalized_entry, index)

                # Thêm tên tệp nguồn dữ liệu để Tier-1/Tier-2 phân biệt ngữ cảnh
                normalized_entry["dataset_source"] = os.path.basename(csv_path)

                # Đẩy vào Redis Stream (giới hạn maxlen bằng approximate=True để tăng hiệu năng)
                r.xadd(QUEUE_NAME, {"log": json.dumps(normalized_entry)}, maxlen=MAX_QUEUE_SIZE, approximate=True)
                total_published += 1

            print(f"[>] Published chunk {chunk_idx + 1} (Total logs sent: {total_published}) -> Stream: {QUEUE_NAME}")
            
            # Giới hạn tốc độ nạp trên mỗi chunk (không phải từng dòng) để tránh nghẽn
            time.sleep(BATCH_DELAY_SECONDS)

        print(f"[+] Finished streaming! Total published logs: {total_published}")

    except KeyboardInterrupt:
        print("\n[*] Stopped manually by Admin.")
    except Exception as e:
        print(f"[!] Streaming failed: {e}")


if __name__ == "__main__":
    MOCK_CSV = "data/raw/Demo-Attack.csv"
    stream_logs_to_redis(MOCK_CSV)
