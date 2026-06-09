"""
Log Subscriber & Kích hoạt Tier 1

Kết nối vào Redis Streams qua consumer group 'sentinel_group', dùng `xreadgroup`
để đảm bảo at-least-once delivery. Sau khi xử lý, `xack` xác nhận tin nhắn đã hoàn tất.
"""

import os
import sys
import json
import time
from typing import Any, cast
import redis  # type: ignore
from dotenv import load_dotenv  # type: ignore

import yaml  # type: ignore

load_dotenv()

# Khắc phục lỗi ModuleNotFound khi chạy trực tiếp file trong python
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.tier1_filter.rule_engine import RuleEngine

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml"
)
try:
    with open(CONFIG_PATH, "r") as f:
        _config = yaml.safe_load(f)
except Exception:
    _config = {}

# Nhận config theo chuẩn OS Env hoặc YAML fallback
REDIS_URL = os.getenv("REDIS_URL", _config.get("redis", {}).get("url", "redis://localhost:6379/0"))
# Hỗ trợ cấu trúc Multi-source cho Log Correlation (MAWILab)
QUEUES = _config.get("redis", {}).get("queues", ["queue_firewall", "queue_waf", "queue_sysmon"])
ESCALATED_QUEUE = _config.get("redis", {}).get("escalated_queue", "queue_hitl")


def start_listening(on_batch_ready=None, batch_size=10, timeout_sec=5):
    """
    on_batch_ready: Hàm callback được gọi khi đủ batch size hoặc hết timeout.
    """
    print(f"[*] Connecting Subscriber to Redis: {REDIS_URL}")
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        print("[+] Redis connection successful. Waiting for live stream...")
    except Exception as e:
        print(f"[!] Subscriber failed to connect to Redis: {e}")
        return

    # Khởi tạo Consumer Group cho từng Stream
    GROUP_NAME = "sentinel_group"
    CONSUMER_NAME = "sentinel_consumer_1"
    for q in QUEUES:
        try:
            r.xgroup_create(q, GROUP_NAME, id="0", mkstream=True)
            print(f"[+] Consumer group '{GROUP_NAME}' created/verified for stream '{q}'")
        except redis.exceptions.ResponseError as e:
            if "BUSYGROUP" in str(e):
                pass
            else:
                print(f"[!] Warning: failed to create consumer group for {q}: {e}")

    # Ghi nhận limitation phục vụ thesis defense
    print(
        "[*] Note: PEL (Pending Entries List) recovery not implemented. "
        "Pending messages from previous crash will be reprocessed manually if needed."
    )

    # Ngưỡng (Threshold) được load từ system_settings.yaml (hiện tại: 15)
    engine = RuleEngine()
    print(f"[*] Tier 1 Firewall Armed (Threshold={engine.risk_threshold}).")
    print(f"[*] Subscribed and listening on multiple streams via group '{GROUP_NAME}': {QUEUES}...")

    # Bộ đệm gom sự cố (Incident-Level Aggregation Buffers)
    batch_buffer = []
    last_batch_time = time.time()

    # Chuẩn bị luồng đọc (dùng dict[Any, Any] để tránh lỗi ép kiểu static analysis của redis-py)
    streams_dict: dict[Any, Any] = {str(q): ">" for q in QUEUES}

    while True:
        try:
            # XREADGROUP lắng nghe trên nhiều stream cùng lúc.
            # Trả về: [[stream_name, [(msg_id, {field: value}), ...]], ...]
            # Tối ưu hóa throughput bằng cách lấy `count=batch_size` thay vì 1
            response = cast(Any, r.xreadgroup(GROUP_NAME, CONSUMER_NAME, streams_dict, count=batch_size, block=1000))
            if response:
                for stream_name, messages in response:
                    for msg_id, data in messages:
                        raw_log = json.loads(data["log"])

                        # Gắn nhãn Provenance (Nguồn gốc) để phục vụ SIEM Correlation
                        raw_log["log_source"] = stream_name

                        # Gọi ngay Tier 1 Rule Engine để cân nhắc
                        evaluated_log = engine.evaluate(raw_log)
                        action = evaluated_log.get("tier1_action", "DROP")

                        # ── Phân luồng định tuyến thông minh (Tier 1 Routing) ─────────
                        if action == "ESCALATE":
                            alert_msg = f"[!] ESCALATE TO AI | Source: {stream_name} | Risk: {evaluated_log.get('tier1_score')} | Vi phạm: {evaluated_log.get('tier1_reasons')}"
                            print(alert_msg)
                            batch_buffer.append(evaluated_log)

                        elif action == "AWAIT_HITL":
                            # Đẩy sang hàng đợi HITL để Streamlit dashboard hiển thị
                            print(f"[*] routing AWAIT_HITL (Infiltration) -> {ESCALATED_QUEUE}")
                            r.rpush(ESCALATED_QUEUE, json.dumps(evaluated_log))

                        elif action == "BLOCK_IP":
                            # Đẩy IP vào blacklist của Redis với TTL 1 giờ
                            src_ip = evaluated_log.get("Source IP") or evaluated_log.get("src_ip", "")
                            if src_ip:
                                print(f"[*] routing BLOCK_IP -> Blacklist: {src_ip}")
                                r.setex(f"blacklist:{src_ip}", 3600, "1")
                            # Ghi nhận vào log quyết định để phục vụ ablation study
                            r.rpush("queue_decisions", json.dumps(evaluated_log))

                        elif action in ("ALERT", "LOG"):
                            # Chỉ ghi nhận vào ablation log phục vụ thống kê nghiên cứu
                            r.rpush("queue_decisions", json.dumps(evaluated_log))

                        # Xác nhận đã xử lý xong tin nhắn trong stream (XACK)
                        r.xack(stream_name, GROUP_NAME, msg_id)

            # Kiểm tra xem có cần trigger batch không
            current_time = time.time()
            if batch_buffer and (
                len(batch_buffer) >= batch_size
                or (current_time - last_batch_time) > timeout_sec
            ):
                if on_batch_ready:
                    print(
                        f"[*] Triggering Agent Workflow for batch of {len(batch_buffer)} logs..."
                    )
                    on_batch_ready(batch_buffer)
                else:
                    # Chế độ độc lập (standalone mode) — ghi log ra màn hình (console)
                    for log in batch_buffer:
                        print(f"[ESCALATE] gt_id={log.get('gt_id')} "
                               f"ip={log.get('Source IP')} score={log.get('tier1_score')}")
                batch_buffer = []
                last_batch_time = current_time
            elif not batch_buffer:
                last_batch_time = current_time  # Đặt lại timer khi nhàn rỗi (tránh timing bug)

        except KeyboardInterrupt:
            print("\n[*] Subscriber offline (Shutdown).")
            break
        except redis.ConnectionError as e:
            print(f"[!] Redis connection lost: {e}. Retrying in 5s...")
            time.sleep(5)
        except json.JSONDecodeError:
            print("[!] Malformed JSON Log received via Redis. Skipping.")
        except Exception as e:
            print(f"[!] Unexpected error in stream processing: {e}")


if __name__ == "__main__":
    start_listening()
