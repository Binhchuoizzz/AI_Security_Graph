"""
Log Subscriber & Tier 1 Trigger

Kết nối trực tiếp vào hàng chờ cấu trúc Redis List, sử dụng vòng chờ chặn `blpop`
để hứng phân tích theo dạng Real-time Streaming. Ngay khi có dữ liệu, trigger 
`RuleEngine` ngay tại RAM và in kết quả.
"""
import redis
import json
import os
import sys

# Khắc phục lỗi ModuleNotFound khi chạy trực tiếp file trong python
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.tier1_filter.rule_engine import RuleEngine

# Nhận config theo chuẩn OS Env
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# Hỗ trợ cấu trúc Multi-source cho Log Correlation (MAWILab)
QUEUES = ["queue_firewall", "queue_waf", "queue_sysmon"]

import time

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

    # Ngưỡng (Threshold) = 30 là mức nhạy khá, dễ dính chùm port 22
    engine = RuleEngine(risk_threshold=30)
    print(f"[*] Tier 1 Firewall Armed (Threshold={engine.risk_threshold}).")
    print(f"[*] Subscribed and listening on multiple queues: {QUEUES}...")

    # Incident-Level Aggregation Buffers
    batch_buffer = []
    last_batch_time = time.time()

    while True:
        try:
            # BLPOP lắng nghe trên nhiều queue cùng lúc.
            # item sẽ là một tuple: ('tên_queue', 'giá_trị_chuyển_vào')
            item = r.blpop(QUEUES, timeout=1) 
            if item:
                source_queue = item[0]
                raw_log = json.loads(item[1])
                
                # Gắn nhãn Provenance (Nguồn gốc) để phục vụ SIEM Correlation
                raw_log['log_source'] = source_queue
                
                # Gọi ngay Tier 1 Rule Engine để cân nhắc
                evaluated_log = engine.evaluate(raw_log)
                
                if evaluated_log['tier1_action'] == "ESCALATE":
                    alert_msg = f"[!] ESCALATE TO AI | Source: {source_queue} | Risk: {evaluated_log['tier1_score']} | Vi phạm: {evaluated_log['tier1_reasons']}"
                    print(alert_msg)
                    batch_buffer.append(evaluated_log)
                else:
                    pass

            # Kiểm tra xem có cần trigger batch không
            current_time = time.time()
            if batch_buffer and (len(batch_buffer) >= batch_size or (current_time - last_batch_time) > timeout_sec):
                if on_batch_ready:
                    print(f"[*] Triggering Agent Workflow for batch of {len(batch_buffer)} logs...")
                    on_batch_ready(batch_buffer)
                batch_buffer = []
                last_batch_time = time.time()

        except KeyboardInterrupt:
            print("\n[*] Subscriber offline (Shutdown).")
            break
        except json.JSONDecodeError:
            print("[!] Malformed JSON Log received via Redis. Skiping.")
        except Exception as e:
            print(f"[!] Critical Error in stream processing: {e}")

if __name__ == "__main__":
    start_listening()
