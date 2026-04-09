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
QUEUE_NAME = "security_logs_stream"

def start_listening():
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
    print(f"[*] Subscribed and listening on {QUEUE_NAME}...")

    while True:
        try:
            # BLPOP sẽ nằm im chờ đợi không ăn CPU, khi có data nó nhả qua ngay lập tức
            # item sẽ là một tuple: ('tên_queue', 'giá_trị_chuyển_vào')
            item = r.blpop(QUEUE_NAME, timeout=0)
            if item:
                raw_log = json.loads(item[1])
                
                # Gọi ngay Tier 1 Rule Engine để cân nhắc
                evaluated_log = engine.evaluate(raw_log)
                
                if evaluated_log['tier1_action'] == "ESCALATE":
                    # Đây là nhánh sẽ kích hoạt việc gọi Agent LangGraph sau này!
                    alert_msg = f"[!] ESCALATE TO AI | Risk: {evaluated_log['tier1_score']} | Vi phạm: {evaluated_log['tier1_reasons']}"
                    print(alert_msg)
                else:
                    # Bỏ comment này nếu muốn nhìn thấy các traffic lành tính "chảy" qua
                    # print(f"[.] DROP: Normal benign traffic ignored.")
                    pass

        except KeyboardInterrupt:
            print("\n[*] Subscriber offline (Shutdown).")
            break
        except json.JSONDecodeError:
            print("[!] Malformed JSON Log received via Redis. Skiping.")
        except Exception as e:
            print(f"[!] Critical Error in stream processing: {e}")

if __name__ == "__main__":
    start_listening()
