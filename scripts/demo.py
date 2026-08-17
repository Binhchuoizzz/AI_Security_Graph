import json
import os
import re
import sys
import time

import redis  # type: ignore
from dotenv import load_dotenv

load_dotenv()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# determine_queue dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import determine_queue  # noqa: E402
from src.streaming.backpressure import LAG_UNKNOWN, consumer_group_lag  # noqa: E402

# Cho phép chỉ định file luồng khác (demo ngắn dùng data/demo_small.json — tập con PHÂN
# TẦNG đủ 4 nguồn + chuỗi APT đa-ngày; xem scripts/build_demo_small.py).
DATA_FILE = os.getenv("UNIFIED_STREAM_FILE") or os.path.join(ROOT, "data", "demo.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
# Giới hạn số event đẩy (demo NGẮN để soi UI). 0 = đẩy hết (mặc định, giữ nguyên hành vi cũ).
STREAM_LIMIT = int(os.getenv("UNIFIED_STREAM_LIMIT", "0"))
MAX_QUEUE_SIZE = 10_000
# Backpressure: các stream subscriber đang đọc + file thống kê THẬT (subscriber ghi).
QUEUES = ("queue_firewall", "queue_waf", "queue_sysmon")
STATS_PATH = os.path.join(ROOT, "config", "pipeline_stats.json")
# Trần backlog LLM (hàng đợi Tier-2 trong RAM). Vượt -> tạm dừng đẩy để không phình RAM.
MAX_LLM_BACKLOG = int(os.getenv("UNIFIED_STREAM_MAX_LLM_BACKLOG", "2000"))
# Trần độ trễ consumer-group (số entry CHƯA được subscriber nhận). Đo bằng lag của
# consumer-group, KHÔNG bằng xlen — xlen KHÔNG giảm khi dùng xreadgroup+xack nên sẽ
# "kẹt" ở mức cao dù subscriber đã xử lý xong (gây dừng OAN, đúng lỗi đã gặp).
STREAM_LAG_MAX = int(os.getenv("UNIFIED_STREAM_MAX_LAG", "5000"))


def _redact_redis_url(url: str) -> str:
    """Ẩn mật khẩu trong REDIS_URL trước khi in/log (redis://:pass@host -> redis://:***@host).

    Mật khẩu Redis CHỈ được sống trong .env — không bao giờ để rò ra stdout/journald.
    """
    return re.sub(r"(://[^:/@]*:)[^@/]*@", r"\1***@", url)


def _wait_for_capacity(redis_client) -> None:
    """BACKPRESSURE — cho phép đẩy 'vô số' log AN TOÀN: producer TỰ chậm lại theo năng lực
    consumer, thay vì tràn Redis stream / phình RAM hàng đợi LLM.

    Tạm dừng khi: độ trễ consumer-group (lag) vượt STREAM_LAG_MAX HOẶC backlog LLM
    (pending_llm_queue do subscriber ghi vào config/pipeline_stats.json) vượt MAX_LLM_BACKLOG.
    Bọc lỗi toàn bộ để KHÔNG bao giờ làm hỏng luồng đẩy (thiếu file/redis coi như 'còn chỗ')."""
    warned = False
    for _ in range(3000):  # trần chờ ~10 phút/batch (đủ để Tier-2 tiêu hoá backlog)
        lag = consumer_group_lag(redis_client, QUEUES)
        backlog = 0
        try:
            with open(STATS_PATH) as f:
                backlog = int(json.load(f).get("pending_llm_queue", 0))
        except Exception:
            backlog = 0
        if lag < STREAM_LAG_MAX and backlog < MAX_LLM_BACKLOG:
            return
        if not warned:
            if lag >= LAG_UNKNOWN:
                # Không phải "consumer chậm" mà là "chưa có consumer nào". Nói đúng tên,
                # vì cách xử lý khác hẳn: chờ subscriber nạp xong mô hình, không phải
                # tăng worker.
                print(
                    "\n[~] Chưa có consumer-group trên stream — subscriber chưa sẵn sàng. "
                    "Dừng đẩy để MAXLEN không huỷ mất log chưa ai đọc…"
                )
            else:
                print(
                    f"\n[~] Backpressure: consumer lag={lag}, LLM backlog={backlog} "
                    f"— chờ consumer bắt kịp (đẩy tiếp khi có chỗ)…"
                )
            warned = True
        time.sleep(0.2)


def _consumed_total() -> int:
    """Số log Tier-1 đã THẬT SỰ xử lý, do subscriber ghi ra (luỹ kế, sống qua restart)."""
    try:
        with open(STATS_PATH) as f:
            return int(json.load(f).get("raw_logs_total", 0))
    except Exception:
        return 0


def _verify_no_loss(redis_client, pushed: int, consumed_before: int) -> None:
    """Đối chiếu ĐẨY vào với TIÊU THỤ ra — mất log KHÔNG được phép im lặng.

    VÌ SAO PHẢI ĐỐI CHIẾU THỦ CÔNG. Không một chỉ số nào của Redis tự tố cáo được việc này:
    khi `MAXLEN` cắt entry chưa ai đọc, Redis DỜI LUÔN `entries-read` của consumer-group cho
    khớp, nên `lag` về 0 và `entries-added == entries-read` — nhìn y hệt "giao đủ".
    Thí nghiệm 17/08/2026: đẩy 700 entry vào stream `maxlen=200`, không ai đọc; `lag` báo
    200, `entries-added` báo 700, `xreadgroup` nhận đúng 200. 500 bản ghi biến mất không dấu.

    Trong sự cố cùng ngày, 91.500/496.885 sự kiện (18,4%) bị huỷ như vậy và lượt chạy vẫn
    "thành công" — mọi tỉ lệ tính trên lượt đó đều sai mẫu số mà không ai biết. Với một luận
    văn thì đó là hỏng ở mức không cứu được sau khi đã trích số, nên chốt chặn nằm ở ĐÂY.
    """
    print("[*] Đối chiếu đẩy-vào / tiêu-thụ-ra (chờ consumer rút hết)…")
    stable = 0
    last = -1
    for _ in range(900):  # trần ~3 phút
        lag = consumer_group_lag(redis_client, QUEUES)
        now = _consumed_total()
        if lag == 0 and now == last:
            stable += 1
            if stable >= 3:
                break
        else:
            stable = 0
        last = now
        time.sleep(0.2)

    consumed = _consumed_total() - consumed_before
    lost = pushed - consumed
    if lost <= 0:
        print(f"[+] TOÀN VẸN: đẩy {pushed} — Tier-1 xử lý {consumed}. Không mất log.")
        return
    pct = lost / pushed * 100 if pushed else 0.0
    print("\n" + "=" * 78)
    print(f"[!!!] MẤT LOG: đẩy {pushed}, Tier-1 chỉ xử lý {consumed} -> THIẾU {lost} ({pct:.1f}%).")
    print("      Nguyên nhân thường gặp: producer chạy trước khi subscriber tạo consumer-group,")
    print(f"      nên MAXLEN={MAX_QUEUE_SIZE} huỷ log chưa ai đọc.")
    print("      MỌI tỉ lệ tính trên lượt chạy này đều SAI MẪU SỐ — đừng trích số, hãy chạy lại.")
    print("=" * 78)


def main():
    if not os.path.exists(DATA_FILE):
        print(f"[-] Data file not found: {DATA_FILE}")
        print("[*] Please run `python scripts/build_demo.py` first.")
        sys.exit(1)

    with open(DATA_FILE) as f:
        events = json.load(f)

    if STREAM_LIMIT > 0:
        events = events[:STREAM_LIMIT]
        print(
            f"[*] UNIFIED_STREAM_LIMIT={STREAM_LIMIT} -> demo NGẮN, chỉ đẩy {len(events)} event đầu."
        )

    print(f"[*] Loaded {len(events)} events from {DATA_FILE}")

    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        redis_client.ping()
    except redis.exceptions.ConnectionError:  # type: ignore[attr-defined]
        print(
            f"[-] Failed to connect to Redis at {_redact_redis_url(REDIS_URL)}. Please start Redis."
        )
        sys.exit(1)

    print(f"[*] Connected to Redis. Starting push (Batch: {BATCH_SIZE}, Delay: {BATCH_DELAY}s)...")

    # Chụp TRƯỚC khi đẩy: `raw_logs_total` là bộ đếm luỹ kế sống qua restart, nên chỉ phần
    # chênh lệch mới thuộc về lượt này.
    consumed_before = _consumed_total()
    total_pushed = 0
    for i in range(0, len(events), BATCH_SIZE):
        _wait_for_capacity(redis_client)  # backpressure: chờ nếu consumer sau lưng
        batch = events[i : i + BATCH_SIZE]
        pipe = redis_client.pipeline()
        for ev in batch:
            q_name = determine_queue(ev)
            # Dữ liệu đã được enrich sẵn trong JSON, chỉ việc đẩy thẳng lên
            pipe.xadd(q_name, {"log": json.dumps(ev)}, maxlen=MAX_QUEUE_SIZE)

        pipe.execute()
        total_pushed += len(batch)
        print(f"  -> Pushed {total_pushed}/{len(events)} events...", end="\r")
        if BATCH_DELAY:
            time.sleep(BATCH_DELAY)

    print(f"\n[+] Finished streaming {total_pushed} events to Redis.")
    _verify_no_loss(redis_client, total_pushed, consumed_before)


if __name__ == "__main__":
    main()
