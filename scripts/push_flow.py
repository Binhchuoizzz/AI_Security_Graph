"""push_flow.py — Đẩy RIÊNG TỪNG luồng dữ liệu lên Redis để demo tách bạch từng kịch bản.

Khác `scripts/demo.py` (đẩy luồng GỘP cicids+dapt+zeroday+adversarial), script này cho phép
đẩy CHỈ MỘT nguồn để trình diễn tách bạch qua FULL pipeline live (Tier-1 → Tier-2 → Dashboard):

  --source cicids       Phân loại lưu lượng CIC-IDS2018 (BLOCK/ALERT/DROP + giảm tải nhiễu)
  --source dapt         Chuỗi APT đa ngày DAPT2020 (APT emergent trong Threat Memory)
  --source zeroday      Zero-day REAL-derived — Welford Z-score bắt cái luật tĩnh bỏ sót
  --source adversarial  120 payload OWASP LLM Top-10 (Tier-1 chặn/escalate → Tier-2 guardrails)

TÁI DÙNG data đã build + logic đã kiểm thử — KHÔNG bịa số liệu:
  - cicids/dapt/zeroday: LỌC từ `data/demo.json` theo `unified_source` (đã enrich sẵn bởi
    `build_demo.py` → `unified_dataset.enrich`). Dựng demo.json trước: `.venv/bin/python
    scripts/build_demo.py`.
  - adversarial: 120 payload từ `experiments/adversarial/*/samples.json`, dựng event đúng shape
    `_build_adversarials` rồi `enrich()` + `determine_queue()` của `unified_dataset` (1 nguồn chân lý).
    Mỗi payload 1 IP TEST-NET riêng (198.51.100.x / 203.0.113.x) để lệnh chặn hiện rõ trên UI.

LƯU Ý QUAN TRỌNG:
  - dapt & zeroday luôn được PREPEND benign warmup (mặc định 150, cờ --warmup) để Welford có
    baseline — nếu không, Z-score zero-day sẽ vô nghĩa (chưa học nền).
  - Cần subscriber chạy trên HOST (`python main.py --mode server`) để Tier-1+Tier-2 xử lý và ghi
    DB/config cho Dashboard đọc. Dashboard container KHÔNG reach Redis (xem DEMO_FLOWS.md mục 0).
  - REDIS_URL (kèm mật khẩu) CHỈ lấy từ .env — không bao giờ in ra stdout/log.

Chạy:
  .venv/bin/python scripts/push_flow.py --source cicids --limit 300
  .venv/bin/python scripts/push_flow.py --source dapt
  .venv/bin/python scripts/push_flow.py --source zeroday --dry-run
  .venv/bin/python scripts/push_flow.py --source adversarial
"""

import argparse
import glob
import json
import os
import re
import sys
import time
from collections import Counter

import redis  # type: ignore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Secret chỉ sống trong .env — nạp trước khi đọc REDIS_URL (script chạy standalone).
from dotenv import load_dotenv  # noqa: E402

from experiments.unified_dataset import determine_queue, enrich  # noqa: E402

load_dotenv()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DEMO_FILE = os.path.join(ROOT, "data", "demo.json")
ADV_GLOB = os.path.join(ROOT, "experiments", "adversarial", "*", "samples.json")
MAX_QUEUE_SIZE = 10_000

# user-facing source -> giá trị unified_source trong demo.json.
# cicids = tập ĐÃ GẮN NHÃN 1250 mẫu (không lấy cicids_max 87k để demo gọn); dapt = 402 sự kiện
# chuỗi APT curated (không lấy dapt_max); zeroday = biến thể real-derived.
SOURCE_MAP = {
    "cicids": ("cicids",),
    "dapt": ("dapt",),
    "zeroday": ("zeroday",),
}


def _redact_redis_url(url: str) -> str:
    """Ẩn mật khẩu trong REDIS_URL trước khi in (redis://:pass@host -> redis://:***@host)."""
    return re.sub(r"(://[^:/@]*:)[^@/]*@", r"\1***@", url)


def _load_demo() -> list[dict]:
    if not os.path.exists(DEMO_FILE):
        print(f"[!] Thiếu {DEMO_FILE}. Dựng trước: .venv/bin/python scripts/build_demo.py")
        sys.exit(1)
    with open(DEMO_FILE, encoding="utf-8") as f:
        return json.load(f)


def _benign_warmup(demo: list[dict], n: int) -> list[dict]:
    """n log benign (cicids) làm baseline Welford — lấy từ chính demo.json (data THẬT)."""
    warm = [
        e
        for e in demo
        if e.get("unified_source") in ("cicids", "cicids_max") and e.get("gt_label") == "Benign"
    ]
    return warm[:n]


def _unified_logs(source: str, limit: int, warmup: int):
    """(queue, log) cho cicids/dapt/zeroday — lọc demo.json (đã enrich); prepend warmup nếu cần."""
    demo = _load_demo()
    srcs = SOURCE_MAP[source]
    events = [e for e in demo if e.get("unified_source") in srcs]
    if limit and limit > 0:
        events = events[:limit]
    if source in ("dapt", "zeroday"):
        events = _benign_warmup(demo, warmup) + events
    for log in events:  # demo.json đã enrich sẵn -> chỉ định tuyến
        yield determine_queue(log), log


def _adversarial_logs(limit: int):
    """(queue, log) cho 120 payload adversarial — mỗi mẫu 1 IP TEST-NET riêng."""
    samples: list[dict] = []
    for path in sorted(glob.glob(ADV_GLOB)):
        with open(path, encoding="utf-8") as f:
            samples.extend(json.load(f))
    if limit and limit > 0:
        samples = samples[:limit]
    for i, s in enumerate(samples):
        octet = i % 250 + 1
        block = "198.51.100" if i < 250 else "203.0.113"
        aid = s.get("id", f"ADV-{i:03d}")
        payload = s.get("payload", "")
        field = s.get("payload_field", "payload")
        log = {
            "Source IP": f"{block}.{octet}",
            "Destination IP": "10.0.0.10",
            "Destination Port": 80,
            "Protocol": 6,
            "service": "HTTP",
            "gt_id": aid,
        }
        if field == "user_agent":
            log["user_agent"] = payload
            log["message"] = ""
        else:
            log["message"] = payload
            log["user_agent"] = f"adv-probe/{aid}"
        elog = enrich({"source": "adversarial", "log": log})
        yield determine_queue(elog), elog


def main():
    ap = argparse.ArgumentParser(description="Đẩy RIÊNG từng luồng lên Redis (demo tách luồng).")
    ap.add_argument(
        "--source",
        required=True,
        choices=["cicids", "dapt", "zeroday", "adversarial"],
        help="Nguồn dữ liệu cần đẩy (chỉ 1 luồng).",
    )
    ap.add_argument("--limit", type=int, default=0, help="Giới hạn số log nguồn (0=tất cả).")
    ap.add_argument(
        "--warmup",
        type=int,
        default=150,
        help="Số benign warmup cho dapt/zeroday (Welford baseline).",
    )
    ap.add_argument("--delay", type=float, default=0.05, help="Giãn cách giữa các log (giây).")
    ap.add_argument(
        "--dry-run", action="store_true", help="Chỉ đếm phân bố queue, KHÔNG đẩy Redis."
    )
    args = ap.parse_args()

    gen = (
        _adversarial_logs(args.limit)
        if args.source == "adversarial"
        else _unified_logs(args.source, args.limit, args.warmup)
    )
    items = list(gen)
    qdist = Counter(q for q, _ in items)
    print(f"[*] Nguồn '{args.source}': {len(items)} log | phân bố queue: {dict(qdist)}")
    if args.source in ("dapt", "zeroday"):
        print(f"    (đã kèm {args.warmup} benign warmup để Welford có baseline)")

    if args.dry_run:
        print("[*] --dry-run: KHÔNG đẩy Redis. Thoát.")
        return

    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
    except Exception as e:  # noqa: BLE001
        print(f"[!] Redis không kết nối được ({_redact_redis_url(REDIS_URL)}): {e}")
        return

    published = 0
    for q, log in items:
        r.xadd(q, {"log": json.dumps(log)}, maxlen=MAX_QUEUE_SIZE, approximate=True)
        published += 1
        if published % 50 == 0:
            print(f"[>] đã đẩy {published}/{len(items)}")
        time.sleep(args.delay)
    print(f"[+] Hoàn tất! Đã đẩy {published} log nguồn '{args.source}'. Theo dõi Dashboard :8501.")


if __name__ == "__main__":
    main()
