"""
push_flow.py — Đẩy RIÊNG từng luồng dữ liệu lên Redis để demo từng kịch bản trước hội đồng.

Khác `stream_unified_online.py` (đẩy luồng GỘP cicids+dapt+zeroday), script này cho phép
đẩy CHỈ MỘT nguồn để trình diễn tách bạch:

  --source cicids       Phân loại lưu lượng CIC-IDS2018 (BLOCK/ALERT/DROP + Noise Reduction)
  --source dapt         Chuỗi tấn công APT đa ngày DAPT2020 (APT emergent trong Threat Memory)
  --source zeroday      7 zero-day (REAL-derived) — Welford Z-score bắt cái static bỏ sót
  --source adversarial  120 payload OWASP LLM Top-10 (Tier-1 chặn/escalate → Tier-2 guardrails)

TÁI DÙNG logic đã kiểm thử — KHÔNG tự bịa dữ liệu:
  - cicids/dapt/zeroday: `build_sequence()` (data thật từ ground_truth.json + dapt2020_chains.jsonl)
    + `enrich()` + `determine_queue()` của stream_unified_online.
  - adversarial: các mẫu experiments/adversarial/<cat>/samples.json + map_to_cicids/determine_queue
    của simulate_traffic. Mỗi mẫu 1 IP TEST-NET duy nhất (198.51.100.x) để block hiện rõ.

LƯU Ý QUAN TRỌNG:
  - dapt & zeroday luôn được PREPEND 150 benign warmup (cicids) để Welford có baseline —
    nếu không, Z-score zero-day sẽ vô nghĩa (chưa học nền).
  - Cần subscriber chạy trên HOST (python main.py --mode server) để Tier-1+Tier-2 xử lý và
    ghi DB/config cho Dashboard đọc. Dashboard container KHÔNG reach Redis.

Chạy:
  .venv/bin/python scripts/push_flow.py --source dapt
  .venv/bin/python scripts/push_flow.py --source cicids --limit 300
  .venv/bin/python scripts/push_flow.py --source adversarial --dry-run
"""

import argparse
import glob
import json
import os
import sys
import time
from collections import Counter

import redis  # type: ignore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from experiments.stream_unified_online import (  # noqa: E402
    build_sequence,
    determine_queue as uni_queue,
    enrich,
)
from scripts.simulate_traffic import (  # noqa: E402
    determine_queue as adv_queue,
    map_to_cicids,
)

REDIS_URL = os.getenv("REDIS_URL", "redis://:SentinelSecurePass2026!@localhost:6379/0")
ADV_GLOB = os.path.join(ROOT, "experiments", "adversarial", "*", "samples.json")
MAX_QUEUE_SIZE = 10_000


def _unified_logs(source: str, limit: int):
    """Sinh (queue, log) cho cicids/dapt/zeroday từ build_sequence(), lọc theo nguồn."""
    seq, warmup, main, apt_truth, n_chains = build_sequence()
    if source == "cicids":
        events = [e for e in seq if e["source"] == "cicids"]
        if limit:
            events = events[:limit]
    else:
        # dapt/zeroday: PREPEND warmup benign để Welford có baseline (không cắt warmup).
        picked = [e for e in main if e["source"] == source]
        events = list(warmup) + picked
    for ev in events:
        log = enrich(ev)
        yield uni_queue(log), log


def _adversarial_logs():
    """Sinh (queue, log) cho 120 payload adversarial — mỗi mẫu 1 IP TEST-NET duy nhất."""
    samples: list[dict] = []
    for path in sorted(glob.glob(ADV_GLOB)):
        with open(path, encoding="utf-8") as f:
            samples.extend(json.load(f))
    for i, s in enumerate(samples):
        octet = i % 250 + 1
        block = "198.51.100" if i < 250 else "203.0.113"
        pf = s.get("payload_field", "payload")
        pay = s.get("payload", "")
        if pf == "user_agent":
            app = {"user_agent": pay, "payload_snippet": ""}
        else:
            app = {"user_agent": "Mozilla/5.0", "payload_snippet": pay}
        nl = {
            "src_ip": f"{block}.{octet}",
            "dst_ip": "10.0.0.10",
            "src_port": 44000 + i,
            "dst_port": 80,
            "protocol": 6,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "flow_duration_us": 50000,
            "fwd_packets": 6,
            "bwd_packets": 5,
            "fwd_bytes": 800,
            "bwd_bytes": 1200,
            "flow_pkts_s": 20.0,
        }
        m = map_to_cicids(nl, app)
        m["gt_id"] = s.get("id", "")
        m["dataset_source"] = "adversarial"
        yield adv_queue(m), m


def main():
    ap = argparse.ArgumentParser(description="Đẩy RIÊNG từng luồng lên Redis (demo hội đồng).")
    ap.add_argument(
        "--source",
        required=True,
        choices=["cicids", "dapt", "zeroday", "adversarial"],
        help="Nguồn dữ liệu cần đẩy (chỉ 1 luồng).",
    )
    ap.add_argument(
        "--limit", type=int, default=0, help="Giới hạn số log (0=tất cả; chỉ áp cho cicids)."
    )
    ap.add_argument("--delay", type=float, default=0.05, help="Giãn cách giữa các log (giây).")
    ap.add_argument(
        "--dry-run", action="store_true", help="Chỉ đếm phân bố queue, KHÔNG đẩy Redis."
    )
    args = ap.parse_args()

    gen = (
        _adversarial_logs()
        if args.source == "adversarial"
        else _unified_logs(args.source, args.limit)
    )
    items = list(gen)
    qdist = Counter(q for q, _ in items)
    print(f"[*] Nguồn '{args.source}': {len(items)} log | phân bố queue: {dict(qdist)}")
    if args.source in ("dapt", "zeroday"):
        print("    (đã kèm 150 benign warmup để Welford có baseline)")

    if args.dry_run:
        print("[*] --dry-run: KHÔNG đẩy Redis. Thoát.")
        return

    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
    except Exception as e:  # noqa: BLE001
        print(f"[!] Redis không kết nối được: {e}")
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
