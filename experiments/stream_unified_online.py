"""
SENTINEL — Unified Streaming ONLINE Publisher
=============================================
Bản ONLINE của `evaluate_unified_stream.py`: thay vì chạy in-process (chỉ Tier-1 +
Threat Memory), script này đẩy **CÙNG một luồng gộp** (CICIDS + DAPT2020 + zero-day,
trộn theo thời gian golden-ratio) lên **Redis Streams**, để nó chảy qua **TOÀN BỘ
hệ thống thật**:

    publisher (file này) → Redis → subscriber (Tier-1 + Welford + APT memory)
        → [event ESCALATE] → LangGraph Agent (Guardrails → RAG → LLM → Executor
          → Audit → Threat Memory) → Dashboard (Streamlit)

KHÁC VỚI offline:
  - Offline = benchmark TẤT ĐỊNH (giữ nguyên `evaluate_unified_stream.py`).
  - Online (file này) = CHỨNG MINH end-to-end + demo realtime; chỉ event đáng ngờ
    được ESCALATE mới gọi LLM (đúng thiết kế SOC).

DÙNG CHUNG nguồn dữ liệu & logic trộn với offline qua `build_stream()` — KHÔNG sinh
thêm/tự bịa: vẫn là data thật từ `ground_truth.json` + `dapt2020_chains.jsonl`.

Chạy (cần Redis online, và `main.py` đang chạy ở terminal khác để xử lý ESCALATE):
    .venv/bin/python experiments/stream_unified_online.py
Kiểm tra logic không cần Redis:
    .venv/bin/python experiments/stream_unified_online.py --dry-run
"""

import argparse
import json
import os
import sys
import time
from collections import Counter

from dotenv import load_dotenv  # type: ignore

load_dotenv()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

from experiments.unified_dataset import build_stream  # noqa: E402

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# Delay mỗi batch (giây) + số sự kiện/batch — giữ demo chạy trong thời gian hợp lý.
BATCH_SIZE = int(os.getenv("UNIFIED_STREAM_BATCH", "50"))
BATCH_DELAY = float(os.getenv("UNIFIED_STREAM_DELAY", "0.3"))
MAX_QUEUE_SIZE = 10_000

# Cùng quy tắc định tuyến đa nguồn với scripts/simulate_traffic.py
FIREWALL_PORTS = {21, 22, 23, 53, 139, 445, 3389}
WAF_PORTS = {80, 443, 8080}


def determine_queue(log: dict) -> str:
    """Port-based → payload/UA → default firewall (khớp simulate_traffic)."""
    try:
        port = int(log.get("Destination Port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if port in FIREWALL_PORTS:
        return "queue_firewall"
    if port in WAF_PORTS:
        return "queue_waf"
    if log.get("payload") or log.get("user_agent"):
        return "queue_waf"
    return "queue_firewall"


def enrich(ev: dict) -> dict:
    """Gắn metadata theo nguồn vào log để subscriber/agent/dashboard dùng được.

    Toàn bộ đi trong MỘT blob JSON dưới field 'log' (đúng giao ước publisher hiện có).
    """
    log = dict(ev["log"])
    log["dataset_source"] = "unified_stream"
    log["unified_source"] = ev["source"]

    if ev["source"] == "dapt":
        # Metadata để subscriber ghi chuỗi APT (emergent) vào Threat Memory.
        log["apt_phase"] = ev.get("phase")
        log["apt_day"] = ev.get("day")
        log["apt_label"] = ev.get("label", "")
        log["apt_is_attack"] = bool(ev.get("is_attack"))
        log["apt_timestamp"] = ev.get("timestamp", "")
    elif ev["source"] == "zeroday":
        log["zd_id"] = ev.get("id")
        log["zd_mitre"] = ev.get("mitre")
        log["zd_name"] = ev.get("name")
    elif ev["source"] == "adversarial":
        # payload OWASP LLM Top-10 để thử Guardrails/Tier-2 khi escalate
        log["adv_id"] = ev["log"].get("gt_id", "")
        log["adv_source"] = "owasp_llm_top10"
    else:  # cicids
        log["gt_label"] = ev.get("label", "")
        log["expected_threat"] = bool(ev.get("expected_threat"))
    return log


def _adversarial_events():
    """120 payload adversarial (OWASP LLM) dưới dạng event luồng gộp. TÁI DÙNG loader
    `_adversarial_logs()` của scripts/push_flow.py (đọc experiments/adversarial/*/samples.json
    + map_to_cicids) — lazy import để tránh vòng import (push_flow import ngược file này)."""
    from scripts.push_flow import _adversarial_logs

    return [{"source": "adversarial", "log": log} for _q, log in _adversarial_logs()]


def build_sequence(include_adversarial: bool = False):
    """Luồng phát: 150 benign warmup TRƯỚC (làm ấm Welford) rồi luồng chính trộn.

    include_adversarial=True: nối thêm 120 payload adversarial vào CUỐI luồng chính để
    1 lệnh đẩy được CICIDS + DAPT + Zero-day + Adversarial (mặc định TẮT để giữ luồng
    phân loại gọn — adversarial là phép thử Guardrails/Tier-2, không phải phân loại flow).
    """
    warmup, main, apt_truth, n_chains = build_stream()
    main = list(main)
    if include_adversarial:
        main = main + _adversarial_events()
    seq = list(warmup) + main  # warmup giữ prefix; main đã sort theo thời gian
    return seq, warmup, main, apt_truth, n_chains


def dry_run(include_adversarial: bool = False):
    """Kiểm tra logic publisher KHÔNG cần Redis: phân bố queue/nguồn + phủ metadata."""
    seq, warmup, main, apt_truth, n_chains = build_sequence(include_adversarial)
    q_counter, src_counter = Counter(), Counter()
    dapt_attack_with_meta = 0
    zd_with_meta = 0
    for ev in seq:
        log = enrich(ev)
        q_counter[determine_queue(log)] += 1
        src_counter[ev["source"]] += 1
        if ev["source"] == "dapt" and log.get("apt_is_attack"):
            if log.get("apt_phase") and log.get("apt_day") is not None:
                dapt_attack_with_meta += 1
        if ev["source"] == "zeroday" and log.get("zd_id") and log.get("zd_mitre"):
            zd_with_meta += 1

    print("=" * 64)
    print("  DRY-RUN: Unified ONLINE publisher (KHÔNG đẩy Redis)")
    print("=" * 64)
    print(f"  Tổng sự kiện phát        : {len(seq)} (warmup {len(warmup)} + main {len(main)})")
    print(f"  Nguồn                    : {dict(src_counter)}")
    print(f"  Định tuyến queue         : {dict(q_counter)}")
    print(f"  DAPT chuỗi / IP-APT thật : {n_chains} / {len(apt_truth)}")
    print(f"  DAPT attack mang apt_meta: {dapt_attack_with_meta}")
    print(f"  Zero-day mang zd_meta    : {zd_with_meta}")
    if include_adversarial:
        print(f"  Adversarial (OWASP LLM)  : {src_counter['adversarial']}")
    # Bất biến tối thiểu để khỏi regress thầm lặng
    assert {"cicids", "dapt", "zeroday"}.issubset(set(src_counter)), "thiếu nguồn"
    assert dapt_attack_with_meta > 0, "DAPT attack không mang metadata APT"
    assert zd_with_meta == src_counter["zeroday"], "zero-day thiếu metadata"
    assert len(apt_truth) >= 1, "không có IP APT thật"
    if include_adversarial:
        assert src_counter["adversarial"] > 0, "bật --include-adversarial nhưng không có mẫu"
    print("  [OK] Bất biến publisher đạt — sẵn sàng đẩy online.")
    return True


def publish(include_adversarial: bool = False):
    import redis  # type: ignore

    print(f"[*] Connecting to Redis: {REDIS_URL}")
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        print("[+] Redis OK.")
    except Exception as e:  # noqa: BLE001
        print(f"[!] Redis không kết nối được: {e}")
        return

    seq, warmup, main, apt_truth, n_chains = build_sequence(include_adversarial)
    print(
        f"[*] Phát {len(seq)} sự kiện (warmup {len(warmup)} + main {len(main)}) "
        f"| DAPT {n_chains} chuỗi, {len(apt_truth)} IP-APT thật"
    )
    print(f"[*] batch={BATCH_SIZE}, delay={BATCH_DELAY}s/batch -> 3 queue (waf/firewall)")

    published = 0
    src_counter = Counter()
    try:
        for i in range(0, len(seq), BATCH_SIZE):
            batch = seq[i : i + BATCH_SIZE]

            # Backpressure: chờ nếu queue đầy (consumer offline/chậm)
            for q in ("queue_waf", "queue_firewall"):
                waited = 0
                while r.xlen(q) > MAX_QUEUE_SIZE:  # type: ignore
                    time.sleep(0.1)
                    waited += 1
                    if waited % 100 == 0:
                        print(
                            f"[!] Backpressure {q}={r.xlen(q)} > {MAX_QUEUE_SIZE}. Consumer chậm?"
                        )

            for ev in batch:
                log = enrich(ev)
                q = determine_queue(log)
                r.xadd(q, {"log": json.dumps(log)}, maxlen=MAX_QUEUE_SIZE, approximate=True)
                published += 1
                src_counter[ev["source"]] += 1

            print(
                f"[>] Batch {i // BATCH_SIZE + 1}: {min(i + BATCH_SIZE, len(seq))}/{len(seq)} "
                f"phát (cicids={src_counter['cicids']} dapt={src_counter['dapt']} "
                f"zeroday={src_counter['zeroday']})"
            )
            time.sleep(BATCH_DELAY)

        print(
            f"[+] Hoàn tất! Đã phát {published} sự kiện lên Redis. "
            f"Theo dõi APT/quyết định ở subscriber (main.py) + Dashboard."
        )
    except KeyboardInterrupt:
        print("\n[*] Dừng bởi người dùng.")
    except Exception as e:  # noqa: BLE001
        print(f"[!] Phát luồng lỗi: {e}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Unified streaming ONLINE publisher")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Chỉ kiểm tra logic (phân bố queue/metadata), KHÔNG đẩy Redis",
    )
    ap.add_argument(
        "--include-adversarial",
        action="store_true",
        help="Nối thêm 120 payload adversarial (OWASP LLM) vào luồng → đẩy TẤT CẢ nguồn 1 lệnh",
    )
    args = ap.parse_args()
    if args.dry_run:
        dry_run(args.include_adversarial)
    else:
        publish(args.include_adversarial)
