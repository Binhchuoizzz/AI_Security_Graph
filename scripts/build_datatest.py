import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import build_stream, enrich


def main():
    print("[*] Generating unified stream (might take a few seconds)...")
    warmup, main_stream, apt_truth, n_chains = build_stream()
    stream = warmup + main_stream

    # Nhặt ra từ từng bộ để đảm bảo đa dạng
    cicids_attacks = [
        e
        for e in stream
        if e.get("source", "").startswith("cicids") and e.get("expected_threat") is True
    ]
    cicids_benign = [
        e
        for e in stream
        if e.get("source", "").startswith("cicids") and e.get("expected_threat") is False
    ]
    dapt = [e for e in stream if e.get("source", "").startswith("dapt")]
    zeroday = [e for e in stream if e.get("source") == "zeroday"]
    adv = [e for e in stream if e.get("source") == "adversarial"]

    print(
        f"Total available: CICIDS Attacks={len(cicids_attacks)}, CICIDS Benign={len(cicids_benign)}, DAPT={len(dapt)}, ZeroDay={len(zeroday)}, Adversarial={len(adv)}"
    )

    random.seed(42)
    demo = []
    # Mục tiêu 2219 logs
    demo.extend(random.sample(zeroday, len(zeroday)))  # 15
    demo.extend(random.sample(adv, len(adv)))  # 4
    demo.extend(random.sample(dapt, min(200, len(dapt))))  # 200

    # 1000 CICIDS attacks and 1000 CICIDS benign
    demo.extend(random.sample(cicids_attacks, min(1000, len(cicids_attacks))))
    demo.extend(random.sample(cicids_benign, min(1000, len(cicids_benign))))

    # Sort them by their original timestamp key `t` to simulate a timeline
    demo.sort(key=lambda x: x.get("t", 0))

    # Enrich the logs directly so demo.py is extremely simple
    enriched_logs = [enrich(ev) for ev in demo]

    out_file = os.path.join(ROOT, "data", "datatest.json")
    with open(out_file, "w") as f:
        json.dump(enriched_logs, f, indent=2)

    print(f"[+] Successfully saved {len(enriched_logs)} enriched events to {out_file}")


if __name__ == "__main__":
    main()
