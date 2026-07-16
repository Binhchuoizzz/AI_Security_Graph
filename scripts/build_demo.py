import os
import sys
import json
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

from experiments.unified_dataset import build_stream

def enrich(ev: dict) -> dict:
    log = dict(ev["log"])
    log["dataset_source"] = "unified_stream"
    log["unified_source"] = ev["source"]

    if ev["source"].startswith("dapt"):
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
        log["adv_id"] = ev["log"].get("gt_id", "")
        log["adv_source"] = "owasp_llm_top10"
    else:  # cicids
        log["gt_label"] = ev.get("label", "")
        log["expected_threat"] = bool(ev.get("expected_threat"))
    return log

def main():
    print("[*] Generating 10k unified stream for DEMO...")
    warmup, main_stream, apt_truth, n_chains = build_stream()
    stream = warmup + main_stream
    
    cicids_attacks = [e for e in stream if e.get("source", "").startswith("cicids") and e.get("expected_threat") == True]
    cicids_benign = [e for e in stream if e.get("source", "").startswith("cicids") and e.get("expected_threat") == False]
    dapt = [e for e in stream if e.get("source", "").startswith("dapt")]
    zeroday = [e for e in stream if e.get("source") == "zeroday"]
    adv = [e for e in stream if e.get("source") == "adversarial"]
    
    random.seed(42)
    demo = []
    
    # Mục tiêu ~10,000 logs
    # Có sẵn 15 ZeroDay và 4 Adversarial (lấy tất cả)
    demo.extend(random.sample(zeroday, len(zeroday))) # 15
    demo.extend(random.sample(adv, len(adv))) # 4
    
    # Lấy toàn bộ 402 mẫu DAPT để chuỗi tấn công hoàn chỉnh nhất
    demo.extend(random.sample(dapt, len(dapt))) # 402
    
    # Khoảng 2000 mẫu tấn công CICIDS (20% tổng số lượng)
    n_cicids_attacks = min(2000, len(cicids_attacks))
    demo.extend(random.sample(cicids_attacks, n_cicids_attacks))
    
    # Bù phần còn lại bằng CICIDS Benign cho đủ 10000
    remaining = 10000 - len(zeroday) - len(adv) - len(dapt) - n_cicids_attacks
    demo.extend(random.sample(cicids_benign, min(remaining, len(cicids_benign))))
    
    # Sort them by their original timestamp key `t` to simulate a timeline
    demo.sort(key=lambda x: x.get("t", 0))
    
    # Enrich the logs directly so demo.py is extremely simple
    enriched_logs = [enrich(ev) for ev in demo]
    
    out_file = os.path.join(ROOT, "data", "demo_10k.json")
    with open(out_file, "w") as f:
        json.dump(enriched_logs, f, indent=2)
        
    print(f"[+] Successfully saved {len(enriched_logs)} enriched events to {out_file}")

if __name__ == "__main__":
    main()
