"""
simulate_traffic.py — Ground Truth Replay & Demo Simulator

MỤC ĐÍCH:
  Script khởi chạy (entrypoint) để phát lại (replay) các mẫu tấn công
  đã gán nhãn từ ground_truth.json lên Redis Streams, phục vụ:
    - Demo giao diện SOC Dashboard trực quan
    - Chạy Ablation Study (đánh giá Tier-1 + Tier-2)
    - Kiểm thử khả năng Guardrails với adversarial payloads

LUỒNG KHÁC PUBLISHER.PY:
  publisher.py      → stream raw CSV (hàng triệu rows, production load test)
  simulate_traffic.py → replay ground_truth.json (750 mẫu, evaluation/demo)

QUAN HỆ:
  Input:  experiments/ground_truth.json  (từ fetch_and_build_dataset.py)
  Output: Redis Streams queue_waf / queue_firewall / queue_sysmon
  Downstream: subscriber.py (xreadgroup) → rule_engine.py → workflow.py
"""

import json
import os
import time
import redis
from dotenv import load_dotenv

load_dotenv()

# ── Cấu hình ─────────────────────────────────────────────────────────────────
REDIS_URL           = os.getenv("REDIS_URL", "redis://localhost:6379/0")
GROUND_TRUTH_FILE   = "experiments/ground_truth.json"
BATCH_SIZE          = int(os.getenv("SIMULATE_BATCH_SIZE", "50"))
BATCH_DELAY_SECONDS = float(os.getenv("SIMULATE_DELAY", "0.5"))
MAX_QUEUE_SIZE      = 10_000


# ── Queue routing ─────────────────────────────────────────────────────────────
def determine_queue(log_entry: dict) -> str:
    """
    Multi-source routing: phân luồng log vào 3 queue để mô phỏng môi trường
    SIEM đa nguồn (WAF / Firewall-IDS / Sysmon-Endpoint).

    Thứ tự ưu tiên: Port-based → Payload/UA → Default firewall.
    Port được ưu tiên hơn payload để tránh SSH+adversarial-payload bị gửi
    nhầm vào queue_waf thay vì queue_firewall.
    """
    port       = int(log_entry.get("Destination Port", 0))
    payload    = log_entry.get("payload", "") or ""
    user_agent = log_entry.get("user_agent", "") or ""

    # Tier 1 — critical service ports (Firewall / IDS sensor)
    if port in [21, 22, 23, 53, 139, 445, 3389]:
        return "queue_firewall"

    # Tier 2 — HTTP/HTTPS ports (WAF sensor)
    if port in [80, 443, 8080]:
        return "queue_waf"

    # Tier 3 — HTTP indicators without recognized port
    if payload or user_agent:
        return "queue_waf"

    # Default — unrecognized / high-volume traffic (DoS/DDoS, scans)
    # NOT sysmon: aggressive traffic without port should hit IDS, not endpoint
    return "queue_firewall"


# ── Key mapping ────────────────────────────────────────────────────────────────
def map_to_cicids(network_layer: dict, app_layer: dict) -> dict:
    """
    Map tất cả fields từ network_layer (ground_truth schema) sang schema
    CIC-IDS2018 mà rule_engine.py expects.
    Giữ nguyên tên key gốc để tránh mất thông tin.
    """
    mapped = {
        # Core routing fields
        "Source IP":          network_layer.get("src_ip", "0.0.0.0"),
        "Destination IP":     network_layer.get("dst_ip", "0.0.0.0"),
        "Source Port":        network_layer.get("src_port", 0),
        "Destination Port":   network_layer.get("dst_port", 0),
        "Protocol":           network_layer.get("protocol", 6),
        "timestamp":          network_layer.get("timestamp", ""),

        # Flow stats (rule engine thresholds)
        "Flow Duration":      network_layer.get("flow_duration_us", 0),
        "Total Fwd Packets":  network_layer.get("fwd_packets", 0),
        "Total Bwd Packets":  network_layer.get("bwd_packets", 0),
        "Total Fwd Bytes":    network_layer.get("fwd_bytes", 0),
        "Total Bwd Bytes":    network_layer.get("bwd_bytes", 0),
        "Flow Pkts/s":        network_layer.get("flow_pkts_s", 0.0),

        # Discriminative features (Z-score baseline)
        "Fwd Seg Size Min":   network_layer.get("fwd_seg_size_min", 0),
        "Init Fwd Win Byts":  network_layer.get("init_fwd_win_byts", 0),
        "Init Bwd Win Byts":  network_layer.get("init_bwd_win_byts", 0),
        "Bwd Pkt Len Min":    network_layer.get("bwd_pkt_len_min", 0),
        "PSH Flag Cnt":       network_layer.get("psh_flag_cnt", 0),
        "service":            network_layer.get("service", ""),

        # Application layer (Guardrails injection)
        "user_agent":         (app_layer or {}).get("user_agent", "") or "",
        "payload":            (app_layer or {}).get("payload_snippet", "") or "",
    }
    return mapped


# ── Main streaming ─────────────────────────────────────────────────────────────
def stream_logs_to_redis() -> None:
    """
    Phát lại (replay) ground_truth.json lên Redis theo batch.
    Mỗi message bao gồm đầy đủ:
      - Network + application layer features
      - Ground truth metadata (gt_id, expected_action, severity, mitre)
      - dataset_source để Tier-2 phân biệt ngữ cảnh
    """
    print(f"[*] Connecting to Redis: {REDIS_URL}")
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        print("[+] Redis connection successful.")
    except Exception as e:
        print(f"[!] Failed to connect to Redis: {e}")
        return

    if not os.path.exists(GROUND_TRUTH_FILE):
        print(f"[!] Ground truth file not found: {GROUND_TRUTH_FILE}")
        return

    with open(GROUND_TRUTH_FILE, "r", encoding="utf-8") as f:
        samples = json.load(f)

    total = len(samples)
    print(f"[*] Loaded {total} samples | batch_size={BATCH_SIZE} | delay={BATCH_DELAY_SECONDS}s/batch")

    total_published = 0
    try:
        for batch_start in range(0, total, BATCH_SIZE):
            batch = samples[batch_start: batch_start + BATCH_SIZE]

            # ── Backpressure: check stream length once per batch ────────────
            wait_count = 0
            for queue_name in ["queue_waf", "queue_firewall", "queue_sysmon"]:
                while r.xlen(queue_name) > MAX_QUEUE_SIZE:  # type: ignore
                    time.sleep(0.1)
                    wait_count += 1
                    if wait_count % 100 == 0:
                        print(
                            f"[!] Backpressure: {queue_name}={r.xlen(queue_name)} "  # type: ignore
                            f"exceeds {MAX_QUEUE_SIZE}. Consumer offline or slow?"
                        )

            # ── Publish batch ──────────────────────────────────────────────
            for sample in batch:
                # Build base log entry
                if "input" in sample:
                    network_layer = sample["input"].get("network_layer", {})
                    app_layer     = sample["input"].get("application_layer", {})
                    mapped_log    = map_to_cicids(network_layer, app_layer)
                elif "logs" in sample and sample["logs"]:
                    # Fallback: adversarial samples that have logs[] not input{}
                    raw = sample["logs"][0]
                    network_layer = raw
                    app_layer = {
                        "payload_snippet": raw.get("payload", ""),
                        "user_agent":      raw.get("user_agent", ""),
                    }
                    mapped_log = map_to_cicids(network_layer, app_layer)
                else:
                    continue

                # ── Ground truth metadata (for E2E correlation) ──────────
                mapped_log["gt_id"]               = sample.get("id", "")
                mapped_log["gt_cicids_label"]      = sample.get("input", {}).get("cicids_label", "")
                mapped_log["gt_expected_action"]   = sample.get("expected_action", "")
                mapped_log["gt_expected_severity"] = sample.get("expected_severity", "")
                mapped_log["gt_expected_mitre"]    = sample.get("expected_mitre_technique", "")
                mapped_log["dataset_source"]       = "ground_truth"

                # ── Route to appropriate stream ───────────────────────────
                target_queue = determine_queue(mapped_log)
                r.xadd(
                    target_queue,
                    {"log": json.dumps(mapped_log)},
                    maxlen=MAX_QUEUE_SIZE,
                    approximate=True,
                )
                total_published += 1

            # ── Batch log + throttle ───────────────────────────────────────
            batch_end = min(batch_start + BATCH_SIZE, total)
            print(
                f"[>] Batch {batch_start // BATCH_SIZE + 1}: "
                f"samples {batch_start + 1}–{batch_end} published "
                f"(total: {total_published}/{total})"
            )
            time.sleep(BATCH_DELAY_SECONDS)

        print(f"[+] Finished! Published {total_published} samples across 3 streams.")

    except KeyboardInterrupt:
        print("\n[*] Stopped by Admin.")
    except Exception as e:
        print(f"[!] Streaming failed: {e}")


if __name__ == "__main__":
    stream_logs_to_redis()
