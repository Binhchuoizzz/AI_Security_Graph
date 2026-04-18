import json
import redis
import time
import os
import random

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# QUEUE_NAME is replaced by a routing logic
GROUND_TRUTH_FILE = "experiments/ground_truth.json"
BATCH_DELAY_SECONDS = 0.5  # Simulate processing interval

def map_keys_to_cicids(network_layer, application_layer):
    """
    Map the normalized keys from ground_truth.json back to what Tier 1 RuleEngine expects,
    plus injecting application layer payloads so Guardrails can detect them.
    """
    # Base mapping for RuleEngine
    mapped = {
        "Source IP": network_layer.get("src_ip", "0.0.0.0"),
        "Destination Port": network_layer.get("dst_port", 0),
        "Total Fwd Packets": network_layer.get("fwd_packets", 0),
        "timestamp": network_layer.get("timestamp", ""),
        "Flow Duration": network_layer.get("flow_duration_ms", 0),
        "Label": "Simulated", # Mark as simulated
    }
    
    # Inject Application Layer Data (for Tier 2 Guardrails & LLM)
    if application_layer:
        mapped["user_agent"] = application_layer.get("user_agent", "")
        mapped["payload"] = application_layer.get("payload_snippet", "")
        
    return mapped

def determine_queue(log_entry: dict) -> str:
    """
    Simulate log source routing (SIEM Multi-sensor capability).
    """
    port = int(log_entry.get("Destination Port", 0))
    payload = log_entry.get("payload", "")
    user_agent = log_entry.get("user_agent", "")
    
    # WAF: Port 80/443 or contains HTTP specifics
    if port in [80, 443, 8080] or payload or user_agent:
        return "queue_waf"
        
    # Firewall/IDS: Common attack ports, heavy traffic
    if port in [21, 22, 23, 3389, 445, 139, 53]:
        return "queue_firewall"
        
    # Sysmon/Endpoint: Everything else
    return "queue_sysmon"

def stream_logs_to_redis():
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

    print(f"[*] Loading samples from {GROUND_TRUTH_FILE}...")
    with open(GROUND_TRUTH_FILE, 'r', encoding='utf-8') as f:
        samples = json.load(f)
        
    total_samples = len(samples)
    print(f"[*] Found {total_samples} samples. Throttling ingestion with {BATCH_DELAY_SECONDS}s delay...")
    
    try:
        for index, sample in enumerate(samples):
            if "input" in sample:
                network_layer = sample["input"].get("network_layer", {})
                app_layer = sample["input"].get("application_layer", {})
                mapped_log = map_keys_to_cicids(network_layer, app_layer)
            elif "logs" in sample and len(sample["logs"]) > 0:
                raw = sample["logs"][0]
                mapped_log = {
                    "Source IP": raw.get("src_ip", "0.0.0.0"),
                    "Destination Port": raw.get("port", 80),
                    "Total Fwd Packets": 100, 
                    "user_agent": raw.get("user_agent", ""),
                    "payload": raw.get("payload", "")
                }
            else:
                continue
                
            # XÁC ĐỊNH NGUỒN LOG (MULTI-SOURCE ROUTING)
            target_queue = determine_queue(mapped_log)

            r.rpush(target_queue, json.dumps(mapped_log))
            print(f"[>] Published sample {index+1}/{total_samples} (ID: {sample['id']}) -> Queue: {target_queue}")
            
            time.sleep(BATCH_DELAY_SECONDS)
            
        print("[+] Finished streaming all samples!")
                
    except KeyboardInterrupt:
        print("\n[*] Stopped manually by Admin.")
    except Exception as e:
        print(f"[!] Streaming failed: {e}")

if __name__ == "__main__":
    stream_logs_to_redis()
