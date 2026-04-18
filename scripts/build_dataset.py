import pandas as pd
import json
import random

LABEL_MAP = {
    "SSH-Patator":        {"mitre": "T1110", "sub": "T1110.001", "action": "BLOCK_IP",    "severity": "HIGH"},
    "FTP-Patator":        {"mitre": "T1110", "sub": "T1110.001", "action": "BLOCK_IP",    "severity": "HIGH"},
    "DoS Hulk":           {"mitre": "T1499", "sub": "T1499.002", "action": "ALERT",       "severity": "HIGH"},
    "DoS GoldenEye":      {"mitre": "T1499", "sub": "T1499.002", "action": "ALERT",       "severity": "HIGH"},
    "DoS slowloris":      {"mitre": "T1499", "sub": "T1499.001", "action": "ALERT",       "severity": "MEDIUM"},
    "Heartbleed":         {"mitre": "T1203", "sub": None,        "action": "BLOCK_IP",    "severity": "CRITICAL"},
    "Web Attack - XSS":   {"mitre": "T1059", "sub": "T1059.007","action": "ALERT",        "severity": "MEDIUM"},
    "Web Attack - Sql Injection": {"mitre": "T1190", "sub": None,"action": "ALERT",       "severity": "HIGH"},
    "Web Attack - Brute Force":   {"mitre": "T1110", "sub": None,"action": "BLOCK_IP",    "severity": "HIGH"},
    "PortScan":           {"mitre": "T1046", "sub": None,        "action": "LOG",         "severity": "LOW"},
    "Bot":                {"mitre": "T1071", "sub": None,        "action": "ALERT",       "severity": "HIGH"},
    "Infiltration":       {"mitre": "T1078", "sub": None,        "action": "AWAIT_HITL",  "severity": "CRITICAL"},
    "BENIGN":             {"mitre": None,    "sub": None,        "action": "LOG",         "severity": "INFO"},
}

FEATURE_COLS = [
    " Source IP", " Destination IP", " Source Port", " Destination Port",
    " Protocol", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    " Total Length of Fwd Packets", " Total Length of Bwd Packets", " Label"
]

def build_ground_truth(csv_path: str, n_per_label: int = 10, output_path: str = "experiments/ground_truth.json"):
    df = pd.read_csv(csv_path, usecols=FEATURE_COLS, low_memory=False)
    df.columns = df.columns.str.strip()
    
    samples = []
    gt_counter = 1
    
    for label, mapping in LABEL_MAP.items():
        subset = df[df["Label"] == label]
        if len(subset) == 0:
            print(f"[WARN] Label '{label}' not found in CSV")
            continue
        
        chosen = subset.sample(min(n_per_label, len(subset)), random_state=42)
        
        for _, row in chosen.iterrows():
            sample = {
                "gt_id": f"GT-{gt_counter:03d}",
                "description": f"{label} attack sample from CICIDS2017",
                "input": {
                    "network_layer": {
                        "src_ip": str(row.get("Source IP", "0.0.0.0")),
                        "dst_ip": str(row.get("Destination IP", "0.0.0.0")),
                        "src_port": int(row.get("Source Port", 0)),
                        "dst_port": int(row.get("Destination Port", 0)),
                        "protocol": int(row.get("Protocol", 6)),
                        "flow_duration_ms": int(row.get("Flow Duration", 0)),
                        "fwd_packets": int(row.get("Total Fwd Packets", 0)),
                        "bwd_packets": int(row.get("Total Backward Packets", 0)),
                        "fwd_bytes": int(row.get("Total Length of Fwd Packets", 0)),
                        "bwd_bytes": int(row.get("Total Length of Bwd Packets", 0)),
                    },
                    "application_layer": {
                        "service": _infer_service(int(row.get("Destination Port", 0))),
                        "payload_snippet": None,
                        "user_agent": None,
                    },
                    "cicids_label": label
                },
                "expected": {
                    "mitre_technique": mapping["mitre"],
                    "mitre_subtechnique": mapping["sub"],
                    "action": mapping["action"],
                    "severity": mapping["severity"],
                },
                "labeling_notes": f"Auto-mapped from CICIDS2017 label '{label}'. VERIFY before use."
            }
            samples.append(sample)
            gt_counter += 1
    
    with open(output_path, "w") as f:
        json.dump(samples, f, indent=2)
    
    print(f"[OK] Generated {len(samples)} samples → {output_path}")
    _print_distribution(samples)

def _infer_service(port: int) -> str:
    return {22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}.get(port, f"PORT_{port}")

def _print_distribution(samples):
    from collections import Counter
    dist = Counter(s["input"]["cicids_label"] for s in samples)
    print("\nLabel distribution:")
    for label, count in dist.most_common():
        print(f"  {label}: {count}")

if __name__ == "__main__":
    import sys
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/cicids2017.csv"
    build_ground_truth(csv_path, n_per_label=10)
