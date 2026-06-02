"""
DAPT2020 Dataset Fetcher & Synthetic Generator

NGUỒN DỮ LIỆU:
  - DAPT2020 (Dynamic Adversary Profile Tracking 2020)
  - Primary: Kaggle download (requires API key)
  - Fallback: Generate synthetic APT chain data matching DAPT2020 structure

SYNTHETIC MODE:
  When DAPT2020 cannot be downloaded, generates realistic multi-day APT
  sequences for validating Tier 2 Long-Term Threat Memory.
  Structure matches DAPT2020: 5 days, multi-phase attack chains.
"""

import os
import sys
import json
import random
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

# DAPT2020 APT phases per day
APT_PHASES = {
    "day1": "Reconnaissance",
    "day2": "Initial_Compromise",
    "day3": "Lateral_Movement",
    "day4": "Data_Exfiltration",
    "day5": "C2_Communication",
}

DAPT_RAW_DIR = "data/raw/dapt2020/"


def download_from_kaggle():
    """Attempt to download DAPT2020 from Kaggle using kagglehub."""
    try:
        import kagglehub
        import shutil
        import pandas as pd
    except ImportError:
        try:
            print("[*] Installing kagglehub...")
            subprocess.run([sys.executable, "-m", "pip", "install", "kagglehub", "pandas", "--quiet"],
                          capture_output=True, check=True)
            import kagglehub
            import shutil
            import pandas as pd
        except Exception as e:
            print(f"[!] Failed to install dependencies: {e}")
            return False

    kaggle_json = os.path.expanduser("~/.kaggle/kaggle.json")
    kaggle_token = os.path.expanduser("~/.kaggle/access_token")
    if not os.path.exists(kaggle_json) and not os.path.exists(kaggle_token) and "KAGGLE_API_TOKEN" not in os.environ:
        print("[!] Kaggle API key not found at ~/.kaggle/kaggle.json or ~/.kaggle/access_token")
        print("    ACTION REQUIRED:")
        print("    1. Go to: https://www.kaggle.com/datasets/sowmyamyneni/dapt2020")
        print("    2. Make sure you have Kaggle API token configured.")
        return False

    try:
        os.makedirs(DAPT_RAW_DIR, exist_ok=True)
        raw_dir = Path(DAPT_RAW_DIR)

        # Map public & private files to target days
        day_mapping = {
            "day1": {
                "public": "csv/enp0s3-monday.pcap_Flow.csv",
                "pvt": "csv/enp0s3-monday-pvt.pcap_Flow.csv"
            },
            "day2": {
                "public": "csv/enp0s3-public-tuesday.pcap_Flow.csv",
                "pvt": "csv/enp0s3-pvt-tuesday.pcap_Flow.csv"
            },
            "day3": {
                "public": "csv/enp0s3-public-wednesday.pcap_Flow.csv",
                "pvt": "csv/enp0s3-pvt-wednesday.pcap_Flow.csv"
            },
            "day4": {
                "public": "csv/enp0s3-public-thursday.pcap_Flow.csv",
                "pvt": "csv/enp0s3-pvt-thursday.pcap_Flow.csv"
            },
            "day5": {
                "public": "csv/enp0s3-tcpdump-friday.pcap_Flow.csv",
                "pvt": "csv/enp0s3-tcpdump-pvt-friday.pcap_Flow.csv"
            }
        }

        # Step 1: Download one file to get standard headers
        print("[*] Downloading header reference file from Kaggle...")
        ref_path = kagglehub.dataset_download("sowmyamyneni/dapt2020", path=day_mapping["day1"]["public"])
        df_ref = pd.read_csv(ref_path, nrows=1)
        headers = df_ref.columns.tolist()

        # Step 2: Download, map, and preprocess each day
        for day_name, files in day_mapping.items():
            dfs = []
            for net_type, remote_path in files.items():
                print(f"[*] Downloading {day_name} {net_type} file...")
                local_path = kagglehub.dataset_download("sowmyamyneni/dapt2020", path=remote_path)
                
                # Check for header
                with open(local_path, "r", encoding="utf-8") as f:
                    first_line = f.readline()
                
                has_header = "Flow ID" in first_line or "Src IP" in first_line
                if has_header:
                    df = pd.read_csv(local_path, low_memory=False)
                else:
                    print(f"    [INFO] Applying standard headers to {remote_path}")
                    df = pd.read_csv(local_path, header=None, low_memory=False)
                    df.columns = headers

                df.columns = df.columns.str.strip()

                # Normalize the label column name to 'label'
                label_col = None
                for col in ["Activity", "Stage", "Label"]:
                    if col in df.columns:
                        label_col = col
                        break
                
                if label_col:
                    df = df.rename(columns={label_col: "label"})
                
                dfs.append(df)

            if dfs:
                combined_df = pd.concat(dfs, ignore_index=True)
                output_path = raw_dir / f"{day_name}.csv"
                combined_df.to_csv(output_path, index=False)
                print(f"[+] Saved merged {day_name}.csv ({len(combined_df)} rows)")

        print("[+] DAPT2020 downloaded and preprocessed successfully!")
        return True
    except Exception as e:
        print(f"[!] Kaggle download failed: {e}")
        return False


def generate_synthetic_dapt2020():
    """
    Generate synthetic DAPT2020-style CSV files.
    Creates 5 day files with realistic APT attack chain data.

    Each file contains:
      - src_ip, dst_ip, src_port, dst_port, protocol
      - timestamp, flow_duration, fwd_packets, bwd_packets
      - label (attack type per day)
    """
    import pandas as pd

    print("[*] Generating synthetic DAPT2020 data...")
    os.makedirs(DAPT_RAW_DIR, exist_ok=True)

    random.seed(42)

    # Define 20 unique attacker IPs (persistent across days)
    attacker_ips = [f"192.168.{i//256}.{i%256+50}" for i in range(20)]
    # Define 30 target IPs
    target_ips = [f"10.0.{i//256}.{i%256+1}" for i in range(30)]

    attack_labels_per_day = {
        "day1": ["Port_Scan", "DNS_Enum", "Service_Discovery"],
        "day2": ["Phishing", "Exploit_Web", "Brute_Force_SSH"],
        "day3": ["Pass_The_Hash", "RDP_Lateral", "SMB_Relay"],
        "day4": ["Large_Upload", "DNS_Tunnel", "HTTP_Exfil"],
        "day5": ["C2_Beacon", "C2_DNS", "Reverse_Shell"],
    }

    for day_name, phase in APT_PHASES.items():
        day_num = int(day_name[-1])
        base_time = datetime(2020, 3, 10 + day_num, 8, 0, 0)
        labels = attack_labels_per_day[day_name]

        rows = []
        # Each attacker generates 30-100 events per day
        for atk_ip in attacker_ips:
            n_events = random.randint(30, 100)
            for j in range(n_events):
                target = random.choice(target_ips)
                label = random.choice(labels)
                ts = base_time + timedelta(seconds=random.randint(0, 36000))

                rows.append({
                    "src_ip": atk_ip,
                    "dst_ip": target,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice([22, 80, 443, 445, 3389, 53, 8080]),
                    "protocol": random.choice([6, 17]),  # TCP or UDP
                    "timestamp": ts.isoformat(),
                    "flow_duration": random.randint(100, 500000),
                    "fwd_packets": random.randint(1, 200),
                    "bwd_packets": random.randint(0, 150),
                    "label": label,
                })

        # Add 200 benign events
        for j in range(200):
            ts = base_time + timedelta(seconds=random.randint(0, 36000))
            rows.append({
                "src_ip": f"172.16.{random.randint(0,5)}.{random.randint(1,254)}",
                "dst_ip": random.choice(target_ips),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 8080]),
                "protocol": 6,
                "timestamp": ts.isoformat(),
                "flow_duration": random.randint(100, 10000),
                "fwd_packets": random.randint(1, 20),
                "bwd_packets": random.randint(1, 20),
                "label": "Benign",
            })

        df = pd.DataFrame(rows)
        path = os.path.join(DAPT_RAW_DIR, f"{day_name}.csv")
        df.to_csv(path, index=False)
        print(f"  {day_name}.csv: {len(df)} events ({phase})")

    print(f"[+] Synthetic DAPT2020 generated in {DAPT_RAW_DIR}")
    return True


def verify_dapt2020():
    """Verify DAPT2020 file structure."""
    import pandas as pd

    expected_files = ["day1.csv", "day2.csv", "day3.csv", "day4.csv", "day5.csv"]
    for f in expected_files:
        path = os.path.join(DAPT_RAW_DIR, f)
        if not os.path.exists(path):
            print(f"  [FAIL] Missing: {path}")
            return False
        df = pd.read_csv(path, nrows=5)
        total = len(pd.read_csv(path))
        print(f"  {f}: {total} rows, cols: {list(df.columns)[:5]}")
    return True


if __name__ == "__main__":
    print("[*] DAPT2020 Dataset Setup")
    print("=" * 50)

    # Check if already exists
    if os.path.exists(os.path.join(DAPT_RAW_DIR, "day1.csv")):
        print("[*] DAPT2020 already exists. Verifying...")
        if verify_dapt2020():
            print("[+] DAPT2020 data verified!")
            sys.exit(0)

    # Try Kaggle download
    print("[*] Attempting Kaggle download...")
    if not download_from_kaggle():
        print("[*] Falling back to synthetic generation...")
        generate_synthetic_dapt2020()

    # Verify
    if verify_dapt2020():
        print("\nPASS: DAPT2020 data ready!")
    else:
        print("\nFAIL: DAPT2020 setup incomplete!")
        sys.exit(1)
