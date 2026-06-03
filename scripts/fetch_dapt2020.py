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
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

# Add current directory to path to allow importing dapt2020_config
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from dapt2020_config import (
    APT_PHASES, DAPT_RAW_DIR, DAPT2020_HEADERS,
    normalize_label, normalize_stage
)


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

                # Normalize column headers safely avoiding duplicate columns
                rename_dict = {}
                seen_targets = set()
                for col in df.columns:
                    col_lower = col.lower()
                    if col_lower == "stage" and "Stage" not in seen_targets:
                        rename_dict[col] = "Stage"
                        seen_targets.add("Stage")
                    elif col_lower in ("activity", "label") and "label" not in seen_targets:
                        rename_dict[col] = "label"
                        seen_targets.add("label")
                df = df.rename(columns=rename_dict)

                # Standardize casing & normalize
                if "label" in df.columns:
                    df["label"] = df["label"].apply(normalize_label)
                if "Stage" in df.columns:
                    df["Stage"] = df["Stage"].apply(normalize_stage)
                
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
    All generated data follows the standard 85-feature schema of DAPT2020.
    """
    import pandas as pd

    print("[*] Generating synthetic DAPT2020 data...")
    os.makedirs(DAPT_RAW_DIR, exist_ok=True)

    random.seed(42)

    # Define 20 unique attacker IPs (persistent across days)
    attacker_ips = [f"192.168.{i//256}.{i%256+50}" for i in range(20)]
    # Define 30 target IPs
    target_ips = [f"10.0.{i//256}.{i%256+1}" for i in range(30)]

    # Real DAPT2020 attack labels
    attack_labels_per_day = {
        "day1": ["Normal"],  # Day 1 is 100% normal/benign
        "day2": ["Network Scan", "Account Discovery", "Directory Bruteforce", "Web Vulnerability Scan", "Account Bruteforce"],
        "day3": ["SQL Injection", "Directory Bruteforce", "Account Bruteforce", "Account Discovery", "CSRF", "Malware Download", "Network Scan"],
        "day4": ["Network Scan", "Backdoor", "Account Discovery", "SQL Injection", "Privilege Escalation"],
        "day5": ["Network Scan", "Command Injection", "Data Exfiltration"],
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
                
                # If label is Normal, Stage is Benign. Otherwise, use standard day phase.
                stage = "Benign" if label == "Normal" else phase

                row_dict = {col: 0 for col in DAPT2020_HEADERS}
                row_dict["Flow ID"] = f"{atk_ip}-{target}-{random.randint(1024, 65535)}-{random.choice([22, 80, 443, 445, 3389, 53, 8080])}-{random.choice([6, 17])}"
                row_dict["Src IP"] = atk_ip
                row_dict["Src Port"] = random.randint(1024, 65535)
                row_dict["Dst IP"] = target
                row_dict["Dst Port"] = random.choice([22, 80, 443, 445, 3389, 53, 8080])
                row_dict["Protocol"] = random.choice([6, 17])
                row_dict["Timestamp"] = ts.strftime("%d/%m/%Y %I:%M:%S %p")
                row_dict["Flow Duration"] = random.randint(100, 500000)
                row_dict["Total Fwd Packet"] = random.randint(1, 200)
                row_dict["Total Bwd packets"] = random.randint(0, 150)
                row_dict["label"] = normalize_label(label)
                row_dict["Stage"] = normalize_stage(stage)
                
                rows.append(row_dict)

        # Add 200 benign events
        for j in range(200):
            ts = base_time + timedelta(seconds=random.randint(0, 36000))
            benign_ip = f"172.16.{random.randint(0,5)}.{random.randint(1,254)}"
            target = random.choice(target_ips)
            
            row_dict = {col: 0 for col in DAPT2020_HEADERS}
            row_dict["Flow ID"] = f"{benign_ip}-{target}-{random.randint(1024, 65535)}-{random.choice([80, 443, 8080])}-6"
            row_dict["Src IP"] = benign_ip
            row_dict["Src Port"] = random.randint(1024, 65535)
            row_dict["Dst IP"] = target
            row_dict["Dst Port"] = random.choice([80, 443, 8080])
            row_dict["Protocol"] = 6
            row_dict["Timestamp"] = ts.strftime("%d/%m/%Y %I:%M:%S %p")
            row_dict["Flow Duration"] = random.randint(100, 10000)
            row_dict["Total Fwd Packet"] = random.randint(1, 20)
            row_dict["Total Bwd packets"] = random.randint(1, 20)
            row_dict["label"] = "Normal"
            row_dict["Stage"] = "Benign"
            
            rows.append(row_dict)

        df = pd.DataFrame(rows)
        # Ensure exact column ordering
        df = df[DAPT2020_HEADERS]
        
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
