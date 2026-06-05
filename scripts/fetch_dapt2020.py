"""
Trình tải và tạo dữ liệu giả lập DAPT2020

NGUỒN DỮ LIỆU:
  - DAPT2020 (Dynamic Adversary Profile Tracking 2020)
  - Chính: Tải từ Kaggle (yêu cầu API key)
  - Dự phòng: Tự sinh dữ liệu chuỗi APT giả lập theo cấu trúc DAPT2020

CHẾ ĐỘ GIẢ LẬP (SYNTHETIC MODE):
  Khi không tải được DAPT2020, tự động tạo chuỗi APT thực tế qua nhiều ngày
  để kiểm định Bộ nhớ Mối đe dọa Dài hạn (Threat Memory) Tier 2.
  Cấu trúc tương đương DAPT2020: 5 ngày, chuỗi tấn công nhiều giai đoạn.
"""

import os
import sys
import random
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

from typing import Any, Dict

# Static analysis tools (VS Code/Pyright) will resolve scripts.dapt2020_config
# Fallback handles direct execution within scripts/ directory
try:
    from scripts.dapt2020_config import (
        APT_PHASES, DAPT_RAW_DIR, DAPT2020_HEADERS,
        normalize_label, normalize_stage
    )
except ImportError:
    from dapt2020_config import (  # type: ignore  # noqa: E402
        APT_PHASES, DAPT_RAW_DIR, DAPT2020_HEADERS,
        normalize_label, normalize_stage
    )


def download_from_kaggle():
    """Thử tải tập dữ liệu DAPT2020 từ Kaggle sử dụng thư viện kagglehub."""
    try:
        import kagglehub
        import pandas as pd
    except ImportError:
        try:
            print("[*] Installing kagglehub...")
            subprocess.run([sys.executable, "-m", "pip", "install", "kagglehub", "pandas", "--quiet"],
                          capture_output=True, check=True)
            import kagglehub
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

        # Ánh xạ các tệp public & private vào các ngày mục tiêu
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

        # Bước 1: Tải một tệp mẫu để lấy tiêu đề cột chuẩn
        print("[*] Downloading header reference file from Kaggle...")
        ref_path = kagglehub.dataset_download("sowmyamyneni/dapt2020", path=day_mapping["day1"]["public"])
        df_ref = pd.read_csv(ref_path, nrows=1)
        headers = df_ref.columns.tolist()

        # Bước 2: Tải, ánh xạ và tiền xử lý dữ liệu từng ngày
        for day_name, files in day_mapping.items():
            dfs = []
            for net_type, remote_path in files.items():
                print(f"[*] Downloading {day_name} {net_type} file...")
                local_path = kagglehub.dataset_download("sowmyamyneni/dapt2020", path=remote_path)
                
                # Kiểm tra xem tệp có chứa tiêu đề cột không
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

                # Chuẩn hóa tiêu đề cột một cách an toàn tránh trùng lặp cột
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

                # Chuẩn hóa kiểu chữ và chuẩn hóa dữ liệu
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
    Tạo các tệp dữ liệu CSV giả lập theo định dạng DAPT2020.
    Tạo 5 tệp ngày với dữ liệu chuỗi tấn công APT thực tế.
    Tất cả dữ liệu được tạo tuân theo schema 85 thuộc tính tiêu chuẩn của DAPT2020.
    """
    import pandas as pd

    print("[*] Generating synthetic DAPT2020 data...")
    os.makedirs(DAPT_RAW_DIR, exist_ok=True)

    random.seed(42)

    # Định nghĩa 20 IP kẻ tấn công duy nhất (kiên trì qua nhiều ngày)
    attacker_ips = [f"192.168.{i//256}.{i%256+50}" for i in range(20)]
    # Định nghĩa 30 IP mục tiêu
    target_ips = [f"10.0.{i//256}.{i%256+1}" for i in range(30)]
    
    # Các nhãn tấn công thực tế trong DAPT2020
    attack_labels_per_day = {
        "day1": ["Normal"],  # Ngày 1 là 100% bình thường/không độc hại
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
        # Mỗi kẻ tấn công tạo ra 30-100 sự kiện mỗi ngày
        for atk_ip in attacker_ips:
            n_events = random.randint(30, 100)
            for j in range(n_events):
                target = random.choice(target_ips)
                label = random.choice(labels)
                ts = base_time + timedelta(seconds=random.randint(0, 36000))
                
                # Nếu nhãn là Normal, Stage là Benign. Ngược lại, sử dụng giai đoạn chuẩn của ngày.
                stage = "Benign" if label == "Normal" else phase

                row_dict: Dict[str, Any] = {col: 0 for col in DAPT2020_HEADERS}
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

        # Thêm 200 sự kiện bình thường (benign)
        for j in range(200):
            ts = base_time + timedelta(seconds=random.randint(0, 36000))
            benign_ip = f"172.16.{random.randint(0,5)}.{random.randint(1,254)}"
            target = random.choice(target_ips)
            
            row_dict: Dict[str, Any] = {col: 0 for col in DAPT2020_HEADERS}
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
        # Đảm bảo thứ tự cột chính xác
        df = df[DAPT2020_HEADERS]
        
        path = os.path.join(DAPT_RAW_DIR, f"{day_name}.csv")
        df.to_csv(path, index=False)
        print(f"  {day_name}.csv: {len(df)} events ({phase})")

    print(f"[+] Synthetic DAPT2020 generated in {DAPT_RAW_DIR}")
    return True


def verify_dapt2020():
    """Xác minh cấu trúc tệp DAPT2020."""
    import pandas as pd

    expected_files = ["day1.csv", "day2.csv", "day3.csv", "day4.csv", "day5.csv"]
    for f in expected_files:
        path = os.path.join(DAPT_RAW_DIR, f)
        if not os.path.exists(path):
            print(f"  [FAIL] Missing: {path}")
            return False
        df = pd.read_csv(path, low_memory=False)
        total = len(df)
        df_sample = df.head(5)
        print(f"  {f}: {total} rows, cols: {list(df_sample.columns)[:5]}")
    return True


if __name__ == "__main__":
    print("[*] DAPT2020 Dataset Setup")
    print("=" * 50)

    # Kiểm tra nếu dữ liệu đã tồn tại
    if os.path.exists(os.path.join(DAPT_RAW_DIR, "day1.csv")):
        print("[*] DAPT2020 already exists. Verifying...")
        if verify_dapt2020():
            print("[+] DAPT2020 data verified!")
            sys.exit(0)

    # Thử tải xuống từ Kaggle
    print("[*] Attempting Kaggle download...")
    if not download_from_kaggle():
        print("[*] Falling back to synthetic generation...")
        generate_synthetic_dapt2020()

    # Xác minh tính đúng đắn
    if verify_dapt2020():
        print("\nPASS: DAPT2020 data ready!")
    else:
        print("\nFAIL: DAPT2020 setup incomplete!")
        sys.exit(1)
