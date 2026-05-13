"""
CSE-CIC-IDS2018 Dataset Fetcher & Ground Truth Builder

NGUỒN DỮ LIỆU:
  - CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)
  - Tải từ AWS S3: s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/
  - Hoặc từ HuggingFace mirror: auliraff/CIC-IDS-Collection

CHIẾN LƯỢC:
  1. Ưu tiên tải từ AWS S3 (nguồn chính thức, đầy đủ CSV)
  2. Fallback sang HuggingFace nếu AWS CLI không khả dụng
  3. Stratified Sampling: Lấy N mẫu/nhãn với random_state=42 (Reproducible)
  4. Output: experiments/ground_truth.json (Tập đề thi chuẩn cho Ablation Study)
"""

import os
import pandas as pd
import json
import subprocess
import glob

# ============================================================================
# LABEL MAP: CSE-CIC-IDS2018 Attack Types → MITRE ATT&CK + Expected Actions
# ============================================================================
LABEL_MAP = {
    "SSH-Bruteforce": {
        "mitre": "T1110",
        "sub": "T1110.001",
        "action": "BLOCK_IP",
        "severity": "HIGH",
    },
    "FTP-BruteForce": {
        "mitre": "T1110",
        "sub": "T1110.001",
        "action": "BLOCK_IP",
        "severity": "HIGH",
    },
    "DoS attacks-Hulk": {
        "mitre": "T1499",
        "sub": "T1499.002",
        "action": "ALERT",
        "severity": "HIGH",
    },
    "DoS attacks-GoldenEye": {
        "mitre": "T1499",
        "sub": "T1499.002",
        "action": "ALERT",
        "severity": "HIGH",
    },
    "DoS attacks-Slowloris": {
        "mitre": "T1499",
        "sub": "T1499.001",
        "action": "ALERT",
        "severity": "MEDIUM",
    },
    "DoS attacks-SlowHTTPTest": {
        "mitre": "T1499",
        "sub": "T1499.001",
        "action": "ALERT",
        "severity": "MEDIUM",
    },
    "DDOS attack-HOIC": {
        "mitre": "T1499",
        "sub": "T1499.002",
        "action": "ALERT",
        "severity": "HIGH",
    },
    "DDOS attack-LOIC-UDP": {
        "mitre": "T1499",
        "sub": "T1499.002",
        "action": "ALERT",
        "severity": "HIGH",
    },
    "Brute Force -Web": {
        "mitre": "T1110",
        "sub": None,
        "action": "BLOCK_IP",
        "severity": "HIGH",
    },
    "Brute Force -XSS": {
        "mitre": "T1059",
        "sub": "T1059.007",
        "action": "ALERT",
        "severity": "MEDIUM",
    },
    "SQL Injection": {
        "mitre": "T1190",
        "sub": None,
        "action": "ALERT",
        "severity": "HIGH",
    },
    "Infilteration": {
        "mitre": "T1078",
        "sub": None,
        "action": "AWAIT_HITL",
        "severity": "CRITICAL",
    },
    "Bot": {
        "mitre": "T1071",
        "sub": None,
        "action": "ALERT",
        "severity": "HIGH",
    },
    "Benign": {
        "mitre": None,
        "sub": None,
        "action": "LOG",
        "severity": "INFO",
    },
}

# CIC-IDS2018 columns of interest
FEATURE_COLS = [
    "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label",
]

# AWS S3 Bucket (CIC-IDS2018 official source)
S3_BUCKET = "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
LOCAL_RAW_DIR = "data/raw/cicids2018/"

# CSV files in the S3 bucket (CIC-IDS2018 naming convention)
CSV_FILES_2018 = [
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
]


def _infer_service(port: int) -> str:
    return {22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}.get(
        port, f"PORT_{port}"
    )


def download_from_aws():
    """Download CSE-CIC-IDS2018 CSV files from AWS S3."""
    os.makedirs(LOCAL_RAW_DIR, exist_ok=True)

    # Check if AWS CLI is available
    try:
        subprocess.run(["aws", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[!] AWS CLI not found. Install with: pip install awscli")
        print("    Or download dataset manually from: https://www.unb.ca/cic/datasets/ids-2018.html")
        return False

    print(f"[*] Downloading CSE-CIC-IDS2018 from AWS S3...")
    print(f"    Source: {S3_BUCKET}")
    print(f"    Target: {LOCAL_RAW_DIR}")

    try:
        cmd = [
            "aws", "s3", "sync", S3_BUCKET, LOCAL_RAW_DIR,
            "--no-sign-request",
            "--exclude", "*",
        ]
        # Include only CSV files we need
        for csv_file in CSV_FILES_2018:
            cmd.extend(["--include", csv_file])

        subprocess.run(cmd, check=True)
        print("[+] Download complete!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] AWS S3 download failed: {e}")
        return False


def fetch_and_build(
    n_per_label: int = 10, output_path: str = "experiments/ground_truth.json"
):
    """
    Load CSE-CIC-IDS2018 CSV files, perform stratified sampling,
    and build ground truth JSON for ablation study.
    """
    print("[*] Bắt đầu xử lý dataset CSE-CIC-IDS2018...")

    # Step 1: Locate CSV files
    csv_files = glob.glob(os.path.join(LOCAL_RAW_DIR, "*.csv"))
    if not csv_files:
        print(f"[!] No CSV files found in {LOCAL_RAW_DIR}")
        print("    Attempting download from AWS S3...")
        if not download_from_aws():
            print("[!] Could not download. Please download CSE-CIC-IDS2018 manually.")
            return
        csv_files = glob.glob(os.path.join(LOCAL_RAW_DIR, "*.csv"))

    all_data = []

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        print(f"  -> Đọc {filename}...")
        try:
            df = pd.read_csv(
                filepath,
                low_memory=False,
                encoding="utf-8",
                on_bad_lines="skip",
            )
            df.columns = df.columns.str.strip()

            # Filter only columns we care about (flexible column matching)
            available_cols = [c for c in FEATURE_COLS if c in df.columns]
            if "Label" not in df.columns:
                print(f"     [WARN] No 'Label' column in {filename}, skipping.")
                continue
            df_filtered = df[available_cols].copy()

            # Normalize label strings
            df_filtered["Label"] = df_filtered["Label"].str.strip()

            # Only keep labels in our LABEL_MAP
            valid_labels = list(LABEL_MAP.keys())
            df_filtered = df_filtered[df_filtered["Label"].isin(valid_labels)]
            all_data.append(df_filtered)
            print(f"     Tìm thấy {len(df_filtered)} mẫu thuộc danh sách cần tìm.")
        except Exception as e:
            print(f"[!] Lỗi khi xử lý file {filename}: {e}")

    if not all_data:
        print("[!] Không có dữ liệu nào được trích xuất!")
        return

    combined_df = pd.concat(all_data, ignore_index=True)
    print(f"[*] Đã gộp thành công. Tổng số mẫu sau lọc: {len(combined_df)}")

    # Step 2: Stratified Sampling (random_state=42 for REPRODUCIBILITY)
    samples = []
    gt_counter = 1

    for label, mapping in LABEL_MAP.items():
        subset = combined_df[combined_df["Label"] == label]
        if len(subset) == 0:
            print(f"[WARN] Label '{label}' không tìm thấy trong bộ dữ liệu.")
            continue

        chosen = subset.sample(min(n_per_label, len(subset)), random_state=42)

        for idx, (_, row) in enumerate(chosen.iterrows()):
            # CIC-IDS2018 processed CSVs don't have Src IP/Dst IP
            # Generate deterministic mock IPs for Tier 1 compatibility
            src_ip = str(row.get("Src IP", f"10.{(gt_counter // 256) % 256}.{gt_counter % 256}.{(idx+1) % 256}"))
            dst_ip = str(row.get("Dst IP", f"192.168.1.{(gt_counter + idx) % 256}"))
            src_port = int(row.get("Src Port", 0)) if pd.notna(row.get("Src Port")) else 0
            dst_port = int(row.get("Dst Port", 0)) if pd.notna(row.get("Dst Port")) else 0

            sample = {
                "id": f"GT-{gt_counter:03d}",
                "description": f"{label} attack sample from CSE-CIC-IDS2018",
                "logs": [
                    {
                        "timestamp": "2018-02-14T10:00:00Z",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": int(row.get("Protocol", 6)) if pd.notna(row.get("Protocol")) else 6,
                        "flow_duration_ms": int(row.get("Flow Duration", 0)) if pd.notna(row.get("Flow Duration")) else 0,
                        "fwd_packets": int(row.get("Tot Fwd Pkts", 0)) if pd.notna(row.get("Tot Fwd Pkts")) else 0,
                        "bwd_packets": int(row.get("Tot Bwd Pkts", 0)) if pd.notna(row.get("Tot Bwd Pkts")) else 0,
                        "fwd_bytes": int(row.get("TotLen Fwd Pkts", 0)) if pd.notna(row.get("TotLen Fwd Pkts")) else 0,
                        "bwd_bytes": int(row.get("TotLen Bwd Pkts", 0)) if pd.notna(row.get("TotLen Bwd Pkts")) else 0,
                        "service": _infer_service(dst_port),
                    }
                ],
                "expected_mitre_technique": (
                    mapping["sub"] if mapping["sub"] else mapping["mitre"]
                ),
                "expected_action": mapping["action"],
            }
            # Add raw network layer for simulate_traffic.py compatibility
            sample["input"] = {
                "network_layer": sample["logs"][0].copy(),
                "application_layer": {
                    "service": _infer_service(dst_port),
                    "payload_snippet": None,
                    "user_agent": None,
                },
                "cicids_label": label,
            }
            samples.append(sample)
            gt_counter += 1

    # Add Adversarial sample for Guardrails testing
    samples.append(
        {
            "id": f"GT-{gt_counter:03d}",
            "description": "SQL Injection in User-Agent with Zero-width joiner (Evasion Attempt - Adversarial)",
            "logs": [
                {
                    "timestamp": "2018-02-14T10:05:00Z",
                    "src_ip": "192.168.1.100",
                    "payload": "SELECT * FROM users WHERE id=1",
                    "user_agent": "Mozilla/5.0 <script>alert(1)</script> \u200d",
                }
            ],
            "expected_mitre_technique": "T1190",
            "expected_action": "ALERT",
        }
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Đã generate {len(samples)} samples ra file {output_path}")

    from collections import Counter
    dist = Counter(
        s.get("input", {}).get("cicids_label", "Adversarial") for s in samples
    )
    print("\nPhân bổ nhãn (Label distribution):")
    for label, count in dist.most_common():
        print(f"  {label}: {count}")


if __name__ == "__main__":
    fetch_and_build(n_per_label=10)
