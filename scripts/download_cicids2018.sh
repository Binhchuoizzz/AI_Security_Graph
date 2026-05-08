#!/bin/bash
# Download CSE-CIC-IDS2018 Dataset from AWS Registry of Open Data

echo "[*] SENTINEL: CSE-CIC-IDS2018 Dataset Downloader"
echo "[!] WARNING: The full dataset is extremely large (~450GB). Ensure you have enough disk space."

DATA_DIR="data/raw/cicids2018_full"
mkdir -p "$DATA_DIR"

echo "[+] Starting download to $DATA_DIR via AWS CLI (no sign-request)..."
# Using --no-sign-request because it is a public bucket in the Registry of Open Data
aws s3 sync --no-sign-request s3://cse-cic-ids2018/ "$DATA_DIR"

echo "[+] Download complete. Files saved to $DATA_DIR."
