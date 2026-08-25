#!/bin/bash
# Tải bộ dữ liệu CSE-CIC-IDS2018 từ AWS Open Data Registry.
# Trang gốc: https://www.unb.ca/cic/datasets/ids-2018.html
#
# Cần AWS CLI (`pip install awscli`) nhưng KHÔNG cần tài khoản: bucket công khai,
# gọi kèm --no-sign-request. Tải về data/raw/cicids2018/*.csv, tổng khoảng 8GB.

set -e

TARGET_DIR="data/raw/cicids2018"
S3_BUCKET="s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"

echo "============================================"
echo "  CSE-CIC-IDS2018 Dataset Downloader"
echo "============================================"

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "[!] AWS CLI not found."
    echo "    Install with: pip install awscli"
    echo "    Or download manually from: https://www.unb.ca/cic/datasets/ids-2018.html"
    exit 1
fi

# Create target directory
mkdir -p "$TARGET_DIR"

echo "[*] Downloading from: $S3_BUCKET"
echo "[*] Saving to: $TARGET_DIR"
echo "[*] This may take 10-30 minutes depending on your connection..."
echo ""

# Download all CSV files from the processed traffic data folder
aws s3 sync "$S3_BUCKET" "$TARGET_DIR" --no-sign-request

echo ""
echo "[+] Download complete!"
echo "[*] Files downloaded:"
ls -lh "$TARGET_DIR"/*.csv 2>/dev/null || echo "  (No CSV files found)"

echo ""
echo "[*] Next step: Run preprocessing"
echo "    python scripts/fetch_and_build_dataset.py"
