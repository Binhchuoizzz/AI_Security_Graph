"""Dựng dataset 1 TRIỆU mẫu CICIDS2018 cho Cổng ML (Tier-1), tỉ lệ 80% attack / 20% benign.

Kế thừa cấu trúc build_100k_dataset.py nhưng:
  - Lấy 800k ATTACK (đa dạng: BruteForce/DoS/DDoS/Web/Infiltration/Botnet) + 200k BENIGN.
  - Dùng CHÍNH XÁC bộ cột đặc trưng của dataset_100k.csv (76 flow-feature CICFlowMeter) để
    model retrain GIỮ NGUYÊN schema -> tương thích MLGateway (pipeline["features"]).
  - Đọc từng file theo chunk + sample ngay -> tiết kiệm RAM (chạy được trên máy 32GB).
  - Dedup (thô CICIDS ~17% trùng) để chống rò rỉ train/test.
  - BỎ Tuesday-20 (báo cáo: lỗi trích xuất nghiêm trọng).
Không xoá/đụng dataset_100k.csv. Output: ml_lab/dataset_1m.csv (cột = 76 feature + Target).
"""

import os

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIC_DIR = os.path.join(ROOT, "data", "raw", "cicids2018")
REF_100K = os.path.join(ROOT, "ml_lab", "dataset_100k.csv")
OUT_FILE = os.path.join(ROOT, "ml_lab", "dataset_1m.csv")

TARGET_ATTACK = 800_000
TARGET_BENIGN = 200_000
PER_FILE_ATTACK_CAP = 250_000  # trần/ngày: đủ cao để pool attack (sau dedup) đạt ~800k mà VẪN
# giữ đa dạng (web-attack days chỉ vài trăm mẫu -> lấy hết; big days: BF/DoS/DDoS/Bot bị cap).
PER_FILE_BENIGN_CAP = 40_000
CHUNK = 250_000
SEED = 42

# Cùng exclude như train_and_compare.py -> feature list KHỚP dataset_100k.
_EXCLUDE = {
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Stage",
    "Label",
    "Target",
}

# Các file ngày (bỏ Tuesday-20 corrupt). Diverse attack families.
_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",  # FTP/SSH BruteForce
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS GoldenEye/Slowloris
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS Hulk/SlowHTTP
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS HOIC/LOIC-UDP
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF/XSS/SQLi (hiếm)
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF/XSS/SQLi (hiếm)
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",  # Infiltration
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",  # Infiltration
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",  # Botnet
]


def _features_from_ref() -> list[str]:
    """76 tên cột feature (theo đúng dataset_100k.csv + quy tắc exclude của train_and_compare)."""
    header = pd.read_csv(REF_100K, nrows=0).columns.tolist()
    return [c for c in header if c not in _EXCLUDE]


def main():
    features = _features_from_ref()
    print(
        f"[*] {len(features)} feature (khớp dataset_100k). Đích: {TARGET_ATTACK} attack / "
        f"{TARGET_BENIGN} benign."
    )

    usecols = features + ["Label"]
    attack_parts: list[pd.DataFrame] = []
    benign_parts: list[pd.DataFrame] = []

    for fname in _FILES:
        path = os.path.join(CIC_DIR, fname)
        if not os.path.exists(path):
            print(f"[!] Thiếu {fname} — bỏ qua.")
            continue
        got_a = got_b = 0
        print(f"[*] Đọc {fname} …", flush=True)
        for chunk in pd.read_csv(
            path, usecols=lambda c: c.strip() in usecols, chunksize=CHUNK, low_memory=False
        ):
            chunk.rename(columns=lambda x: x.strip(), inplace=True)
            # Loại dòng nhiễu tiêu đề (Label == "Label") + thiếu nhãn
            chunk = chunk[chunk["Label"].astype(str).str.strip() != "Label"]
            lbl = chunk["Label"].astype(str).str.strip().str.lower()
            chunk["Target"] = (~lbl.isin(["benign", "normal"])).astype(int)
            feat = chunk[features + ["Target"]].copy()
            for c in features:
                feat[c] = pd.to_numeric(feat[c], errors="coerce")
            feat.replace([np.inf, -np.inf], np.nan, inplace=True)
            feat.dropna(inplace=True)
            feat.drop_duplicates(inplace=True)

            a = feat[feat["Target"] == 1]
            b = feat[feat["Target"] == 0]
            if got_a < PER_FILE_ATTACK_CAP and len(a):
                take = min(len(a), PER_FILE_ATTACK_CAP - got_a)
                attack_parts.append(a.sample(n=take, random_state=SEED) if take < len(a) else a)
                got_a += take
            if got_b < PER_FILE_BENIGN_CAP and len(b):
                take = min(len(b), PER_FILE_BENIGN_CAP - got_b)
                benign_parts.append(b.sample(n=take, random_state=SEED) if take < len(b) else b)
                got_b += take
            if got_a >= PER_FILE_ATTACK_CAP and got_b >= PER_FILE_BENIGN_CAP:
                break
        print(f"    -> attack {got_a} | benign {got_b}", flush=True)

    df_a = pd.concat(attack_parts, ignore_index=True).drop_duplicates()
    df_b = pd.concat(benign_parts, ignore_index=True).drop_duplicates()
    print(f"[*] Pool: attack {len(df_a)} | benign {len(df_b)} (sau dedup)")

    if len(df_a) > TARGET_ATTACK:
        df_a = df_a.sample(n=TARGET_ATTACK, random_state=SEED)
    if len(df_b) > TARGET_BENIGN:
        df_b = df_b.sample(n=TARGET_BENIGN, random_state=SEED)

    df = pd.concat([df_a, df_b], ignore_index=True)
    df = df.sample(frac=1, random_state=SEED).reset_index(drop=True)  # shuffle
    df.to_csv(OUT_FILE, index=False)
    print(
        f"[+] LƯU {OUT_FILE} | shape={df.shape} | "
        f"attack={int(df['Target'].sum())} benign={int((df['Target'] == 0).sum())} "
        f"({df['Target'].mean() * 100:.1f}% attack)"
    )


if __name__ == "__main__":
    main()
