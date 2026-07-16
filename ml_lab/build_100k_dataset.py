import os

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(ROOT, "data", "raw")
OUT_FILE = os.path.join(ROOT, "ml_lab", "dataset_100k.csv")


def map_dapt_to_cicids(df):
    """Map DAPT2020 column names to CICIDS2018 column names."""
    mapping = {
        "Total Fwd Packet": "Tot Fwd Pkts",
        "Total Bwd packets": "Tot Bwd Pkts",
        "Total Length of Fwd Packet": "TotLen Fwd Pkts",
        "Total Length of Bwd Packet": "TotLen Bwd Pkts",
        "Fwd Packet Length Max": "Fwd Pkt Len Max",
        "Fwd Packet Length Min": "Fwd Pkt Len Min",
        "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
        "Fwd Packet Length Std": "Fwd Pkt Len Std",
        "Bwd Packet Length Max": "Bwd Pkt Len Max",
        "Bwd Packet Length Min": "Bwd Pkt Len Min",
        "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
        "Bwd Packet Length Std": "Bwd Pkt Len Std",
        "Flow Bytes/s": "Flow Byts/s",
        "Flow Packets/s": "Flow Pkts/s",
        "Fwd IAT Total": "Fwd IAT Tot",
        "Bwd IAT Total": "Bwd IAT Tot",
        "Fwd Header Length": "Fwd Header Len",
        "Bwd Header Length": "Bwd Header Len",
        "Packet Length Min": "Pkt Len Min",
        "Packet Length Max": "Pkt Len Max",
        "Packet Length Mean": "Pkt Len Mean",
        "Packet Length Std": "Pkt Len Std",
        "Packet Length Variance": "Pkt Len Var",
        "FIN Flag Count": "FIN Flag Cnt",
        "SYN Flag Count": "SYN Flag Cnt",
        "RST Flag Count": "RST Flag Cnt",
        "PSH Flag Count": "PSH Flag Cnt",
        "ACK Flag Count": "ACK Flag Cnt",
        "URG Flag Count": "URG Flag Cnt",
        "CWR Flag Count": "CWE Flag Count",
        "ECE Flag Count": "ECE Flag Cnt",
        "Average Packet Size": "Pkt Size Avg",
        "Fwd Segment Size Avg": "Fwd Seg Size Avg",
        "Bwd Segment Size Avg": "Bwd Seg Size Avg",
        "Fwd Bytes/Bulk Avg": "Fwd Byts/b Avg",
        "Fwd Packet/Bulk Avg": "Fwd Pkts/b Avg",
        "Fwd Bulk Rate Avg": "Fwd Blk Rate Avg",
        "Bwd Bytes/Bulk Avg": "Bwd Byts/b Avg",
        "Bwd Packet/Bulk Avg": "Bwd Pkts/b Avg",
        "Bwd Bulk Rate Avg": "Bwd Blk Rate Avg",
        "Subflow Fwd Packets": "Subflow Fwd Pkts",
        "Subflow Fwd Bytes": "Subflow Fwd Byts",
        "Subflow Bwd Packets": "Subflow Bwd Pkts",
        "Subflow Bwd Bytes": "Subflow Bwd Byts",
        "FWD Init Win Bytes": "Init Fwd Win Byts",
        "Bwd Init Win Bytes": "Init Bwd Win Byts",
        "label": "Label",
    }
    return df.rename(columns=mapping)


def main():
    print("[*] Building 100k Dataset for ML Lab...")

    # 1. Load CICIDS2018 (80k rows)
    cic_path = os.path.join(
        RAW_DIR, "cicids2018", "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    )
    print(f"[*] Reading {cic_path}...")
    df_cic = pd.read_csv(cic_path, nrows=80000, low_memory=False)

    # Clean column names (strip whitespace)
    df_cic.rename(columns=lambda x: x.strip(), inplace=True)

    # Drop rows with NaN or Infinity
    df_cic.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_cic.dropna(inplace=True)

    # Convert 'Label' to target (1 = Attack, 0 = Benign)
    df_cic["Target"] = df_cic["Label"].apply(lambda x: 0 if x.strip().lower() == "benign" else 1)

    # 2. Load DAPT2020 (15k rows)
    dapt_path = os.path.join(RAW_DIR, "dapt2020", "day1.csv")
    print(f"[*] Reading {dapt_path}...")
    df_dapt = pd.read_csv(dapt_path, nrows=15000, low_memory=False)
    df_dapt.rename(columns=lambda x: x.strip(), inplace=True)
    df_dapt = map_dapt_to_cicids(df_dapt)

    # DAPT labels are in 'Label' column. Normal is Benign.
    df_dapt["Target"] = df_dapt.get("Label", df_dapt.get("label", pd.Series(dtype=str))).apply(
        lambda x: 0 if str(x).strip().lower() in ["normal", "benign"] else 1
    )

    # Get common features excluding identifiers
    exclude = [
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow ID",
        "Src IP",
        "Src Port",
        "Dst IP",
        "Stage",
        "label",
        "Label",
        "Target",
    ]
    features = [c for c in df_cic.columns if c in df_dapt.columns and c not in exclude]

    print(f"[*] Found {len(features)} common numeric features.")

    df_cic_subset = df_cic[features + ["Target"]].copy()
    df_dapt_subset = df_dapt[features + ["Target"]].copy()

    # Ensure all data is numeric
    for col in features:
        df_cic_subset[col] = pd.to_numeric(df_cic_subset[col], errors="coerce")
        df_dapt_subset[col] = pd.to_numeric(df_dapt_subset[col], errors="coerce")

    df_cic_subset.fillna(0, inplace=True)
    df_dapt_subset.fillna(0, inplace=True)

    # 3. Generate Zero-day anomalies (3k rows)
    # We take benign flows and mutate them heavily
    print("[*] Generating Zero-Day Anomalies...")
    df_benign = df_cic_subset[df_cic_subset["Target"] == 0].sample(n=3000, replace=True).copy()
    # Mutate numerical features
    df_benign["Flow Duration"] = df_benign["Flow Duration"] * np.random.uniform(
        10, 100, size=len(df_benign)
    )
    if "Tot Fwd Pkts" in df_benign.columns:
        df_benign["Tot Fwd Pkts"] = df_benign["Tot Fwd Pkts"] * np.random.uniform(
            5, 50, size=len(df_benign)
        )
    df_benign["Target"] = 1  # these are now attacks!

    # 4. Generate Adversarial anomalies (2k rows)
    print("[*] Generating Adversarial Examples...")
    df_adv = df_cic_subset[df_cic_subset["Target"] == 1]
    if len(df_adv) > 0:
        df_adv = df_adv.sample(n=2000, replace=True).copy()
        # Mask attack metrics to look like benign (Adversarial Evasion)
        df_benign_stats = df_cic_subset[df_cic_subset["Target"] == 0].mean()
        for col in features:
            df_adv[col] = df_adv[col] * 0.5 + df_benign_stats[col] * 0.5
        df_adv["Target"] = 1
    else:
        df_adv = pd.DataFrame()

    # Combine all
    print("[*] Concatenating and saving...")
    df_final = pd.concat([df_cic_subset, df_dapt_subset, df_benign, df_adv], ignore_index=True)

    # Final cleanup for inf values
    df_final.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_final.dropna(inplace=True)

    # Shuffle
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

    df_final.to_csv(OUT_FILE, index=False)
    print(f"[+] Dataset saved to {OUT_FILE} (Shape: {df_final.shape})")


if __name__ == "__main__":
    main()
