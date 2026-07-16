import glob
import os

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(ROOT, "data", "raw", "cicids2018")
OUT_FILE = os.path.join(ROOT, "ml_lab", "dataset_100k.csv")


def main():
    print("[*] Building 100k Diverse Dataset from CICIDS2018...")

    all_files = glob.glob(os.path.join(RAW_DIR, "*.csv"))

    benign_list = []
    attack_list = []

    benign_per_file = 20000 // len(all_files)
    attack_per_file_target = 80000 // len(all_files)

    for file_path in all_files:
        print(f"[*] Reading {os.path.basename(file_path)}...")
        try:
            df_iter = pd.read_csv(file_path, chunksize=100000, low_memory=False)

            file_benign = []
            file_attack = []

            for chunk in df_iter:
                chunk.rename(columns=lambda x: str(x).strip(), inplace=True)
                chunk = chunk[chunk["Label"] != "Label"]

                if "Label" not in chunk.columns:
                    continue

                b_chunk = chunk[chunk["Label"].astype(str).str.strip().str.lower() == "benign"]
                a_chunk = chunk[chunk["Label"].astype(str).str.strip().str.lower() != "benign"]

                file_benign.append(b_chunk)
                file_attack.append(a_chunk)

                current_b_len = sum(len(x) for x in file_benign)
                current_a_len = sum(len(x) for x in file_attack)

                # To get 80k attacks, we might need to read the entire file if attacks are rare.
                # So we only break if we have an abundance of attacks
                if (
                    current_b_len > benign_per_file * 3
                    and current_a_len > attack_per_file_target * 10
                ):
                    break

            if file_benign:
                df_b = pd.concat(file_benign)
                if len(df_b) > benign_per_file * 2:
                    df_b = df_b.sample(n=benign_per_file * 2, random_state=42)
                benign_list.append(df_b)

            if file_attack:
                df_a = pd.concat(file_attack)
                if len(df_a) > 0:
                    # Keep all attacks we found, no sampling down at the file level
                    attack_list.append(df_a)
                    print(f"    -> Found {len(df_a)} attacks.")
                else:
                    print("    -> No attacks found.")

        except Exception as e:
            print(f"[!] Error processing {file_path}: {e}")

    df_all_benign = pd.concat(benign_list, ignore_index=True)
    df_all_attack = pd.concat(attack_list, ignore_index=True)

    print(f"[*] Total collected: {len(df_all_benign)} Benign, {len(df_all_attack)} Attacks")

    if len(df_all_benign) > 20000:
        df_all_benign = df_all_benign.sample(n=20000, random_state=42)

    if len(df_all_attack) > 80000:
        df_all_attack = df_all_attack.sample(n=80000, random_state=42)

    df_final = pd.concat([df_all_benign, df_all_attack], ignore_index=True)

    df_final.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_final.fillna(0, inplace=True)

    df_final["Target"] = df_final["Label"].apply(
        lambda x: 0 if str(x).strip().lower() == "benign" else 1
    )

    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

    if len(df_final) > 100000:
        df_final = df_final.head(100000)

    df_final.to_csv(OUT_FILE, index=False)
    print(f"[+] Dataset saved to {OUT_FILE} (Shape: {df_final.shape})")

    print("[*] Label distribution:")
    print(df_final["Label"].value_counts())


if __name__ == "__main__":
    main()
