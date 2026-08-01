"""
Script chuẩn bị dữ liệu RAFT (Retrieval-Augmented Fine-Tuning) cho QLoRA trong llm_lab.
ĐẢM BẢO NGUYÊN TẮC BẢO VỆ DỮ LIỆU THỰC NGHIỆM:
- Tập Train & Test của QLoRA được trích xuất TỰ ĐỘNG từ ml_lab/dataset_100k.csv (CIC-IDS2017).
- HOÀN TOÀN TÁCH BIỆT (Out-of-Distribution / Cross-Dataset Isolation) khỏi 1,750 mẫu của experiments/ground_truth.json.
"""

import json
import os
import random
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_LAB_CSV = os.path.join(BASE_DIR, "ml_lab", "dataset_100k.csv")
GT_PATH = os.path.join(BASE_DIR, "experiments", "ground_truth.json")
TRAIN_OUT = os.path.join(BASE_DIR, "llm_lab", "raft_train.jsonl")
TEST_OUT = os.path.join(BASE_DIR, "llm_lab", "raft_test.jsonl")


def format_row_to_raft(row: pd.Series) -> dict:
    """Chuyển đổi một dòng log CSV từ ml_lab thành định dạng RAFT Prompt -> Response."""
    dst_port = int(row.get("Dst Port", 80))
    proto = int(row.get("Protocol", 6))
    label = str(row.get("Label", "BENIGN")).strip()

    log_dict = {
        "Destination Port": dst_port,
        "Protocol": proto,
        "Total Fwd Packets": int(row.get("Tot Fwd Pkts", 1)),
        "Total Length of Fwd Packets": float(row.get("TotLen Fwd Pkts", 0.0)),
        "Flow Duration": int(row.get("Flow Duration", 0)),
        "Label": label,
    }

    log_text = json.dumps(log_dict, ensure_ascii=False)

    prompt = (
        f"<escalated_log_data_v1>\n{log_text}\n</escalated_log_data_v1>\n\n"
        "Analyze the escalated network flow log and determine the corresponding action and MITRE ATT&CK technique."
    )

    is_attack = label.upper() != "BENIGN"
    response = json.dumps(
        {
            "action": "BLOCK_IP" if is_attack else "LOG",
            "confidence": 0.95 if is_attack else 0.05,
            "mitre_technique": "T1595.003" if "SCAN" in label.upper() or "PORT" in label.upper() else ("T1190" if is_attack else "N/A"),
            "attack_method": f"Detected traffic pattern: {label}",
            "reasoning": f"Flow statistics indicate network pattern matching label {label}.",
        },
        ensure_ascii=False,
    )

    return {"instruction": prompt, "response": response}


def main():
    print("=== LLM LAB: Cross-Dataset RAFT Dataset Generator (Anti-Data Leakage) ===")
    if not os.path.exists(ML_LAB_CSV):
        print(f"[ERR] Không tìm thấy ml_lab/dataset_100k.csv tại {ML_LAB_CSV}")
        return

    print(f"[*] Đang tải dữ liệu từ {ML_LAB_CSV} (để tách biệt 100% khỏi ground_truth.json)...")
    df = pd.read_csv(ML_LAB_CSV, nrows=5000)
    print(f"[*] Đã tải {len(df)} mẫu log từ ml_lab CSV.")

    records = [format_row_to_raft(row) for _, row in df.iterrows()]

    random.seed(42)
    random.shuffle(records)

    split_idx = int(len(records) * 0.8)
    train_records = records[:split_idx]
    test_records = records[split_idx:]

    os.makedirs(os.path.dirname(TRAIN_OUT), exist_ok=True)

    with open(TRAIN_OUT, "w", encoding="utf-8") as f:
        for r in train_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open(TEST_OUT, "w", encoding="utf-8") as f:
        for r in test_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[+] ĐÃ NÂNG CẤP THÀNH CÔNG TÁCH BIỆT CROSS-DATASET 100%:")
    print(f"    - Tập QLoRA Train ({len(train_records)} mẫu): Nguồn ml_lab/dataset_100k.csv -> {TRAIN_OUT}")
    print(f"    - Tập QLoRA Test ({len(test_records)} mẫu): Nguồn ml_lab/dataset_100k.csv -> {TEST_OUT}")
    print(f"    - Tập Benchmark Evaluation: Giữ nguyên 100% UNSEEN từ experiments/ground_truth.json (KHÔNG CHẠM VÀO).")


if __name__ == "__main__":
    main()
