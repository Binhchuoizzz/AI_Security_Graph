"""
Script chuẩn bị dữ liệu RAFT (Retrieval-Augmented Fine-Tuning) cho Foundation-Sec-8B.
Tuân thủ nghiêm ngặt quy tắc Chia 80/20 Train/Test Set mới tinh (Unseen Test Data) để chống rò rỉ dữ liệu (Anti-Data Leakage).
"""

import json
import os
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE_DIR, "experiments", "ground_truth.json")
TRAIN_OUT = os.path.join(BASE_DIR, "experiments", "data", "raft_train.jsonl")
TEST_OUT = os.path.join(BASE_DIR, "experiments", "data", "raft_test.jsonl")


def format_raft_prompt(sample: dict) -> dict:
    """Định dạng mẫu log + RAG context thành cặp Prompt -> Response theo định dạng RAFT."""
    logs = sample.get("logs") or []
    log_text = json.dumps(logs, ensure_ascii=False)
    expected_tech = sample.get("expected_mitre_technique", "N/A")

    prompt = (
        f"<escalated_log_data_v1>\n{log_text}\n</escalated_log_data_v1>\n\n"
        "Analyze the escalated security log and determine the corresponding MITRE ATT&CK technique and action."
    )

    response = json.dumps(
        {
            "action": "BLOCK_IP" if expected_tech != "N/A" else "LOG",
            "confidence": 0.95 if expected_tech != "N/A" else 0.1,
            "mitre_technique": expected_tech,
            "attack_method": f"Detected technique {expected_tech} from payload signature",
            "reasoning": f"Log payload analysis identifies patterns matching MITRE ATT&CK technique {expected_tech}.",
        },
        ensure_ascii=False,
    )

    return {"instruction": prompt, "response": response}


def main():
    if not os.path.exists(GT_PATH):
        print(f"[ERR] Không tìm thấy ground_truth.json tại {GT_PATH}")
        return

    with open(GT_PATH, encoding="utf-8") as f:
        data = json.load(f)

    print(f"[*] Tổng số mẫu Ground Truth: {len(data)}")

    # Trộn cố định seed để tái lập kết quả
    random.seed(42)
    random.shuffle(data)

    split_idx = int(len(data) * 0.8)
    train_data = data[:split_idx]
    test_data = data[split_idx:]

    print(f"[*] 80% Train Set (dùng cho QLoRA Fine-Tune): {len(train_data)} mẫu")
    print(f"[*] 20% Unseen Test Set (chỉ dùng đo Benchmark): {len(test_data)} mẫu")

    os.makedirs(os.path.dirname(TRAIN_OUT), exist_ok=True)

    with open(TRAIN_OUT, "w", encoding="utf-8") as f:
        for s in train_data:
            f.write(json.dumps(format_raft_prompt(s), ensure_ascii=False) + "\n")

    with open(TEST_OUT, "w", encoding="utf-8") as f:
        for s in test_data:
            f.write(json.dumps(format_raft_prompt(s), ensure_ascii=False) + "\n")

    print("[+] Đã xuất dữ liệu chuẩn RAFT:")
    print(f"    - Train Set: {TRAIN_OUT}")
    print(f"    - Unseen Test Set: {TEST_OUT}")


if __name__ == "__main__":
    main()
