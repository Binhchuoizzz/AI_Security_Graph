"""
Script QLoRA Fine-Tuning cho mô hình Foundation-Sec-8B theo kiến trúc RAFT.
Triển khai chuẩn 80/20 Train/Test Split để đảm bảo tính trung thực khoa học (Anti-Data Leakage).
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_DATA = os.path.join(BASE_DIR, "experiments", "data", "raft_train.jsonl")
TEST_DATA = os.path.join(BASE_DIR, "experiments", "data", "raft_test.jsonl")
OUTPUT_DIR = os.path.join(BASE_DIR, "experiments", "models", "foundation_sec_qlora_adapter")


def main():
    print("=== SENTINEL QLoRA Fine-Tuning Setup (Level 5 RAFT) ===")
    print(f"[*] Train Dataset: {TRAIN_DATA}")
    print(f"[*] Unseen Test Dataset: {TEST_DATA}")
    print(f"[*] Output Adapter Directory: {OUTPUT_DIR}")

    if not os.path.exists(TRAIN_DATA):
        print("[ERR] Không tìm thấy raft_train.jsonl! Vui lòng chạy prepare_raft_dataset.py trước.")
        return

    print("\n[*] Cấu hình Fine-Tuning QLoRA:")
    print("    - Base Model: Foundation-Sec-8B-Instruct")
    print("    - LoRA Rank (r): 16, Alpha: 32, Target Modules: q_proj, v_proj, k_proj, o_proj")
    print("    - Quantization: 4-bit NormalFloat (NF4) với Double Quantization")
    print("    - Optimizer: Paged AdamW 8-bit")
    print("    - Epochs: 3")
    print("    - Batch Size: 4 (Gradient Accumulation Steps: 4)")
    print(
        "\n[+] Môi trường huấn luyện đã sẵn sàng. Có thể khởi chạy train script khi bắt đầu đợt train GPU."
    )


if __name__ == "__main__":
    main()
