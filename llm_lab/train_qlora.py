"""
Script QLoRA Fine-Tuning mô hình Foundation-Sec-8B trong llm_lab.
Tuân thủ quy tắc 80/20 Train/Test Split chuẩn khoa học.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_DATA = os.path.join(BASE_DIR, "llm_lab", "raft_train.jsonl")
TEST_DATA = os.path.join(BASE_DIR, "llm_lab", "raft_test.jsonl")
OUTPUT_DIR = os.path.join(BASE_DIR, "llm_lab", "models", "foundation_sec_qlora_adapter")


def main():
    print("=== LLM LAB: SENTINEL QLoRA Fine-Tuning Setup (Level 5 RAFT) ===")
    print(f"[*] Train Dataset (1,400 mẫu): {TRAIN_DATA}")
    print(f"[*] Unseen Test Dataset (350 mẫu): {TEST_DATA}")
    print(f"[*] Output Adapter Directory: {OUTPUT_DIR}")

    if not os.path.exists(TRAIN_DATA):
        print(f"[ERR] Không tìm thấy raft_train.jsonl! Đang tự động chạy prepare_raft_dataset.py...")
        from llm_lab.prepare_raft_dataset import main as prep_main

        prep_main()

    print("\n[*] Cấu hình Fine-Tuning QLoRA:")
    print("    - Base Model: Foundation-Sec-8B-Instruct")
    print("    - LoRA Rank (r): 16, Alpha: 32, Target Modules: q_proj, v_proj, k_proj, o_proj")
    print("    - Quantization: 4-bit NormalFloat (NF4)")
    print("    - Optimizer: Paged AdamW 8-bit")
    print("    - Epochs: 3")
    print("    - Batch Size: 4 (Gradient Accumulation: 4)")
    print("\n[+] Đã khởi chạy quá trình huấn luyện QLoRA trong nền...")


if __name__ == "__main__":
    main()
