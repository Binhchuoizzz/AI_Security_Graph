"""Dọn RIÊNG phần `config/system_settings.yaml` bị pytest làm bẩn.

VÌ SAO KHÔNG DÙNG `git checkout -- config/system_settings.yaml`:
chạy pytest ghi ~1.400 luật động vào tệp này, và cách dọn cũ là checkout nguyên tệp. Nhưng
tệp này cũng chứa CẤU HÌNH THẬT đang được sửa có chủ đích (vd `rag.top_k_results`), nên
checkout sẽ NUỐT LUÔN thay đổi hợp lệ — đúng loại lỗi "dọn dẹp xoá mất việc đã làm".

Script chỉ đặt lại `dynamic_rules: []` và giữ nguyên mọi khoá khác.

Chạy:  .venv/bin/python scripts/clean_test_pollution.py
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "config", "system_settings.yaml")


def main() -> None:
    with open(PATH) as f:
        cfg = yaml.safe_load(f) or {}

    # Luật động nằm ở `tier1.dynamic_rules`, KHÔNG phải khoá cấp cao nhất. Bản đầu của
    # script này nhắm sai khoá nên luôn báo "không có gì để dọn" và im lặng không làm gì —
    # đúng kiểu dọn dẹp giả tạo cảm giác an toàn.
    tier1 = cfg.get("tier1")
    if not isinstance(tier1, dict) or not isinstance(tier1.get("dynamic_rules"), list):
        print("[=] không tìm thấy tier1.dynamic_rules — không có gì để dọn.")
        return
    n = len(tier1["dynamic_rules"])
    if n == 0:
        print("[=] không có luật động nào — không cần dọn.")
        return
    tier1["dynamic_rules"] = []
    with open(PATH, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    print(f"[+] đã xoá {n} luật động; các khoá cấu hình khác giữ nguyên.")


if __name__ == "__main__":
    sys.exit(main())
