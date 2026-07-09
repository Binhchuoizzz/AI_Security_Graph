#!/usr/bin/env python3
"""Dựng 'golden baseline' Welford từ lưu lượng benign ĐÃ KIỂM ĐỊNH.

Đọc các mẫu Benign trong ``experiments/ground_truth.json``, ánh xạ qua ``map_cicids``
(đúng schema mà RuleEngine dùng ở runtime), rồi tích lũy trạng thái Welford
(n, mean, M2) cho từng feature Tầng 1. Kết quả lưu vào ``config/golden_baseline.json``.

RuleEngine sẽ seed baseline này lúc khởi tạo khi bật cờ config
``tier1.golden_baseline.enabled: true``; sau khi seed, baseline vẫn tiếp tục cập
nhật online CÓ ĐIỀU KIỆN (chỉ với phán quyết DROP/LOG) như bình thường.

Chạy: ``python experiments/build_golden_baseline.py``
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from experiments.evaluate_unified_stream import map_cicids  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")
OUT_PATH = os.path.join(ROOT, "config", "golden_baseline.json")


def main() -> None:
    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    samples = gt if isinstance(gt, list) else gt.get("samples", gt)

    # RuleEngine với global_stats rỗng (golden_baseline mặc định TẮT nên không tự seed).
    engine = RuleEngine()
    n_benign = 0
    for s in samples:
        inp = s.get("input", {})
        if inp.get("cicids_label", "") != "Benign":
            continue
        nl = inp.get("network_layer", {})
        if not nl:
            continue
        # push KHÔNG điều kiện: mọi mẫu ở đây đều đã được nhãn hóa là benign.
        engine.learn_baseline(map_cicids(nl))
        n_benign += 1

    features = {k: v.as_state() for k, v in engine.global_stats.items() if v.n >= 2}
    profile = {
        "source": "experiments/ground_truth.json (cicids_label == Benign)",
        "n_flows": n_benign,
        "features": features,
    }
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)

    print(f"Golden baseline: {len(features)} feature từ {n_benign} flow benign -> {OUT_PATH}")
    for k, v in features.items():
        print(f"  {k:<32} n={v['n']:>4}  mean={v['mean']:>14.2f}  m2={v['m2']:>18.2f}")


if __name__ == "__main__":
    main()
