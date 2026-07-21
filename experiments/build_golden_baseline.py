#!/usr/bin/env python3
"""Dựng 'golden baseline' Welford từ lưu lượng benign ĐÃ KIỂM ĐỊNH.

Tích lũy trạng thái Welford (n, mean, M2) cho từng feature Tầng 1, lưu vào
``config/golden_baseline.json``. RuleEngine seed baseline này lúc khởi tạo khi bật cờ
``tier1.golden_baseline.enabled: true``; sau đó vẫn cập nhật online CÓ ĐIỀU KIỆN
(chỉ với phán quyết DROP/LOG).

HAI THAY ĐỔI QUAN TRỌNG (2026-07-21)
------------------------------------
1. **Nguồn & cỡ mẫu.** Bản cũ chỉ lấy 300 flow benign từ ``ground_truth.json`` — chính là
   tập BENCHMARK. Vừa quá nhỏ để ước lượng phương sai của phân phối đuôi dài, vừa RÒ RỈ
   dữ liệu (Tầng 1 học trên đúng tập nó bị chấm). Bản này đọc CSV CICIDS gốc và **loại
   trừ tường minh** mọi flow đã xuất hiện trong benchmark (đối chiếu bằng chữ ký đặc
   trưng), rồi lấy mặc định 10.000 flow.

2. **Không gian thống kê.** Baseline được tích lũy ở CÙNG thang mà RuleEngine tính
   Z-score (``scale_feature``: log1p cho đặc trưng khối-lượng/thời-lượng/tốc-độ). File
   kết quả ghi cờ ``transform`` để bên nạp TỪ CHỐI baseline dựng ở thang cũ thay vì suy
   biến im lặng.

Chạy:
    .venv/bin/python experiments/build_golden_baseline.py
    .venv/bin/python experiments/build_golden_baseline.py --n 20000
"""

import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from experiments.unified_dataset import map_cicids  # noqa: E402
from src.tier1_filter.rule_engine import (  # noqa: E402
    BASELINE_TRANSFORM_ID,
    LOG_SCALE_FEATURES,
    RuleEngine,
    RunningStats,
)

GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")
DATATEST_PATH = os.path.join(ROOT, "experiments", "datatest.json")
CIC_DIR = os.path.join(ROOT, "data", "raw", "cicids2018")
OUT_PATH = os.path.join(ROOT, "config", "golden_baseline.json")

# Chữ ký nhận dạng một flow — dùng để LOẠI TRỪ flow đã nằm trong benchmark.
_SIG_FIELDS = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Dst Port",
    "Destination Port",
)


def _flow_signature(d: dict) -> str:
    """Chữ ký ổn định của một flow (không phụ thuộc thứ tự khoá / tên cột biến thể)."""
    parts = []
    for f in _SIG_FIELDS:
        if f in d and d[f] not in ("", None):
            try:
                parts.append(f"{f}={float(d[f]):.4f}")
            except (TypeError, ValueError):
                parts.append(f"{f}={d[f]}")
    return hashlib.sha256("|".join(sorted(parts)).encode()).hexdigest()[:20]


def _benchmark_signatures() -> set[str]:
    """Chữ ký của MỌI flow xuất hiện trong tập benchmark (ground_truth + datatest)."""
    sigs: set[str] = set()
    for path in (GT_PATH, DATATEST_PATH):
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("samples", [])
        for s in items:
            if not isinstance(s, dict):
                continue
            # ground_truth: {"input": {"network_layer": {...}}, "logs": [...]}
            nl = (s.get("input") or {}).get("network_layer") or {}
            if nl:
                sigs.add(_flow_signature(nl))
            for log in s.get("logs") or []:
                if isinstance(log, dict):
                    sigs.add(_flow_signature(log))
            if "Flow Duration" in s or "Dst Port" in s:  # datatest: event phẳng
                sigs.add(_flow_signature(s))
    return sigs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000, help="số flow benign mục tiêu")
    args = ap.parse_args()

    import pandas as pd  # nặng — chỉ nạp khi thật sự chạy

    exclude = _benchmark_signatures()
    print(f"[*] Chữ ký flow benchmark cần LOẠI TRỪ: {len(exclude)}")

    # Bắt đầu từ Welford RỖNG: RuleEngine() tự seed golden lúc init nên nếu không reset
    # ta sẽ tích lũy CHỒNG lên chính golden cũ (n gấp đôi).
    engine = RuleEngine()
    for _k in engine.global_stats:
        engine.global_stats[_k] = RunningStats()

    csvs = sorted(f for f in os.listdir(CIC_DIR) if f.endswith(".csv"))
    # TRẢI ĐỀU qua MỌI ngày: lấy hết quota từ một ngày sẽ cho baseline chỉ phản ánh nhịp
    # lưu lượng của ngày đó (giờ làm việc, dịch vụ đang chạy), không đại diện cho "bình
    # thường" của cả mạng — đúng thứ Z-score cần.
    per_day = max(1, args.n // max(1, len(csvs)))
    n_used = n_skipped = 0
    for csv_name in csvs:
        if n_used >= args.n:
            break
        path = os.path.join(CIC_DIR, csv_name)
        day_used = 0
        day_quota = min(per_day, args.n - n_used)
        # chunk nhỏ: file CICIDS tới hàng GB, không nạp hết vào RAM
        for chunk in pd.read_csv(path, chunksize=20_000, low_memory=False):
            chunk.columns = [str(c).strip() for c in chunk.columns]
            label_col = next((c for c in chunk.columns if c.lower() == "label"), None)
            if label_col is None:
                break
            benign = chunk[chunk[label_col].astype(str).str.strip().str.lower() == "benign"]
            for row in benign.to_dict("records"):
                if day_used >= day_quota:
                    break
                if _flow_signature(row) in exclude:
                    n_skipped += 1
                    continue  # RÒ RỈ: flow này đã nằm trong benchmark
                engine.learn_baseline(map_cicids(row))
                day_used += 1
                n_used += 1
            if day_used >= day_quota:
                break
        print(f"    {csv_name:<52} +{day_used:>5}  -> tổng {n_used}/{args.n}")

    features = {k: v.as_state() for k, v in engine.global_stats.items() if v.n >= 2}
    profile = {
        "source": "data/raw/cicids2018/*.csv (Label == Benign), ĐÃ loại flow trùng benchmark",
        "n_flows": n_used,
        "n_excluded_benchmark_overlap": n_skipped,
        # Cờ để RuleEngine từ chối baseline dựng ở thang khác (chống sai im lặng).
        "transform": BASELINE_TRANSFORM_ID,
        "log_scale_features": sorted(LOG_SCALE_FEATURES),
        "features": features,
    }
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)

    print(
        f"\nGolden baseline: {len(features)} feature từ {n_used} flow benign "
        f"({n_skipped} flow bị loại vì trùng benchmark) -> {OUT_PATH}"
    )
    print(f"Không gian thống kê: {BASELINE_TRANSFORM_ID}\n")
    print(f"{'FEATURE':<32}{'n':>7}{'mean':>12}{'sd':>12}{'sd/mean':>9}  thang")
    for k, v in features.items():
        n, m2 = v["n"], v["m2"]
        sd = (m2 / (n - 1)) ** 0.5 if n > 1 else 0.0
        cv = sd / v["mean"] if v["mean"] else float("nan")
        print(
            f"{k:<32}{n:>7}{v['mean']:>12.3f}{sd:>12.3f}{cv:>9.2f}"
            f"  {'log1p' if k in LOG_SCALE_FEATURES else 'tuyến tính'}"
        )


if __name__ == "__main__":
    main()
