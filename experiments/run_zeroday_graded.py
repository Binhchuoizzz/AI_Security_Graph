"""
SENTINEL — Zero-Day PHÂN CẤP (Graded Deviation Detection Curve)
[Luận văn Ch.4 §Graded Detection Boundary — vượt "7/7 nhị phân", vẽ đường cong phát hiện]
===============================================================
Thay vì chỉ 7 mẫu zero-day ở cực trị (lệch hàng trăm σ -> bắt 7/7 gần như hiển
nhiên), ở đây ta QUÉT độ lệch k ∈ {2,3,3.5,4,5,6,8,10,20,50,100}·σ trên NHIỀU
flow benign THẬT × NHIỀU feature Welford, rồi đo:

  - "noticed"  : Welford gắn cờ dị biệt (Z > 3.5σ)            -> tầng nhận biết
  - "escalated": điểm Tier-1 ≥ risk_threshold -> leo thang Tầng 2  -> tầng hành động

Qua đó xác định RANH GIỚI PHÁT HIỆN thay vì một con số 7/7 tầm thường, và đặt 7
zero-day tiêu biểu (z ≫ 100) vào đúng bối cảnh của đường cong này.

Tất định, Tier-1 ONLY (KHÔNG LLM). Baseline Welford được ĐÓNG BĂNG (snapshot +
restore) trước mỗi probe để mọi probe thấy cùng một baseline -> z = k chính xác.

Chạy:  .venv/bin/python experiments/run_zeroday_graded.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.unified_dataset import _safe_int, build_stream, map_cicids  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "zeroday_graded_results.json")

K_LEVELS = [2.0, 3.0, 3.5, 4.0, 5.0, 6.0, 8.0, 10.0, 20.0, 50.0, 100.0]
THREAT_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}

# Feature Welford để đẩy. KHÔNG dùng "Total Fwd Packets" (sẽ chạm luật tĩnh
# max_fwd_packets) để cô lập đúng đóng góp của Z-score.
PROBE_FEATURES = [
    "Flow Duration",
    "Total Length of Fwd Packets",
    "Total Backward Packets",
    "Total Length of Bwd Packets",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Flow Pkts/s",
]


def snapshot_stats(engine):
    return {k: (s.n, s.old_m, s.new_m, s.old_s, s.new_s) for k, s in engine.global_stats.items()}


def restore_stats(engine, snap):
    for k, (n, om, nm, os_, ns) in snap.items():
        s = engine.global_stats[k]
        s.n, s.old_m, s.new_m, s.old_s, s.new_s = n, om, nm, os_, ns


def static_clean_pool(samples, limit=30):
    """Flow benign THẬT, static-clean (cổng không nhạy cảm, fwd<=1000, không signature)."""
    SENSITIVE = {21, 22, 23, 53, 139, 445, 3389}
    pool = []
    for s in samples:
        if s.get("input", {}).get("cicids_label", "") != "Benign":
            continue
        nl = s.get("input", {}).get("network_layer", {})
        if not nl:
            continue
        if _safe_int(nl.get("dst_port")) in SENSITIVE:
            continue
        if _safe_int(nl.get("fwd_packets")) > 1000:
            continue
        pool.append(nl)
        if len(pool) >= limit:
            break
    return pool


def main():
    print("=" * 70)
    print("  SENTINEL — ZERO-DAY PHÂN CẤP (đường cong phát hiện theo độ lệch)")
    print("=" * 70)

    with open(os.path.join(os.path.dirname(__file__), "ground_truth.json")) as f:
        samples = json.load(f)

    warmup, _main, _apt, _n = build_stream()
    engine = RuleEngine()
    print(f"[*] Warmup baseline Welford trên {len(warmup)} flow benign thật...")
    for ev in warmup:
        engine.evaluate(ev["log"])

    snap = snapshot_stats(engine)
    # feature hợp lệ: đã đủ warmup & có biến động (std > 0.01)
    valid_feats = []
    for feat in PROBE_FEATURES:
        s = engine.global_stats.get(feat)
        if s and s.n >= engine.warmup_count and s.std_dev() > 0.01:
            valid_feats.append((feat, s.mean(), s.std_dev()))
    print(f"[*] Feature hợp lệ ({len(valid_feats)}): {[f[0] for f in valid_feats]}")

    pool = static_clean_pool(samples, limit=30)
    print(f"[*] Pool flow benign nền (static-clean): {len(pool)}")

    rows = []
    for k in K_LEVELS:
        noticed = 0
        escalated = 0
        zsum = 0.0
        n = 0
        for base_nl in pool:
            for feat, mean, std in valid_feats:
                restore_stats(engine, snap)  # đóng băng baseline cho mỗi probe
                engine.session_baseline.reset_window()
                log = map_cicids(base_nl)
                log[feat] = mean + k * std  # đẩy đúng 1 feature lên k·σ
                log["Source IP"] = "10.99.0.1"
                res = engine.evaluate(log)
                z = res.get("tier1_z_score", 0.0)
                act = res.get("tier1_action", "DROP")
                zsum += z
                n += 1
                if z > 3.5:
                    noticed += 1
                if act in THREAT_ACTIONS:
                    escalated += 1
        rows.append(
            {
                "k_sigma": k,
                "n_probes": n,
                "mean_realized_z": round(zsum / n, 2) if n else 0.0,
                "noticed_rate": round(noticed / n, 4) if n else 0.0,
                "escalated_rate": round(escalated / n, 4) if n else 0.0,
            }
        )
        print(
            f"[k={k:>5.1f}σ] realized-Z≈{zsum / n:6.1f} | noticed(Z>3.5)={100 * noticed / n:5.1f}% "
            f"| escalated(→Tier-2)={100 * escalated / n:5.1f}%  (n={n})"
        )

    # ranh giới
    notice_k = next((r["k_sigma"] for r in rows if r["noticed_rate"] >= 0.5), None)
    escal_k = next((r["k_sigma"] for r in rows if r["escalated_rate"] >= 0.5), None)

    out = {
        "k_levels": K_LEVELS,
        "valid_features": [f[0] for f in valid_feats],
        "pool_size": len(pool),
        "notice_boundary_sigma": notice_k,
        "escalate_boundary_sigma": escal_k,
        "sweep": rows,
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Ranh giới: NOTICED ≥{notice_k}σ | ESCALATED ≥{escal_k}σ")
    print(f"[+] Saved -> {OUT_JSON}")


if __name__ == "__main__":
    main()
