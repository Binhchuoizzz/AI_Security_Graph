import json
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import build_stream, enrich

# ── Benchmark CHẤT LƯỢNG + TRUNG THỰC từ FULL 4 luồng data THẬT ──────────────────
# CICIDS đa-ngày (đủ 14 loại tấn công + benign phong phú) + DAPT (day2-5 tấn công THẬT) +
# Zero-day (real-derived) + Adversarial (OWASP THẬT). Cân bằng ~50/50 attack/benign, mỗi
# loại CICIDS lấy CÙNG số lượng (không để Infiltration/DDoS lấn át) -> per-class metric công bằng.
BENCHMARK_DAYS = (
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",  # Bot
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS Hulk / SlowHTTPTest
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS GoldenEye / Slowloris
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS HOIC / LOIC-UDP
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS LOIC-HTTP (tên gốc sai chính tả)
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",  # SSH / FTP-BruteForce
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",  # Infiltration
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",  # benign-heavy
)

PER_ATTACK_CLASS = 100  # mỗi loại CICIDS (nhiều hơn 70 cũ -> per-class metric vững hơn)
N_DAPT = 500  # DAPT day2-5 (tấn công THẬT: scan/BF/SQLi/cmd-inj/exfil)
ZERODAY_REPEAT = 24  # 24 x 15 spec ≈ 360 zero-day (nền benign THẬT, IP riêng, real-derived)


def main():
    print("[*] Building QUALITY 4-stream benchmark data/datatest.json (data THẬT, đa-ngày)...")
    # Đa-ngày CICIDS -> benign phong phú + đủ loại tấn công; DAPT day2-5; zero-day real-derived.
    warmup, main_stream, apt_truth, n_chains = build_stream(
        cicids_max_rows=40_000,
        cicids_max_days=BENCHMARK_DAYS,
        dapt_max_rows=6_000,
        zeroday_repeat=ZERODAY_REPEAT,
    )
    stream = warmup + main_stream
    random.seed(42)

    # 1) CICIDS attacks STRATIFIED theo loại — nguồn 'cicids' = ground_truth (đủ 15 lớp thật).
    atk_by_cls: dict = defaultdict(list)
    for e in stream:
        if e.get("source") == "cicids" and e.get("expected_threat"):
            atk_by_cls[e.get("label", "?")].append(e)
    cicids_attacks = []
    for _cls, evs in sorted(atk_by_cls.items()):
        cicids_attacks.extend(random.sample(evs, min(PER_ATTACK_CLASS, len(evs))))

    # 2) Benign ~= số tấn công (benchmark cân bằng ~50/50 -> F1 có ý nghĩa), lấy từ CICIDS thật.
    cicids_benign = [
        e
        for e in stream
        if e.get("source", "").startswith("cicids") and not e.get("expected_threat")
    ]
    benign = random.sample(cicids_benign, min(len(cicids_attacks), len(cicids_benign)))

    # 3) DAPT + zero-day + adversarial (đủ 4 tập, lấy TẤT CẢ zero-day/adv có trong stream).
    dapt_all = [e for e in stream if e.get("source", "").startswith("dapt")]
    dapt = random.sample(dapt_all, min(N_DAPT, len(dapt_all)))
    zeroday = [e for e in stream if e.get("source") == "zeroday"]
    adv = [e for e in stream if e.get("source") == "adversarial"]

    combined = cicids_attacks + benign + dapt + zeroday + adv
    combined.sort(key=lambda x: x.get("t", 0))

    # demo_signals=False: benchmark KHÔNG rò nhãn TTP vào prompt (giữ tính khách quan).
    enriched = [enrich(ev) for ev in combined]

    out_file = os.path.join(ROOT, "data", "datatest.json")
    with open(out_file, "w") as f:
        json.dump(enriched, f, indent=2)

    n_attack = sum(1 for e in enriched if e.get("expected_threat") or e.get("apt_is_attack"))
    per_cls = {c: min(PER_ATTACK_CLASS, len(v)) for c, v in sorted(atk_by_cls.items())}
    print(f"[+] Đã lưu {len(enriched)} sự kiện -> {out_file}")
    print(
        f"    CICIDS theo loại ({sum(per_cls.values())} tấn công, {len(per_cls)} lớp): {dict(per_cls)}"
    )
    print(f"    benign={len(benign)}  dapt={len(dapt)}  zeroday={len(zeroday)}  adv={len(adv)}")
    print(
        f"    tấn công/threat≈{n_attack}  benign≈{len(enriched) - n_attack}  "
        f"(nguồn: {dict(Counter(e.get('unified_source') for e in enriched))})"
    )


if __name__ == "__main__":
    main()
