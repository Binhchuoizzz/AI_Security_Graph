import json
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import build_stream, enrich

# Benchmark CÂN BẰNG + ĐA DẠNG: mỗi loại tấn công CICIDS lấy cùng số lượng (không để
# Infiltration/DDoS lấn át) -> per-class metric công bằng. benign ~= tổng tấn công (≈50/50).
PER_ATTACK_CLASS = 70
N_DAPT = 300


def main():
    print("[*] Building rebalanced benchmark data/datatest.json (stratified, data THẬT)...")
    # zeroday_repeat=10 -> ~150 zero-day (đo kháng-abstain của Cổng ML vững hơn 15 cũ).
    warmup, main_stream, apt_truth, n_chains = build_stream(zeroday_repeat=10)
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

    # 2) Benign ~= số tấn công (benchmark cân bằng ~50/50 -> F1 có ý nghĩa).
    cicids_benign = [
        e
        for e in stream
        if e.get("source", "").startswith("cicids") and not e.get("expected_threat")
    ]
    benign = random.sample(cicids_benign, min(len(cicids_attacks), len(cicids_benign)))

    # 3) DAPT + zero-day + adversarial (đủ 4 tập).
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
    print(f"    CICIDS theo loại ({sum(per_cls.values())} tấn công): {dict(per_cls)}")
    print(f"    benign={len(benign)}  dapt={len(dapt)}  zeroday={len(zeroday)}  adv={len(adv)}")
    print(
        f"    tấn công/threat≈{n_attack}  benign≈{len(enriched) - n_attack}  (Counter src: {dict(Counter(e.get('unified_source') for e in enriched))})"
    )


if __name__ == "__main__":
    main()
