import json
import os
import random
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import BENCHMARK_DAYS, build_stream, enrich

# ── Benchmark CHẤT LƯỢNG + TRUNG THỰC từ FULL 4 luồng data THẬT ──────────────────
# CICIDS đa-ngày (đủ 14 loại tấn công + benign phong phú) + DAPT (day2-5 tấn công THẬT) +
# Zero-day (real-derived) + Adversarial (OWASP THẬT). Cân bằng ~50/50 attack/benign, mỗi
# loại CICIDS lấy CÙNG số lượng (không để Infiltration/DDoS lấn át) -> per-class metric công bằng.
# Danh sách ngày nay lấy từ `unified_dataset.BENCHMARK_DAYS` — một nguồn chân lý duy nhất,
# thay cho bản chép tay cũ ở đây (xem chú thích trong unified_dataset).

PER_ATTACK_CLASS = 100  # mỗi loại CICIDS (nhiều hơn 70 cũ -> per-class metric vững hơn)
N_DAPT = 500  # DAPT day2-5 (tấn công THẬT: scan/BF/SQLi/cmd-inj/exfil)
ZERODAY_REPEAT = 24  # 24 x 15 spec ≈ 360 zero-day (nền benign THẬT, IP riêng, real-derived)

# CSIC 2010 — request HTTP THẬT (tầng 7). PHẢI có mặt ở đây, không chỉ ở ground_truth.json.
#
# LỖI ĐÃ SỬA: benchmark này TRƯỚC ĐÂY thuần NetFlow (cicids + dapt + zeroday + adversarial),
# nên F1 của Cổng ML — một số headline của luận văn — được đo trên dữ liệu KHÔNG có một
# cuộc tấn công web nào. Trong khi Chương 1 tuyên bố phạm vi là "hai tập benchmark:
# CSE-CIC-IDS2018 và CSIC 2010". Người đọc hiểu rằng cả hai tập tham gia mọi phép đo; thực
# tế CSIC chỉ tham gia phần quy kết kỹ thuật. Trộn CSIC vào đây làm con số ĐÚNG NHƯ LỜI ĐÃ
# VIẾT, và quan trọng hơn: nó đo Cổng ML trên đúng lớp tấn công mà Tier-1 hay chặn nhất.
CSIC_LOAD = 8000  # nạp toàn bộ để phân tầng chạm được trần các lớp hiếm (Path Traversal 26)


def main():
    print("[*] Building QUALITY 4-stream benchmark data/datatest.json (data THẬT, đa-ngày)...")
    # Đa-ngày CICIDS -> benign phong phú + đủ loại tấn công; DAPT day2-5; zero-day real-derived.
    warmup, main_stream, apt_truth, n_chains = build_stream(
        cicids_max_rows=40_000,
        cicids_max_days=BENCHMARK_DAYS,
        dapt_max_rows=6_000,
        zeroday_repeat=ZERODAY_REPEAT,
        csic_max=CSIC_LOAD,
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

    # 4) CSIC 2010 — phân tầng THEO LỚP giống CICIDS, rồi lấy benign BẰNG số tấn công.
    # Không lấy `rows[:n]` thẳng: lớp hiếm (Path Traversal 26, Forced Browsing 27) sẽ chìm
    # dưới 'Anomalous (unclassified)' 3.311 và metric per-class của chúng thành vô nghĩa.
    csic_all = [e for e in stream if e.get("source") == "csic"]
    csic_by_cls: dict = defaultdict(list)
    for e in csic_all:
        if e.get("expected_threat"):
            csic_by_cls[e.get("label", "?")].append(e)
    csic_attacks = []
    for _cls, evs in sorted(csic_by_cls.items()):
        csic_attacks.extend(random.sample(evs, min(PER_ATTACK_CLASS, len(evs))))
    csic_benign_all = [e for e in csic_all if not e.get("expected_threat")]
    csic_benign = random.sample(csic_benign_all, min(len(csic_attacks), len(csic_benign_all)))

    combined = cicids_attacks + benign + dapt + zeroday + adv + csic_attacks + csic_benign
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
    csic_cls = {c: min(PER_ATTACK_CLASS, len(v)) for c, v in sorted(csic_by_cls.items())}
    print(f"    CSIC tấn công ({len(csic_attacks)}, {len(csic_cls)} lớp): {csic_cls}")
    print(f"    CSIC benign={len(csic_benign)}")
    print(
        f"    tấn công/threat≈{n_attack}  benign≈{len(enriched) - n_attack}  "
        f"(nguồn: {dict(Counter(e.get('unified_source') for e in enriched))})"
    )


if __name__ == "__main__":
    main()
