"""SENTINEL — Dựng LUỒNG DEMO NGẮN (~5.000 sự kiện) ĐỦ 4 NGUỒN cho buổi bảo vệ.

TẠI SAO CẦN FILE NÀY (bug thật đã gặp): `run_demo.sh --small` cắt 5.000 sự kiện ĐẦU
của `data/demo.json`. Nhưng luồng đầy đủ được sắp theo THỜI GIAN THẬT, nên các chuỗi APT
đa-ngày chỉ hoàn tất ở vị trí #45.933 / #60.055 / #63.237 → demo ngắn KHÔNG BAO GIỜ hiện
panel "Chiến dịch APT" (một kết quả headline của luận văn). Tương tự, zero-day và
adversarial nằm rải rác nên cũng có thể vắng mặt.

CÁCH LÀM (KHÔNG bịa dữ liệu): đây là TẬP CON PHÂN TẦNG lấy nguyên văn từ
`data/demo.json` — mọi sự kiện đều là bản ghi THẬT (CICIDS2018 / DAPT2020 / zero-day
real-derived / adversarial OWASP), giữ nguyên mọi trường kể cả `apt_day`. Việc duy nhất
ta làm là CHỌN sự kiện nào đi vào tập nhỏ, rồi SẮP LẠI THEO ĐÚNG THỨ TỰ GỐC để quan hệ
thời gian (và do đó cơ chế APT đa-ngày) vẫn nổi lên tự nhiên như luồng đầy đủ.

Đảm bảo mỗi panel Dashboard đều có dữ liệu:
  - Chiến dịch APT   : lấy TRỌN sự kiện của các IP có >= 2 apt_day (ngưỡng is_apt ở
                       ThreatMemoryStore.check_apt_chain) -> chuỗi chắc chắn kích hoạt.
  - Tier-1 chặn/MITRE: phủ ĐỦ các lớp tấn công CICIDS có nhãn (mỗi lớp tối đa N mẫu).
  - Zero-day         : mẫu probe real-derived (Welford bắt, luật tĩnh sót).
  - Adversarial      : lấy TOÀN BỘ (4 payload OWASP thật).
  - Nền benign       : phần còn lại, để Tier-1 vẫn DROP phần lớn (giảm tải thật).

Chạy:  .venv/bin/python scripts/build_demo_small.py [--target 5000]
"""

import argparse
import json
import os
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_FILE = os.path.join(ROOT, "data", "demo.json")
OUT_FILE = os.path.join(ROOT, "data", "demo_small.json")

PER_ATTACK_CLASS = 40  # mỗi lớp tấn công CICIDS lấy tối đa bấy nhiêu (đủ đa dạng MITRE)
N_ZERODAY = 150  # probe zero-day (đủ để panel có số, không làm ngập LLM)
N_DAPT_EXTRA = 120  # sự kiện DAPT khác (nền chiến dịch, ngoài các IP APT đa-ngày)


def _is_attack(ev: dict) -> bool:
    return bool(ev.get("expected_threat") or ev.get("apt_is_attack"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=5000, help="tổng số sự kiện mong muốn")
    args = ap.parse_args()

    with open(SRC_FILE) as f:
        events = json.load(f)
    print(f"[*] Nguồn: {len(events):,} sự kiện THẬT từ data/demo.json")

    # --- 1. Các IP APT ĐA-NGÀY: lấy TRỌN để chuỗi chắc chắn kích hoạt ------- #
    days_by_ip = defaultdict(set)
    for ev in events:
        if ev.get("apt_is_attack"):
            days_by_ip[ev.get("Source IP")].add(ev.get("apt_day"))
    apt_ips = {ip for ip, ds in days_by_ip.items() if len({d for d in ds if d is not None}) >= 2}

    keep: set[int] = set()
    for i, ev in enumerate(events):
        if ev.get("Source IP") in apt_ips and ev.get("unified_source", "").startswith("dapt"):
            keep.add(i)
    print(f"[+] APT đa-ngày: {len(apt_ips)} IP -> giữ TRỌN {len(keep)} sự kiện")

    # --- 2. Adversarial: lấy TOÀN BỘ --------------------------------------- #
    adv = [i for i, e in enumerate(events) if e.get("unified_source") == "adversarial"]
    keep.update(adv)
    print(f"[+] Adversarial (OWASP thật): {len(adv)}")

    # --- 3. Zero-day ------------------------------------------------------- #
    zd = [i for i, e in enumerate(events) if e.get("unified_source") == "zeroday"]
    zd_take = zd[:: max(1, len(zd) // N_ZERODAY)][:N_ZERODAY]  # rải đều, không lấy cụm đầu
    keep.update(zd_take)
    print(f"[+] Zero-day: {len(zd_take)} / {len(zd)} (rải đều)")

    # --- 4. Tấn công CICIDS: phủ ĐỦ mọi lớp có nhãn ------------------------ #
    by_class = defaultdict(list)
    for i, e in enumerate(events):
        if _is_attack(e) and (lab := e.get("gt_label")):
            by_class[lab].append(i)
    for idxs in by_class.values():
        step = max(1, len(idxs) // PER_ATTACK_CLASS)
        keep.update(idxs[::step][:PER_ATTACK_CLASS])
    print(f"[+] Tấn công CICIDS: {len(by_class)} lớp, tối đa {PER_ATTACK_CLASS} mẫu/lớp")

    # --- 5. DAPT khác (nền chiến dịch) ------------------------------------- #
    dapt_other = [
        i
        for i, e in enumerate(events)
        if str(e.get("unified_source", "")).startswith("dapt") and i not in keep
    ]
    step = max(1, len(dapt_other) // N_DAPT_EXTRA)
    keep.update(dapt_other[::step][:N_DAPT_EXTRA])

    # --- 6. Nền BENIGN: lấp cho đủ target (rải đều toàn luồng) ------------- #
    benign = [i for i, e in enumerate(events) if not _is_attack(e) and i not in keep]
    need = max(0, args.target - len(keep))
    step = max(1, len(benign) // need) if need else 1
    keep.update(benign[::step][:need])
    print(f"[+] Nền benign: {min(need, len(benign)):,} (rải đều để Welford có baseline)")

    # --- 7. GIỮ NGUYÊN THỨ TỰ GỐC (quan hệ thời gian -> APT nổi lên đúng) -- #
    subset = [events[i] for i in sorted(keep)]

    with open(OUT_FILE, "w") as f:
        json.dump(subset, f, separators=(",", ":"))

    # --- Báo cáo phân bổ THẬT để đối chiếu --------------------------------- #
    n_atk = sum(1 for e in subset if _is_attack(e))
    print(f"\n[✓] Đã lưu {len(subset):,} sự kiện -> {OUT_FILE}")
    print(f"    Nguồn : {dict(Counter(e.get('unified_source') for e in subset).most_common())}")
    print(
        f"    Tấn công {n_atk:,} ({100 * n_atk / len(subset):.1f}%) · benign {len(subset) - n_atk:,}"
    )
    print(
        f"    Lớp tấn công: {len({e.get('gt_label') for e in subset if _is_attack(e) and e.get('gt_label')})}"
    )
    d2 = defaultdict(set)
    for e in subset:
        if e.get("apt_is_attack"):
            d2[e.get("Source IP")].add(e.get("apt_day"))
    print(f"    IP APT đa-ngày trong tập: {sum(1 for v in d2.values() if len(v) >= 2)} (cần >=1)")


if __name__ == "__main__":
    main()
