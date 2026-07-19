import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import build_stream, enrich

# 10 ngày CICIDS2018 THẬT — phủ ĐỦ 14 loại tấn công + benign khắp nơi (nguồn khối lượng
# cho demo 100k). Mỗi ngày build_stream lấy ~25% tấn công / 75% benign (nhiều benign để drop).
DEMO_DAYS = (
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",  # Bot
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS Hulk / SlowHTTPTest
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",  # DoS GoldenEye / Slowloris
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS HOIC / LOIC-UDP
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS LOIC-HTTP (tên file gốc sai chính tả)
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",  # SSH / FTP-BruteForce
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",  # Infiltration
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",  # Web BF / XSS / SQLi
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",  # benign-heavy
)


def main():
    print("[*] Generating ~100k unified stream for DEMO (data THẬT, đa-ngày CICIDS)...")
    # CICIDS ~84k (đa dạng 14 loại + nhiều benign), DAPT ~12k, zero-day ~3k (real-derived),
    # adversarial 4 (OWASP THẬT). Lấy TẤT CẢ event trong stream (không lấy mẫu con).
    warmup, main_stream, apt_truth, n_chains = build_stream(
        cicids_max_rows=120_000,  # per-ngày cao hơn để bù ngày thiếu benign -> CICIDS ~88k
        cicids_max_days=DEMO_DAYS,
        dapt_max_rows=12_000,  # day2..day5 (có tấn công THẬT) -> ~12k DAPT
        zeroday_repeat=200,  # 200 x 15 spec = ~3000 probe zero-day (nền benign THẬT, IP riêng)
    )
    stream = warmup + main_stream  # warmup giữ prefix; main đã sort theo thời gian

    # demo_signals=True: đính threat-intel THẬT (giai đoạn + TTP DAPT2020) cho DAPT tấn công
    # -> Tier-2 ánh xạ ĐA DẠNG kỹ thuật. CHỈ luồng demo, KHÔNG ảnh hưởng benchmark datatest.json.
    enriched_logs = [enrich(ev, demo_signals=True) for ev in stream]

    out_file = os.path.join(ROOT, "data", "demo.json")
    # Ghi COMPACT (không indent) — file ~100k event, indent=2 sẽ phình gấp đôi. Máy đọc thôi.
    with open(out_file, "w") as f:
        json.dump(enriched_logs, f, separators=(",", ":"))

    # Báo cáo phân bổ THẬT để đối chiếu (đẹp + trung thực).
    dist = Counter(e.get("unified_source") for e in enriched_logs)
    n_attack = sum(1 for e in enriched_logs if e.get("expected_threat") or e.get("apt_is_attack"))
    print(f"[+] Đã lưu {len(enriched_logs)} sự kiện enriched -> {out_file}")
    print(f"    Phân bổ nguồn: {dict(dist.most_common())}")
    print(
        f"    Ước lượng tấn công/threat: {n_attack}  |  còn lại benign (drop): {len(enriched_logs) - n_attack}"
    )


if __name__ == "__main__":
    main()
