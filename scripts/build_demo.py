import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

# enrich + build_stream dùng chung từ unified_dataset — KHÔNG copy tay (1 nguồn chân lý)
from experiments.unified_dataset import BENCHMARK_DAYS, build_stream, enrich

# 10 ngày CICIDS2018 THẬT — phủ ĐỦ 15 loại tấn công + benign khắp nơi (nguồn khối lượng cho
# demo 100k). Mỗi ngày build_stream lấy ~25% tấn công / 75% benign (nhiều benign để drop).
#
# DÙNG CHUNG danh sách với benchmark thay vì chép tay: trước đây đúng danh sách này tồn tại
# ở BA nơi (đây, build_datatest.py, và mặc định của build_stream), nên sửa một chỗ là hai
# chỗ kia trôi lệch trong im lặng — demo và benchmark chạy trên hai nền dữ liệu khác nhau
# mà không có gì báo.
DEMO_DAYS = BENCHMARK_DAYS


def main():
    print("[*] Generating ~100k unified stream for DEMO (data THẬT, đa-ngày CICIDS)...")
    # PHÂN BỔ demo ~100k, ưu tiên NỀN BENIGN DÀY (giống SOC thật: đại đa số log là vô hại)
    # để Tier-1 drop phần lớn và GIẢM TẢI LLM, nhưng vẫn giữ ĐỦ tín hiệu cho MỌI panel UI:
    #   - cicids_max ~91k, tỉ lệ tấn công 6% (thay vì 25%): vẫn phủ ĐỦ 15 lớp tấn công THẬT
    #     (mỗi ngày lấy mẫu ngẫu nhiên từ pool tấn công của ngày đó) -> cột MITRE + Tier-1
    #     block vẫn đa dạng, nhưng KHÔNG còn khối lượng DoS/DDoS lặp làm ngập LLM.
    #   - dapt_max 6k (giảm từ 12k): đây chỉ là nguồn KHỐI LƯỢNG; panel APT KHÔNG phụ thuộc
    #     nguồn này mà lấy từ `dapt` (chuỗi DAPT2020 THẬT) -> cắt an toàn, không mất APT.
    #   - zero-day 60 x 15 spec = 900 probe (đủ để panel zero-day có số, giảm từ 3000).
    #   - adversarial 4 (OWASP THẬT) giữ nguyên.
    warmup, main_stream, apt_truth, n_chains = build_stream(
        cicids_max_rows=125_000,  # yêu cầu cao hơn để bù ngày thiếu benign -> CICIDS ~91k
        cicids_max_days=DEMO_DAYS,
        cicids_attack_ratio=0.06,  # nền benign dày (94%) -> ít ca leo thang hơn hẳn
        dapt_max_rows=6_000,  # nguồn khối lượng DAPT; chuỗi APT lấy từ `dapt` nên vẫn nguyên
        zeroday_repeat=60,  # 60 x 15 spec = ~900 probe zero-day (nền benign THẬT, IP riêng)
        # CSIC 2010 — bằng chứng tầng ỨNG DỤNG THẬT, thay hai nguồn BIÊN SOẠN đã GỠ HẲN
        # (`grayzone` 18 + `webattack` 69). Chúng từng là nguồn DUY NHẤT mang payload trong
        # luồng, nên toàn bộ chỉ số "quy kết kỹ thuật" của đồ án đứng trên 69 mẫu do chính
        # tác giả viết ra — cỡ mẫu quá nhỏ và tự ra đề tự chấm.
        #
        # 8.000 = toàn bộ `data/csic.json`. Trong luồng ~100k thì đây là ~8% sự kiện mang
        # payload thật, đủ để nhóm chấm QUY KẾT có cỡ mẫu nghiêm túc mà không lấn át nền
        # NetFlow (thứ phản ánh đúng hồ sơ tải của một SOC mạng).
        csic_max=8_000,
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
