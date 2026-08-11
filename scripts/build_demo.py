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
    print("[*] Dựng luồng demo ~500k sự kiện (data THẬT, đa-ngày CICIDS)...")
    # ------------------------------------------------------------------ #
    # PHÂN BỔ demo ~500.000 sự kiện, ĐÍCH: 95% benign / 5% tấn công.
    # ------------------------------------------------------------------ #
    # Nguyên tắc: nền benign phải dày như SOC thật để Tier-1 drop phần lớn, còn phần
    # tấn công thì DỒN vào nguồn mang BẰNG CHỨNG TẦNG ỨNG DỤNG (CSIC + tiêm nhiễm) —
    # đó mới là thứ bắt Tier-2 phải suy luận và làm sáng các panel MITRE/RAG/guardrail.
    #
    # Ngân sách tấn công 5% x 500.000 = ~25.000 ca, chia theo thứ tự ưu tiên:
    #   - CSIC 2010     36.000 sự kiện = 18.000 tấn công + 18.000 lành (bộ chia 50/50 cứng
    #     trong build_csic_dataset.py). Chiếm ~72% ngân sách tấn công — CHỦ Ý: payload HTTP
    #     là nguồn duy nhất chấm được QUY KẾT kỹ thuật. 36.000 là trần thực tế: kho thô
    #     còn 36.000 normal / 25.065 anomalous, muốn 50/50 thì 36.000 là mức cao nhất
    #     vẫn giữ được nguyên tắc cân bằng.
    #   - adv_llm          730 = TOÀN BỘ kho công khai (203 deepset + 527 jackhhao).
    #     `_build_adv_llm` cắt ở `min(limit, len(order))` và KHÔNG lặp lại mẫu, nên 730 là
    #     trần cứng; xin nhiều hơn cũng chỉ nhận về 730.
    #   - CICIDS       ~460.000 ở attack_ratio 0,012 -> ~5.500 tấn công trải đủ 15 lớp THẬT.
    #     Đây là khối benign chính (~454.000) mà Tier-1 sẽ drop — đúng vai "nền nhiễu".
    #   - DAPT           1.500 dòng khối lượng (giảm từ 6.000). Panel APT KHÔNG lấy từ đây
    #     mà từ chuỗi `dapt` THẬT, nên cắt sâu vẫn giữ nguyên kill-chain đa ngày.
    #   - zero-day    10 x 15 spec = 150 probe (giảm từ 900). Nhóm này gần như luôn bị
    #     Welford bắt ngay ở Tier-1 nên không cần khối lượng lớn.
    #
    # LƯU Ý TẢI LLM: chỉ dải ESCALATE (0,65 <= C < 0,85) mới chạm Tier-2. CSIC nhiều làm
    # tăng số ca leo thang so với luồng thuần NetFlow trước đây — dùng UNIFIED_STREAM_LIMIT
    # để đẩy từng lát khi cần soi UI nhanh, backpressure trong demo.py lo phần còn lại.
    warmup, main_stream, apt_truth, n_chains = build_stream(
        # Hai tham số dưới được HIỆU CHỈNH TỪ SỐ ĐO của lượt dựng trước (477.829 sự kiện,
        # 5,66% tấn công), KHÔNG phải ước lượng: tỉ lệ giữ lại đo được 437.793/640.000 =
        # 0,6841, và các nguồn ngoài `cicids_max` đóng góp cố định 40.036 sự kiện / 20.723
        # tấn công. Từ đó suy ngược ra mức cần cho đích 500.000 sự kiện / 5,00% tấn công.
        cicids_max_rows=672_000,  # 459.964 / 0,6841 -> CICIDS ~460k sự kiện
        cicids_max_days=DEMO_DAYS,
        cicids_attack_ratio=0.0093,  # 4.277/459.964 -> tổng tấn công về đúng ~25.000 (5,00%)
        dapt_max_rows=1_500,  # chỉ đủ hiển thị; chuỗi APT thật nằm ở nguồn `dapt`
        zeroday_repeat=10,  # 10 x 15 spec = 150 probe, chủ yếu bị Tier-1 bắt
        csic_max=36_000,  # trần cân bằng 50/50 của kho CSIC 2010 đã dựng lại
        adv_llm_max=730,  # TOÀN BỘ kho tiêm nhiễm/jailbreak công khai
    )
    stream = warmup + main_stream  # warmup giữ prefix; main đã sort theo thời gian

    # demo_signals=True: đính threat-intel THẬT (giai đoạn + TTP DAPT2020) cho DAPT tấn công
    # -> Tier-2 ánh xạ ĐA DẠNG kỹ thuật. CHỈ luồng demo, KHÔNG ảnh hưởng benchmark datatest.json.
    enriched_logs = [enrich(ev, demo_signals=True) for ev in stream]

    out_file = os.path.join(ROOT, "data", "demo.json")
    # Ghi COMPACT (không indent) — file ~500k event, indent=2 sẽ phình gấp đôi. Máy đọc thôi.
    with open(out_file, "w") as f:
        json.dump(enriched_logs, f, separators=(",", ":"))

    # Báo cáo phân bổ THẬT để đối chiếu (đẹp + trung thực).
    n = len(enriched_logs)
    dist = Counter(e.get("unified_source") for e in enriched_logs)
    n_attack = sum(1 for e in enriched_logs if e.get("expected_threat") or e.get("apt_is_attack"))
    labels = Counter(str(e.get("gt_label") or "") for e in enriched_logs)
    n_class = len([k for k in labels if k and k not in ("Benign", "None")])
    print(f"[+] Đã lưu {n:,} sự kiện enriched -> {out_file}")
    print(f"    Phân bổ nguồn: {dict(dist.most_common())}")
    print(
        f"    Tấn công/threat: {n_attack:,} ({100 * n_attack / n:.2f}%)  |  "
        f"benign (Tier-1 drop): {n - n_attack:,} ({100 * (n - n_attack) / n:.2f}%)"
    )
    print(f"    Số lớp tấn công phân biệt được: {n_class}")
    print(f"    Chuỗi APT đa-ngày: {n_chains} (mốc chân lý: {len(apt_truth)} IP)")


if __name__ == "__main__":
    main()
