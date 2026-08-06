"""SENTINEL — Tỉ lệ xả tải là HÀM của base-rate tấn công, không phải hằng số của hệ.

KHOẢNG TRỐNG ĐANG LẤP. `measure_latency_baseline.py` cho một con số xả tải duy nhất (74,0%) đo
trên luồng benchmark có 26% tấn công. Câu hỏi hiển nhiên tiếp theo — *"lưu lượng doanh nghiệp thật
chỉ vài phần trăm tấn công thì xả tải bao nhiêu?"* — trước đây chỉ trả lời được bằng phỏng đoán
(">90%"), mà phỏng đoán thì không trích vào luận văn được.

CÁCH LÀM. Xả tải không phải một số, nó là trung bình có trọng số của HAI số:

    xả_tải(p) = (1 − p) · xả_tải_trên_LÀNH  +  p · xả_tải_trên_TẤN_CÔNG

`p` là tỉ lệ tấn công của luồng. Hai vế bên phải là tính chất CỦA HỆ, đo một lần là xong; `p` là
tính chất CỦA MÔI TRƯỜNG. Tách ra rồi thì mọi tuyên bố về base-rate khác đều SUY RA ĐƯỢC từ số đo,
không phải đoán — và cũng thấy ngay vì sao con số benchmark thấp: nó lấy `p = 0,26`.

Đường đi mô phỏng ĐÚNG `subscriber.py`: Tier-1 tự xử (BLOCK/DROP/ALERT/HITL) là XONG; chỉ
`action == "ESCALATE"` mới tới Cổng ML; Cổng ML trả `None` mới thật sự tốn một lần gọi LLM.

Thuần offline, KHÔNG cần LLM. Chạy:
    .venv/bin/python experiments/measure_offload_vs_baserate.py
"""

import argparse
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import wilson_ci  # noqa: E402
from experiments.unified_dataset import (  # noqa: E402
    ESCALATE_ACTION,
    ROOT,
    build_stream,
)
from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

OUT_JSON = os.path.join(ROOT, "experiments", "results", "offload_vs_baserate.json")
DEMO_JSON = os.path.join(ROOT, "data", "demo.json")
N_WARMUP = 150  # số flow LÀNH đầu tiên chỉ dùng học baseline Welford, KHÔNG chấm

# Base-rate để chiếu. 0,26 = luồng benchmark hiện tại (giữ để đối chiếu); các mốc còn lại lấy
# theo dải thường gặp ở lưu lượng doanh nghiệp — nêu là KỊCH BẢN, không phải số đo môi trường.
BASE_RATES = [0.26, 0.20, 0.15, 0.10, 0.05, 0.02, 0.01]


def _engine() -> RuleEngine:
    """Engine sạch: TẮT danh tiếng để tiền sử tích luỹ từ lượt trước không nhiễm vào phép đo."""
    e = RuleEngine()
    e.dynamic_ip_blocks = set()
    e.dynamic_behavioral_rules = []
    e.reputation_enforcement = False
    return e


def _nap_demo():
    """`data/demo.json` — 99.867 sự kiện, ~9,7% tấn công: dạng luồng SOC THẬT (nền lành áp đảo).

    Mỗi dòng ĐÃ là log phẳng (không bọc trong khoá `log` như `build_stream`), kèm `expected_threat`
    và `unified_source`. Lấy `N_WARMUP` flow LÀNH đầu tiên làm mồi Welford rồi loại khỏi phép chấm
    — chấm trên chính tập đã học baseline là test-on-train.
    """
    with open(DEMO_JSON, encoding="utf-8") as f:
        rows = json.load(f)
    warm, chinh = [], []
    for r in rows:
        atk = bool(r.get("expected_threat"))
        if not atk and len(warm) < N_WARMUP:
            warm.append({"log": r, "expected_threat": False})
        else:
            chinh.append({"log": r, "expected_threat": atk})
    return warm, chinh


def main():
    ap = argparse.ArgumentParser(description="Xả tải theo base-rate tấn công")
    ap.add_argument(
        "--source",
        choices=["stream", "demo"],
        default="stream",
        help="stream = build_stream() 26%% tấn công (benchmark); demo = data/demo.json 100k, ~9,7%% (dạng SOC thật)",
    )
    args = ap.parse_args()

    print("=" * 84)
    print(f"  SENTINEL — Xả tải theo base-rate tấn công  ·  nguồn = {args.source}")
    print("=" * 84)

    if args.source == "demo":
        warmup, main_events = _nap_demo()
    else:
        warmup, main_events, _apt, _n = build_stream()
    print(f"[*] {len(warmup)} warmup + {len(main_events)} sự kiện chấm")
    engine, gateway = _engine(), MLGateway()

    for ev in warmup:  # chỉ để học baseline Welford — KHÔNG chấm
        engine.evaluate(ev["log"])

    # [lành, tấn công] × [chặn ở Tier-1, chặn ở Cổng ML, tới LLM]
    dem = {
        False: {"tier1": 0, "ml": 0, "llm": 0},
        True: {"tier1": 0, "ml": 0, "llm": 0},
    }
    for ev in main_events:
        atk = bool(ev.get("expected_threat") or ev.get("is_attack"))
        res = engine.evaluate(dict(ev["log"]))
        if res.get("tier1_action") != ESCALATE_ACTION:
            dem[atk]["tier1"] += 1
            continue
        ml_action, _r, _c = gateway.evaluate(dict(ev["log"]))
        dem[atk]["ml" if ml_action else "llm"] += 1

    ket = {}
    for atk, ten in ((False, "lanh_tinh"), (True, "tan_cong")):
        d = dem[atk]
        n = d["tier1"] + d["ml"] + d["llm"]
        xa = d["tier1"] + d["ml"]
        ket[ten] = {
            "n": n,
            "chan_tier1": d["tier1"],
            "chan_cong_ml": d["ml"],
            "toi_llm": d["llm"],
            "offload_rate": round(xa / n, 4) if n else None,
            "offload_ci95": [round(x, 4) for x in wilson_ci(xa, n)] if n else None,
        }
        print(
            f"\n{ten:10} n={n:6}  Tier-1={d['tier1']:6}  CổngML={d['ml']:6}  "
            f"LLM={d['llm']:5}  ->  XẢ TẢI {xa / n:.2%}"
            if n
            else f"\n{ten}: rỗng"
        )

    ob = ket["lanh_tinh"]["offload_rate"]
    oa = ket["tan_cong"]["offload_rate"]
    print("\n" + "-" * 84)
    print("  CHIẾU SANG BASE-RATE KHÁC   xả_tải(p) = (1-p)·xả_lành + p·xả_tấn_công")
    print("-" * 84)
    chieu = []
    for p in BASE_RATES:
        v = (1 - p) * ob + p * oa
        chieu.append({"attack_rate": p, "offload_rate": round(v, 4)})
        ghi = "  <- luồng benchmark hiện tại" if abs(p - 0.26) < 1e-9 else ""
        print(f"    tấn công {p:5.0%}  ->  xả tải {v:6.2%}{ghi}")
    print("-" * 84)

    out: dict[str, object] = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "n_events": sum(k["n"] for k in ket.values()),
        "theo_nhan": ket,
        "chieu_base_rate": chieu,
        "cong_thuc": "offload(p) = (1-p)*offload_benign + p*offload_attack",
        "cach_doc": (
            "offload_benign/offload_attack là tính chất CỦA HỆ (đo một lần). `p` là tính chất "
            "CỦA MÔI TRƯỜNG. Các dòng chiếu là SUY RA từ hai số đo đó, KHÔNG phải đo trên lưu "
            "lượng doanh nghiệp thật — nói đúng như vậy khi trích. Giả định của phép chiếu: "
            "phân bố loại tấn công và loại lưu lượng lành giữ nguyên khi đổi tỉ lệ trộn."
        ),
    }
    out["nguon"] = args.source
    n_tong = sum(k["n"] for k in ket.values())
    t1 = ket["lanh_tinh"]["chan_tier1"] + ket["tan_cong"]["chan_tier1"]
    mlg = ket["lanh_tinh"]["chan_cong_ml"] + ket["tan_cong"]["chan_cong_ml"]
    llm = ket["lanh_tinh"]["toi_llm"] + ket["tan_cong"]["toi_llm"]
    # Số ĐẦU BẢNG — cái sẽ bị trích. Tính ở đây thay vì để người đọc tự cộng bốn ô trong
    # `theo_nhan`, vì mỗi lần cộng tay là một lần có thể cộng nhầm.
    out.update(
        {
            "attack_rate_do_duoc": round(ket["tan_cong"]["n"] / n_tong, 4) if n_tong else None,
            "offload_tong": round((t1 + mlg) / n_tong, 4) if n_tong else None,
            "offload_tong_ci95": [round(x, 4) for x in wilson_ci(t1 + mlg, n_tong)]
            if n_tong
            else None,
            "chan_tier1_tong": t1,
            "chan_cong_ml_tong": mlg,
            "toi_llm_tong": llm,
            "ti_le_chan_tier1": round(t1 / n_tong, 4) if n_tong else None,
            "ti_le_chan_cong_ml": round(mlg / n_tong, 4) if n_tong else None,
            "ti_le_toi_llm": round(llm / n_tong, 4) if n_tong else None,
        }
    )
    print(
        f"\nTỔNG   xả tải {out['offload_tong']:.2%}  "
        f"(Tier-1 {out['ti_le_chan_tier1']:.2%} + Cổng ML {out['ti_le_chan_cong_ml']:.2%})  "
        f"·  tới LLM {out['ti_le_toi_llm']:.2%}"
    )
    duong = OUT_JSON.replace(".json", f"_{args.source}.json")
    os.makedirs(os.path.dirname(duong), exist_ok=True)
    with open(duong, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] JSON: {duong}")


if __name__ == "__main__":
    main()
