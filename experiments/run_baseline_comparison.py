"""SENTINEL — So sánh với BASELINE NGOÀI (đối chứng cho kiến trúc 2 tầng).

VÌ SAO CẦN: toàn bộ ablation A–F chỉ so SENTINEL với CHÍNH NÓ (bỏ bớt cấu phần). Không
có một dòng nào trả lời câu hỏi mà hội đồng gần như chắc chắn đặt ra: *"so với một IDS
thông thường thì hơn ở chỗ nào?"*. Script này bổ sung hai mốc đối chứng, chạy trên CÙNG
`datatest.json` và CÙNG giao ước nhãn `_is_threat()` — nên số đặt cạnh nhau được.

  H0 — Đoán hằng (ZeroR)   : mốc sàn tuyệt đối, luôn hô một lớp.
  H1 — Chữ ký tĩnh đơn thuần: proxy cho IDS truyền thống kiểu Snort/Suricata. Chỉ luật
       cổng + ngưỡng khối lượng + 29 họ chữ ký WAF; KHÔNG Welford, KHÔNG ML, KHÔNG LLM.
       Tái dùng `static_only_action()` đã có trong `unified_dataset.py`.
  H2 — ML đơn tầng          : chính mô hình LightGBM đang dùng, nhưng áp NGƯỠNG PHẲNG 0.5
       cho MỌI sự kiện — bỏ chính sách 4 dải, bỏ abstain/OOD, bỏ Tier-1, bỏ LLM. Đây là
       "chỉ ném một bộ phân loại vào bài toán", tức baseline học máy kinh điển.
  H3 — LLM-only (`--with-llm`): MỌI sự kiện đi thẳng lên tác tử Tier-2, không Tier-1,
       không Cổng ML. Đây là proxy TRUNG THỰC cho "một dự án chỉ ném LLM vào SOC" và là
       cách HỢP LỆ DUY NHẤT để trả lời "hơn các hệ LLM-SOC khác ở đâu": cùng dữ liệu, cùng
       mô hình, cùng prompt, cùng giao ước chấm, nên chênh lệch quy được về KIẾN TRÚC.
       Chép số headline của CyberRAG/LanG/SplunkLLM vào một bảng thì KHÔNG hợp lệ — khác
       tập, khác tác vụ, khác định nghĩa chỉ số, khác phần cứng. Vì mỗi sự kiện tốn một
       lượt suy luận (~5 s), H3 chạy trên mẫu con phân tầng và MỌI cấu hình khác được chấm
       LẠI trên đúng mẫu con đó.

ĐỌC KẾT QUẢ CHO ĐÚNG: **kỳ vọng H2 thắng SENTINEL về F1/MCC thuần**, vì SENTINEL cố ý
KHÔNG quyết những ca nó không chắc (abstain -> LLM/người). Đó không phải thất bại — luận
điểm của luận văn là giảm tải LLM, độ trễ, và tính giải thích, chứ không phải "phân loại
giỏi hơn". Một so sánh trung thực làm luận điểm SẮC hơn; giấu nó đi mới là điểm yếu.

Vì sao KHÔNG huấn luyện mô hình cổ điển mới: `ml_lab/train_and_compare.py` đã so 5 mô hình
lúc CHỌN mô hình, nhưng đó là trên tập huấn luyện chứ không phải benchmark luận văn; và
`ml_lab/dataset_1m.csv` không còn trong repo. Tái dùng artifact sẵn có vừa trung thực vừa
tái lập được.

H0–H2 thuần ĐỌC, KHÔNG cần LLM. Chạy:
    .venv/bin/python experiments/run_baseline_comparison.py
    .venv/bin/python experiments/run_baseline_comparison.py --limit 500
    .venv/bin/python experiments/run_baseline_comparison.py --with-llm --llm-limit 150
"""

import argparse
import json
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.evaluate_ml_gate import _is_threat  # noqa: E402
from experiments.metrics_core import confusion_report, throughput  # noqa: E402
from experiments.unified_dataset import static_only_action  # noqa: E402
from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "datatest.json")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "baseline_comparison_results.json")

THREAT_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}
# Ngưỡng nhị phân trung dung cho H2 — CỐ Ý không phải 0.85/0.65/0.40 của SENTINEL, vì
# điểm của baseline là "không có chính sách nhiều dải".
PLAIN_THRESHOLD = 0.5


def _score(preds: list[tuple[bool, bool]], elapsed: float, name: str, desc: str) -> dict:
    """preds = [(nhãn_thật_là_tấn_công, hệ_gắn_cờ)] -> gói chỉ số đầy đủ."""
    tp = sum(1 for t, p in preds if t and p)
    fp = sum(1 for t, p in preds if not t and p)
    tn = sum(1 for t, p in preds if not t and not p)
    fn = sum(1 for t, p in preds if t and not p)
    rep = confusion_report(tp, fp, tn, fn)
    return {
        "name": name,
        "description": desc,
        **rep,
        "throughput_eps": throughput(len(preds), elapsed),
        "wall_seconds": round(elapsed, 3),
    }


def baseline_zero_r(events: list) -> dict:
    """H0 — luôn hô lớp ĐA SỐ. Mốc sàn: mọi thứ phải vượt được cái này."""
    t0 = time.perf_counter()
    labels = [_is_threat(e) for e in events]
    predict_attack = sum(labels) * 2 > len(labels)  # lớp đa số
    preds = [(t, predict_attack) for t in labels]
    return _score(
        preds,
        time.perf_counter() - t0,
        "H0_zero_r",
        f"Đoán hằng lớp đa số ({'attack' if predict_attack else 'benign'}) — mốc sàn",
    )


def baseline_static_signature(events: list) -> dict:
    """H1 — IDS chữ ký truyền thống (proxy). Không thống kê, không học, không LLM."""
    engine = RuleEngine()
    t0 = time.perf_counter()
    preds = []
    for ev in events:
        act = static_only_action(engine, ev)
        preds.append((_is_threat(ev), act in THREAT_ACTIONS))
    return _score(
        preds,
        time.perf_counter() - t0,
        "H1_static_signature",
        "Chỉ luật tĩnh + 29 họ chữ ký WAF (proxy Snort/Suricata) — không Welford/ML/LLM",
    )


def baseline_ml_flat(events: list) -> dict:
    """H2 — ML đơn tầng, ngưỡng phẳng 0.5, KHÔNG abstain: mô hình buộc phải quyết mọi ca.

    Khác Cổng ML thật ở đúng chỗ tạo nên kiến trúc: ở đây không có dải ESCALATE, không có
    OOD-abstain, không có kiểm tra phủ đặc trưng. Ca nào model không đủ dữ liệu thì vẫn
    phải đoán — đúng như một bộ phân loại đơn thuần hành xử.
    """
    gw = MLGateway()
    if not gw.pipeline:
        return {"name": "H2_ml_flat", "error": "không nạp được ml_lab/tier_2_model.pkl"}
    model, scaler = gw.pipeline["model"], gw.pipeline["scaler"]
    features = gw.pipeline.get("features", [])

    t0 = time.perf_counter()
    preds = []
    for ev in events:
        x, _n_san, _n_pres = gw._build_raw_vector(ev, features)
        try:
            proba = model.predict_proba(scaler.transform(x))[0]
            pred_attack = float(proba[1]) >= PLAIN_THRESHOLD
        except Exception:
            pred_attack = False  # baseline không có đường thoát an toàn — đoán benign
        preds.append((_is_threat(ev), pred_attack))
    out = _score(
        preds,
        time.perf_counter() - t0,
        "H2_ml_flat",
        f"LightGBM đơn tầng, ngưỡng phẳng {PLAIN_THRESHOLD}, KHÔNG abstain/4-dải/Tier-1/LLM",
    )
    out["threshold"] = PLAIN_THRESHOLD
    return out


def sentinel_tier1_ml(events: list) -> dict:
    """SENTINEL (phần tất định: Tier-1 + Cổng ML) trên CÙNG tập, để đặt cạnh baseline.

    Ca Cổng ML từ chối quyết (abstain/skip) được tính là **có gắn cờ**: trong hệ thật
    chúng đi tiếp lên LLM/người chứ không bị thả. Tính là "bỏ qua" sẽ thổi phồng
    specificity một cách gian lận.
    """
    engine = RuleEngine()
    gw = MLGateway()
    t0 = time.perf_counter()
    preds, n_abstain = [], 0
    for ev in events:
        res = engine.evaluate(dict(ev))
        act = res.get("tier1_action", "DROP")
        if act == "ESCALATE":
            ml_action, _r, _c = gw.evaluate(ev)
            if ml_action is None:
                n_abstain += 1
                flagged = True  # abstain -> lên LLM/người => vẫn là "chưa cho qua"
            else:
                flagged = ml_action in {"BLOCK_IP", "ALERT"}
        else:
            flagged = act in THREAT_ACTIONS
        preds.append((_is_threat(ev), flagged))
    out = _score(
        preds,
        time.perf_counter() - t0,
        "SENTINEL_tier1_ml",
        "Tier-1 (luật + Welford) + Cổng ML 4 dải; abstain tính là CHƯA cho qua",
    )
    out["n_abstain_to_llm"] = n_abstain
    return out


def baseline_llm_only(events: list) -> dict:
    """H3 — "chỉ ném một LLM vào SOC": MỌI sự kiện đi thẳng lên tác tử Tier-2.

    VÌ SAO ĐÂY LÀ BASELINE QUAN TRỌNG NHẤT. Câu hỏi hội đồng chắc chắn hỏi là "hơn các dự
    án dùng LLM cho SOC ở chỗ nào?". KHÔNG thể trả lời bằng cách chép số headline của
    CyberRAG/LanG/SplunkLLM vào một bảng: mỗi công trình đo trên tập khác, tác vụ khác,
    định nghĩa chỉ số khác và phần cứng khác, nên bảng đó sập ngay câu hỏi đầu tiên về tính
    so sánh được. H3 trả lời đúng câu ấy một cách hợp lệ: CÙNG dữ liệu, CÙNG mô hình, CÙNG
    prompt, CÙNG giao ước chấm — chỉ bỏ đi Tier-1 và Cổng ML. Chênh lệch quan sát được vì
    vậy quy được về đúng KIẾN TRÚC, thứ duy nhất đã thay đổi.

    ĐẮT: mỗi sự kiện là một lượt suy luận (~5 s). Luôn chạy trên mẫu con phân tầng, và mọi
    cấu hình khác cũng được chấm lại trên ĐÚNG mẫu con đó — so 150 ca của H3 với 3.204 ca
    của SENTINEL là so hai thứ khác nhau.
    """
    from src.agent.state import SentinelState
    from src.agent.workflow import agent_app
    from src.guardrails import loop_detector

    t0 = time.perf_counter()
    preds: list[tuple[bool, bool]] = []
    n_err = 0
    for i, ev in enumerate(events, 1):
        loop_detector.reset()  # bộ đếm cộng dồn theo luồng; thiếu -> FORCE_STOP sau 10 lượt
        flagged = True  # suy biến an toàn: agent hỏng -> coi như CHƯA cho qua
        try:
            final = agent_app.invoke(
                SentinelState(current_batch_logs=[dict(ev)], current_batch_size=1)
            )
            decisions = final.get("decisions", [])
            if decisions:
                flagged = str(decisions[-1].get("action", "")).upper() in THREAT_ACTIONS
            else:
                n_err += 1
        except Exception:  # noqa: BLE001 — một sự kiện lỗi không được giết cả phép so
            n_err += 1
        preds.append((_is_threat(ev), flagged))
        if i % 25 == 0:
            print(f"    ... H3 {i}/{len(events)} ({time.perf_counter() - t0:.0f}s)")

    out = _score(
        preds,
        time.perf_counter() - t0,
        "H3_llm_only",
        "Mọi sự kiện đi thẳng lên tác tử Tier-2; KHÔNG Tier-1, KHÔNG Cổng ML",
    )
    out["n_agent_errors"] = n_err
    return out


def _stratified(events: list, n: int) -> list:
    """Mẫu con BƯỚC ĐỀU trên toàn tập — giữ tỉ lệ lớp, tất định, không phải N mẫu đầu."""
    if n >= len(events):
        return events
    stride = len(events) / n
    return [events[int(i * stride)] for i in range(n)]


def main():
    ap = argparse.ArgumentParser(description="So sánh SENTINEL với baseline ngoài (offline)")
    ap.add_argument("--data", default=DATA_PATH)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=OUT_JSON)
    ap.add_argument(
        "--with-llm",
        action="store_true",
        help="thêm H3 (LLM-only) — CẦN LLM server, chạy trên mẫu con phân tầng",
    )
    ap.add_argument("--llm-limit", type=int, default=150, help="cỡ mẫu con cho H3")
    args = ap.parse_args()

    if not os.path.exists(args.data):
        print(f"[-] Không thấy data: {args.data} — chạy scripts/build_datatest.py trước.")
        sys.exit(1)
    with open(args.data, encoding="utf-8") as f:
        events = json.load(f)
    if args.limit:
        events = events[: args.limit]

    print("=" * 88)
    print("  SENTINEL — ĐỐI CHỨNG VỚI BASELINE NGOÀI")
    print("=" * 88)
    print(f"[*] {len(events)} sự kiện từ {os.path.basename(args.data)}\n")

    rows = [
        baseline_zero_r(events),
        baseline_static_signature(events),
        baseline_ml_flat(events),
        sentinel_tier1_ml(events),
    ]

    hdr = f"{'Cấu hình':22s} {'MCC':>7s} {'F1':>7s} {'P':>7s} {'R':>7s} {'Spec':>7s} {'EPS':>10s}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        if "error" in r:
            print(f"{r['name']:22s} {r['error']}")
            continue
        print(
            f"{r['name']:22s} {r['mcc']:>7.3f} {r['f1']:>7.3f} {r['precision']:>7.3f} "
            f"{r['recall']:>7.3f} {r['specificity']:>7.3f} {r['throughput_eps']:>10.1f}"
        )

    print(
        "\nĐỌC BẢNG: nếu H2 (ML đơn tầng) có F1/MCC cao hơn SENTINEL, đó là ĐÚNG KỲ VỌNG —\n"
        "SENTINEL cố ý KHÔNG tự quyết ca không chắc mà đẩy lên LLM/người. Đóng góp của\n"
        "kiến trúc nằm ở giảm tải LLM, độ trễ và tính giải thích, không ở F1 thuần. So H1\n"
        "với SENTINEL mới là phép so đúng trọng tâm 'hơn IDS chữ ký ở đâu'."
    )

    # ---- H3 (LLM-only): chỉ khi được yêu cầu, và trên MẪU CON so được ----------- #
    llm_block = None
    if args.with_llm:
        subset = _stratified(events, args.llm_limit)
        print(
            f"\n[*] H3 (LLM-only) trên mẫu con {len(subset)} sự kiện — MỌI cấu hình khác\n"
            f"    cũng được chấm LẠI trên đúng mẫu con này, nếu không thì không so được."
        )
        llm_rows = [
            baseline_zero_r(subset),
            baseline_static_signature(subset),
            baseline_ml_flat(subset),
            sentinel_tier1_ml(subset),
            baseline_llm_only(subset),
        ]
        print(f"\n  [MẪU CON n={len(subset)}]")
        print(hdr)
        print("-" * len(hdr))
        for r in llm_rows:
            if "error" in r:
                print(f"{r['name']:22s} {r['error']}")
                continue
            print(
                f"{r['name']:22s} {r['mcc']:7.4f} {r['f1']:7.4f} {r['precision']:7.4f} "
                f"{r['recall']:7.4f} {r['specificity']:7.4f} {r['throughput_eps']:10.1f}"
            )
        print(
            "\nĐỌC KHỐI NÀY: H3 là proxy TRUNG THỰC cho 'một dự án chỉ ném LLM vào SOC' —\n"
            "cùng dữ liệu, cùng mô hình, cùng prompt, chỉ bỏ Tier-1 và Cổng ML. Nếu H3 có\n"
            "recall ngang SENTINEL nhưng specificity thấp hơn nhiều và EPS kém vài bậc, đó\n"
            "chính là luận điểm kiến trúc — nêu CẢ BA cột, đừng chỉ nêu cột thắng."
        )
        llm_block = {"n_subset": len(subset), "rows": llm_rows}

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset": os.path.basename(args.data),
                "n_events": len(events),
                "baselines": rows,
                "llm_subset_comparison": llm_block,
                "how_to_read": (
                    "H2 thắng SENTINEL về F1 thuần là kỳ vọng thiết kế (SENTINEL abstain "
                    "thay vì đoán bừa). Phép so trọng tâm là H1 (IDS chữ ký) vs SENTINEL, "
                    "và H3 (LLM-only) vs SENTINEL cho câu hỏi 'hơn các dự án LLM-SOC khác "
                    "ở đâu' — H3 là phép so HỢP LỆ duy nhất cho câu hỏi đó vì nó dùng cùng "
                    "dữ liệu/mô hình/prompt; chép số headline của công trình khác vào bảng "
                    "là KHÔNG hợp lệ (khác tập, khác tác vụ, khác định nghĩa chỉ số)."
                ),
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    print(f"\n[+] JSON: {args.out}")


if __name__ == "__main__":
    main()
