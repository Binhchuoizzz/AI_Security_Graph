"""
SENTINEL — Unified Streaming Evaluation (OFFLINE, tất định)
==========================================================
THAY THẾ phương pháp đánh giá "3 luồng tách rời" cũ (CICIDS / DAPT nạp-sẵn /
zero-day chạy riêng), vốn có 2 nhược điểm:
  - DAPT bị nạp TOÀN BỘ chuỗi vào Threat Memory rồi mới `check_apt_chain`
    -> vòng luẩn quẩn (đã báo trước đáp án), không chứng minh được năng lực
    phát hiện APT nổi lên dần.
  - Zero-day và CICIDS chạy ở hai script riêng, không phản ánh một SOC thực tế
    nơi mọi traffic trộn lẫn trên cùng một dòng thời gian.

Cách làm MỚI: gộp cả 3 nguồn vào MỘT luồng sự kiện sắp theo thời gian (dựng bởi
`experiments/unified_dataset.py`), stream TĂNG DẦN qua hệ thống THẬT (Tier-1
RuleEngine + Welford + Threat Memory) với bộ nhớ KHỞI TẠO SẠCH. Nhờ đó:
  1. Phân loại (CICIDS): đo trên stream trộn thật.
  2. APT (DAPT): bộ nhớ tích lũy TỪ stream; `check_apt_chain` chỉ bật sau khi
     đủ sự kiện đa ngày -> phát hiện EMERGENT, đo "độ trễ phát hiện".
  3. Zero-day: outlier signature-less, rule tĩnh bỏ sót nhưng Welford bắt được,
     baseline học ngay từ traffic benign trong cùng luồng.

Bộ DỰNG dữ liệu (build_stream, map_cicids...) nằm ở `unified_dataset.py` để luồng
ONLINE (`scripts/build_datatest.py` → `scripts/demo.py`/`push_datatest.py`)
và các thí nghiệm rigor cùng dùng chung.

Chạy offline (Tier-1 + Memory, tất định, không cần LLM server):
    .venv/bin/python experiments/evaluate_unified_stream.py
"""

import json
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import (  # noqa: E402
    bootstrap_ci,
    confusion_report,
    ip_containment,
    per_class_report,
    weakest_classes,
)
from experiments.unified_dataset import (  # noqa: E402
    ROOT,
    build_stream,
    score_stream,
    warn_unhandled,
)
from src.agent.threat_memory import ThreatMemoryStore  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402


def _f1_of_pairs(pairs) -> float:
    """F1 tính lại từ danh sách cặp (is_threat, flagged) — dùng cho bootstrap CI."""
    tp = sum(1 for t, f in pairs if t and f)
    fp = sum(1 for t, f in pairs if not t and f)
    fn = sum(1 for t, f in pairs if t and not f)
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * p * r / (p + r) if (p + r) else 0.0


EVAL_MEM_DB = os.path.join(ROOT, "experiments", ".unified_eval_memory.db")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "unified_stream_results.json")
REPORT_MD = os.path.join(ROOT, "reports", "unified_stream_evaluation_report.md")


# --------------------------------------------------------------------------- #
# Run the unified stream through the real system
# --------------------------------------------------------------------------- #
def run():
    print("=" * 70)
    print("  SENTINEL — UNIFIED STREAMING EVALUATION (1 luồng gộp, memory sạch)")
    print("=" * 70)

    # Bộ nhớ THẬT nhưng dùng DB tạm + xóa sạch (không đụng production threat_memory)
    if os.path.exists(EVAL_MEM_DB):
        os.remove(EVAL_MEM_DB)
    memory = ThreatMemoryStore(db_path=EVAL_MEM_DB)
    with sqlite3.connect(EVAL_MEM_DB) as c:
        c.execute("DELETE FROM threat_events")

    engine = RuleEngine()

    warmup, main, apt_truth, n_chains = build_stream()
    print(f"\n[*] Nguồn: {len(warmup)} benign (warmup) | {len(main)} sự kiện luồng chính")
    print(f"[*] DAPT: {n_chains} chuỗi | IP là APT thật (>=2 ngày tấn công): {len(apt_truth)}")

    # ---- APT: ghi chuỗi TỪ luồng (phải bám đúng thứ tự sự kiện) ---------- #
    apt_detected: dict = {}  # ip -> {first_event_idx, first_day, fired, ...}
    apt_event_counter: dict = defaultdict(int)

    def _on_dapt(ev, ev_index):
        """Bản án APT phải NỔI LÊN DẦN: ghi sự kiện vào memory rồi mới hỏi lại."""
        if not ev.get("is_attack"):
            return  # benign DAPT = nền nhiễu, KHÔNG ghi vào memory APT
        ip = ev["ip"]
        apt_event_counter[ip] += 1
        before = memory.check_apt_chain(ip)
        memory.record_apt_event(
            src_ip=ip,
            dst_ip=ev["dst_ip"],
            apt_phase=ev["phase"],
            apt_day=ev["day"],
            label=ev["label"],
            timestamp=ev["timestamp"],
        )
        after = memory.check_apt_chain(ip)
        if ip not in apt_detected:
            apt_detected[ip] = {"first_event_idx": ev_index, "first_day": ev["day"], "fired": False}
        # ghi lại khoảnh khắc bản án LẬT từ False -> True
        if (not before["is_apt"]) and after["is_apt"] and not apt_detected[ip]["fired"]:
            apt_detected[ip].update(
                {
                    "fired": True,
                    "fire_event_idx": ev_index,
                    "fire_day": ev["day"],
                    "events_until_fire": apt_event_counter[ip],
                    "phases_at_fire": after.get("phases_seen", ""),
                }
            )

    # ---- Chấm luồng qua hàm DÙNG CHUNG (xem unified_dataset.score_stream) - #
    # Warmup CHỈ học baseline, KHÔNG chấm — chấm nó rồi báo là "độ chính xác" chính là
    # test-on-train. Toàn bộ benign trong ma trận dưới đây là held-out.
    scored = score_stream(engine, warmup, main, collect_zeroday=True, on_dapt=_on_dapt)
    warn_unhandled(scored["excluded_by_source"])

    cls = scored["confusion"]
    scored_by_source = scored["scored_by_source"]
    excluded_by_source = scored["excluded_by_source"]
    zd_results = scored["zeroday"]

    # ---- Metrics --------------------------------------------------------- #
    tp, fp, tn, fn = cls["tp"], cls["fp"], cls["tn"], cls["fn"]
    report = confusion_report(tp, fp, tn, fn)
    precision, recall = report["precision"], report["recall"]
    f1, accuracy = report["f1"], report["accuracy"]

    # Bóc theo TỪNG lớp tấn công: recall gộp có thể che mất một lớp bị bỏ sót SẠCH.
    cls_report = per_class_report(scored["records"])
    # CI bootstrap cho F1 — chạy trên kết quả đã chấm, không tốn thêm lượt gọi nào.
    f1_ci = bootstrap_ci(
        [(r["is_threat"], r["flagged"]) for r in scored["records"]], _f1_of_pairs, seed=42
    )

    apt_fired = {ip: d for ip, d in apt_detected.items() if d.get("fired")}
    apt_truth_seen = apt_truth & set(apt_detected.keys())
    apt_tp = len(apt_truth & set(apt_fired.keys()))
    apt_fn = len(apt_truth_seen) - apt_tp
    lags = [d["events_until_fire"] for ip, d in apt_fired.items() if ip in apt_truth]
    avg_lag = sum(lags) / len(lags) if lags else 0.0

    zd_caught = sum(1 for z in zd_results if z["caught_by_welford"])

    # ---- NGĂN CHẶN MỨC IP -------------------------------------------------- #
    # Báo TÁCH HAI NHÓM, không gộp. Lý do là tính hợp lệ của chính phép đo:
    #   * `dapt` mang IP THẬT của DAPT2020, nơi một host bị chiếm quyền gửi CẢ lưu lượng
    #     lành lẫn tấn công. Đây là ca KHÓ và thật — con số ở đây mới đáng đưa vào luận văn,
    #     kèm Wilson CI vì n rất nhỏ (vài IP kẻ tấn công).
    #   * Các nguồn còn lại có IP TỔNG HỢP (CICIDS bản ML đã bỏ địa chỉ thật). Sau khi tách
    #     dải, một IP tổng hợp hoặc là kẻ tấn công hoặc là lành tính suốt luồng — sạch hơn
    #     đời thật, nên số ở đây đo CƠ CHẾ (lệnh chặn có bật và có dính không) chứ không đo
    #     độ khó. Gộp hai nhóm lại sẽ để nhóm dễ pha loãng nhóm khó.
    ip_trace = scored["ip_trace"]
    containment = {
        "real_ips_dapt2020": ip_containment([e for e in ip_trace if e["source"] == "dapt"]),
        "synthetic_ips_other": ip_containment([e for e in ip_trace if e["source"] != "dapt"]),
        "note": (
            "Chỉ nhóm `real_ips_dapt2020` dùng địa chỉ nguồn THẬT. Nhóm kia có IP tổng hợp "
            "nên đo cơ chế ngăn chặn, KHÔNG đo độ khó — đừng trích như nhau."
        ),
    }

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "stream": {
            "warmup_benign": len(warmup),
            "main_events": len(main),
            "dapt_chains": n_chains,
            "apt_truth_ips": len(apt_truth),
            # Kế toán MINH BẠCH: `main_events` là số sự kiện ĐI QUA hệ thống, KHÁC với số
            # sự kiện được CHẤM. Trước đây báo cáo chỉ in main_events nên đọc nhầm thành
            # cỡ mẫu của ma trận nhầm lẫn (thực tế nhỏ hơn 20 lần).
            "n_scored": tp + fp + tn + fn,
            "scored_by_source": dict(scored_by_source),
            "excluded_by_source": dict(excluded_by_source),
        },
        "classification_cicids": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "f1_ci95_bootstrap": list(f1_ci),
            # MCC là chỉ số CHÍNH: bằng 0 với mọi bộ đoán-một-lớp bất kể tỉ lệ lớp, nên
            # không bị base rate đánh lừa như F1/Accuracy. `accuracy` giữ để đối chiếu
            # tài liệu cũ, luôn đọc kèm `zero_r_accuracy`.
            "mcc": report["mcc"],
            "balanced_accuracy": report["balanced_accuracy"],
            "accuracy": round(accuracy, 4),
            "majority_baseline": report["majority_baseline"],
            "zero_r_accuracy": report["zero_r_accuracy"],
            "accuracy_beats_baseline": report["accuracy_beats_baseline"],
            "specificity": report["specificity"],
        },
        # Quy trách nhiệm mức IP: F1 mức-sự-kiện phạt 497 flow còn lại của một kẻ tấn công
        # đã bị cắt ở flow thứ 3, trong khi vận hành thật coi đó là thành công.
        "ip_containment": containment,
        # Bóc theo lớp: điểm mù không lộ ra nếu chỉ nhìn recall gộp.
        "per_class": cls_report,
        "weakest_classes": weakest_classes(cls_report, k=3),
        "apt_dapt": {
            "apt_truth_ips": len(apt_truth),
            "apt_truth_seen_in_stream": len(apt_truth_seen),
            "detected": apt_tp,
            "missed": apt_fn,
            "recall": round(apt_tp / len(apt_truth_seen), 4) if apt_truth_seen else 0.0,
            "avg_detection_lag_events": round(avg_lag, 2),
        },
        "zeroday": {
            "total": len(zd_results),
            "caught_by_welford_static_missed": zd_caught,
        },
    }

    details = {"apt_detected": apt_detected, "zeroday": zd_results}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "details": details}, f, indent=2, ensure_ascii=False)

    _print_console(summary, apt_fired, apt_truth, zd_results)
    _write_report(summary, apt_fired, apt_truth, zd_results)
    print(f"\n[+] JSON: {OUT_JSON}\n[+] Report: {REPORT_MD}")
    return summary


def _print_console(summary, apt_fired, apt_truth, zd_results):
    c = summary["classification_cicids"]
    a = summary["apt_dapt"]
    s = summary["stream"]
    print("\n" + "-" * 70)
    print("  [1] CLASSIFICATION (mọi nguồn flow CÓ NHÃN, trên luồng trộn)")
    # MCC đứng MỘT MÌNH ở dòng đầu. BalAcc đã bị hạ khỏi headline: nó gần như luôn kể lại
    # cùng một câu chuyện với MCC nhưng trên thang dễ đọc nhầm (0,5 = đoán bừa, không phải
    # 0), nên đặt cạnh nhau chỉ tạo hai con số cho một kết luận. Vẫn giữ trong JSON.
    print(f"      MCC={c['mcc']}   <- chỉ số CHÍNH")
    print(
        f"      F1={c['f1']} (CI95 {c['f1_ci95_bootstrap']})  P={c['precision']}  R={c['recall']}"
    )
    print(
        f"      Acc={c['accuracy']} vs ZeroR={c['zero_r_accuracy']} "
        f"-> {'vượt mốc' if c['accuracy_beats_baseline'] else 'KHÔNG vượt mốc đoán hằng'}"
    )
    print(f"      TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")
    _ct = summary["ip_containment"]["real_ips_dapt2020"]
    if _ct["n_attacker_ips"]:
        _d = _ct["events_before_containment"]
        print("\n  [1b] NGĂN CHẶN MỨC IP — chỉ IP THẬT của DAPT2020 (n nhỏ, đọc kèm CI)")
        print(
            f"      Chặn được {_ct['n_contained']}/{_ct['n_attacker_ips']} IP tấn công "
            f"= {_ct['containment_rate']} (CI95 {_ct['containment_ci95']})"
        )
        print(f"      TỈ LỆ IP LỌT = {_ct['leak_rate']}")
        print(
            f"      Sự kiện lọt trước khi chặn: trung vị {_d['median']}, P95 {_d['p95']}, "
            f"tối đa {_d['max']}"
        )
        print(
            f"      Chặn oan IP lành tính: {_ct['benign_ip_false_block_rate']} "
            f"({_ct['n_benign_ips_blocked']}/{_ct['n_benign_ips']}) <- đối trọng BẮT BUỘC"
        )
    print(f"      Đã chấm: {s['n_scored']} / {s['main_events']} sự kiện luồng chính")
    print(f"      Theo nguồn: {s['scored_by_source']}")
    print(f"      Loại (có lý do): {s['excluded_by_source']}")
    weak = summary.get("weakest_classes") or []
    if weak:
        print(f"      3 lớp YẾU NHẤT (recall): {', '.join(f'{n}={v}' for n, v in weak)}")
    print("  [2] APT (DAPT, phát hiện EMERGENT từ memory sạch)")
    print(
        f"      APT thật thấy trong stream: {a['apt_truth_seen_in_stream']}"
        f" | phát hiện: {a['detected']} | sót: {a['missed']}"
    )
    print(f"      Recall={a['recall']}  | Độ trễ TB: {a['avg_detection_lag_events']} sự kiện")
    for ip, d in sorted(apt_fired.items()):
        if ip in apt_truth:
            print(
                f"        - {ip}: day1=KHÔNG-APT -> BẬT ở ngày {d['fire_day']}"
                f" (sau {d['events_until_fire']} sự kiện)"
            )
    print("  [3] ZERO-DAY (signature-less; static bỏ sót, Welford bắt)")
    for z in zd_results:
        mark = "✅ Welford bắt" if z["caught_by_welford"] else "⚠️ "
        print(
            f"        - {z['id']}: static={z['static_only_action']}"
            f" -> full={z['full_action']} (Z={z['z_score']}) {mark}"
        )
    print("-" * 70)


def _write_report(summary, apt_fired, apt_truth, zd_results):
    c = summary["classification_cicids"]
    a = summary["apt_dapt"]
    z = summary["zeroday"]
    lines = []
    lines.append("# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)\n")
    lines.append(
        "> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + "
        "Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ "
        "thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.\n"
    )
    lines.append(f"> **Sinh lúc:** {summary['timestamp']}\n")
    lines.append("---\n")
    lines.append("## 0. Luồng dữ liệu (toàn DATA THẬT, trộn xen kẽ)\n")
    s = summary["stream"]
    lines.append(
        "Mọi sự kiện là data thật (CICIDS từ `ground_truth.json`, DAPT từ "
        "`dapt2020_chains.jsonl`); zero-day là biến thể **REAL-DERIVED** — nền là "
        "flow benign THẬT, chỉ đẩy **một** feature lên cực trị, rải qua nhiều ngày. "
        "Các nguồn được **trộn xen kẽ trong từng ngày** bằng khóa thời gian golden-"
        "ratio (không xếp khối theo nguồn); DAPT giữ nguyên ngày thật.\n"
    )
    lines.append(
        f"- Warmup benign CICIDS (CHỈ học baseline Welford, **không chấm**): "
        f"**{s['warmup_benign']}**"
    )
    lines.append(
        f"- Luồng chính trộn (benign nền + tấn công CICIDS + mọi sự kiện DAPT + "
        f"zero-day): **{s['main_events']}** sự kiện đi qua hệ thống, "
        f"trong đó **{s['n_scored']}** được chấm phân loại"
    )
    lines.append(
        f"- DAPT chuỗi: **{s['dapt_chains']}** | IP là APT thật (≥2 ngày tấn công): **{s['apt_truth_ips']}**\n"
    )

    lines.append("## 1. Phân loại ở TẦNG LỌC Tier-1 (gate) trên luồng trộn\n")
    lines.append(
        "> Đây là số của **riêng tầng Tier-1** (rule tĩnh + Welford), tức cổng "
        "lọc thô. Tier-1 cố tình chỉ chặn phần tấn công lộ rõ ở tầng mạng và "
        "**đẩy phần tinh vi lên Tier-2** (vì vậy recall ở đây thấp là đúng thiết "
        "kế). F1 của TOÀN hệ thống (Tier-1 + LLM) được đo ở Ablation `Config F`.\n"
    )
    lines.append(
        "> **Phạm vi chấm:** mọi sự kiện flow CÓ NHÃN ground-truth ở luồng chính "
        "(`cicids` từ `ground_truth.json` + `cicids_max`/`dapt_max` trích thẳng từ CSV thô). "
        f"Cỡ mẫu thực chấm: **{s['n_scored']}** trên {s['main_events']} sự kiện luồng chính. "
        "**150 flow benign warmup KHÔNG được chấm** — đó là tập dùng để HỌC baseline Welford, "
        "chấm nó rồi báo là độ chính xác chính là test-on-train; toàn bộ benign trong ma trận "
        "dưới đây là **held-out**.\n"
    )
    lines.append("| Metric (Tier-1 gate) | Giá trị |")
    lines.append("| :--- | :---: |")
    lines.append(f"| **MCC** (chỉ số chính) | **{c['mcc']}** |")
    lines.append(f"| Balanced accuracy | {c['balanced_accuracy']} |")
    lines.append(f"| F1 | {c['f1']} (CI95 {c['f1_ci95_bootstrap']}) |")
    lines.append(f"| Precision | {c['precision']} |")
    lines.append(f"| Recall (attack) | {c['recall']} |")
    lines.append(f"| Specificity (benign) | {c['specificity']} |")
    lines.append(f"| Accuracy | {c['accuracy']} |")
    lines.append(f"| Mốc ZeroR (đoán hằng tốt nhất) | {c['zero_r_accuracy']} |")
    lines.append(
        f"| Accuracy vượt mốc? | {'CÓ' if c['accuracy_beats_baseline'] else '**KHÔNG**'} |"
    )
    lines.append(f"| TP / FP / TN / FN | {c['tp']} / {c['fp']} / {c['tn']} / {c['fn']} |")
    lines.append(f"| Cỡ mẫu đã chấm | {s['n_scored']} |\n")
    lines.append(f"- Đã chấm theo nguồn: `{s['scored_by_source']}`")
    lines.append(f"- Loại khỏi phân loại (có lý do): `{s['excluded_by_source']}`\n")
    lines.append(
        "> **MCC là chỉ số chính, không phải F1.** Một bộ đoán-một-lớp cho MCC = 0 bất kể "
        "tỉ lệ lớp, trong khi F1 và Accuracy đều bị base rate của tập đánh lừa.\n"
    )

    # --- Bóc theo lớp: recall gộp che mất lớp bị bỏ sót sạch ------------------ #
    pc = summary.get("per_class") or {}
    if pc:
        lines.append("### 1.1 Bóc theo TỪNG lớp tấn công\n")
        lines.append(
            "Recall gộp có thể là trung bình của *bắt hết lớp này, bỏ sạch lớp kia*. Bảng "
            "này là bằng chứng cho tính khái quát — và là nơi điểm mù lộ ra.\n"
        )
        lines.append("| Lớp | n | Recall (CI95) | Bỏ sót | Specificity | FP |")
        lines.append("| :--- | ---: | :---: | ---: | :---: | ---: |")
        for lbl, e in sorted(pc.items(), key=lambda kv: kv[1].get("recall", 2)):
            rec = (
                f"{e['recall']} {e.get('recall_ci95', '')}"
                if "recall" in e
                else "— (lớp lành tính)"
            )
            lines.append(
                f"| {lbl} | {e['n']} | {rec} | {e.get('missed', '—')} "
                f"| {e.get('specificity', '—')} | {e.get('false_positives', '—')} |"
            )
        lines.append("")

    lines.append("## 2. Phát hiện APT (DAPT) — EMERGENT, không nạp sẵn\n")
    lines.append(
        "Bộ nhớ bắt đầu **rỗng**; mỗi sự kiện APT được ghi vào memory KHI nó "
        "tới trong luồng, rồi mới hỏi `check_apt_chain`. Bản án APT chỉ bật sau "
        "khi tích lũy đủ sự kiện **đa ngày** — chứng minh phát hiện nổi lên dần, "
        "**không** phải tra đáp án nạp sẵn.\n"
    )
    lines.append(f"- APT thật xuất hiện trong stream: **{a['apt_truth_seen_in_stream']}**")
    lines.append(
        f"- Phát hiện đúng: **{a['detected']}** | Bỏ sót: **{a['missed']}** "
        f"| Recall: **{a['recall']}**"
    )
    lines.append(f"- Độ trễ phát hiện trung bình: **{a['avg_detection_lag_events']} sự kiện**\n")
    lines.append("| Attacker IP | Ngày BẬT cảnh báo APT | Sự kiện tới khi bật |")
    lines.append("| :--- | :---: | :---: |")
    for ip, d in sorted(apt_fired.items()):
        if ip in apt_truth:
            lines.append(
                f"| {ip} | ngày {d['fire_day']} (ngày 1 = chưa APT) | {d['events_until_fire']} |"
            )
    lines.append("")

    lines.append("## 3. Zero-day (signature-less) — static bỏ sót, Welford bắt\n")
    lines.append(
        f"Tổng: **{z['total']}** | Welford bắt được (mà static bỏ sót): "
        f"**{z['caught_by_welford_static_missed']}/{z['total']}**\n"
    )
    lines.append(
        "| ID | Kịch bản | Rule tĩnh (static-only, đối chứng) | Full Tier-1 (Welford) | Z-Score |"
    )
    lines.append("| :--- | :--- | :---: | :---: | :---: |")
    for zr in zd_results:
        mark = "✅" if zr["caught_by_welford"] else "⚠️"
        lines.append(
            f"| {zr['id']} | {zr['name']} | {zr['static_only_action']} (bỏ sót) "
            f"| **{zr['full_action']}** | {zr['z_score']} {mark} |"
        )
    lines.append("")
    lines.append("---\n")
    lines.append("## Kết luận\n")
    lines.append(
        "Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời "
        "gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ "
        "bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và "
        "(3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + "
        "Tier-Consensus Guard được đánh giá ở `evaluate_adversarial.py --mode pipeline`.\n"
    )

    os.makedirs(os.path.dirname(REPORT_MD), exist_ok=True)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    run()
