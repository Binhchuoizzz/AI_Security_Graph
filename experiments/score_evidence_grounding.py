"""SENTINEL — chấm LÁ CHẮN NEO BẰNG CHỨNG từ bản ghi tracer (chỉ số 3.l).

CÂU HỎI. Hệ có bao giờ KHẲNG ĐỊNH một kỹ thuật ATT&CK mà bộ truy xuất chưa từng đưa ra cho
chính lô đó không? Đây là định nghĩa vận hành của "ảo giác" trong phần quy kết: không phải
"trả lời sai" (sai thì đã có 3.a/3.b đo) mà là "khẳng định một thứ KHÔNG có bằng chứng đỡ".

VÌ SAO PHẢI ĐO TỪ TRACER, KHÔNG PHẢI TỪ TỆP KẾT QUẢ. Tệp kết quả chỉ giữ phán quyết CUỐI —
sau khi lá chắn đã hạ cấp. Đọc mỗi phán quyết cuối thì lá chắn nào cũng "đạt 0% ảo giác",
kể cả một lá chắn không làm gì. Bản ghi tracer giữ CẢ HAI ĐẦU (`action_before` /
`action_after`, `llm_technique_raw` / `final_technique_id`) nên tách được hai con số khác
hẳn nhau: bao nhiêu lần model ĐỀ XUẤT thứ không neo được, và bao nhiêu lần thứ đó LỌT ra
ngoài. Chỉ số thứ hai mới là `bad` phải bằng 0.

HAI THƯỚC, CỐ Ý KHÔNG GỘP:
  * `khong_neo_chat` — mã khẳng định không nằm trong danh sách ID của các tài liệu ĐÃ TRUY
    XUẤT. Đây là thước CHẶT, và là thước script này báo cáo.
  * Lá chắn trong `nodes.py` dùng thước RỘNG HƠN: quét regex trên TOÀN VĂN ngữ cảnh RAG, nên
    một mã chỉ được NHẮC TỚI trong thân tài liệu khác cũng tính là có neo. Bản ghi tracer chỉ
    lưu số ký tự của khối ngữ cảnh chứ không lưu toàn văn, nên script này KHÔNG dựng lại được
    thước rộng. Hệ quả cần nêu thẳng: `khong_neo_chat` là CẬN TRÊN của số ca lá chắn bỏ lọt.

Chạy:
    .venv/bin/python experiments/score_evidence_grounding.py --trace logs/rq3/tier2_trace_3b.jsonl
"""

import argparse
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT_JSON = os.path.join(ROOT, "experiments", "results", "evidence_grounding_results.json")


def _parent(tid: str) -> str:
    return tid.split(".")[0] if tid else ""


def _rag_ids(rec: dict) -> set[str]:
    """ID của các tài liệu kỹ thuật ĐÃ TRUY XUẤT cho lô (cả truy vấn kỹ thuật lẫn ngữ cảnh)."""
    rag = rec.get("rag") or {}
    ids = set()
    for key in ("technique_mitre", "context_mitre"):
        for hit in rag.get(key) or []:
            tid = (hit or {}).get("id") or ""
            if tid:
                ids.add(tid)
    return ids


def score(recs: list[dict]) -> dict:
    n = len(recs)
    n_mapper_ran = 0
    n_asserted = 0  # lô mà hệ KHẲNG ĐỊNH một kỹ thuật ở phán quyết cuối
    bad_exact: list[dict] = []  # khẳng định mà mã KHÔNG có trong tài liệu truy xuất
    bad_parent: list[dict] = []  # ... kể cả nới lỏng tới kỹ thuật CHA
    n_no_rag = 0  # lô không truy xuất được tài liệu nào -> lá chắn không có gì để đối chiếu

    shield_fired = 0
    shield_downgrades: Counter = Counter()
    blocks_prevented = 0
    rejected_techniques: Counter = Counter()
    hallucination_shield = 0
    proposed_ungrounded_by: Counter = Counter()

    for r in recs:
        am = r.get("attack_mapper") or {}
        fin = r.get("final") or {}
        if am.get("ran"):
            n_mapper_ran += 1

        if am.get("grounding_shield_fired"):
            shield_fired += 1
            before = am.get("action_before") or ""
            after = am.get("action_after") or ""
            if before != after:
                shield_downgrades[f"{before}->{after}"] += 1
            if am.get("grounding_shield_downgraded_block"):
                blocks_prevented += 1
            rej = am.get("grounding_shield_rejected_technique") or ""
            if rej:
                rejected_techniques[rej] += 1
            # Ai đề xuất mã không neo được: model, hay bộ ánh xạ tự suy sau khi model trả N/A.
            raw = str(am.get("llm_technique_raw") or "").upper()
            proposed_ungrounded_by["model" if raw and raw != "N/A" else "bộ ánh xạ"] += 1
        if am.get("hallucination_shield"):
            hallucination_shield += 1

        tid = (fin.get("mitre_technique_id") or "").strip()
        if not tid:
            continue  # hệ KHÔNG khẳng định kỹ thuật nào -> không thể ảo giác
        n_asserted += 1
        ids = _rag_ids(r)
        if not ids:
            n_no_rag += 1
            continue
        if tid not in ids:
            row = {
                "trace_id": r.get("trace_id"),
                "khang_dinh": tid,
                "action": fin.get("action"),
                "confidence": fin.get("confidence"),
                "mapping_status": fin.get("mapping_status"),
                "rag_ids": sorted(ids),
            }
            bad_exact.append(row)
            if _parent(tid) not in {_parent(i) for i in ids}:
                bad_parent.append(row)

    pct = lambda a, b: round(100 * a / b, 2) if b else 0.0  # noqa: E731
    return {
        "n_ban_ghi": n,
        "n_mapper_chay": n_mapper_ran,
        "n_khang_dinh_ky_thuat": n_asserted,
        # ── chỉ số 3.l: PHẢI bằng 0 ──
        "bad": len(bad_exact),
        "ty_le_ao_giac_pct": pct(len(bad_exact), n_asserted),
        "bad_ke_ca_noi_toi_ky_thuat_cha": len(bad_parent),
        "n_lo_khong_truy_xuat_duoc": n_no_rag,
        # ── tác động THẬT của lá chắn (số này > 0 mới chứng minh lá chắn có làm việc) ──
        "la_chan_neo_kich_hoat": shield_fired,
        "la_chan_ty_le_pct": pct(shield_fired, n_mapper_ran),
        "ha_cap_hanh_dong": dict(shield_downgrades),
        "block_ip_bi_chan_lai": blocks_prevented,
        "ky_thuat_bi_tu_choi_top": rejected_techniques.most_common(10),
        "ai_de_xuat_ma_khong_neo": dict(proposed_ungrounded_by),
        "la_chan_khong_anh_xa_duoc_kich_hoat": hallucination_shield,
        "metric_valid": len(bad_exact) == 0,
        "ghi_chu": (
            "`bad` chấm theo thước CHẶT (ID tài liệu đã truy xuất). Lá chắn trong nodes.py "
            "dùng thước rộng hơn (regex trên toàn văn ngữ cảnh), nên `bad` là CẬN TRÊN của số "
            "ca lá chắn bỏ lọt, không phải số chính xác."
        ),
        "vi_du_bad": bad_exact[:10],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Chấm neo bằng chứng (3.l) từ tracer Tier-2.")
    ap.add_argument("--trace", nargs="+", required=True, help="một hoặc nhiều tệp .jsonl")
    ap.add_argument("--out", default=OUT_JSON)
    args = ap.parse_args()

    recs: list[dict] = []
    per_file: dict[str, int] = {}
    for path in args.trace:
        p = path if os.path.isabs(path) else os.path.join(ROOT, path)
        if not os.path.exists(p):
            raise SystemExit(f"[!] không có tracer: {path} (chạy với SENTINEL_TRACE=1)")
        k = 0
        with open(p, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    recs.append(json.loads(ln))
                    k += 1
                except json.JSONDecodeError:
                    pass  # dòng cụt do tiến trình bị giết -> bỏ, không làm hỏng cả báo cáo
        per_file[path] = k
    if not recs:
        raise SystemExit("[!] tracer rỗng.")

    res = score(recs)
    res["nguon"] = per_file

    print("=" * 72)
    print("  SENTINEL — LÁ CHẮN NEO BẰNG CHỨNG (3.l)")
    print("=" * 72)
    for k, v in per_file.items():
        print(f"  nguồn: {k}  ({v} bản ghi)")
    print(f"  Lô có mapper chạy      : {res['n_mapper_chay']}/{res['n_ban_ghi']}")
    print(f"  Lô hệ KHẲNG ĐỊNH kỹ thuật: {res['n_khang_dinh_ky_thuat']}")
    print(f"  >> ẢO GIÁC (bad)       : {res['bad']}  ({res['ty_le_ao_giac_pct']}%)   <- phải = 0")
    print(
        f"  Lá chắn kích hoạt      : {res['la_chan_neo_kich_hoat']} ({res['la_chan_ty_le_pct']}%)"
    )
    print(f"    hạ cấp hành động     : {res['ha_cap_hanh_dong']}")
    print(f"    BLOCK_IP bị chặn lại : {res['block_ip_bi_chan_lai']}")
    print(f"    ai đề xuất mã hỏng   : {res['ai_de_xuat_ma_khong_neo']}")
    print(f"  Lá chắn KHÔNG ánh xạ được: {res['la_chan_khong_anh_xa_duoc_kich_hoat']}")

    out = args.out if os.path.isabs(args.out) else os.path.join(ROOT, args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    print(f"[+] Đã ghi: {out}")
    return 0 if res["metric_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
