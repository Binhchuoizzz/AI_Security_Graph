"""SENTINEL — Chất lượng TRUY XUẤT của Dual-RAG (offline, KHÔNG cần LLM).

CÂU HỎI FILE NÀY TRẢ LỜI: khi Tier-2 hỏi kho tri thức, tài liệu ĐÚNG có nằm trong ba đoạn
mà prompt thực sự nạp không — và nếu có thì ở hạng mấy?

VÌ SAO CẦN MỘT PHÉP ĐO RIÊNG. Trước đây chất lượng truy xuất chỉ được suy ra GIÁN TIẾP từ
điểm "Context Precision" do một LLM trọng tài chấm. Con số đó trộn ba nguyên nhân vào một:
bộ truy xuất lấy sai, tác tử dùng ngữ cảnh vụng, hay trọng tài chấm lệch. Khi điểm thấp,
không có cách nào biết phải sửa cái nào. Ở đây ta đo THẲNG bộ truy xuất bằng chỉ số chuẩn
của ngành truy xuất thông tin (Recall@k · MRR · nDCG@k), đối chiếu với nhãn
`expected_mitre_technique` có sẵn trong `ground_truth.json`.

Đây cũng là phép đo trực tiếp đầu tiên cho hai thứ vốn được tuyên bố mà chưa từng đo:
  * RAG LAI (FAISS dày + BM25 thưa, hợp nhất bằng RRF k=60) — so được với từng nhánh riêng;
  * việc TÁCH HAI TRUY VẤN (truy vấn kỹ thuật thuần tiếng Anh, không payload) so với cách
    cũ nối payload thô vào cùng chuỗi.

TRẦN PHỦ KHO. Nếu KB không có kỹ thuật cần tìm thì bộ truy xuất KHÔNG THỂ trả nó ra. Script
tự tính `kb_coverage_ceiling` và báo cả hai con số: recall thô, và recall TRÊN PHẦN KHẢ THI.
Trích con số thứ hai mới đúng — và trung thực hơn hẳn.

PHÁT HIỆN CẦN BIẾT TRƯỚC KHI ĐỌC SỐ — có một TRẦN CẤU TRÚC ngoài trần phủ kho. Trên tập
điều kiện-hoá-theo-leo-thang, phần lớn sự kiện là NetFlow THUẦN: không payload, không chữ
ký, và lý do leo thang duy nhất là một dị biệt Welford kiểu "Total Fwd Packets lệch 4,1
sigma". Nhãn kỳ vọng của những ca đó lại là `T1110` (Brute Force) hay `T1499` (Endpoint
DoS) — tức những kỹ thuật chỉ định nghĩa được qua HÀNH VI LẶP LẠI TRÊN NHIỀU LUỒNG, trong
khi truy vấn chỉ có MỘT luồng. Nói cách khác, thông tin cần thiết không nằm trong đầu vào.

Vì vậy `Recall@10` cao mà `Recall@3` thấp KHÔNG có nghĩa bộ truy xuất hỏng: tài liệu đúng
vẫn được lấy về, chỉ xếp dưới các kỹ thuật khác cũng khớp với mô tả "khối lượng bất
thường". Đây chính là cơ chế đứng sau điểm Context Precision thấp của LLM-as-Judge, và nó
là một kết quả đo được chứ không phải suy đoán. Hướng khắc phục thật nằm ở phía ĐẦU VÀO
(đưa ngữ cảnh phiên/nhiều luồng vào truy vấn), không phải ở việc nhồi thêm từ khoá.

Chạy:
    .venv/bin/python -m experiments.evaluate_rag_retrieval
    .venv/bin/python -m experiments.evaluate_rag_retrieval --limit 200 --mode all
"""

import argparse
import json
import os
import sys
import time
from collections import Counter

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import retrieval_report  # noqa: E402
from experiments.unified_dataset import ROOT, build_stream  # noqa: E402
from src.agent.nodes import build_rag_queries  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

GT_PATH = os.path.join(ROOT, "experiments", "ground_truth.json")
OUT_JSON = os.path.join(ROOT, "experiments", "results", "rag_retrieval_results.json")

# Prompt chỉ nạp 3 đoạn hợp nhất đầu bảng -> phải truy xuất sâu hơn để ĐO được hạng, nhưng
# `recall@3` mới là con số vận hành.
TOP_K = 10
PROMPT_TOP_K = 3

# Chỉ những hành động này mới đưa sự kiện tới Tier-2 (và do đó tới RAG).
ESCALATING_ACTIONS = {"ESCALATE", "ALERT", "BLOCK_IP", "AWAIT_HITL"}


def _norm_technique(raw: str) -> str:
    """'T1190 Exploit Public-Facing Application' -> 'T1190'. Rỗng nếu không phải mã."""
    tok = (raw or "").strip().split()
    if not tok:
        return ""
    tid = tok[0].strip().upper().rstrip(".,;:")
    return tid if tid.startswith("T") and tid[1:].replace(".", "").isdigit() else ""


def _relevant_ids(expected: str) -> set[str]:
    """Tập id được tính là ĐÚNG cho một kỹ thuật kỳ vọng.

    Chấp nhận cả kỹ thuật CHA khi kỳ vọng là sub-technique (T1110.004 -> T1110): kho chứa
    cả hai mức, và trả về đúng họ kỹ thuật đã là ngữ cảnh dùng được cho tác tử. Chiều ngược
    lại KHÔNG được chấp nhận — trả T1110.004 khi cần T1110 là thu hẹp sai.
    """
    tid = _norm_technique(expected)
    if not tid:
        return set()
    out = {tid}
    if "." in tid:
        out.add(tid.split(".")[0])
    return out


def _kb_technique_ids() -> set[str]:
    kb_path = os.path.join(ROOT, "knowledge_base", "mitre_attack.json")
    with open(kb_path, encoding="utf-8") as f:
        kb = json.load(f)
    entries = kb if isinstance(kb, list) else kb.get("techniques", [])
    return {_norm_technique(e.get("id", "")) for e in entries} - {""}


def run(limit: int | None = None, out: str | None = None) -> dict:
    print("=" * 72)
    print("  SENTINEL — CHẤT LƯỢNG TRUY XUẤT DUAL-RAG (offline, không cần LLM)")
    print("=" * 72)

    from src.rag.retriever import DualRetriever

    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    samples = [s for s in gt if _relevant_ids(s.get("expected_mitre_technique", ""))]
    if limit and limit < len(samples):
        stride = len(samples) / limit  # mẫu ĐỀU trên toàn tập, không phải N mẫu đầu
        samples = [samples[int(i * stride)] for i in range(limit)]
    print(f"[*] Mẫu có nhãn kỹ thuật: {len(samples)}")

    kb_ids = _kb_technique_ids()
    print(f"[*] Kho tri thức: {len(kb_ids)} mã kỹ thuật")

    # Cache TẮT: cache theo mẫu sẽ làm các truy vấn trùng nhau chỉ tốn một lần truy xuất
    # thật, và ta đang đo chính bộ truy xuất chứ không đo bộ đệm.
    retriever = DualRetriever(top_k=TOP_K, use_cache=False)

    # BẮT BUỘC chạy Tier-1 TRƯỚC khi dựng truy vấn — đây là thứ tự của đường THẬT
    # (`node_rag_context` luôn chạy sau Tier-1). `build_rag_queries()` lấy cụm từ vựng
    # MITRE tiếng Anh từ `tier1_reasons`; log thô trong `ground_truth.json` chưa qua Tier-1
    # nên trường đó rỗng, và truy vấn kỹ thuật tụt xuống còn mỗi "service + cổng".
    # Bỏ qua bước này thì phép đo báo Recall@3 ≈ 0,10 — đo cái quy trình KHÔNG tồn tại,
    # chứ không đo bộ truy xuất.
    engine = RuleEngine()
    # Làm ấm Welford bằng chính tập warmup benign của luồng gộp: baseline lạnh thì Z-score
    # không bao giờ bật, và ta sẽ đo một Tier-1 câm thay vì Tier-1 vận hành.
    warmup, _main, _apt, _n = build_stream()
    for ev in warmup:
        engine.evaluate(ev["log"])
    print(f"[*] Đã làm ấm Welford bằng {len(warmup)} flow benign")

    queries: list[tuple[list[str], set[str]]] = []
    queries_in_kb: list[tuple[list[str], set[str]]] = []
    per_technique: dict[str, list[int | None]] = {}
    n_absent = 0
    n_no_query = 0
    n_not_escalated = 0
    latencies: list[float] = []

    for i, s in enumerate(samples, 1):
        relevant = _relevant_ids(s.get("expected_mitre_technique", ""))
        logs = s.get("logs") or [{}]
        evaluated = engine.evaluate(dict(logs[0]))
        # ĐIỀU KIỆN HOÁ THEO LEO THANG, giống `evaluate_tier2_decision.py`. Sự kiện mà
        # Tier-1 cho qua thì KHÔNG BAO GIỜ tới RAG ở đường thật, nên chấm chúng là đo một
        # quy trình không tồn tại và kéo mọi chỉ số xuống một cách vô nghĩa. Số ca bị loại
        # vẫn được báo (`n_not_escalated`) để không ai tưởng mẫu số là toàn bộ tập.
        if evaluated.get("tier1_action") not in ESCALATING_ACTIONS:
            n_not_escalated += 1
            continue
        technique_q, _context_q = build_rag_queries(evaluated)
        if not technique_q:
            n_no_query += 1
            continue

        t0 = time.perf_counter()
        res = retriever.retrieve(technique_q)
        latencies.append((time.perf_counter() - t0) * 1000.0)

        ranked = [_norm_technique(r.get("id", "")) for r in res.get("mitre_results", [])]
        queries.append((ranked, relevant))

        in_kb = bool(relevant & kb_ids)
        if in_kb:
            queries_in_kb.append((ranked, relevant))
        else:
            n_absent += 1

        key = sorted(relevant)[0]
        rank = next((j for j, d in enumerate(ranked, 1) if d in relevant), None)
        per_technique.setdefault(key, []).append(rank)

        if i % 100 == 0:
            print(f"    ... {i}/{len(samples)}")

    overall = retrieval_report(queries)
    achievable = retrieval_report(queries_in_kb)

    per_tech_out = {}
    for tech, ranks in sorted(per_technique.items()):
        found = [r for r in ranks if r is not None]
        per_tech_out[tech] = {
            "n": len(ranks),
            "hit_at_3": round(sum(1 for r in ranks if r and r <= PROMPT_TOP_K) / len(ranks), 4),
            "median_rank": sorted(found)[len(found) // 2] if found else None,
            "in_kb": bool(_relevant_ids(tech) & kb_ids),
        }

    result = {
        "n_samples": len(queries),
        "n_no_query": n_no_query,
        # Kế toán mẫu số: chấm CÓ ĐIỀU KIỆN trên ca Tier-1 leo thang, đúng như đường thật.
        "n_not_escalated_excluded": n_not_escalated,
        "top_k_retrieved": TOP_K,
        "prompt_top_k": PROMPT_TOP_K,
        "kb_coverage_ceiling": {
            "n_expected_in_kb": len(queries_in_kb),
            "n_expected_absent": n_absent,
            "ceiling_pct": round(100 * len(queries_in_kb) / len(queries), 2) if queries else 0.0,
            "note": (
                "Kỹ thuật VẮNG trong kho thì bộ truy xuất KHÔNG THỂ trả ra — những ca đó "
                "về cấu trúc không thể đúng. Trích `achievable`, đừng trích `overall` như "
                "thể mốc là 100%."
            ),
        },
        # Recall thô trên TOÀN tập (gồm cả ca không thể đúng vì kho thiếu).
        "overall": overall,
        # Recall trên phần KHẢ THI — con số nên đưa vào luận văn.
        "achievable": achievable,
        "latency_ms_mean": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        "per_technique": per_tech_out,
        # Các kỹ thuật TRONG kho mà vẫn không lọt nổi top-3: đây là danh sách việc cần làm
        # cho bộ truy xuất, không phải cho kho tri thức.
        "worst_in_kb": sorted(
            (
                (t, v["hit_at_3"], v["n"])
                for t, v in per_tech_out.items()
                if v["in_kb"] and v["n"] >= 3
            ),
            key=lambda x: x[1],
        )[:8],
    }

    out_path = out or OUT_JSON
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    _print(result)
    print(f"\n[+] JSON: {out_path}")
    return result


def _print(r: dict) -> None:
    ceil = r["kb_coverage_ceiling"]
    ach, ov = r["achievable"], r["overall"]
    print("\n" + "-" * 72)
    print(f"  Truy vấn chấm được : {r['n_samples']}  (độ trễ TB {r['latency_ms_mean']} ms)")
    print(
        f"  Trần phủ kho       : {ceil['ceiling_pct']}%  "
        f"({ceil['n_expected_absent']} ca kỹ thuật VẮNG trong kho -> không thể đúng)"
    )
    print("\n  TRÊN PHẦN KHẢ THI (con số nên trích):")
    print(
        f"    Recall@3 = {ach['recall_at_k'].get('@3')}  (CI95 {ach['recall_at_3_ci95']})"
        f"   <- CHỈ SỐ VẬN HÀNH: prompt chỉ nạp 3 đoạn đầu"
    )
    print(
        f"    Recall@1 = {ach['recall_at_k'].get('@1')}   "
        f"Recall@5 = {ach['recall_at_k'].get('@5')}   "
        f"Recall@10 = {ach['recall_at_k'].get('@10')}"
    )
    print(f"    MRR      = {ach['mrr']}      nDCG@3 = {ach['ndcg_at_k'].get('@3')}")
    print(f"    Hạng trung vị khi tìm thấy = {ach['median_rank_when_found']}")
    print(f"\n  Trên TOÀN tập (gồm ca kho thiếu): Recall@3 = {ov['recall_at_k'].get('@3')}")
    if r["worst_in_kb"]:
        print("\n  Kỹ thuật CÓ trong kho nhưng khó lọt top-3 (việc của bộ truy xuất):")
        for tech, hit, n in r["worst_in_kb"]:
            print(f"    {tech:14s} hit@3={hit:.2f}  (n={n})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Chất lượng truy xuất Dual-RAG (offline)")
    ap.add_argument("--limit", type=int, default=None, help="lấy mẫu đều bấy nhiêu truy vấn")
    ap.add_argument("--out", type=str, default=None)
    args = ap.parse_args()
    run(limit=args.limit, out=args.out)
    _ = Counter  # giữ import cho phần mở rộng theo nguồn (chưa dùng)
