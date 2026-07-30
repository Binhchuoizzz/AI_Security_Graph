"""Quét `rag.top_k_results`: lấy bao nhiêu tài liệu thì RAG trỏ đúng kỹ thuật? (CHỈ ĐỌC)

VÌ SAO CẦN ĐO THAY VÌ ĐOÁN. `top_k` vừa được nối lại vào cấu hình (trước đó cấu hình ghi 3
nhưng mã chạy bằng hằng số 5 — cấu hình bị bỏ qua hoàn toàn). Nâng `top_k` KHÔNG miễn phí:
mỗi tài liệu thêm vào là thêm ~1.000 token trong prompt, mà ngân sách mỗi slot chỉ 8.192
token và log đã cảnh báo chạm 90% ngân sách. Nên phải cân recall tăng được bao nhiêu so với
token bỏ ra, chứ không nâng bừa.

Đo trên nhóm DUY NHẤT có kỹ thuật kỳ vọng suy ra được từ đầu vào: 69 sự kiện web-attack CÓ
payload. Chạy Tier-1 thật rồi dựng truy vấn đúng như `node_rag_context` làm.

Chạy:  .venv/bin/python scripts/sweep_rag_topk.py
"""

import json
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
logging.disable(logging.WARNING)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(ROOT, ".env"))

from src.agent.nodes import build_rag_queries  # noqa: E402
from src.rag.retriever import DualRetriever  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

TOP_KS = (3, 5, 8, 10)


def main() -> None:
    events = json.load(open("data/demo_small.json"))
    labels = json.load(open("data/demo_small.labels.json"))
    wa = [e for e in events if e.get("unified_source") == "webattack"]
    engine = RuleEngine()

    # Dựng truy vấn MỘT LẦN (không phụ thuộc top_k) rồi dùng lại cho mọi cấu hình.
    cases = []
    for e in wa:
        exp = str(labels[e["gt_id"]].get("wa_mitre", "")).split()[0]
        if not exp:
            continue
        log = engine.evaluate(dict(e))
        tq, cq = build_rag_queries([log])
        cases.append((exp, tq, cq))
    print(f"[*] {len(cases)} sự kiện web-attack có kỹ thuật kỳ vọng\n")

    print(
        f"{'top_k':>6s} {'@1':>7s} {'@3':>7s} {'@5':>7s} {'trong top_k':>12s} {'token ước tính':>15s}"
    )
    prev_hit = None
    for k in TOP_KS:
        r = DualRetriever(use_cache=False, top_k=k)
        hit = {1: 0, 3: 0, 5: 0}
        in_k = 0
        chars = 0
        for exp, tq, _cq in cases:
            res = r.retrieve(tq) if tq else {}
            ids = [x.get("id", "") for x in (res.get("mitre_results") or [])]
            chars += len(res.get("mitre_context", "")) + len(res.get("nist_context", ""))
            for kk in (1, 3, 5):
                if exp in ids[:kk]:
                    hit[kk] += 1
            if exp in ids:
                in_k += 1
        n = len(cases)
        tok = chars / n / 4  # ~4 ký tự / token
        mark = ""
        if prev_hit is not None:
            d = in_k - prev_hit
            mark = f"  (+{d} ca)" if d else "  (+0 ca)"
        prev_hit = in_k
        print(
            f"{k:6d} {100 * hit[1] / n:6.1f}% {100 * hit[3] / n:6.1f}% {100 * hit[5] / n:6.1f}% "
            f"{100 * in_k / n:11.1f}% {tok:14.0f}{mark}"
        )

    print(
        "\n'trong top_k' = kỹ thuật đúng nằm ĐÂU ĐÓ trong số tài liệu được nạp vào prompt —\n"
        "đây mới là con số quyết định, vì LLM đọc TẤT CẢ tài liệu được nạp chứ không chỉ hạng 1."
    )


if __name__ == "__main__":
    main()
