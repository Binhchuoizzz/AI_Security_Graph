"""Kiểm MẪU SỐ của mọi chỉ số: N mẫu có thật sự cho N phép đo ĐỘC LẬP không?

VÌ SAO CÓ TỆP NÀY (06/08/2026). Cách rà cũ chỉ kiểm "script chạy đúng tệp, đọc đúng khoá
JSON". Nó bỏ lọt cả một HỌ lỗi mà hai ca dưới đây là ví dụ, và cả hai đều suýt vào luận văn:

  1. TRẦN SO NHẦM DÂN SỐ. `evaluate_rag_retrieval.py` chạy trên toàn `ground_truth` (1.305
     truy vấn, đa số NetFlow thuần) cho Recall@3 = 0,385, rồi con số đó được viện dẫn làm
     "TRẦN" của chỉ số quy kết 80,0% vốn chấm trên lát `payload` (243 truy vấn). Hai mẫu số
     khác nhau. Đọc lên nghe như mâu thuẫn trong khi không hề mâu thuẫn.

  2. MẪU SỐ BỊ CACHE GỘP. `evaluate_adversarial --mode pipeline --category field_injection`
     báo "100/100 kháng được, đều cả 4 vị trí trường". Nhưng khoá cache lớp-2 dựng từ
     `message+payload+uri` và BỎ SÓT `user_agent`, nên 23 mẫu tiêm vào User-Agent chỉ sinh 2
     dấu vân => 2 phán quyết LLM phát lại 21 lần. Cột đó là 2 phép đo, không phải 23.

Cả hai đều VÔ HÌNH với phép rà theo tệp/khoá. Chúng chỉ lộ ra khi hỏi đúng một câu: mẫu số
danh nghĩa và số phép đo ĐỘC LẬP có bằng nhau không.

BA PHÉP KIỂM:
  A. TRÙNG DÂN SỐ — các chỉ số tự nhận so được với nhau (trần/đối chứng) phải cùng mẫu số.
  B. ĐỘC LẬP — với chỉ số chạy qua Tier-2, đếm dấu vân cache khác nhau trên đúng tập đầu
     vào của nó; ít hơn mẫu số nghĩa là tỉ lệ bị thổi phồng bởi bản sao.
  C. BÃO HOÀ — chỉ số mà MỌI mẫu cho cùng một kết quả thì không phân giải được gì; báo kèm
     cận trên CI để thấy n nhỏ tới mức nào.

Chạy:  .venv/bin/python scripts/audit_metric_denominators.py
"""

import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

R = os.path.join(ROOT, "experiments", "results")
OUT_JSON = os.path.join(R, "metric_denominator_audit.json")

findings: list[dict] = []


def note(phep: str, chi_so: str, dat: bool, chi_tiet: str) -> None:
    findings.append({"phep_kiem": phep, "chi_so": chi_so, "dat": dat, "chi_tiet": chi_tiet})
    print(f"  {'OK  ' if dat else 'CỜ  '} [{phep}] {chi_so}: {chi_tiet}")


def load(name: str):
    p = os.path.join(R, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


# ── A. TRÙNG DÂN SỐ ───────────────────────────────────────────────────────────
def kiem_trung_dan_so() -> None:
    print("\n── A. Chỉ số tự nhận so được với nhau có CÙNG mẫu số không ──")
    rrf, e2e = (
        load("attack_mapper_eval_rrf_payload.json"),
        load("attack_mapper_eval_e2e_payload.json"),
    )
    if rrf and e2e:
        ok = (
            rrf["n_samples"] == e2e["n_samples"]
            and rrf["n_with_technique"] == e2e["n_with_technique"]
        )
        note(
            "trùng dân số",
            "3.a ↔ 3.b",
            ok,
            f"{rrf['n_samples']} vs {e2e['n_samples']} mẫu · "
            f"{rrf['n_with_technique']} vs {e2e['n_with_technique']} có kỹ thuật",
        )

    # Trần truy xuất chỉ so được với quy kết khi CÙNG lát bằng chứng.
    rag_all, rag_pl = load("rag_retrieval_results.json"), load("rag_retrieval_results_payload.json")
    if rag_all and rrf:
        note(
            "trùng dân số",
            "3.e lát `all` ↔ 3.a",
            False,
            f"{rag_all['n_samples']} truy vấn vs {rrf['n_with_technique']} mẫu quy kết — "
            "KHÁC dân số, ⛔ không được gọi là trần của nhau",
        )
    if rag_pl and rrf:
        r3 = rag_pl["achievable"]["recall_at_k"]["@3"]
        acc = rrf["technique_exact_match_pct"] / 100
        note(
            "trùng dân số",
            "3.e lát `payload` ↔ 3.a",
            r3 >= acc,
            f"Recall@3 {r3:.3f} vs quy kết {acc:.3f} trên {rag_pl['n_samples']}/"
            f"{rrf['n_with_technique']} mẫu — trần {'đứng trên' if r3 >= acc else '🔴 THẤP HƠN'} kết quả",
        )

    # Lớp tĩnh và Tier-2 KHÔNG được trích thay cho nhau: khác dân số theo thiết kế.
    stat, pipe = load("robustness_results.json"), load("adversarial_pipeline_results.json")
    if stat and pipe:
        note(
            "trùng dân số",
            "2.a ↔ 2.b",
            True,
            f"{stat['summary']['total']} (toàn bộ) vs {pipe['n_tested']} (chỉ mẫu KHÓ) — "
            "khác dân số CÓ CHỦ Ý, tệp JSON đã ghi `scope_note`",
        )


# ── B. ĐỘC LẬP ────────────────────────────────────────────────────────────────
def kiem_doc_lap() -> None:
    print("\n── B. N mẫu có cho N phép đo ĐỘC LẬP không (cache gộp?) ──")
    from experiments.evaluate_adversarial import (
        HARD_CATEGORIES,
        load_hard_samples,
        make_attack_log,
    )
    from src.agent.response_cache import ExactMatchResponseCache
    from src.tier1_filter.rule_engine import RuleEngine

    c, eng = ExactMatchResponseCache(), RuleEngine()

    def dem(nhan: str, cats):
        samples = load_hard_samples(None, cats)
        fps, per_field, per_field_uniq = set(), Counter(), {}
        for i, s in enumerate(samples):
            log = make_attack_log(s.get("payload", ""), s.get("payload_field", "payload"), i)
            fp = c.feature_fingerprint(eng.evaluate(dict(log)))
            fld = s.get("payload_field", "payload")
            per_field[fld] += 1
            per_field_uniq.setdefault(fld, set()).add(fp)
            fps.add(fp)
        gop = len(samples) - len(fps)
        xau = [
            f"{f} {per_field[f]}→{len(per_field_uniq[f])}"
            for f in per_field
            if len(per_field_uniq[f]) < per_field[f]
        ]
        note(
            "độc lập",
            nhan,
            gop == 0,
            f"{len(samples)} mẫu → {len(fps)} phép đo độc lập"
            + (f" · gộp {gop} · theo trường: {', '.join(xau)}" if gop else ""),
        )

    dem("2.b — 678 mẫu KHÓ", HARD_CATEGORIES)
    dem("2.b — field_injection", ["field_injection"])

    # Trace của lượt chạy thật: đếm thẳng cache_hit thay vì suy ra.
    for nhan, path in (
        ("3.b — e2e payload", "logs/rq3/tier2_trace_3b.jsonl"),
        ("3.i — tier2 decision", "logs/rq3/tier2_trace_3i.jsonl"),
    ):
        p = os.path.join(ROOT, path)
        if not os.path.exists(p):
            continue
        n = hit = 0
        lop: Counter = Counter()
        with open(p, encoding="utf-8") as fh:
            for ln in fh:
                if not ln.strip():
                    continue
                r = json.loads(ln)
                n += 1
                llm = r.get("llm") or {}
                if llm.get("cache_hit"):
                    hit += 1
                    lop[llm.get("cache_layer") or "?"] += 1
        note(
            "độc lập",
            nhan,
            hit == 0,
            f"{n} lô → {n - hit} lần gọi LLM thật"
            + (f" · {hit} cache-hit {dict(lop)}" if hit else ""),
        )


# ── C. BÃO HOÀ ────────────────────────────────────────────────────────────────
def kiem_bao_hoa() -> None:
    print("\n── C. Chỉ số có bão hoà ở một giá trị duy nhất không ──")
    from experiments.metrics_core import wilson_ci

    lr = load("llm_robustness_results.json")
    if lr:
        sv = lr["seed_variance"]
        acts = {a for s in sv["per_sample"] for a in s["actions_by_seed"].values()}
        lo, hi = wilson_ci(0, sv["n_samples"])
        note(
            "bão hoà",
            "2.h đổi seed",
            len(acts) > 1,
            f"n={sv['n_samples']}, flip={sv['n_flipped']}, CI95 cận trên **{hi:.4f}**, "
            f"hành động quan sát được: {sorted(acts)}"
            + (" — MỘT hành động duy nhất, không phân giải được gì" if len(acts) == 1 else ""),
        )
        det = lr["determinism"]
        note(
            "bão hoà",
            "2.h tất định",
            det["n_runs"] >= 5 and len(set(det["actions"])) >= 1,
            f"{det['n_runs']} lượt trên **1 mẫu** · {det['distinct_raw_outputs']} chuỗi thô khác nhau",
        )

    ml = load("ml_gate_results.json")
    if ml:
        modes = ml["evasion_resistance"]["by_mode"]
        bh = [k for k, v in modes.items() if v["resistance_rate"] == 1.0]
        note(
            "bão hoà",
            "2.i né tránh",
            len(bh) < len(modes),
            f"{len(bh)}/{len(modes)} chế độ đạt đúng 100% ({', '.join(bh)}) — "
            "chỉ `extreme_broad` phân giải được, ⛔ không gộp trung bình",
        )
        cls = ml["classification"]
        note(
            "mẫu số",
            "1.a Cổng ML",
            False,
            f"vào {cls['total_events']} nhưng CHẤM trên {cls['n_decided_by_ml']} "
            f"(bypass {cls['bypass_rate']:.2%}) — trích 4.236 là sai mẫu số",
        )

    eg = load("evidence_grounding_results.json")
    if eg:
        note(
            "bão hoà",
            "3.l neo bằng chứng",
            eg["la_chan_neo_kich_hoat"] > 0,
            f"bad={eg['bad']}/{eg['n_khang_dinh_ky_thuat']} · lá chắn kích hoạt "
            f"{eg['la_chan_neo_kich_hoat']} lần — có tác động thật, không phải chỉ số rỗng",
        )


def main() -> int:
    print("=" * 78)
    print("KIỂM MẪU SỐ & TÍNH ĐỘC LẬP CỦA MỌI CHỈ SỐ")
    print("=" * 78)
    kiem_trung_dan_so()
    kiem_doc_lap()
    kiem_bao_hoa()

    n_co = sum(1 for f in findings if not f["dat"])
    print("\n" + "=" * 78)
    print(f"{len(findings)} phép kiểm · {n_co} CỜ cần đọc kèm khi trích số")
    print("=" * 78)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "tong_phep_kiem": len(findings),
                "so_co": n_co,
                # KHÔNG có `metric_valid`: cờ ở đây không phải lỗi, mà là điều kiện đọc số.
                # Gắn nhãn pass/fail sẽ khuyến khích làm cho hết cờ thay vì nêu điều kiện.
                "ghi_chu": (
                    "Mỗi CỜ là một điều kiện PHẢI nêu kèm khi trích con số tương ứng, "
                    "không phải một lỗi phải vá."
                ),
                "chi_tiet": findings,
            },
            fh,
            ensure_ascii=False,
            indent=1,
        )
    print(f"[+] Đã ghi: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
