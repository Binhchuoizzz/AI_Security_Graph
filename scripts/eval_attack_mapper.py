#!/usr/bin/env python3
"""
scripts/eval_attack_mapper.py — Đo chất lượng ATT&CK Mapper trên ground_truth.json.

HAI MODE (chọn bằng --mode):
  rrf  : OFFLINE, KHÔNG gọi LLM. Dựng query flow (service/port/...) y như
         node_rag_context -> map_attack(retriever, llm=None) -> RRF top-1.
         Tất định, tái lập 100%, không cần llama.cpp. CÔ LẬP đóng góp của KB
         => đúng công cụ đo delta khi nạp G0129/PlugX (#2a): chạy tag=baseline
         rồi tag=with_g0129 và lấy hiệu.
  e2e  : Chạy FULL agent (triage -> attack_mapper) mỗi sample. Cần llama.cpp
         server (:5000). Đo hệ TRIỂN KHAI thật (đã lẫn accuracy của triage).
         Vì ~5.7s/sample, nên dùng --per-class để subsample phân tầng.

TRUNG THỰC (no-fabrication):
  - In KÈM "trần KB-coverage": % expected technique có trong KB. Exact-match
    KHÔNG THỂ vượt trần này -> diễn giải số cho đúng, không đổ lỗi cho mapper.
  - Script CHỈ sinh số từ run thật; không có hằng số kết quả nào hard-code.
  - Đo cả exact-match VÀ parent-level match (vd T1110.001 ~ T1110) vì KB và GT
    đôi khi lệch mức technique/sub-technique.

CÁCH DÙNG:
  python scripts/eval_attack_mapper.py --mode rrf --tag baseline
  python scripts/eval_attack_mapper.py --mode e2e --per-class 20 --tag e2e_subsample
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict

import numpy as np  # type: ignore

# Project root vào sys.path (đồng bộ conftest)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.agent.attack_mapper import (  # noqa: E402
    WEB_ATTACK_MAP,
    AttackMapperInput,
    map_attack,
    normalize_attack_type,
    normalize_tactic,
)

# Bớt nhiễu log INFO của retriever/HTTP cho console gọn.
for noisy in ("httpx", "sentence_transformers", "src.rag.retriever", "faiss"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

GT_DEFAULT = os.path.join(ROOT, "experiments", "ground_truth.json")
KB_DEFAULT = os.path.join(ROOT, "knowledge_base", "mitre_attack.json")
OUT_DIR = os.path.join(ROOT, "experiments", "results")

CURATED_TECH_IDS = {e["technique_id"] for e in WEB_ATTACK_MAP.values()}
BENIGN = {"None", "", "none", "N/A"}


def _parent(tid: str) -> str:
    return (tid or "").split(".")[0]


def build_flow_query(log: dict) -> str:
    """Dựng query từ log flow — MIRROR node_rag_context (service/port/uri/reasons)."""
    parts = []
    msg = (str(log.get("message", "")) + " " + str(log.get("payload", ""))).strip()
    if msg:
        parts.append(msg)
    svc = log.get("service") or log.get("Service")
    if svc:
        parts.append(f"service {svc}")
    port = log.get("Destination Port") or log.get("dst_port")
    if port not in (None, "", 0):
        parts.append(f"destination port {port}")
    proto = log.get("protocol") or log.get("Protocol")
    if proto not in (None, ""):
        parts.append(f"protocol {proto}")
    uri = log.get("uri") or log.get("URI")
    if uri:
        parts.append(f"uri {uri}")
    for reason in (log.get("tier1_reasons") or [])[:3]:
        parts.append(str(reason))
    q = " ".join(parts).strip()
    return (q or "suspicious network activity")[:300]


def expected_tactic_for(tid: str, kb_index: dict) -> str:
    """Suy tactic kỳ vọng từ technique id qua KB (GT không có field tactic)."""
    rec = kb_index.get(tid) or kb_index.get(_parent(tid))
    if not rec:
        return ""
    canon, _ = normalize_tactic(rec.get("tactic", ""))
    return canon if canon != "Unknown" else ""


def compute_kb_coverage(gt: list, kb_ids: set) -> dict:
    """Trần exact/parent match do KB phủ được bao nhiêu technique kỳ vọng."""
    total = exact = parent = 0
    for s in gt:
        tid = str(s.get("expected_mitre_technique", ""))
        if tid in BENIGN:
            continue
        total += 1
        if tid in kb_ids:
            exact += 1
        if tid in kb_ids or _parent(tid) in kb_ids:
            parent += 1
    return {
        "n_with_technique": total,
        "exact_in_kb_pct": round(exact / total * 100, 1) if total else 0.0,
        "parent_in_kb_pct": round(parent / total * 100, 1) if total else 0.0,
    }


def subsample(gt: list, per_class: int | None, limit: int | None) -> list:
    """Phân tầng theo expected technique (per_class) rồi cắt tổng (limit)."""
    if per_class:
        buckets: dict = defaultdict(list)
        for s in gt:
            buckets[str(s.get("expected_mitre_technique", ""))].append(s)
        out = []
        for _, items in buckets.items():
            out.extend(items[:per_class])
        gt = out
    if limit:
        gt = gt[:limit]
    return gt


# RuleEngine dùng chung cho mode rrf — khởi tạo LƯỜI (chỉ khi thực sự chạy rrf).
_RRF_ENGINE = None


def predict_rrf(sample: dict, retriever) -> tuple[str, str, str, bool, float, dict]:
    """1 sample -> (pred_id, pred_tactic, mapping_status, curated_path, latency_s, extra).

    LỖI ĐO ĐÃ SỬA: bản trước gọi thẳng `build_flow_query(log)` trên log THÔ, tức BỎ QUA
    Tier-1. Nhưng ở production `node_rag_context` LUÔN chạy sau Tier-1, và truy vấn kỹ thuật
    được dựng từ `tier1_reasons` — nguồn DUY NHẤT cấp từ vựng MITRE tiếng Anh
    (`_canonical_attack_terms`). Không có nó, truy vấn tụt về "service X port N" và bộ truy
    xuất mất gần hết tín hiệu.

    Đo được trên bộ 69 web-attack (2026-07-28): đường CŨ báo exact 26%, trong khi đường THẬT
    (chạy Tier-1 trước, dùng `build_rag_queries`) cho technique đúng ở top-1 55% / top-3 62%.
    Chênh 2,4 lần — đủ để đưa một con số sai vào luận văn.
    """
    global _RRF_ENGINE
    logs = sample.get("logs") or []
    log = logs[0] if logs else {}

    if _RRF_ENGINE is None:
        from src.tier1_filter.rule_engine import RuleEngine

        _RRF_ENGINE = RuleEngine()
    evaluated = _RRF_ENGINE.evaluate(dict(log))

    from src.agent.nodes import build_rag_queries

    technique_q, context_q = build_rag_queries(evaluated)
    query = technique_q or build_flow_query(log)
    if context_q:
        query = f"{query} {context_q}"[:300]
    inp = AttackMapperInput(
        attack_type=str(evaluated.get("attack_type", "")),
        payload=query,
        features=log if isinstance(log, dict) else {},
    )
    curated = (
        normalize_attack_type(inp.attack_type, inp.payload, str(inp.features)) in WEB_ATTACK_MAP
    )
    t0 = time.time()
    mapping = map_attack(inp, retriever=retriever, llm=None)  # llm=None -> tất định
    lat = time.time() - t0
    return (
        mapping.mitre_technique_id,
        mapping.mitre_tactic,
        mapping.mapping_status,
        curated,
        lat,
        {},
    )


def predict_e2e(
    sample: dict, agent_app, SentinelState, loop_detector
) -> tuple[str, str, str, bool, float, dict]:
    """1 sample -> chạy full agent; đọc các trường MITRE có cấu trúc từ decision cuối."""
    from src.agent.response_cache import response_cache

    response_cache.clear()  # Ép Zero-Cache 100%: mọi mẫu bắt buộc LLM suy luận từ đầu
    logs = sample.get("logs") or []
    loop_detector.reset()  # BẮT BUỘC: tránh loop-guard cộng dồn qua các invoke
    t0 = time.time()
    final = agent_app.invoke(
        SentinelState(current_batch_logs=logs, current_batch_size=len(logs), narrative_summary="")
    )
    lat = time.time() - t0
    decisions = final.get("decisions", []) if isinstance(final, dict) else []
    dec = decisions[-1] if decisions else {}
    pred_id = dec.get("mitre_technique_id", "")
    pred_tactic = dec.get("mitre_tactic", "")
    status = dec.get("mapping_status", "")  # "" nếu mapper bị gate bỏ qua (conf<=0.7/benign)
    curated = pred_id in CURATED_TECH_IDS and status == "resolved"
    # extra: phân rã NGUYÊN NHÂN — action/confidence của triage + technique free-text.
    extra = {
        "action": dec.get("action", ""),
        "confidence": dec.get("confidence", 0.0),
        "mitre_technique": dec.get("mitre_technique", ""),
    }
    return pred_id, pred_tactic, status, curated, lat, extra


def isolate_for_e2e() -> str:
    """
    CÔ LẬP side-effect của mode e2e khỏi DỮ LIỆU LUẬN VĂN đã commit.

    e2e gọi full agent -> sẽ ghi threat_memory.db, audit_trail.db,
    guardrails_audit.db và (khi BLOCK_IP) cả config/system_settings.yaml.
    Ở đây: (1) trỏ threat_memory sang DB TẠM, (2) no-op mọi hàm GHI bền vững
    (block/alert/HITL qua _log_to_db; feedback-config; audit-chain), (3) trỏ
    MLflow sang thư mục tạm để khỏi gọi mạng. KHÔNG file thesis nào bị chạm.

    Trả về temp_dir (để dọn).
    """
    import tempfile

    import src.agent.nodes as nodes_mod
    import src.response.executor as executor
    from src.agent.response_cache import response_cache
    from src.agent.threat_memory import ThreatMemoryStore
    from src.guardrails import audit_logger
    from src.tier1_filter.feedback_listener import FeedbackListener

    response_cache.clear()  # Xoá toàn bộ response cache RAM khi khởi tạo E2E test
    tmp = tempfile.mkdtemp(prefix="mapper_e2e_")
    os.environ["MLFLOW_TRACKING_URI"] = "file:" + os.path.join(tmp, "mlruns")

    # 1) threat_memory -> store TẠM (schema tự tạo trong __init__)
    nodes_mod.threat_memory = ThreatMemoryStore(db_path=os.path.join(tmp, "threat_memory.db"))

    # 2) no-op mọi hàm GHI bền vững
    def _noop(*a, **k):
        return None

    executor._log_to_db = _noop  # chặn ghi config/audit_trail.db (block_ip/raise_alert/HITL)
    FeedbackListener.receive_new_rule = _noop  # type: ignore  # chặn ghi system_settings.yaml
    audit_logger.log_event = _noop  # type: ignore  # chặn ghi logs/guardrails_audit.db

    # 3) CÔ LẬP CẢ CHIỀU ĐỌC, không chỉ chiều ghi.
    import src.agent.threat_memory as tm_mod

    tm_mod.threat_memory = ThreatMemoryStore(db_path=os.path.join(tmp, "threat_memory.db"))
    print(
        f"[*] e2e ISOLATED: threat_memory+audit+config -> temp ({tmp}); thesis data KHÔNG bị chạm."
    )
    return tmp


def _assert_kb_covers_answers(coverage: dict, kb_path: str) -> None:
    """Chặn phép chấm khi ĐÁP ÁN KHÔNG NẰM TRONG KHO TRI THỨC.

    Cùng loại bẫy đã chặn ở `scripts/compare_llm_models.py::_assert_trace_matches_labels`,
    nhưng ở đây cặp lệch pha là (đề bài, kho tri thức).

    Vì sao im lặng mà nguy hiểm: nếu `ground_truth.json` mang mã kỹ thuật mà KB chưa có, bộ
    truy xuất KHÔNG THỂ trả đúng — và bảng kết quả trông y hệt "hệ thống truy xuất kém".
    Đã cắn một lần: KB thiếu T1595.003 khiến 130 mẫu không bao giờ đúng được.

    KIỂM CHÍNH ĐẠI LƯỢNG, KHÔNG KIỂM PROXY. Bản nháp đầu của chốt này so `mtime` giữa hai
    tệp, và nó lập tức báo động giả: KB dựng 14:31, đề bài 14:42 — lệch 11 phút nhưng độ phủ
    đo thật vẫn 100%. Một chốt hay kêu oan sẽ bị người ta tắt đi, nên nó phải đọc đúng con
    số mà nó bảo vệ.
    """
    exact = float(coverage.get("exact_in_kb_pct") or 0.0)
    if exact >= 100.0:
        return
    n = coverage.get("n_with_technique")
    raise SystemExit(
        f"[!] KHO TRI THỨC THIẾU ĐÁP ÁN: chỉ {exact}% mã kỹ thuật kỳ vọng có trong KB "
        f"(n={n}).\n"
        f"    Trần này là mức TỐI ĐA mà bộ truy xuất có thể đạt — chấm tiếp sẽ ra một con số\n"
        f"    thấp vì KB thiếu, chứ không phải vì hệ thống kém, và không có gì báo.\n"
        f"    {kb_path}\n"
        f"    Dựng lại KB rồi đo lại:\n"
        f"      .venv/bin/python scripts/build_knowledge_base.py\n"
        f"      .venv/bin/python -c 'from src.rag.embedder import build_all_indexes, "
        f"update_checksums_file; update_checksums_file(); build_all_indexes(); "
        f"update_checksums_file()'"
    )


def main():
    ap = argparse.ArgumentParser(description="Đánh giá ATT&CK Mapper (rrf | e2e).")
    ap.add_argument("--mode", choices=["rrf", "e2e"], required=True)
    ap.add_argument(
        "--tag",
        default=None,
        help=(
            "Nhãn run (vào tên file + JSON). BỎ TRỐNG thì tự đặt `{mode}_{evidence-layer}` "
            "— ví dụ `e2e_payload`. Chỉ đặt tay khi thật sự cần một lượt riêng (ví dụ so "
            "trước/sau khi nạp thêm KB); tag tự chế kiểu `clean_rag`, `test_fix` đã từng "
            "sinh ra bốn tệp kết quả mâu thuẫn nhau mà không ai biết tệp nào là thật."
        ),
    )
    ap.add_argument("--ground-truth", default=GT_DEFAULT)
    ap.add_argument("--kb", default=KB_DEFAULT)
    ap.add_argument("--limit", type=int, default=None, help="Cắt tổng số sample.")
    ap.add_argument(
        "--per-class",
        type=int,
        default=None,
        help="Subsample N/expected-technique (khuyến nghị cho e2e).",
    )
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--debug", type=int, default=0, help="In chi tiết N mẫu đầu (exp/pred/status/action)."
    )
    ap.add_argument(
        "--evidence-layer",
        choices=["payload", "flow", "all"],
        default="all",
        help=(
            "Lọc theo TẦNG BẰNG CHỨNG của mẫu. `payload` = chỉ mẫu có bằng chứng tầng ứng "
            "dụng (CSIC/adversarial); `flow` = NetFlow thuần (CICIDS). MẶC ĐỊNH `all` giữ "
            "hành vi cũ."
        ),
    )
    args = ap.parse_args()

    # Tên tệp kết quả PHẢI tự nói lên nó đo cấu hình nào. `rrf` (tắt LLM) và `e2e` (toàn
    # tuyến) trên `payload` và `flow` là bốn con số KHÁC NHAU, không thay thế nhau được.
    if not args.tag:
        args.tag = f"{args.mode}_{args.evidence_layer}"

    with open(args.ground_truth, encoding="utf-8") as f:
        gt_all = json.load(f)

    # KHÔNG TRỘN HAI TẦNG BẰNG CHỨNG TRONG MỘT CON SỐ.
    # Mẫu NetFlow thuần không mang một ký tự payload nào, nên "kỹ thuật kỳ vọng" của chúng
    # KHÔNG suy ra được từ đầu vào bằng bất kỳ phương pháp nào — gộp chung sẽ kéo tụt chỉ số
    # quy kết vì một lý do không liên quan đến năng lực hệ thống, và làm con số vô nghĩa.
    if args.evidence_layer != "all":
        from src.agent.nodes import evidence_layer_of

        # `evidence_layer_of` trả về "application" | "flow" — cùng thứ mà prompt gọi là tầng
        # ứng dụng. Cờ CLI dùng chữ "payload" cho dễ đọc, nên phải ánh xạ; so thẳng chuỗi sẽ
        # lọc ra 0 mẫu trong im lặng.
        want = {"payload": "application", "flow": "flow"}[args.evidence_layer]
        before = len(gt_all)
        gt_all = [s for s in gt_all if evidence_layer_of(s.get("logs") or []) == want]
        print(f"[i] Lọc tầng bằng chứng '{want}': {len(gt_all)}/{before} mẫu")

    # LOẠI MẪU DO TÁC GIẢ BIÊN SOẠN — chạy SAU bộ lọc tầng bằng chứng vì chúng đều mang
    # payload nên đều lọt vào lát `application`. Đo được: 50 mẫu đối địch tự viết, chiếm
    # 16,7% dân số CÓ đáp án ATT&CK, và cả 50 cùng đáp án `T1190` (đẩy T1190 từ 52 lên 102).
    # Không loại thì `technique_exact_match_pct` vừa thưởng cho việc khớp khuôn mẫu của
    # chính tác giả, vừa thưởng cho thiên vị một mã duy nhất.
    from experiments.unified_dataset import drop_authored

    gt_all, _n_authored = drop_authored(gt_all)
    if _n_authored:
        print(f"[i] Loại {_n_authored} mẫu BIÊN SOẠN -> còn {len(gt_all)} mẫu dữ liệu thật.")

    # Kiểm rỗng ĐẶT SAU CẢ HAI bộ lọc, và KHÔNG còn gói trong `if evidence_layer != "all"`:
    # `drop_authored` cũng có thể vét cạn tập, nên guard cũ sẽ bỏ lọt đúng trường hợp đó.
    # SystemExit chứ không `return 1`: `main()` được gọi trần ở cuối tệp (không qua
    # `sys.exit(main())`) nên giá trị trả về bị bỏ qua, và runner bash sẽ tưởng bước này
    # THÀNH CÔNG rồi ghi đè kết quả cũ bằng một lượt chạy rỗng.
    if not gt_all:
        raise SystemExit(
            "[!] Không còn mẫu nào sau khi lọc tầng bằng chứng + mẫu biên soạn — dừng."
        )
    with open(args.kb, encoding="utf-8") as f:
        kb = json.load(f)
    kb_index = {t["id"]: t for t in kb if isinstance(t, dict) and t.get("id")}
    kb_ids = set(kb_index)

    coverage = compute_kb_coverage(gt_all, kb_ids)  # trần tính trên TOÀN GT
    gt = subsample(gt_all, args.per_class, args.limit)

    # Nạp phụ thuộc theo mode (e2e cần server; rrf chỉ cần retriever).
    # CẢ HAI mode đều phải cô lập: mode rrf cũng chạy `RuleEngine.evaluate()` để dựng truy
    # vấn, mà engine đọc `ip_reputation` từ SQLite thật -> kết quả phụ thuộc lượt chạy trước.
    isolate_for_e2e()
    if args.mode == "rrf":
        from src.rag.retriever import DualRetriever

        retriever = DualRetriever(use_cache=True)
        predictor = lambda s: predict_rrf(s, retriever)  # noqa: E731
    else:
        from src.agent.state import SentinelState
        from src.agent.workflow import agent_app
        from src.guardrails import loop_detector

        predictor = lambda s: predict_e2e(s, agent_app, SentinelState, loop_detector)  # noqa: E731

    print(f"[*] mode={args.mode} tag={args.tag} | samples={len(gt)} (toàn GT={len(gt_all)})")
    print(
        f"[*] KB-coverage ceiling (trên toàn GT): exact={coverage['exact_in_kb_pct']}%  "
        f"parent={coverage['parent_in_kb_pct']}%  (n_with_technique={coverage['n_with_technique']})"
    )
    _assert_kb_covers_answers(coverage, args.kb)

    # Bộ đếm
    n_tech = n_exact = n_parent = 0  # mẫu có technique kỳ vọng
    n_tac = n_tac_match = 0  # mẫu có tactic kỳ vọng suy được
    n_benign = 0
    n_fired = n_fired_tech = 0  # mapper THỰC SỰ chạy (qua cổng) / trong đó là mẫu có technique
    latencies: list[float] = []
    per_type: dict = defaultdict(lambda: {"n": 0, "exact": 0, "parent": 0, "tactic": 0, "fired": 0})

    t_start = time.time()
    for i, s in enumerate(gt, 1):
        exp_id = str(s.get("expected_mitre_technique", ""))
        try:
            pred_id, pred_tactic, status, curated, lat, extra = predictor(s)
        except Exception as e:
            print(f"   [ERR] {s.get('id')}: {e}")
            continue
        latencies.append(lat)
        fired = bool(status)  # "" = mapper bị cổng (conf<=0.7/benign) bỏ qua; rrf luôn fired
        if fired:
            n_fired += 1

        if args.debug and i <= args.debug:
            print(
                f"   [dbg] exp={exp_id:11s} pred={pred_id or '-':11s} status={status or 'GATED':12s}"
                f" act={extra.get('action', '')!s:10s} conf={extra.get('confidence', 0.0)}"
            )

        if exp_id in BENIGN:
            n_benign += 1
        else:
            n_tech += 1
            pt = per_type[exp_id]
            pt["n"] += 1
            if fired:
                n_fired_tech += 1
                pt["fired"] += 1
            if pred_id == exp_id or _parent(pred_id) == exp_id or pred_id == _parent(exp_id):
                n_exact += 1
                pt["exact"] += 1
            if pred_id and _parent(pred_id) == _parent(exp_id):
                n_parent += 1
                pt["parent"] += 1
            exp_tac = expected_tactic_for(exp_id, kb_index)
            if exp_tac:
                n_tac += 1
                if pred_tactic and pred_tactic == exp_tac:
                    n_tac_match += 1
                    pt["tactic"] += 1

        if i % 250 == 0:
            print(f"   ... {i}/{len(gt)}  ({time.time() - t_start:.0f}s)")

    def pct(a, b):
        return round(a / b * 100, 2) if b else 0.0

    lat_arr = np.array(latencies) if latencies else np.array([0.0])
    result = {
        "tag": args.tag,
        "mode": args.mode,
        "n_samples": len(gt),
        "n_with_technique": n_tech,
        "n_benign": n_benign,
        "kb_coverage_ceiling": coverage,
        "technique_exact_match_pct": pct(n_exact, n_tech),
        "technique_parent_match_pct": pct(n_parent, n_tech),
        "tactic_match_pct": pct(n_tac_match, n_tac),
        "tactic_eval_n": n_tac,
        # PHÂN RÃ NGUYÊN NHÂN: khi mapper THỰC SỰ chạy thì exact-match bao nhiêu
        # (tách 'mapper sai' khỏi 'triage gated').
        #
        # ĐÃ GỠ ba chỉ số: `mapper_fired_rate_pct`, `mapping_resolved_rate_pct`,
        # `curated_path_rate_pct`. Hai cái đầu bằng đúng 100,0 ở CẢ BỐN lần chạy đã lưu —
        # một chỉ số không bao giờ khác 100 thì không đo gì cả, nó chỉ khẳng định hàm có
        # trả về giá trị. Cái thứ ba trùng khít `technique_exact_match_pct` từng chữ số
        # (64,0/64,0 rồi 62,0/62,0) vì mọi khớp chính xác đều đi qua đường curated — hai
        # tên cho cùng một số làm bảng dài ra mà không thêm thông tin.
        "exact_when_fired_pct": pct(n_exact, n_fired_tech),
        "n_fired_with_technique": n_fired_tech,
        "latency_ms_p50": round(float(np.percentile(lat_arr, 50)) * 1000, 2),
        "latency_ms_p95": round(float(np.percentile(lat_arr, 95)) * 1000, 2),
        "latency_ms_mean": round(float(lat_arr.mean()) * 1000, 2),
        "per_attack_type": {
            k: {
                "n": v["n"],
                "exact_pct": pct(v["exact"], v["n"]),
                "parent_pct": pct(v["parent"], v["n"]),
                "tactic_pct": pct(v["tactic"], v["n"]),
            }
            for k, v in sorted(per_type.items())
        },
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    out_path = args.out or os.path.join(OUT_DIR, f"attack_mapper_eval_{args.tag}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # Console table
    print("\n" + "=" * 64)
    print(f" ATT&CK MAPPER EVAL — tag={args.tag} mode={args.mode}")
    print("=" * 64)
    print(
        f"  samples (eval)        : {result['n_samples']}  (technique={n_tech}, benign={n_benign})"
    )
    print(
        f"  technique exact-match : {result['technique_exact_match_pct']}%  (trần KB exact={coverage['exact_in_kb_pct']}%)"
    )
    print(
        f"  technique parent-match: {result['technique_parent_match_pct']}%  (trần KB parent={coverage['parent_in_kb_pct']}%)"
    )
    print(
        f"  tactic match          : {result['tactic_match_pct']}%  (trên {n_tac} mẫu suy được tactic)"
    )
    print(
        f"  exact WHEN fired      : {result['exact_when_fired_pct']}%  (trên {n_fired_tech} mẫu mapper thực chạy)"
    )
    print(f"  latency ms p50/p95    : {result['latency_ms_p50']} / {result['latency_ms_p95']}")
    print("  per expected technique:")
    for k, v in result["per_attack_type"].items():
        print(
            f"    {k:12s} n={v['n']:4d}  exact={v['exact_pct']:5.1f}%  parent={v['parent_pct']:5.1f}%  tactic={v['tactic_pct']:5.1f}%"
        )
    print(f"\n[+] Saved: {out_path}")


if __name__ == "__main__":
    main()
