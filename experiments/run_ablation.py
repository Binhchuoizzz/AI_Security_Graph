"""
Ablation Study HỢP NHẤT — 6 cấu hình A–F trên 3 chế độ chạy.
=========================================================================
Gộp 3 file cũ (run_ablation_study / run_ablation_bcde / run_ablation_balanced) vào
MỘT entry point. Bản chất thí nghiệm + tên file kết quả GIỮ NGUYÊN (để đối chiếu số
liệu đã trích trong luận văn); đây thuần là tổ chức lại code cho gọn.

  --mode af        Config A (Tier-1 rule-only) vs F (SENTINEL 2 tầng đầy đủ) trên tập
                   phân tầng ground_truth + MLflow.  -> results/ablation_results.json
  --mode bcde      Config B/C/D/E (Pure LLM / Welford+LLM / +dense-RAG / +hybrid-RAG)
                   trên 300 mẫu phân tầng.           -> results/ablation_bcde_results.json
  --mode balanced  6 cấu hình A–F trên tập CÂN BẰNG 1:1 (benign thật để gate Welford có cơ
                   hội DROP true-negative). Cỡ mẫu SUY RA từ số benign sẵn có trong
                   ground_truth (hiện là 80+80); warmup Welford lấy từ CICIDS thô held-out.
                                                    -> results/ablation_balanced_results.json
  --mode mlgate    Config G — GIẢM TẢI LLM bằng Cổng ML (KHÔNG cần LLM). Đo bypass-rate +
                   F1 Cổng ML trên phần escalate.    -> results/ablation_mlgate_results.json
  --mode all       Chạy lần lượt af -> bcde -> balanced -> mlgate.

Gate Welford tính MỘT lần/mẫu, dùng chung C/D/E/F => escalation set giống hệt nhau nên
hiệu số D-C, E-D cô lập đúng đóng góp từng tầng RAG. Verdict B-E = action THÔ do LLM trả
(không áp consensus-guard của F) để đo năng lực phân loại thuần.

Chạy (cần LLM server cho mọi mode trừ phần rule-only):
    .venv/bin/python experiments/run_ablation.py --mode balanced
    .venv/bin/python experiments/run_ablation.py --mode af --limit 50
    .venv/bin/python experiments/run_ablation.py --mode bcde --out /tmp/bcde.json
"""

import json
import os
import re
import sys
import time
from typing import Any

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.action_scoring import score_actions  # noqa: E402
from experiments.unified_dataset import drop_authored  # noqa: E402
from src.agent.llm_client import DECISION_JSON_SCHEMA, llm_client  # noqa: E402
from src.agent.nodes import retriever  # noqa: E402
from src.agent.prompts import build_triage_prompt  # noqa: E402
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402
from src.guardrails import decision_policy  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine, RunningStats  # noqa: E402

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
OUT_AF = os.path.join(RESULTS_DIR, "ablation_results.json")
OUT_BCDE = os.path.join(RESULTS_DIR, "ablation_bcde_results.json")
OUT_BALANCED = os.path.join(RESULTS_DIR, "ablation_balanced_results.json")
OUT_MLGATE = os.path.join(RESULTS_DIR, "ablation_mlgate_results.json")

ATTACK_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"}
VALID_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL", "LOG", "DROP", "ESCALATE"}
N_BENIGN = 150
N_ATTACK = 150


# =========================================================================
# Helpers dùng chung
# =========================================================================
def load_ground_truth():
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def stratified(dataset, limit):
    """Lấy mẫu phân tầng đều trên các lớp tấn công (tất định)."""
    if not limit:
        return dataset
    by_label = {}
    for sample in dataset:
        lbl = sample["input"].get("cicids_label", "unknown")
        by_label.setdefault(lbl, []).append(sample)
    num_classes = len(by_label)
    per_class = max(1, (limit + num_classes - 1) // num_classes)
    selected = []
    for _lbl, samples in by_label.items():
        selected.extend(samples[:per_class])
    return selected[:limit]


def _has_payload(sample: dict) -> bool:
    """Mẫu có BẰNG CHỨNG TẦNG ỨNG DỤNG (message/payload) để quy kết được hay không."""
    for lg in sample.get("logs") or []:
        if str(lg.get("message", "")).strip() or str(lg.get("payload", "")).strip():
            return True
    return False


def attributable(dataset: list, limit: int | None) -> list:
    """Tập con CHẤM ĐƯỢC QUY KẾT: có payload VÀ có mã ATT&CK làm đáp án.

    VÌ SAO KHÔNG DÙNG `stratified()` CHO MODE bcde. `stratified()` lấy đều theo LỚP TẤN CÔNG,
    và các lớp đầu tệp đều là NetFlow thuần. Đo thật: với `--limit 8` thì **0/8** mẫu có
    payload. Không có bằng chứng tầng ứng dụng thì KHÔNG CÓ GÌ để quy kết — cả bốn cấu hình
    cùng ra 0% theo cấu trúc, và thước đo quy kết mới cũng không phân giải được B/C/D/E,
    y hệt bệnh của bảng F1 nhị phân mà nó sinh ra để thay thế.

    Đây đúng là dân số mà `scripts/eval_attack_mapper.py --evidence-layer payload` dùng:
    550 mẫu có bằng chứng ứng dụng, trong đó 300 mẫu có mã ATT&CK làm đáp án.

    LOẠI MẪU BIÊN SOẠN. Đo được trước khi vá: trong 300 mẫu ấy có 50 mẫu do tác giả tự viết
    (`cicids_label == "Adversarial"`) — **16,7%** — và cả 50 cùng đáp án `T1190`, đẩy T1190
    từ 52 lên 102 mẫu. Giữ lại thì thước đo thưởng cho việc khớp khuôn mẫu của chính tác giả
    và cho việc thiên vị một mã duy nhất. Sau khi lọc còn **250 mẫu thật**, 5 mã phân bố
    T1595.003=130 · T1190=52 · T1059.007=30 · T1071.001=26 · T1083=12.
    """
    pool = [
        s
        for s in dataset
        if _has_payload(s) and _TECH_RE.search(str(s.get("expected_mitre_technique", "")))
    ]
    pool, n_authored = drop_authored(pool)
    if n_authored:
        print(
            f"[i] Loại {n_authored} mẫu BIÊN SOẠN khỏi tập chấm quy kết "
            f"-> còn {len(pool)} mẫu dữ liệu thật."
        )
    if not limit:
        return pool
    # Phân tầng theo LỚP trong chính tập chấm được, để không dồn hết vào một loại tấn công.
    by_label: dict[str, list] = {}
    for s in pool:
        by_label.setdefault(s["input"].get("cicids_label", "unknown"), []).append(s)
    per = max(1, (limit + len(by_label) - 1) // max(len(by_label), 1))
    sel: list = []
    # Bù cho đủ `limit` sau khi chia đều: lớp ít mẫu không lấp hết suất của mình, nên chia
    # đều xong thường THIẾU so với limit (đo được: limit=300 chỉ ra 209). Người đọc thấy
    # `--limit 300` mà kết quả ghi n=209 sẽ tưởng có lỗi lọc.
    for _lbl, ss in by_label.items():
        sel.extend(ss[:per])
    if len(sel) < limit:
        taken = {id(s) for s in sel}
        sel.extend(s for s in pool if id(s) not in taken)
    return sel[:limit]


def _print_action_confusion(action_scores: dict) -> None:
    """In bảng chéo kỳ vọng × thực tế cho từng cấu hình.

    `score_actions()` đã dựng sẵn ma trận này nhưng trước đây nó chỉ nằm im trong JSON.
    Đây là thứ DUY NHẤT cho biết hệ sai KIỂU GÌ — vd "hoãn HITL trong khi lẽ ra phải chặn"
    khác hẳn "chặn nhầm log lành tính", dù cả hai chỉ làm tụt cùng một con số accuracy.
    """
    for cfg, sc in action_scores.items():
        conf = sc.get("confusion") or {}
        if not conf:
            continue
        actual_labels = sorted({a for row in conf.values() for a in row})
        print(f"\n  Bảng chéo hành động — {cfg}  (hàng = KỲ VỌNG, cột = THỰC TẾ)")
        print("    " + f"{'kỳ vọng':>12}" + "".join(f"{a:>13}" for a in actual_labels))
        for exp_a in sorted(conf):
            row = conf[exp_a]
            cells = "".join(f"{row.get(a, 0):>13}" for a in actual_labels)
            print("    " + f"{exp_a:>12}" + cells)


def _fresh_engine() -> RuleEngine:
    """RuleEngine CÔ LẬP khỏi golden baseline cho Ablation.

    Ablation là thí nghiệm ĐỐI CHỨNG (so verdict-equivalence + độ trễ theo cấu phần
    trên tập con thiên tấn công), có warmup RIÊNG (synthetic cho af/bcde, benign
    held-out cho balanced). Kể từ khi bật tier1.golden_baseline.enabled=true,
    RuleEngine() tự seed 300 flow benign lúc init — điều đó sẽ LÀM NHIỄU baseline
    có kiểm soát của ablation (gate bỗng DROP true-negative, phá tính tương đương
    phán quyết). Vì thế ablation LUÔN reset Welford về rỗng để tái lập đúng thiết
    kế đối chứng, ĐỘC LẬP với golden (vốn là tính năng của luồng-gộp/triển khai thật)."""
    engine = RuleEngine()
    for _k in engine.global_stats:
        engine.global_stats[_k] = RunningStats()
    return engine


def _synthetic_warmup(rule_engine):
    """Warmup baseline Welford bằng lưu lượng tổng hợp (dùng cho af/bcde)."""
    print("[*] Warmup Rule Engine baseline...")
    for i in range(110):
        val = 15 + (i % 5) - 2
        rule_engine.evaluate(
            {
                "Source IP": f"192.168.1.{10 + i}",
                "Destination Port": 80,
                "Total Fwd Packets": val,
                "Flow Bytes/s": val * 100,
                "Flow Duration": 1000 + (i % 10) * 10,
            }
        )
    print("[+] Warmup complete.")


def build_rag_query(logs):
    """Tái dựng truy vấn RAG y như node_rag_context."""
    if not logs:
        return "suspicious network activity"
    first = logs[0]
    parts = []
    msg = (str(first.get("message", "")) + " " + str(first.get("payload", ""))).strip()
    if msg:
        parts.append(msg)
    svc = first.get("service") or first.get("Service")
    if svc:
        parts.append(f"service {svc}")
    port = first.get("Destination Port") or first.get("dst_port")
    if port not in (None, "", 0):
        parts.append(f"destination port {port}")
    uri = first.get("uri") or first.get("URI")
    if uri:
        parts.append(f"uri {uri}")
    for reason in (first.get("tier1_reasons") or [])[:3]:
        parts.append(str(reason))
    q = " ".join(parts).strip() or "suspicious network activity"
    return q[:300]


def dense_only_context(query_text):
    """RAG chỉ-FAISS (dense-only) cho Config D — KHÔNG BM25, KHÔNG RRF."""
    out = {}
    for source_key, source_name in (("mitre", "MITRE ATT&CK"), ("nist", "NIST SP 800-61r2")):
        if source_key not in retriever.faiss_indexes:
            out[source_key] = f"[{source_name}] No relevant matches found."
            continue
        meta = retriever.metadata[source_key]
        fetch_k = min(retriever.top_k, len(meta))
        emb = retriever.model.encode([query_text], normalize_embeddings=True).astype("float32")
        dense = retriever._dense_search(emb, source_key, fetch_k)  # {idx:{score,rank}}
        ranked = sorted(dense.keys(), key=lambda x: dense[x]["score"], reverse=True)[
            : retriever.top_k
        ]
        if not ranked:
            out[source_key] = f"[{source_name}] No relevant matches found."
            continue
        lines = [f"[{source_name} Context — Top {len(ranked)} matches (dense-only)]"]
        for i, idx in enumerate(ranked, 1):
            safe = retriever.rag_sanitizer.sanitize_retrieve(meta[idx]["text"])
            lines.append(f"\n--- Match {i} (Score: {dense[idx]['score']:.4f}) ---")
            lines.append(safe)
        out[source_key] = "\n".join(lines)
    return f"MITRE ATT&CK:\n{out['mitre']}\n\nNIST SP 800-61r2:\n{out['nist']}"


def hybrid_context(query_text):
    """RAG lai (FAISS+BM25+RRF) cho Config E — qua retriever chính thức."""
    res = retriever.retrieve(query_text)
    return f"MITRE ATT&CK:\n{res.get('mitre_context', '')}\n\nNIST SP 800-61r2:\n{res.get('nist_context', '')}"


def llm_action(logs, rag_context):
    """Gọi LLM trên raw logs (KHÔNG guardrails encapsulation) + RAG tùy chọn.

    Trả `(action, giây, meta)`. `meta` mang KỸ THUẬT LLM TỰ KHAI — bắt buộc phải có thì
    B/C/D/E mới phân giải được: biến độc lập của bốn cấu hình này là CẤU HÌNH RAG, mà RAG
    không đổi việc "có phải mối đe doạ không", nó đổi việc "quy kết kỹ thuật nào". Chấm
    bằng F1 nhị phân nên bốn cấu hình từng ra giống nhau từng bit — thước đo sai đại lượng,
    không phải hệ thống không có khác biệt.
    """
    raw_logs_str = "\n".join(str(log) for log in logs)
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_context)
    meta: dict[str, Any] = {"technique_raw": "", "technique_id": "", "confidence": 0.0}
    t0 = time.time()
    try:
        # ĐỒNG BỘ với Config F: ép JSON hợp lệ (json_schema) + reasoning tiếng Việt, max_tokens rộng.
        raw = llm_client.invoke(
            messages=messages,
            temperature=0.1,
            response_format=DECISION_JSON_SCHEMA,
            max_tokens=1536,
        )
        decision = llm_client.parse_llm_response(raw)
        meta["technique_raw"] = str(decision.get("mitre_technique", "") or "").strip()
        _m = re.search(r"\b(AML\.T\d{4}|T\d{4}(?:\.\d{3})?)\b", meta["technique_raw"], re.I)
        meta["technique_id"] = _m.group(1).upper() if _m else ""
        raw_action = str(decision.get("action", "AWAIT_HITL")).upper().strip()
        if raw_action not in VALID_ACTIONS:
            raw_action = "AWAIT_HITL"
        # ĐỒNG BỘ CHÍNH SÁCH ĐỘ-TIN-CẬY (giống Config F / hệ triển khai): confidence LÁI action.
        # LLM cho là đe doạ (BLOCK_IP/ALERT) -> classify_llm theo confidence (>=0.85 BLOCK ·
        # 0.65-0.85 ALERT · <0.65 AWAIT_HITL). DROP/LOG (sạch) & AWAIT_HITL giữ nguyên.
        try:
            conf = float(decision.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        meta["confidence"] = conf
        if raw_action in ("BLOCK_IP", "ALERT"):
            action = decision_policy.classify_llm(is_threat=True, confidence=conf)
        else:
            action = raw_action
    except Exception as e:
        print(f"   [LLM ERROR] {e}")
        action = "AWAIT_HITL"
        meta["llm_error"] = str(e)[:120]
    return action, time.time() - t0, meta


# Mã kỹ thuật xuất hiện trong khối ngữ cảnh RAG -> tập "có bằng chứng đỡ" của lô đó.
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def score_attribution(
    expected: list[str], claimed: list[str], grounded: list[bool], invoked: list[bool]
) -> dict:
    """Chấm QUY KẾT — thước đo đúng đại lượng cho B/C/D/E (bám RQ3).

    `expected`: mã đúng theo `expected_mitre_technique` ('None' = mẫu không có mã).
    `claimed` : mã LLM tự khai.
    `grounded`: mã đó CÓ nằm trong khối RAG đưa cho chính cấu hình ấy hay không.
    `invoked` : cấu hình này CÓ THỰC SỰ gọi LLM cho mẫu đó hay không.

    `invoked` LÀ BẮT BUỘC, KHÔNG PHẢI TUỲ CHỌN. C/D/E chỉ gọi LLM khi Tier-1 leo thang; các
    mẫu còn lại dừng ở phán quyết Tier-1 và không có cơ hội quy kết. Bản đầu của hàm này
    chấm trên TOÀN BỘ mẫu nên đã trộn "Tier-1 xử lý xong, chưa hỏi LLM" vào cùng rổ với
    "LLM từ chối quy kết". Đo thật trên 8 mẫu: C/D/E ra `abstain_rate = 1.0000` trong khi
    chỉ 2/8 mẫu từng được đưa tới LLM — con số đó không mô tả hành vi nào có thật, và B
    (luôn gọi LLM) thì không so được với chúng vì hai bên khác mẫu số.

    Cùng nguyên tắc `evaluate_rag_retrieval.py` đang dùng: chấm ĐIỀU KIỆN HOÁ THEO LEO THANG,
    và báo luôn `n_invoked` để không ai tưởng mẫu số là toàn tập.

    LƯU Ý ĐỌC SỐ: với B (LLM thuần) và C (Welford+LLM) thì khối RAG RỖNG, nên
    `ungrounded_rate` = 1.0 THEO CẤU TRÚC, không phải phát hiện thực nghiệm. Ý nghĩa của nó
    là: hai cấu hình đó KHÔNG THỂ chứng minh mã mình nêu — mọi quy kết chỉ dựa vào trí nhớ
    tham số. Cặp phân giải thật sự nằm giữa D (dense) và E (lai + RRF), nơi cả hai đều có
    RAG nhưng khác cách truy xuất.
    """
    idx = [i for i in range(len(expected)) if invoked[i]]
    scorable = [i for i in idx if _TECH_RE.search(expected[i] or "")]
    exact = sum(
        1 for i in scorable if claimed[i] and claimed[i].upper() == expected[i].strip().upper()
    )
    parent = sum(
        1
        for i in scorable
        if claimed[i] and claimed[i].split(".")[0] == expected[i].strip().split(".")[0]
    )
    n_claimed = sum(1 for i in idx if claimed[i])
    n_ungrounded = sum(1 for i in idx if claimed[i] and not grounded[i])
    return {
        "n_total": len(expected),
        "n_invoked": len(idx),
        "n_scorable": len(scorable),
        "technique_exact_pct": round(100 * exact / len(scorable), 2) if scorable else None,
        "technique_parent_pct": round(100 * parent / len(scorable), 2) if scorable else None,
        "abstain_rate": round((len(idx) - n_claimed) / len(idx), 4) if idx else None,
        "ungrounded_rate": round(n_ungrounded / n_claimed, 4) if n_claimed else None,
        "n_claimed": n_claimed,
        "n_ungrounded": n_ungrounded,
        "denominator_note": "Chỉ tính mẫu cấu hình này THỰC SỰ gọi LLM (n_invoked).",
    }


def to_pred(action):
    return 1 if action in ATTACK_ACTIONS else 0


def run_gate(logs, rule_engine):
    """Gate Welford/Tier-1 (giống Config F): trả (needs_llm, tier1_verdict)."""
    needs_llm = False
    tier1_verdict = "DROP"
    for log in logs:
        act = rule_engine.evaluate(log).get("tier1_action")
        if act == "ESCALATE":
            needs_llm = True
            break
        elif act in ("BLOCK_IP", "ALERT", "AWAIT_HITL"):
            tier1_verdict = act
    return needs_llm, tier1_verdict


def calc_fpr(y_true, y_pred):
    """False Positive Rate an toàn với trường hợp 1 lớp."""
    try:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        return fp / (fp + tn) if (fp + tn) > 0 else 0.0
    except ValueError:
        return 0.0


# =========================================================================
# MODE: af  — Config A (rule-only) vs F (SENTINEL đầy đủ) + MLflow
# =========================================================================
def run_af(limit=None, out=None):
    import mlflow

    dataset = stratified(load_ground_truth(), limit) if limit else load_ground_truth()
    out_path = out or OUT_AF

    # dict[str, Any]: chứa CẢ các khối config (dict) LẪN các khối tổng hợp thêm sau
    # (expected_actions: list, action_scores: dict) — không đồng nhất kiểu theo thiết kế.
    results: dict[str, Any] = {
        "Config_A": {"y_true": [], "y_pred": [], "latencies": [], "actions": []},
        "Config_F": {
            "y_true": [],
            "y_pred": [],
            "latencies": [],
            "reasoning_outputs": [],
            "actions": [],
        },
    }

    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
    mlflow.set_experiment("Sentinel_Ablation_Study")

    with mlflow.start_run(run_name="Full_Evaluation_Run"):
        mlflow.log_param("dataset_size", len(dataset))
        mlflow.log_param("config_a", "Rule-only (No LLM)")
        mlflow.log_param("config_f", "Full SENTINEL 2-Tier")

        # Hành động KỲ VỌNG của từng mẫu — dùng chung cho A và F khi chấm theo hành động.
        expected_actions: list[str] = []

        print(f"[*] Chay Ablation Study (A vs F) tren {len(dataset)} mau...")
        rule_engine = _fresh_engine()
        _synthetic_warmup(rule_engine)

        ml_bypassed_count = 0

        for idx, sample in enumerate(dataset):
            is_attack = 1 if sample["expected_action"] in ["BLOCK_IP", "ALERT", "AWAIT_HITL"] else 0
            logs = sample.get("logs", [])
            rule_engine.session_baseline.reset_window()

            # --- Config A: chỉ luật cứng ---
            start_time_a = time.time()
            pred_a = 0
            # GIỮ LẠI hành động THẬT của Tier-1 (không chỉ cờ nhị phân) để chấm theo hành
            # động. Với A, `ESCALATE` nghĩa là "cần tầng sau" mà tầng sau bị TẮT -> pipeline
            # CHƯA phân giải; score_actions tính riêng, không coi là phát hiện.
            action_a = "LOG"
            for log in logs:
                result = rule_engine.evaluate(log)
                _act = result.get("tier1_action")
                if _act in ["BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"]:
                    pred_a = 1
                    action_a = _act
                    break
            latency_a = time.time() - start_time_a
            results["Config_A"]["y_true"].append(is_attack)
            results["Config_A"]["y_pred"].append(pred_a)
            results["Config_A"]["latencies"].append(latency_a)
            results["Config_A"]["actions"].append(action_a)
            expected_actions.append(sample["expected_action"])

            # --- Config F: SENTINEL 2 tầng đầy đủ ---
            start_time_f = time.time()
            pred_f = 0
            needs_llm = False
            tier1_verdict = "DROP"
            for log in logs:
                act = rule_engine.evaluate(log).get("tier1_action")
                if act == "ESCALATE":
                    needs_llm = True
                    break
                elif act in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
                    tier1_verdict = act

            reasoning_output = {
                "sample_id": sample["id"],
                "expected_action": sample["expected_action"],
                "expected_mitre": sample.get("expected_mitre_technique", ""),
                "narrative_summary": "",
                "decisions": [],
                "escalated_to_llm": needs_llm,
                # LOG ĐẦU VÀO đại diện — bắt buộc để `evaluate_reasoning.py` chấm được
                # NEO BẰNG CHỨNG (đối chiếu `field=value` trong lập luận với giá trị THẬT).
                # Không có nó thì không phân biệt được model TRÍCH số từ log hay BỊA ra.
                "log": logs[0] if logs else {},
            }

            if needs_llm:
                initial_state = SentinelState(
                    current_batch_logs=logs,
                    current_batch_size=len(logs),
                    narrative_summary="",
                )
                from src.guardrails import loop_detector

                loop_detector.reset()
                try:
                    final_state = agent_app.invoke(initial_state)
                    decisions = final_state.get("decisions", [])
                    reasoning_output["narrative_summary"] = final_state.get("narrative_summary", "")
                    reasoning_output["decisions"] = decisions
                    if decisions:
                        action = decisions[-1].get("action", "UNKNOWN")
                        # DI SẢN kiến trúc CŨ: field `ml_model` từng do một node ML-triage
                        # bên trong agent gắn. Sau khi Cổng ML DỜI về Tier-1/subscriber, agent
                        # (`agent_app`) KHÔNG còn node ML nào -> field này không bao giờ được
                        # gắn, nên counter này LUÔN = 0 trong Config F. Phép đo giảm-tải Cổng ML
                        # THẬT nằm ở `--mode mlgate` (Config G). Giữ lại để tương thích shape output.
                        if decisions[-1].get("ml_model"):
                            ml_bypassed_count += 1
                        results["Config_F"]["actions"].append(action)
                        if action in ["BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"]:
                            pred_f = 1
                except Exception as e:
                    print(f"Loi chay Config F cho mau {sample['id']}: {e}")
                    pred_f = 0
                    results["Config_F"]["actions"].append("ERROR")
            else:
                results["Config_F"]["actions"].append(f"TIER1_{tier1_verdict}")
                if tier1_verdict in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
                    pred_f = 1

            latency_f = time.time() - start_time_f
            results["Config_F"]["y_true"].append(is_attack)
            results["Config_F"]["y_pred"].append(pred_f)
            results["Config_F"]["latencies"].append(latency_f)
            results["Config_F"]["reasoning_outputs"].append(reasoning_output)

            print(
                f"[{idx + 1}/{len(dataset)}] {sample['id']} | True: {is_attack} | "
                f"Pred A: {pred_a} ({latency_a:.3f}s) | Pred F: {pred_f} ({latency_f:.3f}s)"
            )

        # ── CHẤM THEO HÀNH ĐỘNG (thước đo CHÍNH) ────────────────────────────────────
        action_scores = {
            "Config_A": score_actions(expected_actions, results["Config_A"]["actions"]),
            "Config_F": score_actions(expected_actions, results["Config_F"]["actions"]),
        }
        results["expected_actions"] = expected_actions
        results["action_scores"] = action_scores

        # ── CẢNH BÁO BASE-RATE gắn thẳng vào kết quả ─────────────────────────────────
        # Tập ground_truth phân tầng thiên TẤN CÔNG rất nặng. Trên đó, một hàm
        # `return True` cũng đạt F1 xấp xỉ base rate — nên F1 nhị phân ở chế độ này KHÔNG
        # đo được năng lực, và chính nó là nguồn gốc con số "0,967" từng bị trích như một
        # thành tích. Gắn cờ vào JSON để người đọc kết quả (và người viết luận văn) thấy
        # ngay, thay vì phải nhớ cảnh báo nằm ở một tài liệu khác.
        _y = results["Config_A"]["y_true"]
        _rate = round(sum(_y) / len(_y), 4) if _y else 0.0
        results["metric_health"] = {
            "attack_base_rate": _rate,
            "is_base_rate_artifact": _rate >= 0.85,
            "binary_f1_trustworthy": _rate < 0.85,
            "primary_metric": "action_scores.action_accuracy + autonomous_precision",
            "warning": (
                "Tập này thiên tấn công nặng: F1/Accuracy nhị phân xấp xỉ base rate nên "
                "KHÔNG phân biệt được cấu hình. Dùng chấm-theo-hành-động làm thước đo "
                "chính; muốn so độ chính xác thì chạy `--mode balanced`."
            )
            if _rate >= 0.85
            else "",
        }

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Da luu ket qua vao {out_path}")

        print("\n" + "=" * 78)
        print("CHẤM THEO HÀNH ĐỘNG CUỐI CÙNG (thước đo CHÍNH — phân biệt được cấu hình)")
        print("=" * 78)
        print(f"{'':>10} {'khớp HĐ':>9} {'tự quyết':>9} {'hoãn HITL':>10} {'chưa g.quyết':>13}")
        for cfg, sc in action_scores.items():
            if not sc.get("n"):
                continue
            print(
                f"{cfg:>10} {sc['action_accuracy']:>9.4f} {sc['autonomy_rate']:>9.4f} "
                f"{sc['defer_rate']:>10.4f} {sc['unresolved_rate']:>13.4f}"
            )
            mlflow.log_metric(f"{cfg}_ActionAccuracy", float(sc["action_accuracy"]))
            mlflow.log_metric(f"{cfg}_AutonomyRate", float(sc["autonomy_rate"]))
            if sc["autonomous_precision"] is not None:
                mlflow.log_metric(f"{cfg}_AutonomousPrecision", float(sc["autonomous_precision"]))
        if results["metric_health"]["is_base_rate_artifact"]:
            print(
                f"\n[!] CẢNH BÁO BASE-RATE: tập này {results['metric_health']['attack_base_rate']:.1%} "
                f"tấn công -> F1/Accuracy nhị phân xấp xỉ base rate, KHÔNG phân biệt được\n"
                f"    cấu hình. Dùng bảng chấm-theo-hành-động ở trên; so độ chính xác thì "
                f"chạy `--mode balanced`."
            )

        # ── BẢNG CHÉO 4 LỚP HÀNH ĐỘNG — hệ sai KIỂU GÌ, không chỉ sai bao nhiêu ──────
        # `score_actions` đã dựng sẵn ma trận này nhưng trước đây chỉ nằm im trong JSON.
        _print_action_confusion(action_scores)

        _ap_a = action_scores["Config_A"].get("autonomous_precision")
        _ap_f = action_scores["Config_F"].get("autonomous_precision")
        print(
            f"\n  Độ chính xác KHI TỰ QUYẾT:  A={_ap_a}  F={_ap_f}"
            "\n  (khi hệ dám tự hành động thì nó có đáng tin không — câu hỏi vận hành thật)"
        )

        ya_t, ya_p = results["Config_A"]["y_true"], results["Config_A"]["y_pred"]
        yf_t, yf_p = results["Config_F"]["y_true"], results["Config_F"]["y_pred"]
        f1_a = f1_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec_a = precision_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec_a = recall_score(ya_t, ya_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        f1_f = f1_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec_f = precision_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec_f = recall_score(yf_t, yf_p, zero_division=0)  # pyright: ignore[reportArgumentType]

        fpr_a = calc_fpr(results["Config_A"]["y_true"], results["Config_A"]["y_pred"])
        fpr_f = calc_fpr(results["Config_F"]["y_true"], results["Config_F"]["y_pred"])

        total_f = len(results["Config_F"]["actions"])
        hitl_count = results["Config_F"]["actions"].count("AWAIT_HITL")
        hitl_ratio = (hitl_count / total_f) * 100 if total_f > 0 else 0.0

        cache_stats = (
            retriever.cache.get_stats()
            if hasattr(retriever, "cache") and retriever.cache
            else {"hit_rate": 0.0}
        )
        cache_hit_rate = cache_stats.get("hit_rate", 0.0)

        ml_bypass_rate = (ml_bypassed_count / total_f) * 100 if total_f > 0 else 0.0

        mlflow.log_metric("Config_A_F1", float(f1_a))
        mlflow.log_metric("Config_A_Precision", float(prec_a))
        mlflow.log_metric("Config_A_Recall", float(rec_a))
        mlflow.log_metric("Config_A_FPR", float(fpr_a))
        mlflow.log_metric("MTTD_Proxy_Tier1_sec", float(np.mean(results["Config_A"]["latencies"])))
        mlflow.log_metric("Config_F_F1", float(f1_f))
        mlflow.log_metric("Config_F_Precision", float(prec_f))
        mlflow.log_metric("Config_F_Recall", float(rec_f))
        mlflow.log_metric("Config_F_FPR", float(fpr_f))
        mlflow.log_metric("MTTR_Proxy_Tier2_sec", float(np.mean(results["Config_F"]["latencies"])))
        mlflow.log_metric("HITL_Escalation_Rate_pct", hitl_ratio)
        mlflow.log_metric("RAG_Cache_Hit_Rate_pct", cache_hit_rate)
        mlflow.log_metric("ML_Bypass_Rate_pct", ml_bypass_rate)

        print(
            f"\n[+] Config A: F1={f1_a:.4f} | Prec={prec_a:.4f} | Rec={rec_a:.4f} | "
            f"FPR={fpr_a:.4f} | MTTD_Proxy={np.mean(results['Config_A']['latencies']):.3f}s"
        )
        print(
            f"[+] Config F: F1={f1_f:.4f} | Prec={prec_f:.4f} | Rec={rec_f:.4f} | "
            f"FPR={fpr_f:.4f} | MTTR_Proxy={np.mean(results['Config_F']['latencies']):.3f}s"
        )
        print(
            f"[+] Operational: RAG Cache Hit Rate = {cache_hit_rate:.1f}% | HITL Ratio = {hitl_ratio:.1f}% | ML Bypass Rate = {ml_bypass_rate:.1f}%"
        )
        print(
            "[!] DISCLAIMER: Processing Latency is used as a proxy for MTTD/MTTR under offline "
            "dataset constraints. Real-world ingestion and human review times are not included."
        )
        print("[+] Da ghi metrics len MLflow.")


# =========================================================================
# MODE: bcde  — Config B/C/D/E trên 300 mẫu phân tầng
# =========================================================================
def run_bcde(limit=300, out=None):
    out_path = out or OUT_BCDE
    dataset = attributable(load_ground_truth(), limit)
    print(
        f"[*] Ablation B-E trên {len(dataset)} mẫu CHẤM ĐƯỢC QUY KẾT "
        f"(có payload + có mã ATT&CK). KHÔNG dùng phân tầng theo lớp như mode af: "
        f"lớp NetFlow thuần không có bằng chứng để quy kết."
    )

    rule_engine = _fresh_engine()
    _synthetic_warmup(rule_engine)

    R: dict[str, Any] = {
        c: {
            "y_true": [],
            "y_pred": [],
            "latencies": [],
            "escalated": [],
            "actions": [],
            # Hai trường mới: kỹ thuật LLM tự khai, và mã đó CÓ neo trong khối RAG của
            # chính cấu hình ấy hay không. Đây là đại lượng mà B/C/D/E thực sự tác động.
            "techniques": [],
            "grounded": [],
            # Cấu hình này CÓ gọi LLM cho mẫu đó không. C/D/E chỉ gọi khi Tier-1 leo thang;
            # thiếu cờ này thì "chưa hỏi LLM" bị đếm chung với "LLM từ chối quy kết".
            "llm_invoked": [],
        }
        for c in "BCDE"
    }
    expected_actions: list[str] = []
    expected_techs: list[str] = []

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        # Mặc định: gate KHÔNG escalate -> C/D/E dừng ở phán quyết Tier-1. Khởi tạo ở đây
        # để biến luôn bound dù đi nhánh nào (an toàn kiểu + ý nghĩa rõ khi chấm hành động).
        a_c = a_d = a_e = tier1_verdict
        # `m_*` giữ kỹ thuật LLM khai; `ctx_*` giữ khối RAG đã đưa cho chính cấu hình đó —
        # phải là ĐÚNG khối ấy thì "có neo hay không" mới có nghĩa. Dùng chung một khối cho
        # cả D và E sẽ xoá mất khác biệt giữa dense-only và lai+RRF, tức xoá luôn thứ đang đo.
        m_c = m_d = m_e = {"technique_id": ""}
        ctx_c = ctx_d = ctx_e = ""
        a_b, l_b, m_b = llm_action(logs, "")  # B — Pure LLM (KHÔNG RAG)
        if needs_llm:  # C — Welford + LLM (no RAG)
            a_c, l_c, m_c = llm_action(logs, "")
            p_c = to_pred(a_c)
        else:
            l_c, p_c = 0.0006, tier1_pred
        if needs_llm:  # D — Welford + dense RAG
            ctx_d = dense_only_context(query)
            a_d, l_d, m_d = llm_action(logs, ctx_d)
            p_d = to_pred(a_d)
        else:
            l_d, p_d = 0.0006, tier1_pred
        if needs_llm:  # E — Welford + hybrid RAG (FAISS+BM25+RRF)
            ctx_e = hybrid_context(query)
            a_e, l_e, m_e = llm_action(logs, ctx_e)
            p_e = to_pred(a_e)
        else:
            l_e, p_e = 0.0006, tier1_pred

        # Hành động THẬT của từng config. Khi gate KHÔNG escalate, C/D/E dừng ở phán
        # quyết Tier-1 nên hành động là `tier1_verdict` — ghi đúng như vậy để chấm theo
        # hành động phản ánh ĐÚNG thứ pipeline thực sự làm.
        expected_actions.append(sample["expected_action"])
        expected_techs.append(str(sample.get("expected_mitre_technique", "") or ""))
        for c, pred, lat, act, meta, ctx in (
            ("B", to_pred(a_b), l_b, a_b, m_b, ""),
            ("C", p_c, l_c, a_c if needs_llm else tier1_verdict, m_c, ctx_c),
            ("D", p_d, l_d, a_d if needs_llm else tier1_verdict, m_d, ctx_d),
            ("E", p_e, l_e, a_e if needs_llm else tier1_verdict, m_e, ctx_e),
        ):
            R[c]["y_true"].append(is_attack)
            R[c]["y_pred"].append(pred)
            R[c]["latencies"].append(lat)
            R[c]["escalated"].append(1 if (c == "B" or needs_llm) else 0)
            R[c]["actions"].append(act)
            tid = str(meta.get("technique_id", "") or "")
            R[c]["techniques"].append(tid)
            R[c]["grounded"].append(bool(tid) and tid in set(_TECH_RE.findall(ctx)))
            # B luôn gọi LLM (đó là định nghĩa "LLM thuần"); C/D/E chỉ khi Tier-1 leo thang.
            R[c]["llm_invoked"].append(True if c == "B" else needs_llm)

        print(
            f"[{idx + 1}/{len(dataset)}] {sample['id']} | true={is_attack} esc={int(needs_llm)} "
            f"| B={to_pred(a_b)} C={p_c} D={p_d} E={p_e}"
        )

    R["expected_actions"] = expected_actions
    R["expected_techniques"] = expected_techs
    R["action_scores"] = {c: score_actions(expected_actions, R[c]["actions"]) for c in "BCDE"}
    # THƯỚC ĐO CHÍNH của chế độ này. Biến độc lập B/C/D/E là CẤU HÌNH RAG, và RAG không đổi
    # việc "có phải mối đe doạ không" — nó đổi việc "quy kết kỹ thuật nào". Chấm bằng F1 nhị
    # phân là đo sai đại lượng, và đó là lý do bốn cấu hình từng ra giống nhau TỪNG BIT.
    R["attribution_scores"] = {
        c: score_attribution(
            expected_techs, R[c]["techniques"], R[c]["grounded"], R[c]["llm_invoked"]
        )
        for c in "BCDE"
    }
    # CẢNH BÁO LỰC KIỂM ĐỊNH. C/D/E chỉ gọi LLM khi Tier-1 leo thang, và trên mẫu có payload
    # tỉ lệ leo thang đo được chỉ ~17%. Với `--limit 12` thì C/D/E mỗi cấu hình chỉ có 2 ca —
    # không đủ để nói D khác E hay không. Ở cỡ đầy đủ (300 mẫu) sẽ được ~50 ca mỗi cấu hình.
    _min_inv = min(R["attribution_scores"][c]["n_invoked"] for c in "CDE")
    R["attribution_underpowered"] = _min_inv < 30
    if R["attribution_underpowered"]:
        R["attribution_power_warning"] = (
            f"C/D/E chỉ được gọi {_min_inv} lần — KHÔNG đủ để so D với E. Chạy `--limit 300` "
            f"(hoặc bỏ --limit) để có ~50 ca mỗi cấu hình trước khi trích bất kỳ so sánh nào."
        )
    R["metric_note"] = (
        "Thước đo CHÍNH: attribution_scores. F1/Prec/Rec nhị phân giữ lại chỉ để đối chiếu "
        "lịch sử — nó KHÔNG phân giải được B/C/D/E. `ungrounded_rate` của B và C bằng 1.0 "
        "THEO CẤU TRÚC (không có RAG thì không có gì để neo); cặp so sánh có nghĩa là D "
        "(dense-only) với E (lai FAISS+BM25+RRF)."
    )

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {out_path}\n")

    _lbl = {
        "B": "LLM thuần",
        "C": "+ Welford",
        "D": "+ RAG dense",
        "E": "+ RAG lai RRF",
    }

    print("QUY KẾT KỸ THUẬT (thước đo CHÍNH — bám RQ3):")
    print(
        f"  {'':>3} {'cấu hình':<15} {'exact':>8} {'parent':>8} {'không neo':>10} {'bỏ trống':>9}"
    )
    for c in "BCDE":
        at = R["attribution_scores"][c]

        def _p(v, pct=False):
            return "  —" if v is None else (f"{v:>7.2f}%" if pct else f"{v:>9.4f}")

        print(
            f"  {c:>3} {_lbl[c]:<15} {_p(at['technique_exact_pct'], True)} "
            f"{_p(at['technique_parent_pct'], True)} {_p(at['ungrounded_rate'])} "
            f"{_p(at['abstain_rate'])}"
        )
    print("  (mẫu số = số ca cấu hình đó THỰC SỰ gọi LLM, không phải toàn tập):")
    for c in "BCDE":
        at = R["attribution_scores"][c]
        print(
            f"      {c}: gọi LLM {at['n_invoked']}/{at['n_total']} · chấm được {at['n_scorable']}"
        )
    print("  * B và C không có RAG -> 'không neo' = 1.0 THEO CẤU TRÚC. So D với E.")
    if R.get("attribution_underpowered"):
        print(f"  ⚠️  {R['attribution_power_warning']}")
    print()

    print("CHẤM THEO HÀNH ĐỘNG:")
    print(f"  {'':>3} {'khớp HĐ':>9} {'tự quyết':>9} {'hoãn':>8} {'chưa g.quyết':>13}")
    for c in "BCDE":
        sc = R["action_scores"][c]
        print(
            f"  {c:>3} {sc['action_accuracy']:>9.4f} {sc['autonomy_rate']:>9.4f} "
            f"{sc['defer_rate']:>8.4f} {sc['unresolved_rate']:>13.4f}"
        )
    print()

    print("F1 nhị phân — CHỈ để đối chiếu lịch sử, KHÔNG phân giải được B/C/D/E:")
    for c in "BCDE":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec = precision_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec = recall_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        esc = 100.0 * np.mean(R[c]["escalated"])
        mean_lat = float(np.mean(R[c]["latencies"]))
        print(
            f"  [Config {c}] F1={f1:.4f} | Prec={prec:.4f} | Rec={rec:.4f} "
            f"| escalate={esc:.1f}% | mean_lat={mean_lat:.3f}s"
        )


# =========================================================================
# MODE: balanced  — 6 cấu hình A–F trên tập CÂN BẰNG 150/150
# =========================================================================
def _raw_benign_warmup_logs(n: int, exclude: list) -> list[dict]:
    """Nạp `n` flow benign THẬT từ CSV CICIDS thô để warmup Welford, LOẠI TRỪ mọi flow đã
    có trong tập chấm (đối chiếu bằng chữ ký đặc trưng).

    Vì sao không dùng golden baseline: `_fresh_engine()` CỐ Ý xoá Welford để ablation là
    thí nghiệm đối chứng độc lập. Vì sao không cắt đôi benign của ground_truth: chỉ có 80
    mẫu, cắt đôi thì tập chấm còn 40/40 và McNemar mất gần hết lực kiểm định. CSV thô cho
    warmup dồi dào mà vẫn held-out.

    Trả [] nếu không có dữ liệu thô -> caller suy biến sang cắt đôi ground_truth.
    """
    cic_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw", "cicids2018"
    )
    if not os.path.isdir(cic_dir):
        return []
    csvs = sorted(f for f in os.listdir(cic_dir) if f.endswith(".csv"))
    if not csvs:
        return []

    from experiments.build_golden_baseline import _flow_signature
    from experiments.unified_dataset import map_cicids

    excluded_sigs = set()
    for s in exclude:
        for log in s.get("logs", []) or []:
            if isinstance(log, dict):
                excluded_sigs.add(_flow_signature(log))

    try:
        import pandas as pd

        out: list[dict] = []
        for csv_name in csvs:
            if len(out) >= n:
                break
            df = pd.read_csv(os.path.join(cic_dir, csv_name), nrows=20_000, low_memory=False)
            df.rename(columns=lambda c: str(c).strip(), inplace=True)
            label_col = next((c for c in df.columns if c.lower() == "label"), None)
            if label_col is None:
                continue
            benign_rows = df[df[label_col].astype(str).str.strip().str.lower() == "benign"]
            for row in benign_rows.to_dict("records"):
                if len(out) >= n:
                    break
                log = map_cicids(row)
                if _flow_signature(log) in excluded_sigs:
                    continue  # trùng tập chấm -> rò rỉ, bỏ
                out.append(log)
        return out
    except Exception as e:
        print(f"[!] Không nạp được warmup benign từ CSV thô ({e}) -> suy biến sang ground_truth.")
        return []


def balanced_subset(dataset):
    """Trả về (subset, warmup_logs): tập CHẤM cân bằng benign==attack + warmup held-out.

    LỖI ĐÃ SỬA (2026-07-27): bản cũ hard-code `benign[:150]` và `benign[150:300]` trong khi
    `ground_truth.json` chỉ có **80** mẫu benign. Hệ quả kép, cả hai đều âm thầm:
      1. Tập "cân bằng" thực ra là 80 benign + 150 attack (35% benign) — KHÔNG cân bằng,
         đúng thứ mà chế độ này sinh ra để tránh.
      2. `benign[150:300]` bắt đầu NGOÀI mảng nên luôn trả [] -> warmup 0 flow, tức Welford
         chưa bao giờ ấm trong suốt ablation "cân bằng", trái với mô tả trong luận văn.
    Nay cỡ mẫu SUY RA TỪ dữ liệu thật: chia đôi benign sẵn có thành phần CHẤM và phần
    WARMUP held-out, rồi lấy đúng bấy nhiêu attack để hai lớp bằng nhau.
    """
    benign = [s for s in dataset if s["expected_action"] == "LOG"]
    attack = [s for s in dataset if s["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL")]

    # Warmup ƯU TIÊN lấy từ CICIDS THÔ: held-out theo CẤU TẠO (khác nguồn dòng với
    # ground_truth, lại còn loại trừ theo chữ ký) nên KHÔNG phải hy sinh mẫu benign của
    # tập chấm. Chỉ khi không có CSV thô mới chia đôi benign — đánh đổi cỡ mẫu lấy warmup.
    warmup_logs = _raw_benign_warmup_logs(n=150, exclude=benign)
    if warmup_logs:
        n_benign_score = min(N_BENIGN, len(benign))
        warmup_benign: list = []
    else:
        n_benign_score = min(N_BENIGN, len(benign) // 2)
        warmup_benign = benign[n_benign_score:]
    benign_sel = benign[:n_benign_score]

    # Attack lấy PHÂN TẦNG đều theo lớp, đúng bằng số benign -> cân bằng THẬT 1:1.
    n_attack = min(N_ATTACK, n_benign_score)
    by_label = {}
    for s in attack:
        lbl = s["input"].get("cicids_label", "unknown")
        by_label.setdefault(lbl, []).append(s)
    num_classes = len(by_label)
    per_class = max(1, (n_attack + num_classes - 1) // num_classes)
    attack_sel = []
    for _lbl, samples in by_label.items():
        attack_sel.extend(samples[:per_class])
    attack_sel = attack_sel[:n_attack]

    if not warmup_logs:
        warmup_logs = [log for s in warmup_benign for log in s.get("logs", [])]
    return benign_sel + attack_sel, warmup_logs


def run_balanced(out=None):
    out_path = out or OUT_BALANCED
    dataset, warmup_logs = balanced_subset(load_ground_truth())
    n_b = sum(1 for s in dataset if s["expected_action"] == "LOG")
    n_a = len(dataset) - n_b
    print(f"[*] Ablation CÂN BẰNG: {len(dataset)} mẫu ({n_b} benign + {n_a} attack)")

    # Chốt tính chất, không phải kiểm tra phòng thủ: nếu hai lớp lệch hoặc warmup rỗng thì
    # con số sinh ra KHÔNG còn là thứ luận văn mô tả — thà dừng còn hơn báo cáo sai lặng lẽ.
    if n_b != n_a:
        raise SystemExit(
            f"[!] Tập 'cân bằng' bị lệch: {n_b} benign vs {n_a} attack. Kiểm tra "
            f"balanced_subset() / cỡ ground_truth trước khi trích số vào luận văn."
        )
    if not warmup_logs:
        raise SystemExit(
            "[!] Warmup benign RỖNG -> Welford không bao giờ ấm, Z-score không bao giờ bật. "
            "Kết quả sẽ chỉ phản ánh luật tĩnh, KHÔNG phải cấu hình được mô tả."
        )

    rule_engine = _fresh_engine()
    print(f"[*] Warmup baseline Welford trên {len(warmup_logs)} flow benign THẬT (held-out)...")
    for log in warmup_logs:
        rule_engine.evaluate(dict(log))
    print("[+] Warmup complete.")

    R: dict[str, Any] = {
        c: {"y_true": [], "y_pred": [], "latencies": [], "escalated": [], "actions": []}
        for c in "ABCDEF"
    }
    expected_actions: list[str] = []

    for idx, sample in enumerate(dataset):
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        logs = sample.get("logs", [])
        rule_engine.session_baseline.reset_window()

        # --- A: Tier-1 rule-only ---
        t0 = time.time()
        pred_a = 0
        action_a = "LOG"  # giữ hành động THẬT của Tier-1 để chấm theo hành động
        for log in logs:
            _act = rule_engine.evaluate(log).get("tier1_action")
            if _act in ("BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"):
                pred_a = 1
                action_a = _act
                break
        lat_a = time.time() - t0

        # --- Gate Welford dùng chung C/D/E/F ---
        needs_llm, tier1_verdict = run_gate(logs, rule_engine)
        tier1_pred = 1 if tier1_verdict in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        query = build_rag_query(logs)

        # Mặc định như trên: không escalate -> C/D/E giữ phán quyết Tier-1.
        a_c = a_d = a_e = tier1_verdict
        # `_` nuốt phần meta (kỹ thuật LLM khai): chế độ `balanced` chấm theo HÀNH ĐỘNG trên
        # tập cân bằng 150/150, không chấm quy kết — phần đó là việc của chế độ `bcde`.
        a_b, l_b, _ = llm_action(logs, "")  # B — Pure LLM
        p_b = to_pred(a_b)

        if needs_llm:  # C/D/E
            a_c, l_c, _ = llm_action(logs, "")
            p_c = to_pred(a_c)
            a_d, l_d, _ = llm_action(logs, dense_only_context(query))
            p_d = to_pred(a_d)
            a_e, l_e, _ = llm_action(logs, hybrid_context(query))
            p_e = to_pred(a_e)
        else:
            l_c = l_d = l_e = 0.0006
            p_c = p_d = p_e = tier1_pred

        # --- F: SENTINEL đầy đủ (agent_app + Consensus Guard) ---
        t0 = time.time()
        pred_f = 0
        action_f = tier1_verdict  # mặc định: gate không escalate -> dừng ở phán quyết Tier-1
        if needs_llm:
            from src.guardrails import loop_detector

            loop_detector.reset()
            action_f = "ERROR"  # nếu agent ném lỗi thì đây là sự thật, không phải "LOG"
            try:
                final_state = agent_app.invoke(
                    SentinelState(
                        current_batch_logs=logs,
                        current_batch_size=len(logs),
                        narrative_summary="",
                    )
                )
                decisions = final_state.get("decisions", [])
                if decisions:
                    action_f = decisions[-1].get("action", "UNKNOWN")
                    if action_f in ("BLOCK_IP", "ALERT", "AWAIT_HITL", "ESCALATE"):
                        pred_f = 1
            except Exception as e:
                print(f"   [F ERROR] {sample['id']}: {e}")
        else:
            pred_f = tier1_pred
        lat_f = time.time() - t0

        expected_actions.append(sample["expected_action"])
        for c, pred, lat, esc, act in (
            ("A", pred_a, lat_a, 0, action_a),
            ("B", p_b, l_b, 1, a_b),
            ("C", p_c, l_c, 1 if needs_llm else 0, a_c if needs_llm else tier1_verdict),
            ("D", p_d, l_d, 1 if needs_llm else 0, a_d if needs_llm else tier1_verdict),
            ("E", p_e, l_e, 1 if needs_llm else 0, a_e if needs_llm else tier1_verdict),
            ("F", pred_f, lat_f, 1 if needs_llm else 0, action_f),
        ):
            R[c]["y_true"].append(is_attack)
            R[c]["y_pred"].append(pred)
            R[c]["latencies"].append(lat)
            R[c]["escalated"].append(esc)
            R[c]["actions"].append(act)

        print(
            f"[{idx + 1}/{len(dataset)}] {sample['id']} true={is_attack} esc={int(needs_llm)} "
            f"| A={pred_a} B={p_b} C={p_c} D={p_d} E={p_e} F={pred_f}"
        )

    R["expected_actions"] = expected_actions
    R["action_scores"] = {c: score_actions(expected_actions, R[c]["actions"]) for c in "ABCDEF"}

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(R, f, indent=2)
    print(f"\n[+] Saved -> {out_path}\n")

    print("CHẤM THEO HÀNH ĐỘNG (thước đo CHÍNH — tập CÂN BẰNG):")
    print(f"  {'Cfg':>3} {'khớp HĐ':>9} {'tự quyết':>9} {'đúng|tự quyết':>14} {'hoãn':>8}")
    for c in "ABCDEF":
        sc = R["action_scores"][c]
        _ap = sc["autonomous_precision"]
        print(
            f"  {c:>3} {sc['action_accuracy']:>9.4f} {sc['autonomy_rate']:>9.4f} "
            f"{(f'{_ap:.4f}' if _ap is not None else '—'):>14} {sc['defer_rate']:>8.4f}"
        )
    print()

    print(f"{'Cfg':>3} | {'F1':>6} | {'Prec':>6} | {'Rec':>6} | {'Esc%':>5} | {'Lat(s)':>7}")
    for c in "ABCDEF":
        yt, yp = R[c]["y_true"], R[c]["y_pred"]
        f1 = f1_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        prec = precision_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        rec = recall_score(yt, yp, zero_division=0)  # pyright: ignore[reportArgumentType]
        esc = 100.0 * np.mean(R[c]["escalated"])
        lat = float(np.mean(R[c]["latencies"]))
        print(f"{c:>3} | {f1:>6.4f} | {prec:>6.4f} | {rec:>6.4f} | {esc:>5.1f} | {lat:>7.3f}")


def run_mlgate(limit=None, out=None):
    """Config G — GIẢM TẢI LLM bằng Cổng ML (chiều Performance/Efficiency, KHÔNG cần LLM).

    Mô phỏng đường thật: Tier-1 gate quyết event nào ESCALATE (đáng lẽ gọi LLM); cho phần
    escalate đó qua Cổng ML. ML tự quyết -> BYPASS = tiết kiệm 1 lượt LLM. Đo:
      - ml_bypass_rate = (escalate được ML giải quyết) / (tổng escalate)
      - F1/P/R của Cổng ML trên phần bypass
      - độ trễ TIẾT KIỆM: không-ML mọi escalate tốn ~LLM_MS; có-ML phần bypass chỉ tốn ~ML_MS
    Số LLM_MS/ML_MS là tham chiếu (từ latency_benchmark) chỉ để CHIẾU mức tiết kiệm — không
    phải phép đo latency mới.
    """
    from src.tier1_filter.ml_gateway import MLGateway

    dataset = stratified(load_ground_truth(), limit) if limit else load_ground_truth()
    out_path = out or OUT_MLGATE
    engine = _fresh_engine()
    _synthetic_warmup(engine)
    gw = MLGateway()
    if not gw.pipeline:
        print("[-] Không nạp được Cổng ML — bỏ mode mlgate.")
        return
    n = n_escalated = n_bypass = 0
    yt, yp = [], []
    print(f"[*] Chạy Config G (ML offload) trên {len(dataset)} mẫu (không gọi LLM)…")
    for sample in dataset:
        logs = sample.get("logs", [])
        is_attack = 1 if sample["expected_action"] in ("BLOCK_IP", "ALERT", "AWAIT_HITL") else 0
        engine.session_baseline.reset_window()
        needs_llm, _ = run_gate(logs, engine)
        n += 1
        if not needs_llm:
            continue
        n_escalated += 1
        for log in logs:
            a, _r, _c, _s = gw.evaluate_detailed(log)
            if a is not None:
                n_bypass += 1
                yt.append(is_attack)
                yp.append(1 if a in ("BLOCK_IP", "ALERT") else 0)
                break

    bypass_rate = n_bypass / n_escalated if n_escalated else 0.0
    f1 = float(f1_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    prec = float(precision_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    rec = float(recall_score(yt, yp, zero_division=0)) if yt else 0.0  # pyright: ignore[reportArgumentType]
    # ĐÃ GỠ `projected_latency_saved_pct` (+ ref_llm_ms/ref_ml_ms/projected_llm_calls_saved).
    # Lý do: nó KHÔNG phải phép đo. Công thức là `bypass_rate` nhân với hai HẰNG SỐ GIẢ ĐỊNH
    # cứng trong mã (LLM 5000 ms, ML 0,3 ms), nên con số ~80% chỉ là cách viết lại
    # `ml_bypass_rate` dưới đơn vị thời gian. Nguy hiểm ở chỗ nó nằm ngay cạnh một con số
    # ĐO THẬT rất giống (`latency_benchmark.json`, giảm ~83%) — người đọc không có cách nào
    # phân biệt cái nào đo, cái nào giả định. Cần tuyên bố về độ trễ thì trích
    # `measure_latency_baseline.py`. `projected_llm_calls_saved` cũng bị gỡ vì trùng khít
    # `n_ml_bypass` — một con số thì chỉ nên có MỘT cái tên.
    result = {
        "dataset_size": n,
        "n_escalated_would_call_llm": n_escalated,
        "n_ml_bypass": n_bypass,
        "ml_bypass_rate": round(bypass_rate, 4),
        "ml_f1_on_bypass": round(f1, 4),
        "ml_precision_on_bypass": round(prec, 4),
        "ml_recall_on_bypass": round(rec, 4),
        "note": (
            "Config G đo GIẢM TẢI LLM của Cổng ML (tỉ lệ ca Cổng ML tự quyết). "
            "Tuyên bố về ĐỘ TRỄ phải trích latency_benchmark.json — nơi độ trễ được ĐO, "
            "không phải chiếu từ hằng số giả định."
        ),
    }
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(
        f"[+] Config G: escalate={n_escalated} | ML bypass={n_bypass} "
        f"({bypass_rate:.1%}) | F1(bypass)={f1:.4f} P={prec:.4f} R={rec:.4f}"
        f"\n[+] JSON: {out_path}"
    )
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Ablation Study hợp nhất (A–F + G ML offload)")
    ap.add_argument("--mode", choices=["af", "bcde", "balanced", "mlgate", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None, help="Giới hạn số mẫu (af/bcde)")
    ap.add_argument("--out", type=str, default=None, help="Ghi đè path output (chỉ khi 1 mode)")
    args = ap.parse_args()

    # ĐÓNG BĂNG việc SINH luật động trong suốt lượt đo. Bắt buộc, không phải tuỳ chọn:
    # `run_af` dùng CHUNG một `rule_engine` cho Config A và Config F, nên luật do tác tử của
    # F sinh ra sẽ có hiệu lực ngay với A ở mẫu kế tiếp — baseline được chính treatment nâng
    # đỡ, và delta A->F nói giảm đóng góp của Tầng 2. Xem chú thích dài ở
    # `feedback_listener.receive_new_rule`. Đặt TRƯỚC mọi import chạm tới engine.
    os.environ["SENTINEL_FREEZE_DYNAMIC_RULES"] = "1"
    print("[*] Luật động: ĐÓNG BĂNG trong lượt đo (chống nhiễm baseline + để tái lập được).")

    if args.out and args.mode == "all":
        ap.error("--out chỉ dùng khi chạy 1 mode (af|bcde|balanced), không dùng với 'all'.")

    if args.mode in ("af", "all"):
        run_af(limit=args.limit, out=args.out)
    if args.mode in ("bcde", "all"):
        run_bcde(limit=args.limit or 300, out=args.out)
    if args.mode in ("balanced", "all"):
        run_balanced(out=args.out)
    if args.mode in ("mlgate", "all"):
        run_mlgate(limit=args.limit, out=args.out if args.mode == "mlgate" else None)
