"""Gom TOÀN BỘ kết quả đo của lượt chạy chốt vào một tệp Markdown duy nhất.

CHỈ ĐỌC VÀ TRÌNH BÀY — không tính lại, không suy diễn, không sửa gì. Mỗi con số đi kèm tệp
nguồn và mốc thời gian để đối chiếu ngược. Những chỗ script gốc TỰ gắn cờ không đáng tin thì
giữ nguyên cờ đó, không giấu.

Chạy:  .venv/bin/python scripts/export_final_report.py
Ra:    reports/KET_QUA_CHOT_<ngày>.md
"""

import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "experiments", "results")
OUT = os.path.join(ROOT, "reports", f"KET_QUA_CHOT_{time.strftime('%Y-%m-%d')}.md")


def g(name: str) -> dict:
    try:
        with open(os.path.join(R, name), encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def when(name: str) -> str:
    p = os.path.join(R, name)
    if not os.path.exists(p):
        return "—"
    return time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(p)))


def fmt(v, nd=4):
    if isinstance(v, float):
        return f"{v:.{nd}f}".rstrip("0").rstrip(".")
    return "—" if v is None else str(v)


L: list[str] = []
w = L.append

w(f"# SENTINEL — Kết quả đo lượt CHỐT ({time.strftime('%d/%m/%Y')})\n")
w("> Xuất tự động từ `experiments/results/*.json`. Mỗi mục ghi rõ tệp nguồn + mốc thời gian.")
w("> Cờ 'không đáng tin' do CHÍNH script gốc gắn được giữ nguyên.\n")

# ── 1. Dữ liệu ───────────────────────────────────────────────────────────────
w("## 1. Nền dữ liệu\n")
w("| tệp | n | mốc |")
w("| :-- | --: | :-- |")
for path in ("experiments/ground_truth.json", "data/datatest.json"):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            n = len(json.load(open(p, encoding="utf-8")))
        except Exception:
            n = "?"
        w(
            f"| `{path}` | {n:,} | {time.strftime('%m-%d %H:%M', time.localtime(os.path.getmtime(p)))} |"
        )
gb = os.path.join(ROOT, "config", "golden_baseline.json")
if os.path.exists(gb):
    w(
        f"| `config/golden_baseline.json` | seed Welford | {time.strftime('%m-%d %H:%M', time.localtime(os.path.getmtime(gb)))} |"
    )
w("")

# ── 2. Cổng ML ───────────────────────────────────────────────────────────────
mg = g("ml_gate_results.json")
cls = mg.get("classification", {}) if isinstance(mg.get("classification"), dict) else mg
w(f"## 2. Cổng ML — `ml_gate_results.json` ({when('ml_gate_results.json')})\n")
w("Tập: `datatest.json` cân bằng, CÓ CSIC. Chỉ số chính là **MCC/BalAcc**, không phải F1.\n")
w("| chỉ số | giá trị |")
w("| :-- | --: |")
for k in (
    "mcc",
    "balanced_accuracy",
    "f1",
    "precision",
    "recall",
    "specificity",
    "bypass_rate",
    "abstain_rate",
    "n_skip_payload",
    "latency_ms_mean",
):
    if k in cls:
        w(f"| {k} | {fmt(cls[k])} |")
if "confusion_matrix" in cls or "cm" in cls:
    w(f"| ma trận nhầm lẫn | `{cls.get('confusion_matrix') or cls.get('cm')}` |")
w("")

# ── 3. Ablation ──────────────────────────────────────────────────────────────
af = g("ablation_results.json")
acts = af.get("action_scores", {})
w(f"## 3. Ablation A/F — `ablation_results.json` ({when('ablation_results.json')})\n")
w(
    "Tập: `ground_truth.json` (1.750). **Luật động ĐÓNG BĂNG** nên baseline không bị treatment nâng đỡ.\n"
)
if acts:
    w("| chỉ số | Config A (không LLM) | Config F (đủ LLM) |")
    w("| :-- | --: | --: |")
    for k, lab in (
        ("action_accuracy", "đúng hành động"),
        ("autonomous_precision", "tự quyết đúng"),
        ("autonomy_rate", "tỉ lệ tự quyết"),
        ("defer_rate", "chuyển người"),
        ("unresolved_rate", "BỎ NGỎ"),
    ):
        w(
            f"| {lab} | {fmt(acts.get('Config_A', {}).get(k))} | {fmt(acts.get('Config_F', {}).get(k))} |"
        )
mh = af.get("metric_health") or {}
if mh:
    w(
        f"\n> ⚠️ `metric_health`: base rate tấn công **{fmt(mh.get('attack_base_rate'))}**, "
        f"`binary_f1_trustworthy = {mh.get('binary_f1_trustworthy')}`. "
        f"Thước đo chính: `{mh.get('primary_metric')}`.\n"
    )

# B–E: thước đo CHÍNH là QUY KẾT, không phải F1 nhị phân. Bản trước lọc bỏ mọi giá trị kiểu
# dict nên hai tệp ablation in ra `{}` — toàn bộ số nằm ở khoá lồng, và báo cáo mất trắng
# phần quan trọng nhất mà không có gì báo.
bcde = g("ablation_bcde_results.json")
_attr = bcde.get("attribution_scores") or {}
if _attr:
    w(
        f"### Config B–E — quy kết kỹ thuật (`ablation_bcde_results.json`, {when('ablation_bcde_results.json')})\n"
    )
    w("Biến độc lập là **cấu hình RAG**, nên biến phụ thuộc phải là **quy kết** chứ không phải")
    w("phát hiện nhị phân — đó là lý do bảng F1 cũ cho B ≡ C ≡ D ≡ E giống nhau từng bit.\n")
    w("| | cấu hình | exact | parent | không neo | bỏ trống |")
    w("| :-- | :-- | --: | --: | --: | --: |")
    _lbl = {"B": "LLM thuần", "C": "+ Welford", "D": "+ RAG dense", "E": "+ RAG lai RRF"}
    for c in "BCDE":
        a = _attr.get(c, {})
        w(
            f"| {c} | {_lbl[c]} | {fmt(a.get('technique_exact_pct'), 2)}% | "
            f"{fmt(a.get('technique_parent_pct'), 2)}% | {fmt(a.get('ungrounded_rate'))} | "
            f"{fmt(a.get('abstain_rate'))} |"
        )
    if bcde.get("metric_note"):
        w(f"\n> {bcde['metric_note']}\n")

for tag, lab in (
    ("ablation_balanced_results.json", "Balanced (khử base-rate)"),
    ("ablation_bcde_results.json", "Config B–E — chấm theo hành động"),
):
    d = g(tag)
    acts_x = d.get("action_scores") or {}
    if not acts_x:
        continue
    keys = sorted(acts_x.keys())
    w(f"**{lab}** — `{tag}` ({when(tag)})\n")
    w("| chỉ số | " + " | ".join(keys) + " |")
    w("| :-- | " + " | ".join("--:" for _ in keys) + " |")
    for k, lb in (
        ("action_accuracy", "đúng hành động"),
        ("autonomous_precision", "tự quyết đúng"),
        ("autonomy_rate", "tỉ lệ tự quyết"),
        ("defer_rate", "chuyển người"),
        ("unresolved_rate", "BỎ NGỎ"),
    ):
        w(f"| {lb} | " + " | ".join(fmt(acts_x[c].get(k)) for c in keys) + " |")
    w("")

_mg = g("ablation_mlgate_results.json")
if _mg:
    flat = {k: v for k, v in _mg.items() if not isinstance(v, (list, dict))}
    w(
        f"**Config G (ML offload)** — `ablation_mlgate_results.json` "
        f"({when('ablation_mlgate_results.json')}): `{json.dumps(flat, ensure_ascii=False)[:300]}`\n"
    )

# ── 4. Quy kết ───────────────────────────────────────────────────────────────
w("## 4. Quy kết kỹ thuật MITRE\n")
w("Tập: 300 mẫu CSIC có payload (`--evidence-layer payload`).\n")
w("| chế độ | exact | parent | tactic | trần KB | p50 (ms) | tệp |")
w("| :-- | --: | --: | --: | --: | --: | :-- |")
for tag, lab in (
    ("attack_mapper_eval_csic_payload_rrf.json", "rrf (tất định)"),
    ("attack_mapper_eval_csic_payload_e2e.json", "e2e (toàn tuyến)"),
):
    d = g(tag)
    if d:
        cov = d.get("kb_coverage_ceiling", {})
        w(
            f"| {lab} | {fmt(d.get('technique_exact_match_pct'), 2)}% | "
            f"{fmt(d.get('technique_parent_match_pct'), 2)}% | {fmt(d.get('tactic_match_pct'), 2)}% | "
            f"{fmt(cov.get('exact_in_kb_pct'), 1)}% | {fmt(d.get('latency_ms_p50'), 1)} | {when(tag)} |"
        )
w("")
for tag, lab in (
    ("attack_mapper_eval_csic_payload_rrf.json", "rrf"),
    ("attack_mapper_eval_csic_payload_e2e.json", "e2e"),
):
    d = g(tag)
    pt = d.get("per_attack_type") or {}
    if pt:
        w(
            f"**Theo kỹ thuật ({lab})**: "
            + " · ".join(
                f"{k} {fmt(v.get('exact_pct'), 1)}% (n={v.get('n')})" for k, v in sorted(pt.items())
            )
        )
w("")

# ── 5. LLM-Judge ─────────────────────────────────────────────────────────────
re_ = g("reasoning_eval_results.json")
md, ag = re_.get("metadata", {}), re_.get("aggregate", {})
w(
    f"## 5. Chất lượng lập luận — `reasoning_eval_results.json` ({when('reasoning_eval_results.json')})\n"
)
if md:
    w(f"- Trọng tài: **{md.get('judge_model')}**")
    w(f"- Tác tử:   **{md.get('agent_model')}**")
    w(f"- n = {md.get('escalated_samples')} / {md.get('total_samples')}\n")
if ag:
    w("| trục | trung bình | độ lệch |")
    w("| :-- | --: | --: |")
    for k in ("context_precision", "answer_relevancy", "faithfulness", "context_recall"):
        v = ag.get(k, {})
        if v:
            w(f"| {k} | {fmt(v.get('mean'), 2)} | {fmt(v.get('std'), 2)} |")
    eg = ag.get("evidence_grounding") or {}
    if eg:
        w(
            f"\n- Tỉ lệ trích dẫn bằng chứng: **{fmt(eg.get('grounding_rate'), 4)}** "
            f"(trung bình {fmt(eg.get('mean_citations'), 2)} trích dẫn/phán quyết)"
        )
    rh = ag.get("run_health") or {}
    if rh.get("n_incomplete_schema"):
        w(
            f"\n> ⚠️ `n_incomplete_schema = {rh['n_incomplete_schema']}` / {rh.get('n_scored')} — "
            f"script gốc tuyên bố lượt đo **không đáng tin**. Phải truy nguyên trước khi trích.\n"
        )

# ── 6. Độ trễ ────────────────────────────────────────────────────────────────
lat = g("latency_benchmark.json")
w(f"## 6. Độ trễ — `latency_benchmark.json` ({when('latency_benchmark.json')})\n")
if lat:
    w(
        f"```json\n{json.dumps({k: v for k, v in lat.items() if not isinstance(v, list)}, ensure_ascii=False, indent=2)[:900]}\n```\n"
    )
w("> ⚠️ Phép đo này ép lấy **50 benign + 50 tấn công**, Tier-1 chỉ loại được 11/100 nên 89 ca")
w("> vẫn gọi LLM — hai tầng thành ra CHẬM hơn LLM-only. Lợi thế của kiến trúc đến từ ~92%")
w("> lưu lượng bị loại trên luồng THẬT. **Phải đo lại trên `build_stream()` mới trích được.**\n")

# ── 7. An ninh + toàn tuyến ──────────────────────────────────────────────────
w("## 7. An ninh · toàn tuyến · các bài còn lại\n")
w("> Cỡ mẫu ghi trong nhãn ĐỌC TỪ CHÍNH TỆP, không viết cứng. Nhãn cũ ghi `adversarial` là")
w('> "120 mẫu, 5 nhóm" trong khi tệp chỉ có **12** — bộ 120 mẫu là `robustness_results.json`')
w("> và nó ra 50%. Hai bài khác nhau bị gọi chung một tên là cách số liệu bị trích nhầm.\n")
_adv_n = (g("adversarial_pipeline_results.json").get("resisted") or 0) + (
    g("adversarial_pipeline_results.json").get("compromised") or 0
)
_rob_n = (g("robustness_results.json").get("summary") or {}).get("total")
for tag, lab in (
    ("adversarial_pipeline_results.json", f"Kháng tiêm nhiễm qua đường ống (n={_adv_n})"),
    ("llm_robustness_results.json", "Kháng nhiễu prompt (tất định + đổi seed)"),
    ("robustness_results.json", f"Kháng né tránh mã hoá/cấu trúc (n={_rob_n})"),
    ("audit_tamper_results.json", "RQ2 · Chống chối bỏ chuỗi HMAC (sửa/chèn/xoá)"),
    ("cache_efficiency_results.json", "RQ1 · Bộ đệm Tầng 1.75 (hit-rate trên truy vấn thật)"),
    (
        "tier_capability_audit.json",
        "Năng lực 3 tầng (15 ca viết tay — phép thử CHỨC NĂNG, KHÔNG phải chỉ số benchmark)",
    ),
    ("unified_stream_results.json", "Toàn tuyến (build_stream)"),
    ("tier2_decision_results.json", "Phán quyết Tier-2 (tập ĐÃ qua Tier-1 VÀ Cổng ML)"),
    ("zeroday_graded_results.json", "Zero-day theo cấp độ"),
    ("threshold_sensitivity_results.json", "Độ nhạy ngưỡng Welford"),
    ("apt_negative_control_results.json", "Đối chứng âm APT"),
    ("context_stress_results.json", "Quá tải ngữ cảnh"),
):
    d = g(tag)
    if not d:
        continue
    flat = {k: v for k, v in d.items() if not isinstance(v, (list, dict))}
    sub = {k: v for k, v in d.items() if isinstance(v, dict)}
    w(f"### {lab}\n`{tag}` ({when(tag)})\n")
    if flat:
        w(f"```json\n{json.dumps(flat, ensure_ascii=False, indent=2)[:700]}\n```")
    for sk, sv in list(sub.items())[:3]:
        w(f"- `{sk}`: `{json.dumps(sv, ensure_ascii=False)[:300]}`")
    w("")

# ── 8. Độ tươi ───────────────────────────────────────────────────────────────
w("## 8. Độ tươi toàn bộ tệp kết quả\n")
w("| mốc | tệp |")
w("| :-- | :-- |")
for f in sorted(os.listdir(R), key=lambda x: -os.path.getmtime(os.path.join(R, x))):
    if f.endswith(".json"):
        w(f"| {when(f)} | `{f}` |")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(L) + "\n")
print(f"[+] Đã xuất: {OUT}  ({len(L)} dòng)")
