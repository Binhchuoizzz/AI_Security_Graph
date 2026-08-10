"""Sinh HÌNH KẾT QUẢ cho Chương 4, cả bản EN và VI, THẲNG TỪ `experiments/results/*.json`.

VÌ SAO PHẢI CÓ TỆP NÀY. Thư mục `images/` từng chứa năm ảnh kết quả đề ngày 22/07 — trước mọi
lần chạy lại, và hai trong số đó thuộc chỉ số đã bị loại khỏi luận văn. Ảnh là artefact tĩnh: nó
không tự biết mình đã cũ. Cách duy nhất để hình không bao giờ lệch số là **không gõ tay con số
nào trong tệp này**; mọi giá trị đều đọc từ JSON, nên chạy lại script sau mỗi lượt đo là hình tự
đúng theo.

Quy ước trình bày: xám + MỘT màu nhấn để in đen trắng vẫn đọc được; nhãn trục luôn kèm mẫu số;
số liệu EN và VI giống hệt nhau, chỉ khác chữ.

Chạy:  .venv/bin/python scripts/plot_thesis_figures.py
"""

import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
R = os.path.join(ROOT, "experiments", "results")
OUT = {
    "en": os.path.join(ROOT, "docs/Thesis/latex/thesis_latex_en/images"),
    "vi": os.path.join(ROOT, "docs/Thesis/latex/thesis_latex_vi/images"),
}

# DejaVu Sans có đủ dấu tiếng Việt; Helvetica/Arial trên máy này thì không chắc.
plt.rcParams.update(
    {
        # Thân bài luận văn chạy Times (mathptmx). Chữ trong hình phải CÙNG HỌ serif,
        # không thì mỗi trang có hình lại lộ ra hai kiểu chữ. DejaVu Serif đi kèm
        # matplotlib và có đủ dấu tiếng Việt; Times thật thì không chắc máy nào cũng có.
        "font.family": "DejaVu Serif",
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 150,
    }
)

INK = "#2f3b40"  # xám đậm — mặc định
GREY = "#b9c2c6"  # xám nhạt — nền/phụ
ACCENT = "#b5341f"  # MỘT màu nhấn duy nhất
ACCENT2 = "#7a8b91"  # xám trung gian, cho cột thứ ba


def load(name):
    p = os.path.join(R, name)
    if not os.path.exists(p):
        print(f"  [!] thiếu {name} — bỏ qua hình liên quan")
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def save_one(fig, stem, lang):
    os.makedirs(OUT[lang], exist_ok=True)
    p = os.path.join(OUT[lang], f"{stem}.pdf")
    fig.savefig(p, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print(f"  ✓ {lang}/{stem}.pdf")


# ── Hình 1 — phễu xả tải theo tầng, hai luồng ────────────────────────────────
T1 = {
    "en": dict(
        title="Offload by tier, two streams with different attack base rates",
        tiers=["Tier 1", "ML Gate", "→ Tier 2 (LLM)"],
        rows=[
            "Benchmark stream\n{a:,} events · {p} attack",
            "SOC-like stream\n{a:,} events · {p} attack",
        ],
        xlabel="Share of the stream (%)",
    ),
    "vi": dict(
        title="Xả tải theo tầng trên hai luồng có tỉ lệ tấn công nền khác nhau",
        tiers=["Tầng 1", "Cổng ML", "→ Tầng 2 (LLM)"],
        rows=[
            "Luồng benchmark\n{a} sự kiện · {p} tấn công",
            "Luồng dạng SOC\n{a} sự kiện · {p} tấn công",
        ],
        xlabel="Tỉ lệ trong luồng (%)",
    ),
}


def fig_offload(lang):
    s, d = load("offload_vs_baserate_stream.json"), load("offload_vs_baserate_demo.json")
    if not (s and d):
        return
    t = T1[lang]
    fmt = (lambda n: f"{n:,}") if lang == "en" else (lambda n: f"{n:,}".replace(",", "."))
    pct = (
        (lambda x: f"{100 * x:.1f}%")
        if lang == "en"
        else (lambda x: f"{100 * x:.1f}%".replace(".", ","))
    )
    labels = [
        t["rows"][0].format(a=s["n_events"], p=pct(s["attack_rate_do_duoc"]))
        if lang == "en"
        else t["rows"][0].format(a=fmt(s["n_events"]), p=pct(s["attack_rate_do_duoc"])),
        t["rows"][1].format(a=d["n_events"], p=pct(d["attack_rate_do_duoc"]))
        if lang == "en"
        else t["rows"][1].format(a=fmt(d["n_events"]), p=pct(d["attack_rate_do_duoc"])),
    ]
    data = (
        np.array(
            [
                [s["ti_le_chan_tier1"], s["ti_le_chan_cong_ml"], s["ti_le_toi_llm"]],
                [d["ti_le_chan_tier1"], d["ti_le_chan_cong_ml"], d["ti_le_toi_llm"]],
            ]
        )
        * 100
    )

    fig, ax = plt.subplots(figsize=(6.6, 2.15))
    colours = [INK, ACCENT2, ACCENT]
    left = np.zeros(2)
    y = np.arange(2)
    for i, (tier, c) in enumerate(zip(t["tiers"], colours, strict=False)):
        ax.barh(
            y,
            data[:, i],
            left=left,
            height=0.5,
            color=c,
            label=tier,
            edgecolor="white",
            linewidth=0.8,
        )
        for j in range(2):
            if data[j, i] >= 6:
                ax.text(
                    left[j] + data[j, i] / 2,
                    y[j],
                    pct(data[j, i] / 100),
                    ha="center",
                    va="center",
                    color="white",
                    fontsize=8.5,
                    fontweight="bold",
                )
        left += data[:, i]
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel(t["xlabel"])
    ax.set_title(t["title"], pad=8)
    ax.legend(ncol=3, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.35))
    ax.grid(axis="x", color=GREY, alpha=0.35, linewidth=0.6)
    ax.set_axisbelow(True)
    save_one(fig, "fig_offload_funnel", lang)


# ── Hình 2 — phân phối độ trễ, thang log ─────────────────────────────────────
T2 = {
    "en": dict(
        title="End-to-end latency, {n} events (log scale)",
        two="Two-tier (SENTINEL)",
        base="Single-tier LLM baseline",
        xlabel="Latency per event (ms, log scale)",
        ylabel="Cumulative share of events",
        med="median",
        p95="95th pct",
    ),
    "vi": dict(
        title="Độ trễ toàn tuyến trên {n} sự kiện (thang log)",
        two="Hai tầng (SENTINEL)",
        base="Đường LLM đơn tầng",
        xlabel="Độ trễ mỗi sự kiện (ms, thang log)",
        ylabel="Tỉ lệ tích luỹ số sự kiện",
        med="trung vị",
        p95="phân vị 95",
    ),
}


def fig_latency(lang):
    lb = load("latency_benchmark.json")
    if not lb:
        return
    t = T2[lang]
    two = np.sort(np.array(lb["per_event_two_tier_ms"], dtype=float))
    base = np.sort(np.array(lb["per_event_baseline_ms"], dtype=float))
    two = np.clip(two, 1e-3, None)
    base = np.clip(base, 1e-3, None)
    cdf = np.arange(1, len(two) + 1) / len(two)

    fig, ax = plt.subplots(figsize=(6.6, 2.7))
    ax.step(two, cdf, where="post", color=ACCENT, linewidth=1.9, label=t["two"])
    ax.step(
        base,
        np.arange(1, len(base) + 1) / len(base),
        where="post",
        color=INK,
        linewidth=1.6,
        linestyle="--",
        label=t["base"],
    )
    ax.set_xscale("log")
    ax.set_xlabel(t["xlabel"])
    ax.set_ylabel(t["ylabel"])
    ax.set_ylim(0, 1.02)
    ax.set_title(t["title"].format(n=lb["n_events"]), pad=8)

    for x, c, _lab in (
        (lb["two_tier_median_ms"], ACCENT, t["med"]),
        (lb["two_tier_p95_ms"], ACCENT, t["p95"]),
        (lb["baseline_median_ms"], INK, t["med"]),
        (lb["baseline_p95_ms"], INK, t["p95"]),
    ):
        ax.axvline(x, color=c, alpha=0.30, linewidth=0.9, linestyle=":")
    ax.annotate(
        f"{t['med']} {_num(lb['two_tier_median_ms'], lang, 2)} ms",
        xy=(lb["two_tier_median_ms"], 0.5),
        xytext=(lb["two_tier_median_ms"] * 1.9, 0.26),
        color=ACCENT,
        fontsize=8,
        ha="left",
    )
    ax.annotate(
        f"{t['med']} {_num(lb['baseline_median_ms'], lang)} ms",
        xy=(lb["baseline_median_ms"], 0.5),
        xytext=(lb["baseline_median_ms"] * 0.030, 0.44),
        color=INK,
        fontsize=8,
        ha="left",
    )
    # Kết quả ngược chiều phải ĐỌC ĐƯỢC, không phải nhét vào góc: đuôi của hệ hai tầng
    # nằm BÊN PHẢI đường đơn tầng, tức p95 xấu hơn.
    ax.text(
        0.985,
        0.055,
        f"{t['p95']}: {_num(lb['two_tier_p95_ms'], lang)} ms  vs  {_num(lb['baseline_p95_ms'], lang)} ms\n"
        + ("→ the two-tier tail is slower" if lang == "en" else "→ đuôi của hệ hai tầng chậm hơn"),
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=8,
        color=ACCENT,
        bbox=dict(boxstyle="round,pad=0.35", facecolor="#fbeeeb", edgecolor=ACCENT, linewidth=0.9),
    )
    ax.legend(frameon=False, loc="center left", bbox_to_anchor=(0.02, 0.68))
    ax.grid(color=GREY, alpha=0.30, linewidth=0.6)
    ax.set_axisbelow(True)
    save_one(fig, "fig_latency_ecdf", lang)


def _num(x, lang, nd=1):
    s = f"{x:,.{nd}f}"
    return s if lang == "en" else s.replace(",", " ").replace(".", ",").replace(" ", ".")


# ── Hình 3 — rào chắn tĩnh: chặn theo xuất xứ, kèm ĐỐI CHỨNG ÂM ──────────────
T3 = {
    "en": dict(
        title="Static pre-filter: block rate by provenance, against its false-flag rate",
        bars=[
            "Published\ncorpora",
            "Author-\ncomposed",
            "Cross-check",
            "FALSE FLAGS\non benign logs",
        ],
        ylabel="Rate (%)",
        note="n = {n}",
    ),
    "vi": dict(
        title="Lớp lọc tĩnh: tỉ lệ chặn theo xuất xứ, đặt cạnh tỉ lệ báo nhầm",
        bars=["Nguồn\ncông bố", "Tác giả\ntự soạn", "Kiểm chéo", "BÁO NHẦM\ntrên log lành"],
        ylabel="Tỉ lệ (%)",
        note="n = {n}",
    ),
}
PUB = ["prompt_injection_hf", "jailbreak_hf", "advbench_gcg", "field_injection"]
AUT = ["encoding_bypass", "structural_attacks", "rag_poisoning"]
CRS = ["semantic_confusion", "jailbreak"]


def fig_guardrail(lang):
    rb, neg = load("robustness_results.json"), load("adversarial_negative_results.json")
    if not (rb and neg):
        return
    t = T3[lang]
    d = rb["detailed_results"]

    def agg(cats):
        tot = sum(d[c]["stats"]["total"] for c in cats)
        blk = sum(d[c]["stats"]["fully_blocked"] for c in cats)
        return tot, 100 * blk / tot

    groups = [agg(PUB), agg(AUT), agg(CRS), (neg["n_benign"], neg["false_flag_rate_pct"])]
    vals = [g[1] for g in groups]
    ns = [g[0] for g in groups]
    colours = [ACCENT, GREY, GREY, INK]

    fig, ax = plt.subplots(figsize=(6.6, 2.6))
    x = np.arange(4)
    ax.bar(x, vals, width=0.55, color=colours, edgecolor="white", linewidth=0.8)
    for i, (v, _n) in enumerate(zip(vals, ns, strict=False)):
        lab = f"{v:.1f}%" if lang == "en" else f"{v:.1f}%".replace(".", ",")
        ax.text(
            i,
            v + 1.6,
            lab,
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=colours[i] if colours[i] != GREY else INK,
        )
    ax.axvline(2.5, color=GREY, linewidth=1.0, linestyle="--")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{b}\n{t['note'].format(n=n)}" for b, n in zip(t["bars"], ns, strict=False)]
    )
    ax.set_ylabel(t["ylabel"])
    ax.set_ylim(0, max(vals) * 1.22)
    ax.set_title(t["title"], pad=8)
    ax.grid(axis="y", color=GREY, alpha=0.32, linewidth=0.6)
    ax.set_axisbelow(True)
    save_one(fig, "fig_guardrail_rates", lang)


# ── Hình 4 — quy kết theo kỹ thuật: trần truy xuất / RRF / toàn tuyến ────────
T4 = {
    "en": dict(
        title="Attribution by technique against the retrieval ceiling",
        series=["Retrieval hit@3", "Retrieval only (no LLM)", "Full agent"],
        ylabel="Rate (%)",
    ),
    "vi": dict(
        title="Quy kết theo từng kỹ thuật, đặt cạnh trần truy xuất",
        series=["Truy xuất hit@3", "Chỉ truy xuất (không LLM)", "Toàn tuyến"],
        ylabel="Tỉ lệ (%)",
    ),
}


def fig_attribution(lang):
    rrf, e2e, rag = (
        load("attack_mapper_eval_rrf_payload.json"),
        load("attack_mapper_eval_e2e_payload.json"),
        load("rag_retrieval_results_payload.json"),
    )
    if not (rrf and e2e and rag):
        return
    t = T4[lang]
    techs = sorted(rrf["per_attack_type"], key=lambda k: -rrf["per_attack_type"][k]["n"])
    per_ret = rag["per_technique"]
    labels, hit, only, full = [], [], [], []
    for tk in techs:
        parent = tk.split(".")[0]
        labels.append(f"{tk}\nn={rrf['per_attack_type'][tk]['n']}")
        hit.append(100 * per_ret.get(parent, {}).get("hit_at_3", 0.0))
        only.append(rrf["per_attack_type"][tk]["exact_pct"])
        full.append(e2e["per_attack_type"][tk]["exact_pct"])

    fig, ax = plt.subplots(figsize=(6.6, 2.8))
    x = np.arange(len(labels))
    w = 0.26
    ax.bar(x - w, hit, w, color=GREY, label=t["series"][0], edgecolor="white", linewidth=0.6)
    ax.bar(x, only, w, color=INK, label=t["series"][1], edgecolor="white", linewidth=0.6)
    ax.bar(x + w, full, w, color=ACCENT, label=t["series"][2], edgecolor="white", linewidth=0.6)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylabel(t["ylabel"])
    ax.set_ylim(0, 112)
    ax.set_title(t["title"], pad=8)
    ax.legend(ncol=3, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.24))
    ax.grid(axis="y", color=GREY, alpha=0.32, linewidth=0.6)
    ax.set_axisbelow(True)
    save_one(fig, "fig_rq3_attribution", lang)


# ── Hình 5 — phễu phân loại của Tier-2 ───────────────────────────────────────
T5 = {
    "en": dict(
        title="Tier 2 alert triage: the value is in the deferral channel, not the verdict",
        inp="{n} alerts in\n{p} genuine threats",
        conf="CONFIRMED — {n}\nfalse positives {fp}",
        defer="DEFERRED — {n}  ({share} of volume)\nholds {rec} of all threats · true rate {dens}\n{x}× enrichment — {w} less to read",
        arrow_conf="confirm",
        arrow_defer="defer to analyst",
    ),
    "vi": dict(
        title="Phân loại cảnh báo ở Tầng 2: giá trị nằm ở kênh hoãn, không ở phán quyết",
        inp="{n} cảnh báo vào\n{p} là đe doạ thật",
        conf="KHẲNG ĐỊNH — {n}\nbáo giả {fp}",
        defer="HOÃN — {n}  ({share} khối lượng)\nchứa {rec} tổng đe doạ · tỉ lệ thật {dens}\nlàm giàu {x}× — đọc ít hơn {w}",
        arrow_conf="khẳng định",
        arrow_defer="chuyển chuyên viên",
    ),
}


def fig_triage(lang):
    td = load("tier2_decision_results.json")
    if not td:
        return
    t, s = T5[lang], td["summary"]
    tr = s["triage"]
    pc = (
        (lambda v, nd=2: f"{100 * v:.{nd}f}%")
        if lang == "en"
        else (lambda v, nd=2: f"{100 * v:.{nd}f}%".replace(".", ","))
    )
    xx = (lambda v: f"{v:.2f}") if lang == "en" else (lambda v: f"{v:.2f}".replace(".", ","))

    nfmt = (lambda n: f"{n:,}") if lang == "en" else (lambda n: f"{n:,}".replace(",", "."))

    fig, ax = plt.subplots(figsize=(6.6, 2.5))
    ax.axis("off")
    box = dict(boxstyle="round,pad=0.45", linewidth=1.4)
    ax.text(
        0.01,
        0.62,
        t["inp"].format(n=nfmt(tr["n_alerts_in"]), p=pc(tr["true_alert_rate_in"], 1)),
        ha="left",
        va="center",
        fontsize=9,
        bbox={**box, "facecolor": "#eef1f2", "edgecolor": INK},
    )
    ax.text(
        0.42,
        0.92,
        t["conf"].format(n=nfmt(tr["n_confirmed"]), fp=pc(tr["fp_rate_on_confirmed"])),
        ha="left",
        va="center",
        fontsize=9,
        color=INK,
        bbox={**box, "facecolor": "#f5f5f5", "edgecolor": GREY},
    )
    ax.text(
        0.06,
        0.14,
        t["defer"].format(
            n=nfmt(tr["n_deferred"]),
            share=pc(tr["defer_rate"]),
            rec=pc(tr["threat_recall_in_deferred"], 1),
            dens=pc(tr["deferred_true_rate"]),
            x=xx(tr["deferred_enrichment_x"]),
            w=pc(tr["workload_reduction"]),
        ),
        ha="left",
        va="center",
        fontsize=9,
        color=ACCENT,
        fontweight="bold",
        bbox={**box, "facecolor": "#fbeeeb", "edgecolor": ACCENT, "linewidth": 1.8},
    )
    ax.annotate(
        "",
        xy=(0.41, 0.90),
        xytext=(0.24, 0.74),
        arrowprops=dict(arrowstyle="->", color=GREY, lw=1.6),
    )
    ax.annotate(
        "",
        xy=(0.14, 0.29),
        xytext=(0.11, 0.50),
        arrowprops=dict(arrowstyle="->", color=ACCENT, lw=2.0),
    )
    ax.text(0.245, 0.815, t["arrow_conf"], fontsize=7.5, color="#6b7679")
    ax.text(0.155, 0.385, t["arrow_defer"], fontsize=7.5, color=ACCENT)
    ax.set_title(t["title"], pad=6, loc="left")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    save_one(fig, "fig_triage_funnel", lang)


# ── Hình 6 — bóc tách thành phần + chất lượng lập luận ───────────────────────
# Hai khối kết quả này trước đây chỉ có bảng và chữ. Vẽ ra để đọc được bằng mắt:
# trái là đóng góp từng tầng (kèm KTC 95%), phải là bốn trục chấm lập luận.
T6 = {
    "en": dict(
        title_a="Ablation: action accuracy (95% CI)",
        title_b="Reasoning quality (judge, 1–5)",
        xlabel_a="Action accuracy (%)",
        note_a="A/F: n=1,700   ·   B--E: n=300, separate slice",
        rows_a=[
            ("A  Tier 1 only", "A"),
            ("F  Full two-tier", "F"),
            ("B  LLM, no retrieval", "B"),
            ("C/D/E  + retrieval", "C"),
        ],
        axes_b=[
            ("Answer relevancy", "answer_relevancy"),
            ("Context recall", "context_recall"),
            ("Faithfulness", "faithfulness"),
            ("Context precision", "context_precision"),
        ],
        mean_b="mean {v}",
        ground="Evidence grounding {v} of justifications cite a checkable log value",
    ),
    "vi": dict(
        title_a="Bóc tách: đúng hành động (KTC 95%)",
        title_b="Chất lượng lập luận (chấm 1–5)",
        xlabel_a="Độ chính xác hành động (%)",
        note_a="A/F: n=1.700   ·   B--E: n=300, lát mẫu riêng",
        rows_a=[
            ("A  Chỉ Tầng 1", "A"),
            ("F  Hai tầng đầy đủ", "F"),
            ("B  LLM, không truy xuất", "B"),
            ("C/D/E  + truy xuất", "C"),
        ],
        axes_b=[
            ("Độ liên quan câu trả lời", "answer_relevancy"),
            ("Độ bao phủ ngữ cảnh", "context_recall"),
            ("Độ trung thành ngữ cảnh", "faithfulness"),
            ("Độ chính xác ngữ cảnh", "context_precision"),
        ],
        mean_b="trung bình {v}",
        ground="Neo bằng chứng {v} lời biện giải dẫn được giá trị log kiểm chứng lại",
    ),
}


def fig_ablation_quality(lang):
    ab, rq = load("ablation_action_scores.json"), load("reasoning_eval_results.json")
    if not (ab and rq):
        return
    t = T6[lang]
    dec = (lambda s: s) if lang == "en" else (lambda s: s.replace(".", ","))
    pc = lambda v, nd=2: dec(f"{100 * v:.{nd}f}%")  # noqa: E731
    sc = lambda v: dec(f"{v:.2f}")  # noqa: E731

    fig, (axa, axb) = plt.subplots(1, 2, figsize=(7.6, 3.0), gridspec_kw={"wspace": 0.95})

    cfg = ab["configs"]
    ys = list(range(len(t["rows_a"])))[::-1]
    for y, (_label, key) in zip(ys, t["rows_a"], strict=True):
        c = cfg[key]
        v = 100 * c["action_accuracy"]
        lo, hi = (100 * x for x in c["action_accuracy_ci95"])
        col = ACCENT if key == "F" else INK if key == "A" else ACCENT2
        axa.barh(y, v, height=0.58, color=col, zorder=2)
        axa.errorbar(
            v,
            y,
            xerr=[[v - lo], [hi - v]],
            fmt="none",
            ecolor="#3d4a4f",
            elinewidth=1.2,
            capsize=3,
            zorder=3,
        )
        axa.text(hi + 1.6, y, pc(c["action_accuracy"]), va="center", fontsize=8.2, color=INK)
    axa.axhline(1.5, color=GREY, lw=0.9, ls=":")
    axa.set_yticks(ys, [r[0] for r in t["rows_a"]], fontsize=8.2)
    axa.set_xlim(0, 58)
    axa.set_xlabel(t["xlabel_a"])
    axa.set_title(t["title_a"], loc="left", pad=6, fontsize=9)
    axa.text(0, -0.42, t["note_a"], transform=axa.transAxes, fontsize=7.2, color="#6b7679")
    axa.grid(axis="x", color=GREY, lw=0.5, alpha=0.5, zorder=0)
    axa.set_axisbelow(True)

    agg = rq["aggregate"]
    ys = list(range(len(t["axes_b"])))
    for y, (_label, key) in zip(ys, t["axes_b"], strict=True):
        v = agg[key]["mean"]
        col = ACCENT if key == "context_precision" else GREY
        axb.barh(y, v, height=0.58, color=col, zorder=2)
        axb.text(v + 0.12, y, sc(v), va="center", fontsize=8.2, color=INK)
    axb.axvline(agg["overall_mean"], color=INK, lw=1.1, ls="--", zorder=3)
    # nhãn trung bình đặt DƯỚI cột thấp nhất: đặt ở đỉnh thì nó đè lên tiêu đề ô
    axb.text(
        agg["overall_mean"] + 0.08,
        -0.42,
        t["mean_b"].format(v=sc(agg["overall_mean"])),
        fontsize=7.4,
        color=INK,
        va="center",
    )
    axb.set_yticks(ys, [a[0] for a in t["axes_b"]], fontsize=8.2)
    axb.set_xlim(0, 5)
    axb.set_xticks([0, 1, 2, 3, 4, 5])
    axb.set_title(t["title_b"], loc="left", pad=6, fontsize=9)
    axb.text(
        0,
        -0.42,
        t["ground"].format(v=pc(agg["evidence_grounding"]["grounding_rate"], 1)),
        transform=axb.transAxes,
        fontsize=7.2,
        color=ACCENT,
    )
    axb.grid(axis="x", color=GREY, lw=0.5, alpha=0.5, zorder=0)
    axb.set_axisbelow(True)

    save_one(fig, "fig_ablation_quality", lang)


def main():
    print("=" * 74)
    print("SINH HÌNH KẾT QUẢ CHƯƠNG 4 — mọi số đọc từ experiments/results/*.json")
    print("=" * 74)
    for lang in ("en", "vi"):
        print(f"\n── {lang.upper()} ──")
        fig_offload(lang)
        fig_latency(lang)
        fig_guardrail(lang)
        fig_attribution(lang)
        fig_triage(lang)
        fig_ablation_quality(lang)
    print("\n[+] Xong. Biên dịch lại luận văn để hình mới vào PDF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
