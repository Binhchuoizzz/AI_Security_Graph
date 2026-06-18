import json
import os

import matplotlib.pyplot as plt

ROBUSTNESS_RESULTS_PATH = os.path.join(
    os.path.dirname(__file__), "results", "robustness_results.json"
)
SENSITIVITY_RESULTS_PATH = os.path.join(
    os.path.dirname(__file__), "results", "threshold_sensitivity_results.json"
)
ZERODAY_GRADED_PATH = os.path.join(
    os.path.dirname(__file__), "results", "zeroday_graded_results.json"
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "results", "plots")


def plot_robustness():
    if not os.path.exists(ROBUSTNESS_RESULTS_PATH):
        print(f"[!] Chua chay test robustness. Khong tim thay {ROBUSTNESS_RESULTS_PATH}")
        return

    with open(ROBUSTNESS_RESULTS_PATH) as f:
        data = json.load(f)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. Biểu đồ Tỷ lệ Kháng (Resistance / Block Rate) theo từng nhóm tấn công
    summary = data.get("summary", {})
    breakdown = summary.get("by_category", {})
    categories = []
    block_pcts = []

    for cat, stats in breakdown.items():
        categories.append(cat.replace("_", " ").title())
        total = stats.get("total", 1) or 1
        blocked = stats.get("blocked", 0)
        block_pcts.append((blocked / total) * 100)

    plt.figure(figsize=(10, 6))
    bars = plt.bar(
        categories,
        block_pcts,
        color=["#ff9999", "#66b3ff", "#99ff99", "#ffcc99", "#c2a5ff"][: len(categories)],
    )
    plt.ylim(0, 110)
    plt.ylabel("Resistance / Block Rate (%)", fontsize=12)
    plt.title("Sentinel Guardrails Resistance (Block) Rate by Attack Category", fontsize=14)

    # Thêm nhãn giá trị trên đầu cột
    for bar in bars:
        yval = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            yval + 2,
            f"{yval:.1f}%",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    out_file = os.path.join(OUTPUT_DIR, "robustness_block_rate.png")
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Saved Resistance (Block) Rate Plot -> {out_file}")

    # 2. Biểu đồ tròn Tỷ lệ Chính xác Tổng thể
    plt.figure(figsize=(8, 8))
    acc = summary.get("accuracy", 0.0)
    err = 100 - acc

    plt.pie(
        [acc, err],
        labels=["Accurate", "Missed/Bypassed"],
        autopct="%1.1f%%",
        startangle=90,
        colors=["#4CAF50", "#F44336"],
    )
    plt.title("Overall Prediction Accuracy (Adversarial Testing)", fontsize=14)
    out_file2 = os.path.join(OUTPUT_DIR, "robustness_accuracy_pie.png")
    plt.savefig(out_file2, dpi=300)
    print(f"[+] Saved Accuracy Pie Plot -> {out_file2}")


def plot_threshold_sensitivity():
    """Đường cong độ nhạy ngưỡng Welford (Z-score) — bảo vệ lựa chọn 3.5σ."""
    if not os.path.exists(SENSITIVITY_RESULTS_PATH):
        print(f"[!] Chua chay sensitivity. Khong tim thay {SENSITIVITY_RESULTS_PATH}")
        return

    with open(SENSITIVITY_RESULTS_PATH) as f:
        data = json.load(f)
    rows = data["sweep"]
    op = data.get("operating_point", 3.5)

    taus = [r["z_threshold"] for r in rows]
    f1 = [r["f1"] for r in rows]
    prec = [r["precision"] for r in rows]
    rec = [r["recall"] for r in rows]
    fp = [r["benign_fp_rate"] for r in rows]
    esc = [r["escalation_rate"] for r in rows]
    zd = [r["zeroday_caught"] / max(r["zeroday_total"], 1) for r in rows]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(taus, prec, "o-", color="#2E7D32", label="Precision (Tier-1)", linewidth=2)
    plt.plot(taus, rec, "s-", color="#1565C0", label="Recall (Tier-1)", linewidth=2)
    plt.plot(taus, f1, "^-", color="#6A1B9A", label="F1 (Tier-1)", linewidth=2)
    plt.plot(taus, fp, "v--", color="#EF6C00", label="Benign false-positive rate", linewidth=2)
    plt.plot(taus, esc, "d--", color="#C62828", label="Escalation rate (Tier-2 load)", linewidth=2)
    plt.plot(taus, zd, "*-", color="#00838F", label="Zero-day recall (7/7 at all τ)", linewidth=2)

    plt.axvline(op, color="gray", linestyle=":", linewidth=1.5)
    plt.text(op + 0.04, 0.02, f"Operating point\nτ = {op}σ", fontsize=9, color="gray")

    plt.xlabel("Welford Z-score threshold  τ  (σ)", fontsize=12)
    plt.ylabel("Rate", fontsize=12)
    plt.title("Tier-1 Welford Threshold Sensitivity (real mixed stream, LLM-free)", fontsize=13)
    plt.ylim(-0.02, 1.05)
    plt.grid(True, alpha=0.3)
    plt.legend(loc="center right", fontsize=9)

    out_file = os.path.join(OUTPUT_DIR, "threshold_sensitivity.png")
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Saved Threshold Sensitivity Plot -> {out_file}")


def plot_zeroday_graded():
    """Đường cong phát hiện zero-day theo độ lệch (graded) — thay '7/7 tầm thường'."""
    if not os.path.exists(ZERODAY_GRADED_PATH):
        print(f"[!] Chua chay graded zero-day. Khong tim thay {ZERODAY_GRADED_PATH}")
        return

    with open(ZERODAY_GRADED_PATH) as f:
        data = json.load(f)
    rows = data["sweep"]
    ks = [r["k_sigma"] for r in rows]
    det = [100 * r["escalated_rate"] for r in rows]
    notice = [100 * r["noticed_rate"] for r in rows]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(ks, notice, "o--", color="#1565C0", label="Noticed (Z > 3.5σ)", linewidth=2)
    plt.plot(ks, det, "s-", color="#C62828", label="Escalated to Tier-2", linewidth=2)
    plt.xscale("log")
    plt.axvline(3.5, color="green", linestyle=":", linewidth=1.5)
    plt.text(3.6, 5, "deployed\nτ = 3.5σ", fontsize=9, color="green")
    eb = data.get("escalate_boundary_sigma")
    if eb:
        plt.axvline(eb, color="gray", linestyle=":", linewidth=1.2)
        plt.text(eb + 0.3, 60, f"saturation\n≈ {eb}σ", fontsize=9, color="gray")
    plt.text(60, 92, "7 headline\nzero-days\n(Z ≫ 100σ)", fontsize=8, color="#6A1B9A", ha="center")

    plt.xlabel("Injected single-feature deviation  k  (σ, log scale)", fontsize=12)
    plt.ylabel("Detection rate (%)", fontsize=12)
    plt.title("Graded Zero-Day Detection Boundary (Tier-1 Welford, n=210/level)", fontsize=13)
    plt.ylim(-3, 105)
    plt.grid(True, alpha=0.3, which="both")
    plt.legend(loc="center left", fontsize=10)

    out_file = os.path.join(OUTPUT_DIR, "zeroday_graded.png")
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Saved Graded Zero-Day Plot -> {out_file}")


if __name__ == "__main__":
    plot_robustness()
    plot_threshold_sensitivity()
    plot_zeroday_graded()
