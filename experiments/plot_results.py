import json
import os
import matplotlib.pyplot as plt
import numpy as np

ROBUSTNESS_RESULTS_PATH = os.path.join(
    os.path.dirname(__file__), "robustness_results.json"
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "plots")


def plot_robustness():
    if not os.path.exists(ROBUSTNESS_RESULTS_PATH):
        print(
            f"[!] Chua chay test robustness. Khong tim thay {ROBUSTNESS_RESULTS_PATH}"
        )
        return

    with open(ROBUSTNESS_RESULTS_PATH, "r") as f:
        data = json.load(f)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. Biểu đồ Tỷ lệ Chặn (Defeat Rate)
    labels = ["Structural Injection", "Encoding Bypass", "Semantic Confusion"]
    # Phân tích dữ liệu từ category_breakdown
    breakdown = data.get("category_breakdown", {})
    categories = []
    defeat_pcts = []

    for cat, stats_wrapper in breakdown.items():
        categories.append(cat.replace("_", " ").title())
        stats = stats_wrapper.get("stats", {})
        total = stats.get("total", 1)
        blocked = stats.get("fully_blocked", 0)
        defeat_pcts.append((blocked / total) * 100)

    plt.figure(figsize=(10, 6))
    bars = plt.bar(
        categories,
        defeat_pcts,
        color=["#ff9999", "#66b3ff", "#99ff99", "#ffcc99"][: len(categories)],
    )
    plt.ylim(0, 110)
    plt.ylabel("Defeat Rate (%)", fontsize=12)
    plt.title("Sentinel Guardrails Defeat Rate by Attack Category", fontsize=14)

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

    out_file = os.path.join(OUTPUT_DIR, "robustness_defeat_rate.png")
    plt.savefig(out_file, dpi=300, bbox_inches="tight")
    print(f"[+] Saved Defeat Rate Plot -> {out_file}")

    # 2. Biểu đồ tròn Tỷ lệ Chính xác Tổng thể
    plt.figure(figsize=(8, 8))
    metrics = data.get("metrics", {})
    acc = metrics.get("overall_prediction_accuracy", 0.0) * 100
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


if __name__ == "__main__":
    plot_robustness()
