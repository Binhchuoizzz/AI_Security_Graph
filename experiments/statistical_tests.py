import json
import os
import numpy as np
from scipy import stats
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score

ABLATION_RESULTS_PATH = os.path.join(os.path.dirname(__file__), "ablation_results.json")


def mcnemar_test(y_true, y_pred1, y_pred2):
    """
    Kiểm định McNemar để so sánh sự khác biệt của 2 bộ phân loại (classifier) trên cùng tập dữ liệu.
    Trả về p-value.
    """
    # Xây dựng bảng ngẫu nhiên (contingency table)
    # b: classifier 1 đúng, classifier 2 sai
    # c: classifier 1 sai, classifier 2 đúng
    b = 0
    c = 0
    for yt, yp1, yp2 in zip(y_true, y_pred1, y_pred2):
        c1_correct = yt == yp1
        c2_correct = yt == yp2
        if c1_correct and not c2_correct:
            b += 1
        elif not c1_correct and c2_correct:
            c += 1

    if b + c == 0:
        return 1.0  # Không có sự khác biệt nào

    # Giá trị kiểm định chi-bình-phương McNemar
    chi2 = ((abs(b - c) - 1) ** 2) / (b + c)
    # p-value từ phân phối chi-bình-phương với 1 bậc tự do
    p_value = stats.distributions.chi2.sf(chi2, 1)
    return p_value


def calculate_metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),  # type: ignore
        "recall": recall_score(y_true, y_pred, zero_division=0),  # type: ignore
        "f1": f1_score(y_true, y_pred, zero_division=0),  # type: ignore
    }


def run_tests():
    if not os.path.exists(ABLATION_RESULTS_PATH):
        print(f"[!] Chua chay ablation_study. Khong tim thay {ABLATION_RESULTS_PATH}")
        return

    with open(ABLATION_RESULTS_PATH, "r") as f:
        data = json.load(f)

    y_true = data["Config_A"]["y_true"]
    y_pred_A = data["Config_A"]["y_pred"]
    latencies_A = data["Config_A"]["latencies"]

    y_pred_F = data["Config_F"]["y_pred"]
    latencies_F = data["Config_F"]["latencies"]

    print("=" * 50)
    print(" STATISTICAL TESTS FOR ABLATION STUDY")
    print("=" * 50)

    # 1. Chỉ số đánh giá bộ phân loại
    metrics_A = calculate_metrics(y_true, y_pred_A)
    metrics_F = calculate_metrics(y_true, y_pred_F)

    print("\n--- PERFORMANCE METRICS ---")
    print(
        f"Config A (Rule-only): F1 = {metrics_A['f1']:.4f} | Prec = {metrics_A['precision']:.4f} | Rec = {metrics_A['recall']:.4f}"
    )
    print(
        f"Config F (Full Sent): F1 = {metrics_F['f1']:.4f} | Prec = {metrics_F['precision']:.4f} | Rec = {metrics_F['recall']:.4f}"
    )

    # 2. Kiểm định McNemar cho Accuracy/F1
    p_val_mcnemar = mcnemar_test(y_true, y_pred_A, y_pred_F)
    print("\n--- MCNEMAR'S TEST (Classification Difference) ---")
    print(f"H0: Hieu nang 2 mo hinh la tuong duong nhau.")
    print(f"P-value: {p_val_mcnemar:.5f}")
    if p_val_mcnemar < 0.05:
        print(
            ">> Ket luan: Su khac biet ve hieu nang la CO Y NGHIA THONG KE (p < 0.05)."
        )
    else:
        print(">> Ket luan: Khong du bang chung bac bo H0.")

    # 3. Kiểm định Mann-Whitney U cho Độ trễ
    mean_lat_A = np.mean(latencies_A)
    mean_lat_F = np.mean(latencies_F)

    print("\n--- LATENCY METRICS ---")
    print(f"Config A (Rule-only): Mean = {mean_lat_A:.4f}s")
    print(f"Config F (Full Sent): Mean = {mean_lat_F:.4f}s")

    stat, p_val_mw = stats.mannwhitneyu(
        latencies_A, latencies_F, alternative="two-sided"
    )
    print("\n--- MANN-WHITNEY U TEST (Latency Difference) ---")
    print(f"H0: Do tre phan phoi tuong dong giua 2 Config.")
    print(f"P-value: {p_val_mw:.5f}")
    if p_val_mw < 0.05:
        print(">> Ket luan: Su khac biet ve do tre la CO Y NGHIA THONG KE (p < 0.05).")
    else:
        print(">> Ket luan: Khong du bang chung bac bo H0.")

    print("=" * 50)


if __name__ == "__main__":
    run_tests()
