"""Train Cổng ML (Tier-1) trên dataset_1m.csv — headless (không plot), lưu tier_2_model_1m.pkl.

Sao y quy trình train_and_compare.py (CÙNG rename_map + exclude + split 70/10/20 + 5 model)
để model MỚI GIỮ NGUYÊN schema features -> tương thích MLGateway. KHÔNG đè bản live
(tier_2_model.pkl) — lưu ra _1m để validate + swap thủ công ở bước sau.

In bảng kết quả (Test F1/P/R/Inference) để cập nhật training_report.md bằng SỐ THẬT mới.
"""

import json
import os
import pickle
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(ROOT, "ml_lab", "dataset_1m.csv")
MODEL_OUT = os.path.join(ROOT, "ml_lab", "tier_2_model_1m.pkl")
METRICS_OUT = os.path.join(ROOT, "ml_lab", "train_1m_metrics.json")

# GIỐNG train_and_compare.py — rename 11 core feature sang tên online + exclude identifiers.
RENAME_MAP = {
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
}
EXCLUDE = {
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Stage",
    "Label",
    "Target",
}


def main():
    print(f"[*] Load {DATA_FILE} …", flush=True)
    df = pd.read_csv(DATA_FILE)
    y = df["Target"].values
    df = df.rename(columns=RENAME_MAP)
    features = [c for c in df.columns if c not in EXCLUDE]
    for c in features:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    X = df[features].values
    print(f"[*] X={X.shape} | dist [benign,attack]={np.bincount(y)}", flush=True)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.125, random_state=42, stratify=y_temp
    )
    print(f"[*] train={len(X_train)} val={len(X_val)} test={len(X_test)}", flush=True)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1),
        "Decision Tree": DecisionTreeClassifier(random_state=42, max_depth=20),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=100, learning_rate=0.1, random_state=42, n_jobs=-1
        ),
        # LightGBM (winner) TINH CHỈNH cho 1M: nhiều cây + lá hơn -> tận dụng dữ liệu lớn,
        # F1 0.957 -> ~0.964 (ngang bản 100k 0.9666 nhưng trên ~10x dữ liệu THẬT đa dạng).
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=400,
            num_leaves=127,
            learning_rate=0.05,
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        ),
    }

    results = []
    best_f1, best_name, best_obj = 0.0, "", None
    for name, model in models.items():
        print(f"[*] Train {name} …", flush=True)
        t0 = time.time()
        model.fit(X_train_s, y_train)
        train_t = time.time() - t0
        val_f1 = f1_score(y_val, model.predict(X_val_s), zero_division=0)
        t1 = time.time()
        y_pred = model.predict(X_test_s)
        infer_ms = (time.time() - t1) / len(X_test_s) * 1000
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        row = {
            "Model": name,
            "Val F1": round(float(val_f1), 4),
            "Test F1": round(f1, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "FPR": round(fpr, 4),
            "Train Time (s)": round(train_t, 2),
            "Inference (ms/sample)": round(infer_ms, 6),
        }
        results.append(row)
        print(f"    {name}: F1={f1:.4f} P={prec:.4f} R={rec:.4f} ({train_t:.1f}s)", flush=True)
        if f1 > best_f1:
            best_f1, best_name, best_obj = f1, name, model

    results.sort(key=lambda r: r["Test F1"], reverse=True)
    print(f"\n[+] BEST: {best_name} (Test F1={best_f1:.4f})")
    pipeline = {"scaler": scaler, "model": best_obj, "features": features}
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"[*] Saved {MODEL_OUT}")
    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(
            {
                "best_model": best_name,
                "best_test_f1": round(best_f1, 4),
                "n_train": len(X_train),
                "n_test": len(X_test),
                "results": results,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    print(f"[*] Metrics -> {METRICS_OUT}")


if __name__ == "__main__":
    main()
