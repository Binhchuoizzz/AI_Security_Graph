import os
import pickle

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(ROOT, "ml_lab", "dataset_100k.csv")
MODEL_OUT = os.path.join(ROOT, "ml_lab", "tier_2_model.pkl")


def main():
    print(f"[*] Loading dataset from {DATA_FILE}...")
    df = pd.read_csv(DATA_FILE)

    print(f"[*] Total dataset size: {df.shape}")

    # Take first 50k for training
    df_train = df.iloc[:50000].copy()
    print(f"[*] Training on first {len(df_train)} rows")

    # Exclude identifiers and non-numeric columns
    exclude = [
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
    ]
    features = [c for c in df_train.columns if c not in exclude]

    # Ensure all features are strictly numeric and handle Infinity/NaN
    for c in features:
        df_train[c] = pd.to_numeric(df_train[c], errors="coerce")
    df_train.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_train.fillna(0, inplace=True)

    # Features and Target
    y_train = df_train["Target"].values
    X_train = df_train[features].values
    feature_names = features

    # Train individual components
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    clf = DecisionTreeClassifier(random_state=42, max_depth=20)
    clf.fit(X_train_scaled, y_train)

    # Quick eval on train set
    preds = clf.predict(X_train_scaled)
    print("\n[*] Train Evaluation:")
    print(classification_report(y_train, preds))

    # Save the pipeline as dictionary
    save_dict = {"scaler": scaler, "model": clf, "features": feature_names}
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(save_dict, f)

    print(f"[+] Model saved to {MODEL_OUT}")

    # Keep the last 50k for demo
    df_demo = df.iloc[50000:].copy()
    demo_out = os.path.join(ROOT, "ml_lab", "demo_50k_cicids.csv")
    df_demo.to_csv(demo_out, index=False)
    print(f"[+] Demo dataset (last {len(df_demo)} rows) saved to {demo_out}")


if __name__ == "__main__":
    main()
