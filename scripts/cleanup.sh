#!/bin/bash

echo "[*] Cleaning up SENTINEL temporary artifacts..."

# Remove MLflow artifacts
echo "[+] Removing MLflow artifacts (mlruns/, mlflow.db, mlflow.log)..."
rm -rf mlruns/ mlflow.db mlflow.log

# Remove experiment output json files (keep ground truth!)
echo "[+] Removing experiment temporary JSON results..."
rm -rf experiments/ablation_results.json
rm -rf experiments/robustness_results.json

# Remove FAISS indexes
echo "[+] Removing FAISS index caches (will be rebuilt on next embedder run)..."
rm -rf knowledge_base/faiss_index/*

# Remove old logs (keep directory)
echo "[+] Removing old execution logs..."
rm -rf logs/*.log

echo "[*] Cleanup complete! Workspace is clean and ready for Thesis Defense."
