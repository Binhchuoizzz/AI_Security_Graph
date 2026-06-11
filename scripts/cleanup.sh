#!/bin/bash

echo "[*] Cleaning up SENTINEL temporary artifacts..."

# Remove MLflow artifacts
echo "[+] Removing MLflow artifacts (mlruns/, mlflow.db, mlflow.log)..."
rm -rf mlruns/ mlflow.db mlflow.log

# Remove experiment output files (keep benchmarks: ground_truth.json, adversarial_samples.json)
echo "[+] Removing experiment result artifacts (experiments/results/ + temp eval DB)..."
rm -f experiments/results/*.json
rm -f experiments/results/plots/*.png
rm -f experiments/.unified_eval_memory.db

# Remove FAISS indexes
echo "[+] Removing FAISS index caches (will be rebuilt on next embedder run)..."
rm -rf knowledge_base/faiss_index/*

# Remove old logs (keep directory)
echo "[+] Removing old execution logs..."
rm -rf logs/*.log

echo "[*] Cleanup complete! Workspace is clean and ready for Thesis Defense."
