#!/bin/bash
# =============================================================================
# SENTINEL — Dọn artifact TẠM (an toàn cho dữ liệu luận văn).
#
# AN TOÀN: script này CHỈ xóa thứ tái tạo được / không được Git theo dõi.
# Nó KHÔNG xóa experiments/results/*.json hay plots/*.png — đó là DỮ LIỆU THỰC
# NGHIỆM đã commit (LFS). Muốn xóa kết quả thật, làm thủ công + ý thức rõ.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

echo "[*] Cleaning SENTINEL temporary artifacts (an toàn, không đụng dữ liệu thesis)..."

# 1. MLflow (tái tạo khi chạy lại experiment) — gitignored
echo "[+] MLflow artifacts (mlruns/, mlflow.db, mlflow.log)..."
rm -rf mlruns/ mlflow.db mlflow.log

# 2. DB đánh giá TẠM (mỗi experiment tự tạo lại) — gitignored
echo "[+] Temp evaluation DBs (.unified_eval_memory.db, .apt_negctrl_memory.db, .apt_test*.db)..."
rm -f experiments/.unified_eval_memory.db experiments/.apt_negctrl_memory.db experiments/.apt_test*.db 2>/dev/null

# 3. FAISS index (rebuild bằng: python src/rag/embedder.py) — gitignored, checksums giữ nguyên
echo "[+] FAISS index caches (rebuild qua embedder)..."
rm -rf knowledge_base/faiss_index/* 2>/dev/null

# 4. Log thực thi cũ (giữ thư mục) — gitignored
echo "[+] Old execution logs (logs/*.log)..."
rm -rf logs/*.log 2>/dev/null

# 5. Cache Python/lint/test (tái tạo tự động) — gitignored
echo "[+] Python/lint/test caches (__pycache__, .pytest_cache, .ruff_cache, *.pyc)..."
find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null
rm -rf .pytest_cache .ruff_cache 2>/dev/null

# GHI CHÚ: KHÔNG xóa experiments/results/*.json, experiments/results/plots/*.png
# (dữ liệu luận văn đã commit), ground_truth.json, adversarial/*/samples.json.
echo "[*] Cleanup complete — dữ liệu thực nghiệm (results/, plots/, ground_truth) được GIỮ NGUYÊN."
