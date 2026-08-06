#!/usr/bin/env bash
# Chờ lượt RQ1 thoát rồi chạy RQ2 ĐẦY ĐỦ (gồm khối cần LLM).
#
# CHỜ, không chạy song song. `adv_pipeline` của RQ2 và `latency_baseline` của RQ1 cùng tranh
# GPU, mà `latency_baseline` đang ĐO ĐỘ TRỄ — chạy chồng lên nhau thì số độ trễ thu được là của
# một máy đang tranh tài nguyên, tức sai lệch do chính phép đo gây ra.
#
#   Dùng:  bash scripts/run_rq2_after_rq1.sh <PID_lượt_RQ1>

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PID_CHO="${1:?thiếu PID của lượt RQ1 đang chạy}"
mkdir -p logs/rq2

echo "⏳ [$(date +'%F %T')] Chờ RQ1 (PID $PID_CHO) thoát rồi mới chạy RQ2…"
while kill -0 "$PID_CHO" 2>/dev/null; do sleep 30; done
echo "▶ [$(date +'%F %T')] RQ1 xong — bắt đầu RQ2 đầy đủ"

# Chốt lại báo cáo RQ1 lần cuối (latency_benchmark.json nay đã có).
.venv/bin/python scripts/collect_rq1_report.py \
  --ledger "$(ls -t logs/rq1/_ledger_*.tsv | head -1)" || true

RQ2_WITH_LLM=1 bash scripts/run_rq2_all.sh
echo "▉ [$(date +'%F %T')] RQ1 + RQ2 đã xong"
