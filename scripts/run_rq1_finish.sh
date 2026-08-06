#!/usr/bin/env bash
# Chạy nốt hai bước còn lại của RQ1, RẺ TRƯỚC ĐẮT SAU, rồi gom báo cáo.
#
#   1.n  train_1m           ~5 phút   (offline, CPU)
#   1.e/1.h latency n=500   ~4 giờ    (nhánh LLM-only bắn thẳng 500 ca lên LLM)
#   gom báo cáo             vài giây
#
# Vì sao train_1m đi TRƯỚC: nó dùng `n_jobs=-1` chiếm hết lõi CPU, mà latency thì ĐO ĐỘ TRỄ.
# Chạy sau (hoặc chồng lên) thì số độ trễ thu được là của một máy đang quá tải. Xong sớm cũng
# có nghĩa là có số 1.n để đọc ngay thay vì chờ hết 4 tiếng.
#
#   Dùng:  bash scripts/run_rq1_finish.sh <đường_dẫn_ledger>

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LEDGER="${1:?thiếu đường dẫn ledger TSV}"
export SENTINEL_FREEZE_DYNAMIC_RULES=1
PY=.venv/bin/python
LOGDIR=logs/rq1
mkdir -p "$LOGDIR"

buoc() {
  local ten="$1"; shift
  local t0 t1 rc
  echo "════════ [$(date +%H:%M:%S)] $ten" | tee -a "$LOGDIR/_console.log"
  t0=$(date +%s)
  "$@" > "$LOGDIR/${ten}.log" 2>&1
  rc=$?
  t1=$(date +%s)
  printf '%s\t%d\t%d\t%s\n' "$ten" "$rc" "$((t1-t0))" "$(date -d @"$t0" +%H:%M:%S)" >> "$LEDGER"
  if [ $rc -ne 0 ]; then
    echo "   ⚠️  HỎNG (mã $rc) sau $((t1-t0))s — xem $LOGDIR/${ten}.log" | tee -a "$LOGDIR/_console.log"
  else
    echo "   ✓ xong sau $((t1-t0))s" | tee -a "$LOGDIR/_console.log"
  fi
  return 0
}

echo "▶ RQ1 phần còn lại — bắt đầu $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"

buoc train_1m           $PY ml_lab/train_1m.py
# Gom lần 1: có 1.n rồi thì đọc được NGAY, không phải chờ hết nhánh độ trễ 4 tiếng.
buoc gom_bao_cao_som    $PY scripts/collect_rq1_report.py --ledger "$LEDGER"

buoc latency_baseline   $PY experiments/measure_latency_baseline.py --n 500
buoc gom_bao_cao        $PY scripts/collect_rq1_report.py --ledger "$LEDGER"

echo "▉ RQ1 (đủ 1.a–1.n) — xong $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"
echo
column -t -s $'\t' "$LEDGER"
ls -t reports/RQ1_KET_QUA_*.md | head -1
