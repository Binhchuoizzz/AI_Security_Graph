#!/usr/bin/env bash
# Nối 1.n vào một lượt run_rq1_all.sh ĐANG CHẠY, rồi gom lại báo cáo.
#
# Vì sao cần script này: lượt hiện tại khởi động trước khi 1.n được đưa vào run_rq1_all.sh.
# Giết nó để chạy lại thì mất trắng phần offline đã xong và cả bước LLM đang dở. Thay vào đó
# chờ nó thoát rồi chạy tiếp — kết quả giống hệt như thể 1.n đã nằm sẵn trong lượt đó.
#
# CHỜ, không chạy song song: train_1m dùng `n_jobs=-1` (chiếm hết lõi CPU) còn lượt đang chạy
# thì có `measure_latency_baseline` ĐO ĐỘ TRỄ. Chạy chồng lên nhau thì số độ trễ thu được là
# của một máy đang quá tải — sai lệch do chính phép đo gây ra.
#
#   Dùng:  bash scripts/run_rq1_tail.sh <PID_lượt_đang_chạy> <đường_dẫn_ledger>

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PID_CHO="${1:?thiếu PID của lượt đang chạy}"
LEDGER="${2:?thiếu đường dẫn ledger TSV}"

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

echo "⏳ Chờ PID $PID_CHO thoát rồi mới chạy tiếp…" | tee -a "$LOGDIR/_console.log"
while kill -0 "$PID_CHO" 2>/dev/null; do sleep 30; done
echo "▶ Lượt chính đã xong lúc $(date +'%F %T') — chạy nốt 1.n" | tee -a "$LOGDIR/_console.log"

buoc train_1m    $PY ml_lab/train_1m.py

# Gom LẠI: báo cáo do lượt chính sinh ra chưa có 1.n vì lúc đó chưa train xong.
buoc gom_bao_cao $PY scripts/collect_rq1_report.py --ledger "$LEDGER"

echo "▉ RQ1 (đủ 1.a–1.n) — xong $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"
echo
column -t -s $'\t' "$LEDGER"
ls -t reports/RQ1_KET_QUA_*.md | head -1
