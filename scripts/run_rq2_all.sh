#!/usr/bin/env bash
# Chạy TOÀN BỘ chỉ số RQ2 rồi gom số ra một báo cáo. Cùng khuôn với `run_rq1_all.sh`.
#
# Thiết kế:
#   - Một script hỏng KHÔNG giết cả lượt (`|| true`).
#   - Nhật ký riêng từng bước ở logs/rq2/ kèm thời lượng và mã thoát.
#   - RẺ TRƯỚC, ĐẮT SAU. Khối A (không LLM) xong trong ~1 phút; khối B cần LLM.
#
# `adversarial_pipeline` MẶC ĐỊNH KHÔNG CHẠY: 678 mẫu khó × ~23 s/lần gọi ≈ **4,3 giờ**. Bật bằng
# `RQ2_WITH_LLM=1`. Lượt gần nhất chạy với `--limit 5` cho ra coverage **5,2%** và chính script tự
# gắn `metric_valid=false` — tức con số "kháng 100%" hiện có KHÔNG trích được. Muốn trích thì phải
# chạy đủ, không có đường tắt.
#
# 2.i (kháng né tránh ở lớp ML) nằm trong `evaluate_ml_gate.py` — thuộc lượt RQ1, không lặp ở đây.
# Nếu chưa chạy RQ1 thì chạy `bash scripts/run_rq1_all.sh` trước, hoặc riêng
# `.venv/bin/python experiments/evaluate_ml_gate.py`.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export SENTINEL_FREEZE_DYNAMIC_RULES=1   # BẮT BUỘC: không thì phép đo tự sinh luật rồi tự hưởng lợi
PY=.venv/bin/python
LOGDIR=logs/rq2
mkdir -p "$LOGDIR"

STAMP=$(date +%Y%m%d_%H%M%S)
LEDGER="$LOGDIR/_ledger_${STAMP}.tsv"
printf 'buoc\tma_thoat\tgiay\tbat_dau\n' > "$LEDGER"

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

echo "▶ RQ2 — bắt đầu $(date +'%F %T')" | tee "$LOGDIR/_console.log"

# ── A. Không cần LLM ─────────────────────────────────────────────────────────
# `static` và `negative` là MỘT CẶP, không tách. Tỉ lệ chặn trên mẫu tấn công chỉ có nghĩa khi
# đặt cạnh tỉ lệ báo nhầm trên log lành: một lớp gắn cờ mọi thứ cũng đạt "chặn 100%".
buoc adv_static         $PY experiments/evaluate_adversarial.py --mode static
buoc adv_negative       $PY experiments/evaluate_adversarial.py --mode negative
buoc audit_tamper       $PY experiments/run_audit_tamper.py

# ── B. Cần LLM ───────────────────────────────────────────────────────────────
# CẢ KHỐI nằm sau cùng một cổng. `llm_robustness` rẻ hơn `adv_pipeline` nhiều nhưng vẫn chiếm
# GPU — chạy chồng lên một phép ĐO ĐỘ TRỄ đang diễn ra (RQ1 1.h) thì con số độ trễ thu được là
# của một máy đang tranh tài nguyên. Chỉ số của RQ khác không được làm hỏng số của RQ này.
if [ "${RQ2_WITH_LLM:-0}" = "1" ]; then
  buoc llm_robustness   $PY experiments/run_llm_robustness.py
  # KHÔNG truyền `--limit`: bỏ trống = chạy hết 678 mẫu khó = coverage 100%.
  buoc adv_pipeline     $PY experiments/evaluate_adversarial.py --mode pipeline
else
  printf 'llm_robustness\tBO_QUA\t0\t%s\n' "$(date +%H:%M:%S)" >> "$LEDGER"
  printf 'adv_pipeline\tBO_QUA\t0\t%s\n' "$(date +%H:%M:%S)" >> "$LEDGER"
  echo "⏭  BỎ QUA khối cần LLM (adv_pipeline: 678 mẫu × ~23 s ≈ 4,3 giờ). Muốn 2.b + 2.h thì chạy:" | tee -a "$LOGDIR/_console.log"
  echo "     RQ2_WITH_LLM=1 bash scripts/run_rq2_all.sh" | tee -a "$LOGDIR/_console.log"
fi

# ── C. Gom số ────────────────────────────────────────────────────────────────
buoc gom_bao_cao        $PY scripts/collect_rq2_report.py --ledger "$LEDGER"

echo "▉ RQ2 — xong $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"
echo
column -t -s $'\t' "$LEDGER"
