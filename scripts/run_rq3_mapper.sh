#!/usr/bin/env bash
# Chạy TOÀN BỘ phép đo quy kết ATT&CK (3.a–3.d) rồi gom số.
#
# Đây là chỉ số RQ3 duy nhất còn thiếu sau lượt RQ1+RQ2 ngày 05/08/2026. Các tệp kết quả cũ
# nằm trong `experiments/results/_archive_pre_2026-08/` được sinh TRƯỚC giao ước
# `drop_authored()` và mâu thuẫn nhau (68,4% với 2,33% cho cùng chế độ e2e) — KHÔNG trích.
#
# RẺ TRƯỚC, ĐẮT SAU:
#   Khối A — `rrf` tắt LLM, tất định, vài phút. Đây là TRẦN do truy xuất quyết định.
#   Khối B — `e2e` chạy full agent, ~12,5 s/mẫu (đo bằng thăm dò 5 mẫu).
#
# HIỆU SỐ `rrf` − `e2e` LÀ SỐ ĐÁNG QUAN TÂM NHẤT: nó tách lỗi TRUY XUẤT khỏi lỗi SINH.
#
# Sàn đoán bừa phải nêu kèm mọi tỉ lệ: payload 52,0% (T1595.003 = 130/250);
# flow 35,7% (T1499.002 = 400/1.120).
#
# KHÔNG tự đặt `--tag`: bỏ trống thì script tự đặt `{mode}_{layer}`. Tag tự chế từng sinh ra
# bốn tệp kết quả mâu thuẫn mà không ai biết tệp nào thật.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export SENTINEL_FREEZE_DYNAMIC_RULES=1   # BẮT BUỘC: không thì phép đo tự sinh luật rồi tự hưởng lợi
PY=.venv/bin/python
LOGDIR=logs/rq3
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

echo "▶ RQ3 quy kết ATT&CK — bắt đầu $(date +'%F %T')" | tee "$LOGDIR/_console.log"

# ── A. Tắt LLM — trần từ truy xuất (vài phút) ────────────────────────────────
buoc rrf_payload  $PY scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload
buoc rrf_flow     $PY scripts/eval_attack_mapper.py --mode rrf --evidence-layer flow
buoc rrf_all      $PY scripts/eval_attack_mapper.py --mode rrf --evidence-layer all

# ── B. Toàn tuyến — cần LLM ──────────────────────────────────────────────────
# payload chạy ĐỦ 500 mẫu (250 chấm được): đây là con số RQ3 chính, không subsample.
buoc e2e_payload  $PY scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload

# flow có 1.200 mẫu = ~4,2 giờ nếu chạy đủ. Lấy mẫu phân tầng 20/lớp để chặn trần thời gian;
# `--per-class` giữ cân bằng lớp nên tỉ lệ vẫn đọc được, chỉ là khoảng tin cậy rộng hơn.
buoc e2e_flow     $PY scripts/eval_attack_mapper.py --mode e2e --evidence-layer flow --per-class 20

echo "▉ RQ3 — xong $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"
echo
column -t -s $'\t' "$LEDGER"
