#!/usr/bin/env bash
# Chạy TOÀN BỘ chỉ số RQ1 rồi gom số ra một báo cáo.
#
# Thiết kế:
#   - Một script hỏng KHÔNG giết cả lượt (`|| true`) — chạy qua đêm mà mất trắng vì một lỗi
#     ở bước 2 là thứ không chấp nhận được.
#   - Nhật ký riêng từng bước ở logs/rq1/ kèm thời lượng và mã thoát -> truy được bước nào hỏng.
#   - Thứ tự: OFFLINE trước (rẻ, xong sớm để có cái mà đọc), rồi mới tới hai bước cần LLM.
#   - `measure_latency_baseline` MẶC ĐỊNH KHÔNG CHẠY. Một mình nó tốn ~3,3 giờ, bằng 10 lần tổng
#     tám bước còn lại cộng lại — để mặc định thì mỗi lần muốn xem một con số nhỏ cũng phải chờ
#     qua đêm. Bật bằng `RQ1_WITH_LATENCY=1`.
#
# 1.n (`ml_lab/train_1m.py`) xếp CUỐI khối offline, TRƯỚC mọi bước cần LLM: nó chạy `n_jobs=-1`
# nên ngốn hết lõi CPU, mà `measure_latency_baseline` lại đang ĐO ĐỘ TRỄ — chạy chồng lên nhau
# thì con số độ trễ đo được là của một máy đang quá tải, không phải của hệ thống.
# Nó lưu ra `ml_lab/tier_2_model_1m.pkl`, KHÔNG đụng bản triển khai `ml_lab/tier_2_model.pkl`,
# nên số 1.a–1.d đo ở trên vẫn là của đúng mô hình đang chạy.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export SENTINEL_FREEZE_DYNAMIC_RULES=1   # BẮT BUỘC: không thì phép đo tự sinh luật rồi tự hưởng lợi
PY=.venv/bin/python
LOGDIR=logs/rq1
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

echo "▶ RQ1 — bắt đầu $(date +'%F %T')" | tee "$LOGDIR/_console.log"

# ── A. Offline, không cần LLM ────────────────────────────────────────────────
buoc ml_gate            $PY experiments/evaluate_ml_gate.py
buoc ablation_mlgate    $PY experiments/run_ablation.py --mode mlgate
buoc ml_threshold_sweep $PY experiments/run_ml_threshold_sweep.py
buoc offload_mechanisms $PY scripts/audit_offload_mechanisms.py
buoc unified_stream     $PY experiments/evaluate_unified_stream.py
buoc cache_efficiency   $PY experiments/run_cache_efficiency.py
buoc train_1m           $PY ml_lab/train_1m.py
# 1.e tách khỏi 1.h: xả tải là đại lượng THUẦN ĐỊNH TUYẾN, đo offline vài phút là xong — không có
# lý do gì bắt nó chờ lượt đo độ trễ. Chạy hai luồng vì xả tải là HÀM của tỉ lệ tấn công:
#   stream = build_stream() 31,6% tấn công (luồng benchmark)
#   demo   = data/demo.json 99.717 sự kiện, 9,8% tấn công (dạng SOC thật, nền lành áp đảo)
buoc offload_stream     $PY experiments/measure_offload_vs_baserate.py --source stream
buoc offload_demo       $PY experiments/measure_offload_vs_baserate.py --source demo

# ── B. Cần LLM ───────────────────────────────────────────────────────────────
# `--with-llm` bật H3 (LLM-only): MỌI sự kiện đi thẳng lên Tier-2, không Tier-1, không Cổng ML.
# Đây là phép so HỢP LỆ duy nhất cho câu "hơn các dự án LLM-SOC khác ở đâu" — cùng dữ liệu, cùng
# mô hình, cùng prompt. Chép số headline của công trình khác vào bảng thì không hợp lệ (khác tập,
# khác tác vụ, khác định nghĩa chỉ số). Mọi cấu hình khác được chấm lại trên ĐÚNG mẫu con của H3.
buoc baseline_compare   $PY experiments/run_baseline_comparison.py --with-llm --llm-limit 150
buoc feedback_loop      $PY experiments/evaluate_feedback_loop.py
# n=500: nhánh LLM-only bắn THẲNG cả n sự kiện lên LLM (~23 s/lần đo được), nên n quyết định gần
# như toàn bộ thời lượng lượt chạy — 1.000 tốn ~8 giờ, 500 tốn ~3,3. 500 mẫu mỗi nhánh vẫn thừa
# cho Mann-Whitney U và cho khoảng tin cậy phần trăm; đo thêm chỉ tốn giờ, không đổi kết luận.
if [ "${RQ1_WITH_LATENCY:-0}" = "1" ]; then
  buoc latency_baseline $PY experiments/measure_latency_baseline.py --n 500
else
  printf 'latency_baseline\tBO_QUA\t0\t%s\n' "$(date +%H:%M:%S)" >> "$LEDGER"
  echo "⏭  BỎ QUA latency_baseline (~3,3 giờ). Muốn số 1.h thì chạy:" | tee -a "$LOGDIR/_console.log"
  echo "     RQ1_WITH_LATENCY=1 bash scripts/run_rq1_all.sh" | tee -a "$LOGDIR/_console.log"
fi

# ── C. Gom số ────────────────────────────────────────────────────────────────
buoc gom_bao_cao        $PY scripts/collect_rq1_report.py --ledger "$LEDGER"

echo "▉ RQ1 — xong $(date +'%F %T')" | tee -a "$LOGDIR/_console.log"
echo
column -t -s $'\t' "$LEDGER"
