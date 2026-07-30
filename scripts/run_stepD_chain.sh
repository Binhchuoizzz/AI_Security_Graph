#!/usr/bin/env bash
# =============================================================================
# CHUỖI D — ba bước dọn cuối, tự chạy NGAY SAU khi Chuỗi C kết thúc.
#
# Cả ba đều GHI vào tệp mà Chuỗi C đang ĐỌC (`config/golden_baseline.json`,
# `config/system_settings.yaml`) nên tuyệt đối không chạy song song:
#   B. Dựng lại seed Welford rồi SO SÁNH — chỉ chạy lại 4 bài offline NẾU tệp thật sự đổi.
#   C. Chạy lại run_context_stress (nó đo chính hành vi tràn ngữ cảnh, mà ngân sách vừa
#      đổi 8192 -> 16384).
#   F. pytest + ruff + pyrefly, sau cùng.
# =============================================================================
set -uo pipefail
cd /home/binhchuoiz/Projects/Thesis/AI_Security_Graph
PY=.venv/bin/python
# Nơi giữ bản sao seed để SO SÁNH. Phải là đường dẫn tự lập, KHÔNG phải scratchpad của một
# phiên làm việc cụ thể: bản trước ghi cứng /tmp/claude-1000/.../<id-phiên>/scratchpad nên
# lượt chạy sau (id phiên khác) `cp` vào thư mục không tồn tại -> `diff` so với tệp rỗng ->
# LUÔN báo "seed ĐỔI" và chạy lại 4 bài Welford vô ích.
SCRATCH=${SENTINEL_SCRATCH:-/tmp/sentinel-benchmark-$USER}
mkdir -p "$SCRATCH"

log() { echo "[$(date +%H:%M:%S)] $*"; }
run() { log "▶ $1"; shift; "$@" && log "   ✔ xong" || log "   ✘ THẤT BẠI (mã $?)"; }

# ── Chờ Chuỗi C ─────────────────────────────────────────────────────────────
log "chờ Chuỗi C kết thúc…"
while pgrep -f run_stepC_chain.sh >/dev/null; do sleep 60; done
log "✔ Chuỗi C đã dừng"

# ── B. Seed Welford: dựng lại rồi SO SÁNH ───────────────────────────────────
# Lý do phải so chứ không chạy lại mù: seed đọc benign từ CSV CICIDS thô, còn datatest chỉ
# dùng để dựng tập chữ ký LOẠI TRỪ. Chữ ký CSIC là request HTTP nên gần như chắc chắn không
# trùng dòng CSV nào — nếu đúng vậy thì tệp không đổi và 4 bài offline khỏi phải chạy lại.
cp config/golden_baseline.json "$SCRATCH/gb.before.json" 2>/dev/null
run "build_golden_baseline (dựng lại sau khi datatest có CSIC)" $PY experiments/build_golden_baseline.py

if diff -q <(jq -S . "$SCRATCH/gb.before.json" 2>/dev/null) \
           <(jq -S . config/golden_baseline.json 2>/dev/null) >/dev/null 2>&1; then
  log "   → seed KHÔNG đổi. Thứ tự dựng nay đã đúng; 4 bài Welford giữ nguyên kết quả."
else
  log "   → seed ĐỔI. Phải chạy lại 4 bài phụ thuộc Welford."
  for s in evaluate_unified_stream run_zeroday_graded run_threshold_sensitivity run_apt_negative_control; do
    run "$s (seed mới)" $PY experiments/$s.py
  done
fi

# ── C. Ngân sách ngữ cảnh vừa đổi -> bài đo tràn ngữ cảnh phải chạy lại ─────
run "run_context_stress (ngân sách 8192 -> 16384)" $PY experiments/run_context_stress.py

# ── F. Kiểm thử toàn bộ ─────────────────────────────────────────────────────
# `SENTINEL_FREEZE_DYNAMIC_RULES=1` là bản vá hôm nay: pytest KHÔNG còn ghi ~1.400 luật động
# vào config nữa, nên không cần sao lưu/phục hồi thủ công như trước.
RULES_BEFORE=$(grep -c 'pattern:' config/system_settings.yaml)
log "▶ pytest (luật động ĐÓNG BĂNG) — trước khi chạy: $RULES_BEFORE luật"
SENTINEL_FREEZE_DYNAMIC_RULES=1 $PY -m pytest tests/ -q 2>&1 | tail -12
RULES_AFTER=$(grep -c 'pattern:' config/system_settings.yaml)
if [ "$RULES_BEFORE" = "$RULES_AFTER" ]; then
  log "   ✔ config SẠCH: vẫn $RULES_AFTER luật — cờ đóng băng có tác dụng"
else
  log "   ✘ config BỊ BẨN: $RULES_BEFORE -> $RULES_AFTER. Phục hồi từ bản sao lưu!"
fi

run "ruff" .venv/bin/ruff check .
log "▶ pyrefly"
uvx pyrefly check --python-interpreter-path .venv/bin/python 2>&1 | tail -6

# ── Tổng kết độ tươi ────────────────────────────────────────────────────────
log "=== ĐỘ TƯƠI KẾT QUẢ ==="
ls -t experiments/results/*.json | while read -r f; do
  printf "   %s  %s\n" "$(date -r "$f" '+%m-%d %H:%M')" "$(basename "$f")"
done
log "=== CHUỖI D XONG ==="
