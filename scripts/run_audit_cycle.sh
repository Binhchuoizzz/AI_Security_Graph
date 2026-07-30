#!/usr/bin/env bash
# SENTINEL — Chạy MỘT lượt audit đầy đủ trên luồng demo, có thể lặp lại y hệt.
#
# VÌ SAO CÓ FILE NÀY: một chiến dịch audit cần nhiều lượt SO SÁNH ĐƯỢC VỚI NHAU. Gõ tay mỗi
# lượt thì khác nhau ở những chỗ không ai nhớ (quên export SENTINEL_TRACE, quên sao lưu log
# trước khi reset_all cắt cụt nó, lỡ dùng run_demo.sh vốn ép SENTINEL_LITE=1 -> đổi sang
# Llama-3-8B mà không báo). Script này cố định toàn bộ những điểm đó.
#
# KHÔNG dùng scripts/run_demo.sh: nó đặt SENTINEL_LITE=1 và ghi đè LLM_MODEL_FILE.
#
# Cách dùng:
#   scripts/run_audit_cycle.sh cold  <nhãn>   # reset sạch rồi chạy   (lượt nguội)
#   scripts/run_audit_cycle.sh warm  <nhãn>   # KHÔNG reset, chạy tiếp (đo giảm tải)
#   scripts/run_audit_cycle.sh restart <nhãn> # restart subscriber, GIỮ dữ liệu bền
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
MODE=${1:?mode: cold|warm|restart}
LABEL=${2:?nhãn cho lượt chạy, vd run2}
OUT="reports/runs/$LABEL"
mkdir -p "$OUT" logs/_prerun_backup

export SENTINEL_TRACE=1
export SENTINEL_AGENT_WORKERS=${SENTINEL_AGENT_WORKERS:-2}
export UNIFIED_STREAM_FILE=${UNIFIED_STREAM_FILE:-data/demo_small.json}
export UNIFIED_STREAM_BATCH=${UNIFIED_STREAM_BATCH:-50}
export UNIFIED_STREAM_DELAY=${UNIFIED_STREAM_DELAY:-0.1}

echo "=== LƯỢT '$LABEL' (mode=$MODE) ==="

# Xác minh model ĐANG PHỤC VỤ trước khi tốn hàng chục phút chạy.
MODEL=$(curl -s http://127.0.0.1:5000/v1/models | grep -oP '"name":"\K[^"]+' | head -1)
echo "[*] model đang phục vụ: ${MODEL:-KHÔNG PHẢN HỒI}"
[ -z "$MODEL" ] && { echo "[!] LLM không phản hồi — dừng."; exit 1; }

# reset_all mở subscriber.log ở chế độ 'w' -> CẮT CỤT. Sao lưu trước.
[ -f logs/subscriber.log ] && cp logs/subscriber.log "logs/_prerun_backup/subscriber.PRE-$LABEL.log"
[ -f logs/tier2_trace.jsonl ] && cp logs/tier2_trace.jsonl "$OUT/../tier2_trace.PRE-$LABEL.jsonl"

case "$MODE" in
  cold)
    .venv/bin/python scripts/reset_all.py | tail -14
    # PHẢI restart subscriber sau reset. Bản trước KHÔNG restart, nên lượt "nguội" vẫn giữ
    # nguyên cache phán quyết trong RAM của lượt trước trong khi Redis/reputation đã bị xoá
    # -> trạng thái LAI, không nguội cũng không ấm, và mọi so sánh giữa các lượt đều lệch.
    pkill -f "main.py --mode server" 2>/dev/null
    sleep 3
    nohup .venv/bin/python main.py --mode server --log-level INFO > logs/subscriber.log 2>&1 &
    sleep 25
    ;;
  restart)
    # Chỉ xoá cache RAM: giữ reputation/blacklist/luật động/threat-memory.
    pkill -f "main.py --mode server" 2>/dev/null
    sleep 3
    nohup .venv/bin/python main.py --mode server --log-level INFO > logs/subscriber.log 2>&1 &
    sleep 25
    ;;
  warm)
    echo "[*] warm: KHÔNG reset, KHÔNG restart — dùng nguyên trạng thái hiện có."
    ;;
  *) echo "mode không hợp lệ"; exit 1 ;;
esac

# Đúng MỘT subscriber, nếu không stream bị chia đôi và mọi số đếm sai.
N=$(pgrep -fc "main.py --mode server" || echo 0)
echo "[*] subscriber đang chạy: $N (kỳ vọng 1)"
[ "$N" != "1" ] && echo "[!] CẢNH BÁO: số subscriber != 1"

# Chờ nạp xong model embedding trước khi đẩy.
for _ in $(seq 1 40); do
  grep -q "Starting Tier 1 Subscriber Loop" logs/subscriber.log && break
  sleep 2
done

MARK=$(wc -l < logs/tier2_trace.jsonl 2>/dev/null || echo 0)
echo "[*] tracer trước khi đẩy: $MARK dòng"
# Bộ đếm phân bổ giảm tải là LUỸ KẾ -> chụp TRƯỚC/SAU rồi trừ mới ra số của riêng lượt này.
cp config/pipeline_stats.json "$OUT/pipeline_stats.BEFORE.json" 2>/dev/null || echo '{}' > "$OUT/pipeline_stats.BEFORE.json"
START=$(date +%s)
.venv/bin/python scripts/demo.py 2>&1 | tail -2

# Chờ rút cạn: hàng đợi Tier-2 nằm trong RAM nên KHÔNG quan sát được từ ngoài —
# chốt bằng "số dòng tracer đứng yên đủ lâu".
echo "[*] chờ Tier-2 rút cạn..."
PREV=-1; STABLE=0
while [ "$STABLE" -lt 10 ]; do
  sleep 30
  NOW=$(wc -l < logs/tier2_trace.jsonl 2>/dev/null || echo 0)
  if [ "$NOW" = "$PREV" ]; then STABLE=$((STABLE+1)); else STABLE=0; echo "    lô=$NOW"; fi
  PREV=$NOW
done
ELAPSED=$(( $(date +%s) - START ))
echo "[*] xong sau ${ELAPSED}s — tổng $PREV lô (lượt này: $((PREV-MARK)))"

cp config/pipeline_stats.json "$OUT/pipeline_stats.AFTER.json" 2>/dev/null || true
cp logs/subscriber.log "$OUT/subscriber.log" 2>/dev/null

# CHỈ lấy phần tracer SINH RA TRONG LƯỢT NÀY. Bản trước copy cả tệp rồi chấm — với lượt warm
# (tracer không bị xoá) thì số của lượt trước bị trộn vào, và "giảm tải" sẽ bị che hoàn toàn.
tail -n +$((MARK + 1)) logs/tier2_trace.jsonl > "$OUT/tier2_trace.jsonl" 2>/dev/null || true
cp logs/tier2_trace.jsonl "$OUT/tier2_trace.CUMULATIVE.jsonl"
echo "[*] lô của riêng lượt này: $(wc -l < "$OUT/tier2_trace.jsonl")"

.venv/bin/python scripts/audit_live_run.py --trace "$OUT/tier2_trace.jsonl" \
  --json "$OUT/audit.json" | tee "$OUT/audit.txt"
.venv/bin/python scripts/diff_pipeline_stats.py "$OUT" | tee -a "$OUT/audit.txt"
echo "[✓] kết quả -> $OUT/"
