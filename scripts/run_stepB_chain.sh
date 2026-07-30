#!/usr/bin/env bash
# BƯỚC 4: benchmark FULL, chạy sau khi Chuỗi A xong và lỗi mapper đã vá.
#
# TỰ KIỂM TRƯỚC KHI CHẠY — chạy full mất hàng giờ, sai điều kiện đầu vào là mất trắng cả đêm:
#   1. Chuỗi A phải HOÀN TẤT (nếu không, .env còn trỏ model của lượt đo dở)
#   2. Server phải phục vụ ĐÚNG model đã chốt
#   3. Bản vá mapper phải có mặt trong mã
#   4. `config/system_settings.yaml` phải được sao lưu (ablation ghi luật động vào đó)
#
# CHẠY:  nohup bash scripts/run_stepB_chain.sh > logs/stepB.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
say() { echo "[$(date +%H:%M:%S)] $*"; }

WANT_MODEL=${WANT_MODEL:-Foundation-Sec-8B-Instruct}

say "▶ chờ Chuỗi A hoàn tất..."
while ! grep -q "CHUỖI A HOÀN TẤT" logs/stepA.log 2>/dev/null; do
  pgrep -f "run_stepA_chain.sh" >/dev/null || {
    say "✘ Chuỗi A đã dừng mà không báo HOÀN TẤT — DỪNG"; exit 1; }
  sleep 60
done
say "✔ Chuỗi A xong"

# ── Điều kiện 2: đúng model ─────────────────────────────────────────────────
SERVING=$(curl -s -m 10 http://127.0.0.1:5000/v1/models | grep -oP '"name":"\K[^"]+' | head -1)
case "$SERVING" in
  *"$WANT_MODEL"*) say "✔ server đang phục vụ $SERVING" ;;
  *) say "✘ server phục vụ '$SERVING', cần '$WANT_MODEL' — DỪNG"; exit 1 ;;
esac

# ── Điều kiện 3: bản vá mapper đã có ────────────────────────────────────────
if ! grep -q "_MAPPER_GUESS_MUST_BE_GROUNDED" src/agent/nodes.py; then
  say "✘ chưa thấy bản vá 'mapper chỉ được đoán khi có neo RAG' — DỪNG"
  exit 1
fi
say "✔ bản vá mapper có mặt"

# ── Điều kiện 4: sao lưu config (ablation ghi ~1.400 luật động vào đây) ──────
BAK="config/system_settings.yaml.pre-ablation.bak"
cp config/system_settings.yaml "$BAK" || { say "✘ không sao lưu được config — DỪNG"; exit 1; }
say "✔ đã sao lưu config -> $BAK"

say "=== BẮT ĐẦU BENCHMARK FULL (20 bước, hàng giờ) ==="
bash scripts/run_full_ablation.sh
RC=$?
say "=== benchmark full kết thúc (mã $RC) ==="

say "▶ khôi phục config sạch luật test"
cp "$BAK" config/system_settings.yaml
say "=== CHUỖI B HOÀN TẤT ==="
