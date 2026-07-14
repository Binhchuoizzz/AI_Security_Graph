#!/usr/bin/env bash
# =============================================================================
# SENTINEL — CHẠY FULL DEMO BẰNG **MỘT LỆNH**
# =============================================================================
# Dựng TOÀN BỘ hệ thống thật rồi đẩy LUỒNG GỘP (CICIDS + DAPT2020 + Zero-day +
# Adversarial) chảy qua pipeline đầy đủ → Dashboard điền dần.
#
#   ./scripts/run_demo.sh              # full: hạ tầng + subscriber + UI + đẩy luồng
#   ./scripts/run_demo.sh --no-push    # chỉ dựng hạ tầng (subscriber + UI), KHÔNG đẩy
#   ./scripts/run_demo.sh --small      # đẩy tập nhỏ (demo nhanh, ít chờ LLM)
#
# Sau khi chạy: mở http://localhost:8501 (đăng nhập: manager).
# Tắt để giải phóng RAM:  pkill -f "main.py --mode server" ; docker-compose stop
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
DC="docker-compose"; command -v docker-compose >/dev/null 2>&1 || DC="docker compose"
LLM_URL="${LLM_API_BASE:-http://127.0.0.1:5000/v1}"
SUB_LOG="logs/subscriber.log"
mkdir -p logs

PUSH="full"
case "${1:-}" in
  --no-push) PUSH="none" ;;
  --small)   PUSH="small" ;;
esac

echo "▶ [1/5] Hạ tầng: Redis + LLM (llama.cpp) + MLflow + Dashboard containers…"
$DC up -d >/dev/null

echo "▶ [2/5] Chờ LLM cục bộ sẵn sàng (Gemma-2-9B qua llama.cpp)…"
for i in $(seq 1 60); do
  if curl -sf -m 3 "$LLM_URL/models" >/dev/null 2>&1; then echo "   ✓ LLM online"; break; fi
  [ "$i" -eq 60 ] && { echo "   ✗ LLM chưa lên — xem: docker logs sentinel_llm"; exit 1; }
  sleep 3
done

echo "▶ [3/5] Reset SẠCH + bật ĐÚNG 1 subscriber (Tier-1 Welford + Tier-2 LangGraph)…"
$PY scripts/reset_all.py

echo "   • chờ subscriber nạp xong RAG/embeddings…"
for i in $(seq 1 40); do
  if grep -q "Starting Tier 1 Subscriber Loop" "$SUB_LOG" 2>/dev/null; then echo "   ✓ subscriber sẵn sàng"; break; fi
  [ "$i" -eq 40 ] && { echo "   ! subscriber chưa báo sẵn sàng (vẫn tiếp tục — Redis đệm luồng)"; break; }
  sleep 2
done

echo "▶ [4/5] Dashboard Streamlit → http://localhost:8501"
if pgrep -f "streamlit run" >/dev/null 2>&1; then
  echo "   ✓ UI đã chạy"
else
  nohup "$PY" -m streamlit run src/ui/app.py >logs/ui.log 2>&1 &
  echo "   ✓ đã bật UI (log: logs/ui.log)"
fi

if [ "$PUSH" = "none" ]; then
  echo "✓ Hạ tầng sẵn sàng (bỏ qua đẩy luồng). Mở http://localhost:8501 — đăng nhập: manager."
  exit 0
fi

echo "▶ [5/5] ĐẨY LUỒNG GỘP → Dashboard (CICIDS + DAPT + Zero-day + Adversarial)…"
if [ "$PUSH" = "small" ]; then
  UNIFIED_STREAM_BATCH="${UNIFIED_STREAM_BATCH:-50}" UNIFIED_STREAM_DELAY="${UNIFIED_STREAM_DELAY:-0.1}" \
    "$PY" experiments/stream_unified_online.py --include-adversarial
else
  "$PY" experiments/stream_unified_online.py --include-adversarial
fi

echo ""
echo "✓ Hoàn tất đẩy luồng. Tier-1 xử lý tức thì; các ca ESCALATE tiếp tục chạy qua LLM"
echo "  vài phút — Dashboard http://localhost:8501 sẽ điền dần (đúng thiết kế SOC)."
