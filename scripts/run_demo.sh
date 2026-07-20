#!/usr/bin/env bash
# =============================================================================
# SENTINEL — CHẠY FULL DEMO BẰNG **MỘT LỆNH**
# =============================================================================
# Dựng hạ tầng + UI rồi đẩy LUỒNG GỘP (CICIDS + DAPT2020 + Zero-day + Adversarial)
# chảy qua pipeline đầy đủ → Dashboard điền dần.
#
# ⚠️ Mặc định script KHÔNG tự reset (giữ trạng thái hiện tại để tái lập). Muốn demo SẠCH
#    (dọn danh tiếng + chuỗi APT + luật động cũ), dùng cờ --fresh (tự chạy reset_all).
#    Hoặc tự chạy trước: python scripts/reset_all.py && ./scripts/run_demo.sh
#    (Nếu subscriber chưa chạy và không có --fresh, script dừng và nhắc bạn chạy reset_all.)
#
#   ./scripts/run_demo.sh              # đẩy luồng (yêu cầu subscriber đã chạy sẵn)
#   ./scripts/run_demo.sh --fresh      # RESET sạch (reputation+APT+luật) rồi đẩy — demo trong sạch
#   ./scripts/run_demo.sh --no-push    # chỉ dựng hạ tầng + UI, KHÔNG đẩy
#   ./scripts/run_demo.sh --small      # đẩy tập nhỏ (demo nhanh, ít chờ LLM)
#   ./scripts/run_demo.sh --fresh --small   # kết hợp được: reset sạch + đẩy tập nhỏ
#   SENTINEL_LITE=0 ./scripts/run_demo.sh   # baseline nặng: Gemma 2 9B, ctx 16384, 2 parallel
#
# Mặc định script chạy ở chế độ LOW-VRAM cho máy RAM 32GB / GPU VRAM thấp:
# - Llama 3 8B Q5_K_M
# - ctx 8192
# - 1 parallel
# - tắt Neo4j (vì là nhánh V2 tùy chọn, không nằm trên đường đi lõi)
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
FRESH="0"
for arg in "$@"; do
  case "$arg" in
    --no-push) PUSH="none" ;;
    --small)   PUSH="small" ;;
    --fresh)   FRESH="1" ;;   # tự chạy reset_all trước (demo SẠCH: dọn reputation+APT+luật)
  esac
done

# Profile phần cứng mặc định cho máy hiện tại: nhẹ hơn để tránh OOM VRAM/RAM.
# THROUGHPUT: dải điểm mới (Cổng ML chặn/alert/drop phần lớn ở Tier-1, chỉ 0.65–0.85 escalate)
# đã CẮT MẠNH tải LLM -> backlog nhỏ. Tăng AGENT_WORKERS (chỉ thread, KHÔNG tốn thêm VRAM) để
# pipeline phần RAG/guardrails chồng lên thời gian chờ LLM; GIỮ N_PARALLEL để không phình VRAM.
if [ "${SENTINEL_LITE:-1}" = "1" ]; then
  : "${LLM_MODEL_FILE:=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf}"
  : "${LLAMA_ARG_CTX_SIZE:=8192}"
  : "${LLAMA_ARG_N_PARALLEL:=1}"
  : "${SENTINEL_AGENT_WORKERS:=2}"
  : "${SENTINEL_ENABLE_NEO4J:=0}"
else
  : "${LLM_MODEL_FILE:=gemma-2-9b-it-Q6_K.gguf}"
  : "${LLAMA_ARG_CTX_SIZE:=16384}"
  : "${LLAMA_ARG_N_PARALLEL:=2}"
  : "${SENTINEL_AGENT_WORKERS:=4}"
  : "${SENTINEL_ENABLE_NEO4J:=1}"
fi
export LLM_MODEL_FILE LLAMA_ARG_CTX_SIZE LLAMA_ARG_N_PARALLEL SENTINEL_AGENT_WORKERS SENTINEL_ENABLE_NEO4J

if [ "$SENTINEL_ENABLE_NEO4J" = "1" ]; then
  echo "▶ [1/5] Hạ tầng: Redis + LLM (llama.cpp) + MLflow + Dashboard + Neo4j containers…"
  $DC up -d >/dev/null
else
  echo "▶ [1/5] Hạ tầng: Redis + LLM (llama.cpp) + MLflow + Dashboard containers… (Neo4j tắt để tiết kiệm RAM)"
  $DC up -d redis llm mlflow agent_ui >/dev/null
fi

echo "▶ [2/5] Chờ LLM cục bộ sẵn sàng (${LLM_MODEL_FILE} qua llama.cpp)…"
for i in $(seq 1 60); do
  if curl -sf -m 3 "$LLM_URL/models" >/dev/null 2>&1; then echo "   ✓ LLM online"; break; fi
  [ "$i" -eq 60 ] && { echo "   ✗ LLM chưa lên — xem: docker logs sentinel_llm"; exit 1; }
  sleep 3
done

if [ "$FRESH" = "1" ]; then
  echo "▶ [3/5] --fresh: reset_all (dọn reputation + APT + luật động + blacklist + stream, bật lại đúng 1 subscriber)…"
  "$PY" scripts/reset_all.py
  echo "   ✓ đã reset về trạng thái SẠCH — APT/danh tiếng sẽ dựng LẠI từ đầu trong lần đẩy này."
else
  echo "▶ [3/5] Kiểm tra subscriber (KHÔNG tự reset — dùng --fresh để dọn sạch, hoặc tự chạy reset_all)…"
fi
if pgrep -f "main.py --mode server" >/dev/null 2>&1; then
  echo "   ✓ subscriber đang chạy — dùng TRẠNG THÁI HIỆN TẠI (không dọn DB/luật động)."
else
  echo "   ✗ CHƯA có subscriber đang chạy. Hãy chạy TRƯỚC (hoặc dùng --fresh để tự reset+bật):"
  echo "       $PY scripts/reset_all.py"
  echo "     (reset_all: dọn DB + luật động trong system_settings.yaml + bật đúng 1 subscriber)"
  exit 1
fi

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
  # BUG CŨ: --small chỉ đổi BATCH/DELAY mà KHÔNG đặt UNIFIED_STREAM_LIMIT, nên vẫn đẩy
  # ĐỦ ~100k sự kiện — trái hẳn mô tả "đẩy tập nhỏ, ít chờ LLM". Hậu quả: buổi demo bị
  # giới hạn thời gian vẫn phải chờ hàng giờ cho LLM rút hết hàng đợi.
  # Nay giới hạn THẬT (mặc định 5.000 sự kiện, ghi đè bằng UNIFIED_STREAM_LIMIT).
  echo "   (--small: giới hạn ${UNIFIED_STREAM_LIMIT:-5000} sự kiện đầu để demo nhanh)"
  UNIFIED_STREAM_LIMIT="${UNIFIED_STREAM_LIMIT:-5000}" \
  UNIFIED_STREAM_BATCH="${UNIFIED_STREAM_BATCH:-50}" UNIFIED_STREAM_DELAY="${UNIFIED_STREAM_DELAY:-0.1}" \
    "$PY" scripts/demo.py
else
  "$PY" scripts/demo.py
fi

echo ""
echo "✓ Hoàn tất đẩy luồng. Tier-1 xử lý tức thì; các ca ESCALATE tiếp tục chạy qua LLM"
echo "  vài phút — Dashboard http://localhost:8501 sẽ điền dần (đúng thiết kế SOC)."
