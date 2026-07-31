#!/usr/bin/env bash
# BƯỚC 1+2 nối tiếp, không cần trông: chờ 2 lượt đẩy xong -> so sánh giảm tải -> đo LẠI cả
# ba model trên trace MỚI (khoá nối `gt_id` khớp sidecar, nên cột "đúng kỹ thuật" mới có
# nghĩa — đây chính là thứ còn thiếu để chốt model).
#
# CHẠY:  nohup bash scripts/run_stepA_chain.sh > logs/stepA.log 2>&1 &
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
say() { echo "[$(date +%H:%M:%S)] $*"; }

# ── 1. Chờ chuỗi 2 lượt đẩy kết thúc ────────────────────────────────────────
say "▶ chờ 2 lượt đẩy nối tiếp kết thúc..."
while ! grep -q "HOÀN TẤT" logs/consecutive_fsec.log 2>/dev/null; do
  # Nếu tiến trình đẩy chết mà chưa ghi HOÀN TẤT -> thoát, đừng chờ vô hạn.
  pgrep -f "run_audit_cycle.sh" >/dev/null || pgrep -f "consecutive_fsec" >/dev/null || {
    sleep 60
    grep -q "HOÀN TẤT" logs/consecutive_fsec.log 2>/dev/null || {
      say "✘ chuỗi đẩy đã dừng mà không báo HOÀN TẤT — DỪNG chuỗi A"; exit 1; }
  }
  sleep 60
done
say "✔ 2 lượt đẩy xong"

# ── 2. Chốt trace làm bộ prompt phát lại ────────────────────────────────────
# Dùng lượt NGUỘI (p1_fsec): mẫu lớn nhất, chưa bị trí nhớ cắt bớt.
TRACE=reports/runs/p1_fsec/tier2_trace.jsonl
if [ ! -s "$TRACE" ]; then
  say "✘ không thấy $TRACE — DỪNG"; exit 1
fi
say "✔ trace phát lại: $(wc -l < "$TRACE") lô"

# `compare_llm_models.py` đọc hằng số TRACE trỏ tới p1_cold. Trỏ lại bằng biến môi trường
# thì phải sửa mã; đơn giản và an toàn hơn: chép đè vào đúng đường dẫn nó đọc.
mkdir -p reports/runs/p1_cold
cp "$TRACE" reports/runs/p1_cold/tier2_trace.jsonl
say "✔ đã trỏ bộ phát lại sang trace mới"

# ── 3. Đo LẠI cả ba model trên trace mới ────────────────────────────────────
# XOÁ kết quả cũ: chúng đo trên trace + sidecar CŨ, để lẫn vào bảng là so nhầm thế hệ.
rm -f reports/model_bench/*.json
say "✔ đã xoá kết quả model cũ (đo trên trace/sidecar cũ, không so được)"

run_model() {  # run_model <tệp gguf> <ctx>
  say "▶ đo $1 (ctx=$2)"
  $PY scripts/compare_llm_models.py --model "$1" --ctx "$2" --limit 60 \
    || say "✘ $1 THẤT BẠI (bỏ qua, chạy tiếp model sau)"
}

run_model Foundation-Sec-8B-Instruct-Q4_K_M.gguf 32768
run_model WhiteRabbitNeo-V3-7B-Q4_K_M.gguf       32768
# Foundation-Sec PHẢI đo ở 32768 như hai model kia. Lượt trước chạy nó ở 8192 với `-np 2` = 4.096
# token/khe, trong khi prompt Tier-2 thật p50 ≈ 7.700 token -> hỏng 60/60 lượt trong 0,02
# giây. Đó là hỏng do CẤU HÌNH, không phải kết luận về chất lượng model; so sánh ba model ở
# ba ngân sách khác nhau thì bảng kết quả không nói lên điều gì.
run_model foundation-sec-8b-instruct-Q4_K_M.gguf                32768

# ── 4. Trả .env về model đang chọn + dựng lại container ─────────────────────
say "▶ khôi phục Foundation-Sec làm model phục vụ"
sed -i 's/^LLM_MODEL_FILE=.*/LLM_MODEL_FILE=Foundation-Sec-8B-Instruct-Q4_K_M.gguf/' .env
sed -i 's/^LLAMA_ARG_CTX_SIZE=.*/LLAMA_ARG_CTX_SIZE=32768/' .env
docker-compose up -d --force-recreate --no-deps llm >/dev/null 2>&1

say "=== BẢNG SO SÁNH CUỐI (trace mới, khoá nối khớp) ==="
$PY scripts/compare_llm_models.py --report
say "=== CHUỖI A HOÀN TẤT ==="
