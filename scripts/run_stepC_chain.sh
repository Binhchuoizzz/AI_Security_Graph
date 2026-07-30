#!/usr/bin/env bash
# =============================================================================
# CHUỖI C — chạy lại TOÀN BỘ phần đo còn lại TRÊN MÃ ĐÃ VÁ.
#
# Vì sao phải cắt Chuỗi B giữa chừng thay vì đợi:
#   1. `evaluate_tier2_decision` gọi không kèm --limit nên nó nuốt CẢ 8.323 sự kiện escalate
#      của luồng (không phải 1.750 mẫu ground_truth). Sau 8h35 mới xong 3.675/8.323 — còn
#      ~11 tiếng nữa cho MỘT chỉ số. Script đã có sẵn lấy mẫu STRIDED đều trên toàn tập;
#      n=800 cho khoảng tin cậy đủ chặt mà tốn ~2h.
#   2. Quan trọng hơn: tiến trình đó nạp `attack_mapper` lúc 21h54, tức chạy trên mã CHƯA
#      có bản vá ưu tiên kỹ thuật con. Kết quả phải bỏ dù có đợi hết.
#
# Bốn bản vá áp lúc 05h40-05h45 (ưu tiên kỹ thuật con · đóng băng luật động · chốt chặn
# trọng tài trùng bị cáo · ngân sách context) nên MỌI bước dùng LLM/mapper đều phải chạy lại.
# Các bước 1-10 của Chuỗi B (Cổng ML, Welford, zero-day, ngưỡng, APT, context-stress) KHÔNG
# đụng tới bốn chỗ đó nên giữ nguyên kết quả.
#
# Thứ tự: số của RQ trước, BONUS sau cùng.
# =============================================================================
set -uo pipefail
cd /home/binhchuoiz/Projects/Thesis/AI_Security_Graph
PY=.venv/bin/python
AGENT_MODEL=Foundation-Sec-8B-Instruct-Q4_K_M.gguf
JUDGE_MODEL=Meta-Llama-3-8B-Instruct-Q5_K_M.gguf
GT=experiments/ground_truth.json
T2_LIMIT=800

log() { echo "[$(date +%H:%M:%S)] $*"; }
run() { log "▶ $1"; shift; "$@" && log "   ✔ xong" || log "   ✘ THẤT BẠI (mã $?)"; }

serve() {  # PHẢI xuất biến ra env chứ không chỉ ghi .env — docker-compose ưu tiên env
  sed -i "s/^LLM_MODEL_FILE=.*/LLM_MODEL_FILE=$1/" .env
  sed -i "s/^LLAMA_ARG_CTX_SIZE=.*/LLAMA_ARG_CTX_SIZE=$2/" .env
  LLM_MODEL_FILE="$1" LLAMA_ARG_CTX_SIZE="$2" \
    docker-compose up -d --force-recreate --no-deps llm >/dev/null 2>&1
  for _ in $(seq 1 60); do
    got=$(curl -s --max-time 3 http://127.0.0.1:5000/v1/models \
          | $PY -c 'import sys,json;print(json.load(sys.stdin)["data"][0]["id"])' 2>/dev/null)
    [ "$got" = "$1" ] && { log "   ✔ server phục vụ $1"; return 0; }
    sleep 10
  done
  log "   ✘ server KHÔNG phục vụ $1 sau 10 phút"; return 1
}

# ── 0) Phục hồi config: bỏ 753 luật động do CHÍNH lượt đo sinh ra ───────────
if [ -f config/system_settings.yaml.pre-ablation.bak ]; then
  cp config/system_settings.yaml.pre-ablation.bak config/system_settings.yaml
  sed -i 's/^  max_context_tokens: 8192$/  max_context_tokens: 16384/' config/system_settings.yaml
  log "✔ phục hồi config: $(grep -c 'pattern:' config/system_settings.yaml) luật, ctx=16384"
fi

serve "$AGENT_MODEL" 32768 || exit 1

# ── 1) Quy kết kỹ thuật — rẻ nhất, cho biết ngay bản vá ăn bao nhiêu ────────
run "eval_attack_mapper rrf (CÓ vá ưu tiên kỹ thuật con)" \
  $PY scripts/eval_attack_mapper.py --mode rrf --ground-truth "$GT" \
  --evidence-layer payload --tag csic_payload_rrf

# ── 2) af — baseline SẠCH (luật động đóng băng) ─────────────────────────────
run "run_ablation --mode af (baseline không còn bị nhiễm)" \
  $PY experiments/run_ablation.py --mode af

# ── 3) Các bước LLM còn lại của phần lõi ────────────────────────────────────
run "evaluate_tier2_decision (n=$T2_LIMIT strided / 8323)" \
  $PY experiments/evaluate_tier2_decision.py --limit "$T2_LIMIT"
run "evaluate_adversarial (kháng guardrail Tier-2)"  $PY experiments/evaluate_adversarial.py
run "measure_latency_baseline (độ trễ đầu-cuối)"     $PY experiments/measure_latency_baseline.py
run "run_llm_robustness (kháng nhiễu prompt)"        $PY experiments/run_llm_robustness.py
run "audit_tier_capability (đủ 3 tầng, CÓ LLM)"      $PY experiments/audit_tier_capability.py
run "eval_attack_mapper e2e (CÓ vá)" \
  $PY scripts/eval_attack_mapper.py --mode e2e --ground-truth "$GT" \
  --evidence-layer payload --tag csic_payload_e2e

# ── 4) LLM-Judge với TRỌNG TÀI KHÁC HỌ ──────────────────────────────────────
# Đọc `reasoning_outputs` đã lưu trong ablation_results.json nên PHẢI chạy sau af.
# `assert_cross_family` sẽ chặn cứng nếu server vẫn đang phục vụ model tác tử.
serve "$JUDGE_MODEL" 32768 || exit 1
log "▶ evaluate_reasoning (trọng tài $JUDGE_MODEL)"
SENTINEL_AGENT_MODEL="$AGENT_MODEL" $PY experiments/evaluate_reasoning.py \
  && log "   ✔ xong" || log "   ✘ THẤT BẠI"
serve "$AGENT_MODEL" 32768 || exit 1

# ── 5) BONUS sau cùng ───────────────────────────────────────────────────────
run "run_ablation --mode balanced (A–F 150/150) [BONUS]" $PY experiments/run_ablation.py --mode balanced
run "run_ablation --mode bcde (Config B–E) [BONUS]"      $PY experiments/run_ablation.py --mode bcde --limit 300

log "=== CHUỖI C XONG ==="
