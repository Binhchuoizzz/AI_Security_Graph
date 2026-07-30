#!/usr/bin/env bash
# =============================================================================
# SENTINEL — FULL ABLATION + toàn bộ chỉ số đánh giá (kể cả LLM), chạy TUẦN TỰ.
# Chạy thâu đêm: log ra reports/full_ablation_<ts>.log, mỗi bước có mốc thời gian.
#
# Điều kiện: LLM server (llama.cpp OpenAI endpoint) PHẢI đang chạy tại LLM_API_BASE
# (mặc định http://127.0.0.1:5000/v1). Các bước OFFLINE vẫn chạy dù không có LLM.
#
# Dùng:  ./scripts/run_full_ablation.sh          # full (offline + LLM)
#        ./scripts/run_full_ablation.sh --offline-only
#        AF_LIMIT=200 BCDE_LIMIT=150 ./scripts/run_full_ablation.sh   # rút gọn để test nhanh
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
LLM_BASE="${LLM_API_BASE:-http://127.0.0.1:5000/v1}"
TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p reports
LOG="reports/full_ablation_${TS}.log"
OFFLINE_ONLY=0
[ "${1:-}" = "--offline-only" ] && OFFLINE_ONLY=1

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
run() {  # run "<label>" <cmd...>
  local label="$1"; shift
  log "▶ BẮT ĐẦU: $label"
  local t0=$SECONDS
  if "$@" >>"$LOG" 2>&1; then
    log "✔ XONG:   $label  (${SECONDS}s tính từ đầu, +$((SECONDS - t0))s)"
  else
    log "✘ LỖI:    $label — xem $LOG (tiếp tục bước sau)"
  fi
}

log "=== FULL ABLATION RUN $TS ===  log=$LOG"

# ── 0) Dựng benchmark 4-luồng mới nhất ──────────────────────────────────────
run "build_datatest (benchmark 4-luồng)" $PY scripts/build_datatest.py
# Baseline Welford PHẢI dựng lại sau khi dataset đổi: golden_baseline.json seed trạng thái
# (n, mean, M2) cho Tier-1; giữ baseline cũ trên dataset mới thì ngưỡng Z-score lệch pha với
# phân phối dữ liệu, và mọi số zero-day/threshold phía sau đều sai theo. Bước này TRƯỚC ĐÂY
# không có trong runner nên "chạy full" vẫn dùng baseline cũ.
run "build_golden_baseline (seed Welford)" $PY experiments/build_golden_baseline.py

# ── 1) OFFLINE (không cần LLM) ──────────────────────────────────────────────
run "evaluate_ml_gate (Cổng ML, datatest)"          $PY experiments/evaluate_ml_gate.py
run "run_ablation --mode mlgate (Config G offload)" $PY experiments/run_ablation.py --mode mlgate
run "evaluate_unified_stream (Tier-1 + APT + zero)" $PY experiments/evaluate_unified_stream.py
run "run_zeroday_graded (Welford sweep)"            $PY experiments/run_zeroday_graded.py
run "run_threshold_sensitivity (Welford τ)"         $PY experiments/run_threshold_sensitivity.py
# Bốn bài OFFLINE dưới đây có tệp kết quả trong experiments/results/ nhưng TRƯỚC ĐÂY không
# nằm trong runner -> mỗi lần "chạy full" chúng vẫn giữ số CŨ, lệch pha với phần còn lại.
run "run_apt_negative_control (đối chứng âm APT)"   $PY experiments/run_apt_negative_control.py
run "run_context_stress (quá tải ngữ cảnh)"         $PY experiments/run_context_stress.py
run "audit_tier_capability (năng lực 3 tầng)"       $PY experiments/audit_tier_capability.py --no-llm
# Bộ 69 web-attack TỰ SOẠN đã bị GỠ HẲN. Quy kết kỹ thuật nay đo trên phần CSIC 2010
# (request HTTP THẬT) nằm trong chính experiments/ground_truth.json, tách ra bằng cờ
# --evidence-layer payload. KHÔNG bỏ cờ đó: phần CICIDS của đề là NetFlow thuần, không có
# một ký tự payload, nên "kỹ thuật kỳ vọng" của nó không suy ra được từ đầu vào — trộn vào
# sẽ kéo tụt chỉ số vì lý do không liên quan tới năng lực hệ thống.
WEBATK=experiments/ground_truth.json
LAYER="--evidence-layer payload"
run "eval_attack_mapper --mode rrf (quy kết RRF)"   $PY scripts/eval_attack_mapper.py --mode rrf --ground-truth "$WEBATK" $LAYER --tag csic_payload_rrf

# ── 2) Preflight LLM ────────────────────────────────────────────────────────
if [ "$OFFLINE_ONLY" = "1" ]; then
  log "⏭  --offline-only: BỎ QUA các bước cần LLM."
  log "=== KẾT THÚC (offline) — log=$LOG ==="
  exit 0
fi
log "▶ Preflight LLM tại $LLM_BASE ..."
if ! curl -s -m 5 "$LLM_BASE/models" >/dev/null 2>&1; then
  log "✘ LLM server KHÔNG phản hồi tại $LLM_BASE — DỪNG phần LLM."
  log "   Bật server rồi chạy lại (chỉ phần LLM): ./scripts/run_full_ablation.sh"
  log "=== KẾT THÚC (chỉ offline; LLM bị bỏ do server down) — log=$LOG ==="
  exit 2
fi
log "✔ LLM server OK."

# ── 3) LLM-dependent (thâu đêm) — thứ tự ƯU TIÊN: quan trọng nhất chạy TRƯỚC ────
# (af headline + balanced 6-config + 3 eval-LLM trước; bcde ít quan trọng nhất -> cuối)
AF_LIMIT="${AF_LIMIT:-}"
BCDE_LIMIT="${BCDE_LIMIT:-300}"
AF_ARGS=(--mode af); [ -n "$AF_LIMIT" ] && AF_ARGS+=(--limit "$AF_LIMIT")
# CORE trước (af headline + 3 eval-LLM) -> xong sớm ~5h; balanced/bcde là BONUS chạy sau.
run "run_ablation --mode af (Config A + F, full pipeline)" $PY experiments/run_ablation.py "${AF_ARGS[@]}"
run "evaluate_reasoning (LLM-Judge Coherence/Accuracy)"    $PY experiments/evaluate_reasoning.py
run "evaluate_tier2_decision (agent trên ca escalate)"     $PY experiments/evaluate_tier2_decision.py
run "evaluate_adversarial (kháng guardrail Tier-2)"        $PY experiments/evaluate_adversarial.py
run "measure_latency_baseline (độ trễ đầu-cuối)"           $PY experiments/measure_latency_baseline.py
run "run_llm_robustness (kháng nhiễu prompt)"              $PY experiments/run_llm_robustness.py
run "audit_tier_capability (đủ 3 tầng, CÓ LLM)"            $PY experiments/audit_tier_capability.py
run "eval_attack_mapper --mode e2e (quy kết đầu-cuối)"     $PY scripts/eval_attack_mapper.py --mode e2e --ground-truth "$WEBATK" $LAYER --tag csic_payload_e2e
run "run_ablation --mode balanced (A–F, 150/150) [BONUS]"  $PY experiments/run_ablation.py --mode balanced
run "run_ablation --mode bcde (Config B–E) [BONUS]"        $PY experiments/run_ablation.py --mode bcde --limit "$BCDE_LIMIT"

# ── 4) Tóm tắt số liệu chính ────────────────────────────────────────────────
log "=== TÓM TẮT (đọc từ results/*.json) ==="
$PY - <<'PY' 2>>"$LOG" | tee -a "$LOG"
import json, os
R = "experiments/results"
def g(f):
    p = os.path.join(R, f)
    try:
        return json.load(open(p))
    except Exception:
        return {}
mg = g("ml_gate_results.json").get("classification", {})
mgate = g("ablation_mlgate_results.json")
print(f"  Cổng ML (datatest): F1={mg.get('f1')} P={mg.get('precision')} R={mg.get('recall')} bypass={mg.get('bypass_rate')}")
print(f"  Config G offload: {mgate.get('bypass_rate', mgate.get('savings',''))}  F1(bypass)={mgate.get('f1_bypass', mgate.get('f1',''))}")
af = g("ablation_results.json")
for c in ("Config_A","Config_F"):
    m = af.get(c, {}).get("metrics", af.get(c, {}))
    print(f"  {c}: F1={m.get('f1')} P={m.get('precision')} R={m.get('recall')}")
bcde = g("ablation_bcde_results.json")
for c in ("Config_B","Config_C","Config_D","Config_E"):
    m = bcde.get(c, {}).get("metrics", bcde.get(c, {}))
    if m: print(f"  {c}: F1={m.get('f1')}")
rea = g("reasoning_eval_results.json")
print(f"  LLM-Judge (reasoning): {rea.get('overall', rea.get('average_scores',''))}")
t2 = g("tier2_decision_results.json")
print(f"  Tier-2 decision: {t2.get('summary', {})}")
PY
log "=== KẾT THÚC FULL ABLATION — log=$LOG ==="
