#!/usr/bin/env bash
# SENTINEL — Ba lần đẩy NỐI TIẾP để đo cơ chế GIẢM TẢI ("nhớ mặt").
#
# VÌ SAO CÓ FILE NÀY: chiến dịch trước chạy 3 lượt nhưng lượt nào cũng gọi reset_all, mà
# reset_all xoá sạch blacklist + luật động + ip_reputation. Mỗi lượt do đó khởi động từ trí
# nhớ RỖNG, nên "đẩy lần 2 có nhẹ hơn lần 1 không" chưa từng được trả lời. Ở đây chỉ lượt
# ĐẦU được reset; hai lượt sau chạy đè lên nguyên trạng — đúng kịch bản cần đo.
#
# Chuỗi chạy hàng giờ, nên gộp vào MỘT tiến trình nền: mất kết nối giữa chừng cũng không gãy.
#
# Dùng:  nohup bash scripts/run_consecutive_pushes.sh > logs/consecutive.log 2>&1 &
#        SKIP_P1=1 bash scripts/run_consecutive_pushes.sh   # #1 đang chạy sẵn -> chỉ chờ rồi làm tiếp
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SKIP_P1=${SKIP_P1:-0}
say() { echo "[$(date +%H:%M:%S)] $*"; }

wait_for() {  # wait_for <thư mục lượt>  — chờ audit.json xuất hiện VÀ tracer đứng yên
  local out="$1" prev=-1 stable=0 now
  while [ ! -f "$out/audit.json" ]; do
    now=$(wc -l < logs/tier2_trace.jsonl 2>/dev/null || echo 0)
    [ "$now" = "$prev" ] && stable=$((stable + 1)) || stable=0
    prev=$now
    # 40 lần x 30s = 20 phút đứng yên mà vẫn chưa có audit.json -> coi như hỏng, thoát.
    [ "$stable" -ge 40 ] && { say "✘ $out treo (tracer đứng yên 20 phút) — DỪNG"; return 1; }
    sleep 30
  done
  return 0
}

if [ "$SKIP_P1" = "0" ]; then
  say "▶ ĐẨY #1 (nguội — reset + restart subscriber)"
  bash scripts/run_audit_cycle.sh cold p1_cold
else
  say "▶ ĐẨY #1 đang chạy sẵn — chờ nó xong"
  wait_for reports/runs/p1_cold || exit 1
fi
say "✔ đẩy #1 xong: $(wc -l < reports/runs/p1_cold/tier2_trace.jsonl 2>/dev/null || echo '?') lô"

# GIỮA HAI LƯỢT: KHÔNG reset, KHÔNG restart. Cả blacklist Redis (TTL 1h), ip_reputation
# (SQLite, vĩnh viễn), luật động lẫn cache phán quyết trong RAM đều phải còn nguyên —
# đó chính là thứ đang được đo.
say "▶ ĐẨY #2 (warm — giữ nguyên trí nhớ)"
bash scripts/run_audit_cycle.sh warm p2_warm
say "✔ đẩy #2 xong: $(wc -l < reports/runs/p2_warm/tier2_trace.jsonl 2>/dev/null || echo '?') lô"

say "▶ ĐẨY #3 (warm — lần thứ ba liên tiếp)"
bash scripts/run_audit_cycle.sh warm p3_warm
say "✔ đẩy #3 xong: $(wc -l < reports/runs/p3_warm/tier2_trace.jsonl 2>/dev/null || echo '?') lô"

say "=== SO SÁNH BA LƯỢT ==="
.venv/bin/python scripts/compare_pushes.py p1_cold p2_warm p3_warm
say "=== HOÀN TẤT ==="
