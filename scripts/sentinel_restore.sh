#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT_DIR="$HOME/demo_snapshot_final"

if [ ! -d "$SNAPSHOT_DIR" ]; then
    echo "[ERROR] Không tìm thấy thư mục ảnh chụp: $SNAPSHOT_DIR"
    exit 1
fi

echo "--> [1/4] Dừng mọi tiến trình subscriber/producer nền để chống ghi đè bộ đếm..."
pkill -f "main.py --mode server" || true
pkill -f "scripts/demo.py" || true
sleep 1

echo "--> [2/4] Khôi phục 7 tệp trạng thái 500k log từ $SNAPSHOT_DIR..."
cp "$SNAPSHOT_DIR/audit_trail.db"       "$ROOT/config/"
cp "$SNAPSHOT_DIR/threat_memory.db"     "$ROOT/config/"
cp "$SNAPSHOT_DIR/system_settings.yaml" "$ROOT/config/"
cp "$SNAPSHOT_DIR/pipeline_stats.json"  "$ROOT/config/"
cp "$SNAPSHOT_DIR/tier1_blocks.json"    "$ROOT/config/"
cp "$SNAPSHOT_DIR/guardrails_audit.db"  "$ROOT/logs/"
cp "$SNAPSHOT_DIR/tier2_trace.jsonl"    "$ROOT/logs/"

echo "--> [3/4] Chuẩn hóa quyền đọc ghi (0666) cho Docker Streamlit..."
chmod 666 "$ROOT/config/pipeline_stats.json" \
          "$ROOT/config/tier1_blocks.json" \
          "$ROOT/config/audit_trail.db" \
          "$ROOT/config/threat_memory.db" \
          "$ROOT/config/system_settings.yaml" \
          "$ROOT/logs/guardrails_audit.db" \
          "$ROOT/logs/tier2_trace.jsonl" 2>/dev/null || true

echo "--> [4/4] Dọn dẹp hàng đợi Redis stream còn sót..."
.venv/bin/python -c "
import os, sys; sys.path.insert(0, '.')
from dotenv import load_dotenv; load_dotenv()
import redis
try:
    r = redis.Redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'), decode_responses=True)
    for q in ['queue_waf', 'queue_firewall', 'queue_sysmon', 'queue_decisions', 'queue_hitl']:
        r.delete(q)
    bl = r.keys('blacklist:*')
    if bl:
        r.delete(*bl)
    print('    -> Đã dọn sạch Redis queues.')
except Exception as e:
    print('    -> Redis bỏ qua:', e)
" || true

echo "============================================================"
echo "--> ĐÃ KHÔI PHỤC NGUYÊN TRẠNG 500K LOG BAN ĐẦU THÀNH CÔNG!"
echo "--> Hãy nhấn F5 (hoặc phím R) trên tab trình duyệt Streamlit!"
echo "============================================================"
