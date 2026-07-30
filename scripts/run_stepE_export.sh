#!/usr/bin/env bash
# CHUỖI E — chờ Chuỗi D xong rồi XUẤT BÁO CÁO. Không sửa gì, chỉ đọc và trình bày.
set -uo pipefail
cd /home/binhchuoiz/Projects/Thesis/AI_Security_Graph
log() { echo "[$(date +%H:%M:%S)] $*"; }
log "chờ Chuỗi D…"
while pgrep -f run_stepD_chain.sh >/dev/null; do sleep 60; done
log "✔ Chuỗi D xong — xuất báo cáo"
.venv/bin/python scripts/export_final_report.py
log "=== XONG TẤT CẢ ==="
