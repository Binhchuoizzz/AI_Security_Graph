"""reset_all.py — Reset SẠCH hệ thống demo trong MỘT lệnh: DỪNG → XOÁ → BẬT LẠI.

Chống 2 lỗi hay gặp khi quản subscriber thủ công:
  1. Chạy >1 subscriber cùng consumer group -> log bị CHIA -> dashboard thiếu số
     (vd đẩy 120 chỉ thấy 63).
  2. Reset xong QUÊN bật lại subscriber -> log kẹt Redis -> dashboard = 0.

Việc thực hiện (đúng thứ tự an toàn):
  1. DỪNG mọi subscriber cũ (pkill 'main.py --mode server') + xác minh đã tắt.
  2. XOÁ: SQLite (audit_trail, threat_memory), pipeline_stats.json, tier1_blocks.json,
     luật động (system_settings.yaml), Redis stream + blacklist.
  3. BẬT LẠI ĐÚNG 1 subscriber (trừ khi --no-restart) + xác minh đúng 1 tiến trình.

Ưu điểm so với gõ tay: pkill chạy TRONG tiến trình Python (không dính lỗi exit-144
do SIGTERM lan sang shell), và luôn kiểm đếm lại số subscriber sau mỗi bước.

Chạy:
  .venv/bin/python scripts/reset_all.py              # reset + bật lại subscriber
  .venv/bin/python scripts/reset_all.py --no-restart # chỉ reset, không bật lại
  .venv/bin/python scripts/reset_all.py --dry-run    # chỉ in việc sẽ làm, KHÔNG đổi gì
"""

import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Secret chỉ sống trong .env — nạp trước khi đọc REDIS_URL (script chạy standalone).
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://localhost:5000/v1")
SUBSCRIBER_PATTERN = "main.py --mode server"
STREAMS = ["queue_waf", "queue_firewall", "queue_sysmon", "queue_decisions", "queue_hitl"]


def _count_subscribers() -> int:
    """Đếm tiến trình subscriber THẬT (python chạy main.py --mode server).

    Tránh false-positive kinh điển: shell wrapper / pgrep / grep có thể chứa CHUỖI
    'main.py --mode server' -> bị đếm nhầm. Ta xác thực /proc/<pid>/cmdline: argv[0]
    phải là python interpreter (loại zsh/bash/pgrep) và args phải có main.py --mode server.
    """
    out = subprocess.run(["pgrep", "-f", SUBSCRIBER_PATTERN], capture_output=True, text=True)
    count = 0
    for pid in out.stdout.split():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [p.decode(errors="replace") for p in f.read().split(b"\x00") if p]
        except OSError:
            continue  # tiến trình vừa thoát
        if not argv:
            continue
        exe = os.path.basename(argv[0]).lower()
        joined = " ".join(argv)
        if "python" in exe and "main.py" in joined and "--mode" in joined and "server" in joined:
            count += 1
    return count


def stop_subscribers(dry_run: bool = False) -> None:
    n = _count_subscribers()
    print(f"[1/3] DỪNG subscriber — đang chạy: {n}")
    if dry_run:
        print("      (dry-run: bỏ qua pkill)")
        return
    if n == 0:
        print("      (không có tiến trình nào để dừng)")
        return
    subprocess.run(["pkill", "-f", SUBSCRIBER_PATTERN], capture_output=True)
    for _ in range(12):  # chờ tối đa 6s cho SIGTERM
        time.sleep(0.5)
        if _count_subscribers() == 0:
            break
    if _count_subscribers():  # cứng đầu -> SIGKILL
        subprocess.run(["pkill", "-9", "-f", SUBSCRIBER_PATTERN], capture_output=True)
        time.sleep(1)
    print(f"      -> còn lại: {_count_subscribers()} (kỳ vọng 0)")


def clear_data(dry_run: bool = False) -> None:
    print("[2/3] XOÁ dữ liệu app + Redis stream")
    import sqlite3

    import redis  # type: ignore

    from src.agent.threat_memory import MEMORY_DB_PATH as THREAT
    from src.response.executor import DB_PATH as AUDIT

    db_tables = {
        THREAT: ["ip_reputation", "known_entities", "apt_indicators", "threat_events"],
        AUDIT: ["audit_trail", "login_attempts"],
    }

    if dry_run:
        for db, tbls in db_tables.items():
            if not os.path.exists(db):
                continue
            with sqlite3.connect(db) as c:
                for t in tbls:
                    try:
                        cnt = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608
                        print(f"      [dry] {os.path.basename(db)}::{t} = {cnt} dòng")
                    except sqlite3.OperationalError:
                        pass
        try:
            r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            for k in STREAMS:
                # queue_decisions/queue_hitl là LIST, queue_waf... là STREAM -> đọc đúng kiểu.
                ktype = r.type(k)
                size = r.xlen(k) if ktype == "stream" else r.llen(k) if ktype == "list" else 0
                print(f"      [dry] {k} ({ktype}) = {size}")
            bl_keys: list = r.keys("blacklist:*")  # type: ignore
            print(f"      [dry] blacklist:* = {len(bl_keys)} IP")
        except Exception as e:  # noqa: BLE001
            print(f"      [dry] Redis: {e}")
        return

    # --- SQLite ---
    for db, tbls in db_tables.items():
        try:
            with sqlite3.connect(db) as c:
                for t in tbls:
                    try:
                        c.execute(f"DELETE FROM {t}")  # noqa: S608
                    except sqlite3.OperationalError:
                        pass  # bảng chưa tồn tại (DB mới) -> bỏ qua
                c.commit()
            print(f"      -> xoá bảng trong {os.path.basename(db)}")
        except Exception as e:  # noqa: BLE001
            print(f"      [!] lỗi xoá {os.path.basename(db)}: {e}")

    # --- config JSON (counter + Tier-1 blocks) ---
    try:
        with open(os.path.join(ROOT, "config", "pipeline_stats.json"), "w") as f:
            json.dump({"raw_logs_total": 0, "tier1_dropped_total": 0}, f)
        with open(os.path.join(ROOT, "config", "tier1_blocks.json"), "w") as f:
            json.dump([], f)
        print("      -> reset pipeline_stats.json + tier1_blocks.json")
    except Exception as e:  # noqa: BLE001
        print(f"      [!] lỗi reset config JSON: {e}")

    # --- luật động + whitelist (qua API HỆ THỐNG, không tự ghi file) ---
    # FeedbackListener sở hữu logic rule/whitelist + đã bền với cross-UID Docker (0666 +
    # _ensure_lock_writable). reset_all chỉ GỌI API, không reimplement việc ghi YAML.
    from src.tier1_filter.feedback_listener import FeedbackListener

    fl = FeedbackListener()
    ok_rules = fl.clear_all_dynamic_rules()
    ok_wl = fl.reset_whitelist_to_defaults()
    if ok_rules and ok_wl:
        print("      -> xoá luật động + reset whitelist (qua FeedbackListener)")
    else:
        print(f"      [!] clear_rules={ok_rules} reset_whitelist={ok_wl} — kiểm quyền config/")

    # --- Redis stream + blacklist ---
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        for k in STREAMS:
            r.delete(k)
        bl: list = r.keys("blacklist:*")  # type: ignore
        if bl:
            r.delete(*bl)
        print(f"      -> xoá {len(STREAMS)} stream + {len(bl)} blacklist IP")
    except Exception as e:  # noqa: BLE001
        print(f"      [!] Redis không xoá được: {e}")


def start_subscriber(dry_run: bool = False) -> None:
    print("[3/3] BẬT LẠI subscriber (đúng 1)")
    if dry_run:
        print("      (dry-run: bỏ qua khởi động)")
        return
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    log = open(os.path.join(ROOT, "logs", "subscriber.log"), "w")  # noqa: SIM115
    env = {**os.environ, "REDIS_URL": REDIS_URL, "LLM_API_BASE": LLM_API_BASE}
    # start_new_session=True -> tiến trình con SỐNG TIẾP sau khi script này thoát (như nohup).
    subprocess.Popen(
        [sys.executable, "main.py", "--mode", "server", "--log-level", "INFO"],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )
    for _ in range(10):
        time.sleep(0.5)
        if _count_subscribers() >= 1:
            break
    n = _count_subscribers()
    print(f"      -> subscriber đang chạy: {n} (kỳ vọng 1)")
    if n != 1:
        print("      [!] CẢNH BÁO: số subscriber != 1 — kiểm tra logs/subscriber.log")
    else:
        print("      (đang nạp model ~25s; theo dõi: tail -f logs/subscriber.log)")


def main():
    ap = argparse.ArgumentParser(
        description="Reset SẠCH hệ thống demo (DỪNG → XOÁ → BẬT LẠI) trong 1 lệnh."
    )
    ap.add_argument(
        "--no-restart", action="store_true", help="Chỉ reset, KHÔNG bật lại subscriber."
    )
    ap.add_argument("--dry-run", action="store_true", help="Chỉ in việc sẽ làm, KHÔNG thay đổi gì.")
    args = ap.parse_args()

    print("=== SENTINEL reset_all ===" + (" [DRY-RUN]" if args.dry_run else ""))
    stop_subscribers(args.dry_run)
    clear_data(args.dry_run)
    if args.no_restart:
        print("[3/3] --no-restart: BỎ QUA bật lại subscriber.")
    else:
        start_subscriber(args.dry_run)
    print("=== hoàn tất ===")


if __name__ == "__main__":
    main()
