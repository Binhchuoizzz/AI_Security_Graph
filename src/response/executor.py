"""
Mock Executor Module cho Hệ thống Phản hồi tự động.
Mô phỏng các hành động khóa IP, cách ly Host và gửi Cảnh báo.
"""
import sqlite3
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'audit_trail.db')

def _init_db():
    """Khoi tao SQLite Database cho audit trail neu chua co."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                target TEXT,
                reason TEXT
            )
        ''')
        conn.commit()

_init_db()

def _log_to_db(action: str, target: str, reason: str):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO audit_trail (timestamp, action, target, reason) VALUES (?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), action, target, reason)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Loi ghi audit trail: {e}")

def block_ip(ip: str, reason: str):
    logger.warning(f" [FIREWALL MOCK] BLOCKING IP: {ip} | Lý do: {reason}")
    _log_to_db("BLOCK_IP", ip, reason)

def quarantine_host(host: str, reason: str):
    logger.warning(f" [EDR MOCK] QUARANTINE HOST: {host} | Lý do: {reason}")
    _log_to_db("QUARANTINE", host, reason)

def raise_alert(msg: str, reason: str):
    logger.info(f" [SIEM MOCK] ALERT: {msg} | Lý do: {reason}")
    _log_to_db("ALERT", msg, reason)

def get_audit_trail(limit=50):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT timestamp, action, target, reason FROM audit_trail ORDER BY id DESC LIMIT ?", (limit,))
            rows = c.fetchall()
        return [{"timestamp": r[0], "action": r[1], "target": r[2], "reason": r[3]} for r in rows]
    except Exception:
        return []
