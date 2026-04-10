"""
Guardrails: State Monitor

Giám sát trạng thái LangGraph State để đảm bảo:
  1. Context Window không bị tràn (Overflow Protection).
  2. Đồ thị không rơi vào vòng lặp vô hạn (Infinite Loop Detection).
  3. Ghi log kiểm toán (Audit Trail) mọi quyết định của Agent.
"""
import time
import yaml
import os
import sqlite3
import json
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'system_settings.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)


class ContextOverflowGuard:
    """
    Kiểm soát kích thước Context Window.
    Nếu prompt + log data vượt quá ngân sách token tối đa -> cắt bớt.
    """
    def __init__(self):
        config = load_config()
        self.max_tokens = config['llm']['max_context_tokens']
        self.log_budget = config['guardrails']['token_budget']

    def check(self, prompt_tokens: int, log_tokens: int) -> dict:
        total = prompt_tokens + log_tokens
        is_overflow = total > self.max_tokens
        return {
            "total_tokens": total,
            "max_allowed": self.max_tokens,
            "is_overflow": is_overflow,
            "action": "TRUNCATE_LOGS" if is_overflow else "PASS"
        }


class LoopDetector:
    """
    Phát hiện LangGraph bị mắc kẹt trong vòng lặp vô hạn.
    Nếu cùng một Node được gọi > max_iterations lần -> Force Stop.
    """
    def __init__(self, max_iterations: int = 10):
        self.max_iterations = max_iterations
        self.node_counter = {}

    def record_visit(self, node_name: str) -> dict:
        self.node_counter[node_name] = self.node_counter.get(node_name, 0) + 1
        count = self.node_counter[node_name]

        if count > self.max_iterations:
            return {
                "node": node_name,
                "visits": count,
                "action": "FORCE_STOP",
                "reason": f"Infinite loop detected: Node '{node_name}' visited {count} times"
            }
        return {
            "node": node_name,
            "visits": count,
            "action": "CONTINUE"
        }

    def reset(self):
        self.node_counter = {}


class AuditLogger:
    """
    Ghi lại toàn bộ quyết định của Agent vào SQLite DB (audit_trail.db).
    Phục vụ cho việc truy vết (Forensics) và báo cáo Ablation Study.
    """
    def __init__(self):
        config = load_config()
        self.db_path = config['logging']['audit_db_path']
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                tier1_score INTEGER,
                tier1_action TEXT,
                guardrail_injected BOOLEAN,
                agent_decision TEXT,
                agent_reasoning TEXT,
                mitre_technique TEXT,
                iso_control TEXT,
                hitl_approved BOOLEAN,
                latency_ms REAL,
                metadata TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log_event(self, event: dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (
                timestamp, event_type, source_ip, tier1_score, tier1_action,
                guardrail_injected, agent_decision, agent_reasoning,
                mitre_technique, iso_control, hitl_approved, latency_ms, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            event.get('event_type', 'UNKNOWN'),
            event.get('source_ip'),
            event.get('tier1_score'),
            event.get('tier1_action'),
            event.get('guardrail_injected', False),
            event.get('agent_decision'),
            event.get('agent_reasoning'),
            event.get('mitre_technique'),
            event.get('iso_control'),
            event.get('hitl_approved'),
            event.get('latency_ms'),
            json.dumps(event.get('metadata', {}))
        ))
        conn.commit()
        conn.close()
