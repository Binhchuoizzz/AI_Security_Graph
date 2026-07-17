"""
Kho lưu trữ bộ nhớ tình báo mối đe dọa dài hạn (Long-Term Threat Intelligence Memory Store)

MỤC ĐÍCH:
  SENTINEL hiện tại chỉ có Session Memory (trong RAM, mất khi restart).
  Module này bổ sung PERSISTENT MEMORY (SQLite) cho 3 chức năng:

  1. THEO DÕI DANH TIẾNG IP (IP REPUTATION TRACKING):
     Ghi nhận lịch sử hành vi IP qua nhiều ngày/tuần.
     → Phát hiện APT low-and-slow (tấn công chậm, ít lưu lượng mỗi ngày).

  2. BỐI CẢNH TỔ CHỨC (ORGANIZATIONAL CONTEXT):
     Lưu danh sách tools/services hợp pháp nội bộ (Nessus scanner, pentest IPs).
     → Agent tự động nhận ra traffic từ internal security tools, tránh false positive.

  3. TƯƠNG QUAN APT (APT CORRELATION):
     Tự động flag IP bị escalate > N lần trong M ngày.
     → Tương quan sự kiện dài hạn mà Session Memory không làm được.

  THIẾT KẾ:
  - Persistent Store: SQLite (nhẹ, không cần server, tích hợp Python stdlib)
  - Tables: ip_reputation, known_entities, apt_indicators
  - Cơ chế suy hao (Decay Mechanism): Điểm reputation score giảm dần theo thời gian nếu IP im lặng
  - Tích hợp: Inject vào LLM prompt qua node_llm_triage
"""

import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from src.guardrails.output_sanitizer import output_sanitizer

logger = logging.getLogger(__name__)

MEMORY_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "threat_memory.db")

# Khóa GHI cấp MODULE (dùng chung cho MỌI ThreatMemoryStore vì cùng ghi 1 file DB): serialize
# các thao tác read-modify-write (reputation) + INSERT (APT event) khi nhiều worker Tier-2 chạy
# song song. Đơn luồng (production/test) không tranh chấp = chi phí ~0, hành vi Y HỆT như trước.
_write_lock = threading.Lock()


class ThreatMemoryStore:
    """
    Bộ nhớ dài hạn bền vững (Persistent Long-Term Memory) cho SENTINEL Agent.
    Lưu trữ danh tiếng IP (IP reputation), bối cảnh tổ chức (organizational context), và các dấu hiệu APT.
    """

    def __init__(self, db_path: str = MEMORY_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _ensure_db_writable(self):
        """Đảm bảo file DB có thể ghi được bởi cả host (uid 1000) và container (uid 999)."""
        try:
            if os.path.exists(self.db_path) and not os.access(self.db_path, os.W_OK):
                os.remove(self.db_path)
        except OSError:
            pass
        try:
            if os.path.exists(self.db_path):
                os.chmod(self.db_path, 0o666)  # noqa: S103
        except OSError:
            pass

    def _init_db(self):
        """Khởi tạo cấu trúc bảng (schema) nếu chưa tồn tại."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._ensure_db_writable()
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # Bảng 1: IP Reputation — theo dõi hành vi IP dài hạn
            c.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    total_incidents INTEGER DEFAULT 0,
                    total_blocks INTEGER DEFAULT 0,
                    total_alerts INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    reputation_score REAL DEFAULT 0.0,
                    tags TEXT DEFAULT '',
                    last_mitre_technique TEXT DEFAULT '',
                    notes TEXT DEFAULT ''
                )
            """)

            # Bảng 2: Known Entities — tools/services hợp pháp nội bộ
            c.execute("""
                CREATE TABLE IF NOT EXISTS known_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    added_by TEXT DEFAULT 'system',
                    added_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Bảng 3: APT Indicators — correlation dài hạn
            c.execute("""
                CREATE TABLE IF NOT EXISTS apt_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    first_detected TEXT,
                    last_detected TEXT,
                    occurrence_count INTEGER DEFAULT 1,
                    related_ips TEXT DEFAULT '',
                    mitre_chain TEXT DEFAULT '',
                    status TEXT DEFAULT 'MONITORING'
                )
            """)

            # Bảng 4: Threat Events — APT chain tracking from DAPT2020
            c.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT DEFAULT '',
                    apt_phase TEXT,
                    apt_day INTEGER,
                    label TEXT DEFAULT '',
                    timestamp TEXT DEFAULT '',
                    recorded_at TEXT DEFAULT ''
                )
            """)

            # Nạp các thực thể đã biết mặc định nếu bảng trống
            c.execute("SELECT COUNT(*) FROM known_entities")
            if c.fetchone()[0] == 0:
                now_str = datetime.now().isoformat()
                c.execute(
                    """
                    INSERT INTO known_entities (entity_type, entity_value, description, added_by, added_at, is_active)
                    VALUES
                    ('Jump_Host', '192.168.1.254', 'Máy chủ nhảy quản trị nội bộ', 'system', ?, 1),
                    ('Security_Scanner', '10.0.0.99', 'Máy quét bảo mật Nessus định kỳ', 'system', ?, 1),
                    ('Active_Directory', '192.168.1.10', 'Máy chủ AD Domain Controller', 'system', ?, 1)
                """,
                    (now_str, now_str, now_str),
                )

            conn.commit()
        logger.info(f"[THREAT MEMORY] Initialized at {self.db_path}")

    # =========================================================================
    # DANH TIẾNG IP
    # =========================================================================

    def record_incident(self, ip: str, action: str, mitre_technique: str = ""):
        """
        Ghi nhận một sự cố liên quan đến IP.
        Tự động tăng reputation score dựa trên mức độ nghiêm trọng (severity).
        """
        ip = output_sanitizer.sanitize(ip)
        action = output_sanitizer.sanitize(action)
        mitre_technique = output_sanitizer.sanitize(mitre_technique)
        now = datetime.now(timezone.utc).isoformat()
        score_delta = {
            "BLOCK_IP": 30.0,
            "QUARANTINE": 25.0,
            "ALERT": 50.0,
            "AWAIT_HITL": 5.0,
            "LOG": 1.0,
        }.get(action, 0.0)

        with _write_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()

            # Thêm mới hoặc cập nhật danh tiếng IP (Upsert)
            c.execute(
                "SELECT ip, total_incidents, reputation_score FROM ip_reputation WHERE ip = ?",
                (ip,),
            )
            row = c.fetchone()

            if row:
                new_incidents = row[1] + 1
                new_score = min(row[2] + score_delta, 100.0)  # Giới hạn tối đa là 100
                block_delta = 1 if action == "BLOCK_IP" else 0
                alert_delta = 1 if action == "ALERT" else 0
                c.execute(
                    """
                    UPDATE ip_reputation
                    SET total_incidents = ?, reputation_score = ?, last_seen = ?,
                        total_blocks = total_blocks + ?, total_alerts = total_alerts + ?,
                        last_mitre_technique = ?
                    WHERE ip = ?
                """,
                    (new_incidents, new_score, now, block_delta, alert_delta, mitre_technique, ip),
                )
            else:
                c.execute(
                    """
                    INSERT INTO ip_reputation
                    (ip, total_incidents, total_blocks, total_alerts, first_seen, last_seen,
                     reputation_score, last_mitre_technique)
                    VALUES (?, 1, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        ip,
                        1 if action == "BLOCK_IP" else 0,
                        1 if action == "ALERT" else 0,
                        now,
                        now,
                        score_delta,
                        mitre_technique,
                    ),
                )

            conn.commit()

    def get_ip_reputation(self, ip: str) -> dict | None:
        """Lấy thông tin reputation của IP."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
            row = c.fetchone()
            if row:
                return dict(row)
        return None

    def get_high_risk_ips(self, min_score: float = 50.0, limit: int = 20) -> list[dict]:
        """Lấy danh sách IPs có reputation score cao (nguy hiểm)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    """
                    SELECT * FROM ip_reputation
                    WHERE reputation_score >= ?
                    ORDER BY reputation_score DESC
                    LIMIT ?
                """,
                    (min_score, limit),
                )
                return [dict(row) for row in c.fetchall()]
        except sqlite3.OperationalError:
            self._init_db()  # DB chưa khởi tạo (vd đang reset) -> tạo bảng, trả rỗng an toàn
            return []

    def decay_reputation(self, decay_rate: float = 0.95, inactive_days: int = 7):
        """
        Giảm điểm danh tiếng cho các IP không hoạt động (inactive) quá N ngày.
        Chạy định kỳ (ví dụ: mỗi ngày) để tránh dữ liệu cũ (stale data).
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=inactive_days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute(
                """
                UPDATE ip_reputation
                SET reputation_score = reputation_score * ?
                WHERE last_seen < ? AND reputation_score > 1.0
            """,
                (decay_rate, cutoff),
            )
            affected = c.rowcount
            conn.commit()
        if affected > 0:
            logger.info(f"[THREAT MEMORY] Decayed reputation for {affected} inactive IPs")

    def reset_ip_reputation(self, ip: str) -> None:
        """Reset reputation score của IP về 0 (ví dụ khi admin gỡ chặn / whitelist)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("UPDATE ip_reputation SET reputation_score = 0.0 WHERE ip = ?", (ip,))
                conn.commit()
                logger.info(f"[THREAT MEMORY] Reset reputation score for IP {ip}")
        except Exception as e:
            logger.error(f"[THREAT MEMORY] Failed to reset reputation for {ip}: {e}")

    # =========================================================================
    # ORGANIZATIONAL CONTEXT (Known Entities)
    # =========================================================================

    def add_known_entity(
        self, entity_type: str, entity_value: str, description: str = "", added_by: str = "system"
    ):
        """
        Thêm thực thể hợp pháp (internal tool, pentest IP, scanner).

        entity_type: 'scanner', 'pentest_ip', 'admin_tool', 'scheduled_scan'
        entity_value: IP, tên máy chủ (hostname), hoặc tên công cụ (tool name)
        """
        entity_type = output_sanitizer.sanitize(entity_type)
        entity_value = output_sanitizer.sanitize(entity_value)
        description = output_sanitizer.sanitize(description)
        added_by = output_sanitizer.sanitize(added_by)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute(
                    """
                    INSERT OR REPLACE INTO known_entities
                    (entity_type, entity_value, description, added_by, added_at, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                """,
                    (entity_type, entity_value, description, added_by, now),
                )
                conn.commit()
            logger.info(f"[THREAT MEMORY] Added known entity: {entity_type}={entity_value}")
        except Exception as e:
            logger.error(f"[THREAT MEMORY] Failed to add entity: {e}")

    def remove_known_entity(self, entity_value: str):
        """Vô hiệu hóa entity (soft delete)."""
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE known_entities SET is_active = 0 WHERE entity_value = ?", (entity_value,)
            )
            conn.commit()

    def is_known_entity(self, value: str) -> dict | None:
        """
        Kiểm tra xem IP/tool có phải entity hợp pháp nội bộ không.
        Trả về dict nếu match, None nếu không.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                """
                SELECT * FROM known_entities
                WHERE entity_value = ? AND is_active = 1
            """,
                (value,),
            )
            row = c.fetchone()
            if row:
                return dict(row)
        return None

    def get_all_known_entities(self) -> list[dict]:
        """Lấy toàn bộ known entities đang active."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT * FROM known_entities WHERE is_active = 1 ORDER BY added_at DESC")
                return [dict(row) for row in c.fetchall()]
        except sqlite3.OperationalError:
            self._init_db()
            return []

    # =========================================================================
    # THEO DÕI CHUỖI APT (Tích hợp DAPT2020)
    # =========================================================================

    def record_apt_event(
        self,
        src_ip: str,
        dst_ip: str = "",
        apt_phase: str | None = None,
        apt_day: int | None = None,
        label: str = "",
        timestamp: str = "",
    ):
        """Ghi nhận một sự kiện đe dọa đơn lẻ để theo dõi chuỗi APT."""
        src_ip = output_sanitizer.sanitize(src_ip)
        dst_ip = output_sanitizer.sanitize(dst_ip)
        if apt_phase:
            apt_phase = output_sanitizer.sanitize(apt_phase)
        label = output_sanitizer.sanitize(label)
        timestamp = output_sanitizer.sanitize(timestamp)
        now = datetime.now(timezone.utc).isoformat()
        with _write_lock, sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO threat_events
                (src_ip, dst_ip, apt_phase, apt_day, label, timestamp, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (src_ip, dst_ip, apt_phase, apt_day, label, timestamp, now),
            )
            conn.commit()

    def check_apt_chain(self, src_ip: str) -> dict:
        """
        Kiểm tra xem IP này có thuộc một chuỗi APT đã biết hay không.
        Trả về thông tin leo thang nếu phát hiện tấn công nhiều giai đoạn (multi-stage).

        Một IP được đánh dấu là APT nếu xuất hiện trong các sự kiện thuộc ít nhất 2 ngày khác nhau.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """SELECT COUNT(DISTINCT apt_day), MAX(apt_day), GROUP_CONCAT(DISTINCT apt_phase)
                   FROM threat_events
                   WHERE src_ip = ? AND apt_phase IS NOT NULL""",
                (src_ip,),
            )
            row = cursor.fetchone()

        day_count, max_day, phases = row

        if day_count and day_count >= 2:
            return {
                "is_apt": True,
                "chain_length": day_count,
                "max_day_seen": max_day,
                "phases_seen": phases,
                "severity_escalation": "CRITICAL" if day_count >= 3 else "HIGH",
            }
        return {"is_apt": False, "chain_length": day_count or 0}

    def ingest_dapt_chains(self, chains_path: str = "data/processed/dapt2020_chains.jsonl"):
        """
        Nạp các chuỗi APT DAPT2020 từ JSONL vào bảng threat_events.
        Mỗi chuỗi chứa các sự kiện từ cùng một IP tấn công qua nhiều ngày.
        """
        import json

        if not os.path.exists(chains_path):
            logger.warning(f"DAPT2020 chains not found: {chains_path}")
            return 0

        count = 0
        with open(chains_path, encoding="utf-8") as f:
            for line in f:
                chain = json.loads(line)
                for event in chain.get("events", []):
                    self.record_apt_event(
                        src_ip=event.get("src_ip", chain["attacker_ip"]),
                        dst_ip=event.get("dst_ip", ""),
                        apt_phase=event.get("phase"),
                        apt_day=event.get("day"),
                        label=event.get("label", ""),
                        timestamp=event.get("timestamp", ""),
                    )
                    count += 1

        logger.info(f"[THREAT MEMORY] Ingested {count} DAPT2020 events")
        return count

    # =========================================================================
    # APT CORRELATION
    # =========================================================================

    def check_apt_pattern(
        self, ip: str, threshold_incidents: int = 5, threshold_days: int = 7
    ) -> dict | None:
        """
        Kiểm tra xem IP có pattern APT không.
        APT = IP bị escalate >= threshold_incidents lần trong threshold_days ngày.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=threshold_days)).isoformat()
        reputation = self.get_ip_reputation(ip)

        if not reputation:
            return None

        if (
            reputation["total_incidents"] >= threshold_incidents
            and reputation["first_seen"] <= cutoff
        ):
            return {
                "ip": ip,
                "is_apt_candidate": True,
                "total_incidents": reputation["total_incidents"],
                "days_active": (
                    datetime.now(timezone.utc) - datetime.fromisoformat(reputation["first_seen"])
                ).days,
                "reputation_score": reputation["reputation_score"],
                "last_mitre": reputation.get("last_mitre_technique", ""),
            }
        return None

    def record_apt_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        confidence: float,
        related_ips: str = "",
        mitre_chain: str = "",
    ):
        """Ghi nhận APT indicator cho correlation dài hạn."""
        indicator_type = output_sanitizer.sanitize(indicator_type)
        indicator_value = output_sanitizer.sanitize(indicator_value)
        related_ips = output_sanitizer.sanitize(related_ips)
        mitre_chain = output_sanitizer.sanitize(mitre_chain)
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            c = conn.cursor()
            # Kiểm tra xem đã tồn tại chưa
            c.execute(
                """
                SELECT id, occurrence_count FROM apt_indicators
                WHERE indicator_type = ? AND indicator_value = ?
            """,
                (indicator_type, indicator_value),
            )
            row = c.fetchone()

            if row:
                c.execute(
                    """
                    UPDATE apt_indicators
                    SET occurrence_count = ?, last_detected = ?, confidence = ?,
                        related_ips = ?, mitre_chain = ?
                    WHERE id = ?
                """,
                    (row[1] + 1, now, confidence, related_ips, mitre_chain, row[0]),
                )
            else:
                c.execute(
                    """
                    INSERT INTO apt_indicators
                    (indicator_type, indicator_value, confidence, first_detected,
                     last_detected, related_ips, mitre_chain)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        indicator_type,
                        indicator_value,
                        confidence,
                        now,
                        now,
                        related_ips,
                        mitre_chain,
                    ),
                )
            conn.commit()

    # =========================================================================
    # PROMPT CONTEXT GENERATION
    # =========================================================================

    def get_context_for_prompt(self, source_ip: str, max_tokens: int = 300) -> str:
        """
        Sinh ngữ cảnh từ Bộ nhớ dài hạn để đưa vào LLM prompt.
        Giúp Agent nắm bắt lịch sử hoạt động của IP trước khi phân tích batch mới.
        """
        parts = []

        # 1. Danh tiếng IP (IP Reputation)
        rep = self.get_ip_reputation(source_ip)
        if rep and rep["total_incidents"] > 0:
            parts.append(
                f"=== LONG-TERM MEMORY: IP {source_ip} ===\n"
                f"  History: {rep['total_incidents']} incidents, "
                f"{rep['total_blocks']} blocks, {rep['total_alerts']} alerts\n"
                f"  Reputation Score: {rep['reputation_score']:.1f}/100 "
                f"({'HIGH RISK' if rep['reputation_score'] >= 50 else 'MODERATE' if rep['reputation_score'] >= 20 else 'LOW'})\n"
                f"  First Seen: {rep['first_seen']}\n"
                f"  Last MITRE: {rep.get('last_mitre_technique', 'N/A')}"
            )

        # 2. Kiểm tra thực thể nội bộ đã biết (Known Entity check)
        entity = self.is_known_entity(source_ip)
        if entity:
            parts.append(
                f"  ⚠️ KNOWN INTERNAL ENTITY: {entity['entity_type']} — "
                f"{entity['description']}. Consider FALSE POSITIVE."
            )

        # 3. Kiểm tra mẫu APT (APT check — dựa trên lịch sử incidents)
        apt = self.check_apt_pattern(source_ip)
        if apt and apt["is_apt_candidate"]:
            parts.append(
                f"  🔴 APT CANDIDATE: Active for {apt['days_active']} days, "
                f"{apt['total_incidents']} incidents. ESCALATE SEVERITY."
            )

        # 3b. Chuỗi APT đa-ngày từ threat_events (cơ chế EMERGENT của luồng gộp —
        # record_apt_event tích lũy dần; bản án bật khi đủ >=2 ngày tấn công).
        chain = self.check_apt_chain(source_ip)
        if chain.get("is_apt"):
            parts.append(
                f"  🔴 APT CHAIN (multi-day): {chain['chain_length']} distinct days, "
                f"phases: {chain.get('phases_seen', 'N/A')} — severity "
                f"{chain.get('severity_escalation', 'HIGH')}. "
                f"Treat as an ONGOING APT campaign, not an isolated event."
            )

        if not parts:
            return ""

        context = "\n".join(parts)
        # Tỉ lệ ký tự/token ước lượng
        if len(context) > max_tokens * 4:  # rough char-to-token ratio
            context = context[: max_tokens * 4] + "\n  ... [TRUNCATED]"
        return context

    def get_stats(self) -> dict:
        """Lấy thống kê tổng quan cho Dashboard."""
        empty = {
            "total_tracked_ips": 0,
            "high_risk_ips": 0,
            "known_entities": 0,
            "apt_indicators": 0,
        }
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM ip_reputation")
                total_ips = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM ip_reputation WHERE reputation_score >= 50")
                high_risk = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM known_entities WHERE is_active = 1")
                known = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM apt_indicators WHERE status = 'MONITORING'")
                apt = c.fetchone()[0]
            return {
                "total_tracked_ips": total_ips,
                "high_risk_ips": high_risk,
                "known_entities": known,
                "apt_indicators": apt,
            }
        except sqlite3.OperationalError:
            self._init_db()
            return empty

    def get_all_threat_events(self, limit: int = 50) -> list[dict]:
        """Lấy toàn bộ threat events cho UI."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT id, src_ip, dst_ip, apt_phase, apt_day, label, timestamp FROM threat_events ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                return [dict(row) for row in c.fetchall()]
        except sqlite3.OperationalError:
            self._init_db()
            return []

    def get_threat_events_for_ip(self, ip: str, limit: int = 50) -> list[dict]:
        """Lấy threat events liên quan đến IP cụ thể (IP nguồn hoặc IP đích)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                "SELECT id, src_ip, dst_ip, apt_phase, apt_day, label, timestamp FROM threat_events WHERE src_ip = ? OR dst_ip = ? ORDER BY id DESC LIMIT ?",
                (ip, ip, limit),
            )
            return [dict(row) for row in c.fetchall()]


# Thực thể duy nhất (Singleton)
threat_memory = ThreatMemoryStore()
