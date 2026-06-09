"""
Seed dữ liệu demo thực tế cho HITL Dashboard (chống panel rỗng khi trình diễn trước Hội đồng).

Nạp qua ĐÚNG các hàm thật để bảo toàn:
  - HMAC log-chaining của audit_trail (config/audit_trail.db)
  - Schema threat_memory (IP reputation, known entities, APT events/indicators)
  - Quy trình PENDING_APPROVAL -> ACTIVE của dynamic rules (HITL approval)

Idempotent ở mức hợp lý (entities/rules check trùng; incidents là append-by-design).
Chạy:  .venv/bin/python scripts/seed_demo_data.py
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.response.executor import _log_to_db
from src.agent.threat_memory import ThreatMemoryStore
from src.tier1_filter.feedback_listener import FeedbackListener


# =========================================================================
# 1) AUDIT TRAIL — cảnh báo/quyết định thực tế (Tab 1: Alerts)
#    (action, target, reason) — reason theo format [MITRE] [confidence] <Tiếng Việt>
# =========================================================================
AUDIT_EVENTS = [
    ("BLOCK_IP", "45.155.205.233",
     "[MITRE: T1190 - Exploit Public-Facing Application] [Độ tin cậy: 0.96] Phát hiện chuỗi tấn công SQL Injection vào tham số id của /admin.php nhằm trích xuất bảng users. Chặn IP để bảo vệ cơ sở dữ liệu."),
    ("BLOCK_IP", "185.220.101.47",
     "[MITRE: T1110.004 - Credential Stuffing] [Độ tin cậy: 0.94] IP thực hiện hơn 500 lượt đăng nhập tự động vào /login với cặp credential rò rỉ. Hành vi credential stuffing rõ ràng, tiến hành chặn."),
    ("BLOCK_IP", "103.97.176.12",
     "[MITRE: T1505.003 - Web Shell] [Độ tin cậy: 0.92] Truy cập /shell.jsp?cmd=whoami cho thấy web shell đã được cài. Chặn nguồn và cách ly file."),
    ("ALERT", "10.1.1.45",
     "[MITRE: T1498.001 - Direct Network Flood] [Độ tin cậy: 0.78] Lưu lượng tăng đột biến (5000+ gói/luồng) tới cổng 80 — dấu hiệu SYN/UDP flood. Cảnh báo, không chặn vì có thể bị giả mạo nguồn (spoofed)."),
    ("ALERT", "172.16.0.88",
     "[MITRE: T1046 - Network Service Discovery] [Độ tin cậy: 0.71] IP nội bộ quét 18 cổng non-HTTP khác nhau trong thời gian ngắn — hành vi trinh sát quét cổng. Cảnh báo để điều tra nguồn nội bộ."),
    ("AWAIT_HITL", "192.168.1.77",
     "[MITRE: T1078 - Valid Accounts] [Độ tin cậy: 0.55] Đăng nhập thành công sau nhiều lần thất bại từ một IP nội bộ ngoài giờ. Mơ hồ giữa quản trị hợp lệ và lạm dụng tài khoản — chuyển con người kiểm duyệt."),
    ("AWAIT_HITL", "10.0.0.142",
     "[MITRE: T1041 - Exfiltration Over C2 Channel] [Độ tin cậy: 0.62] Luồng dữ liệu ra ngoài lớn bất thường tới endpoint từng bị gắn cờ C2. Cần con người xác nhận trước khi cô lập host giá trị cao."),
    ("BLOCK_IP", "91.219.236.166",
     "[MITRE: T1486 - Data Encrypted for Impact] [Độ tin cậy: 0.97] Host beacon tới hạ tầng ransomware đã biết, kèm xóa shadow copy. Chặn C2 và cách ly khẩn cấp."),
    ("ALERT", "45.83.64.1",
     "[MITRE: T1568 - Dynamic Resolution] [Độ tin cậy: 0.74] Hàng loạt truy vấn DNS tới các domain sinh bởi thuật toán (DGA), tỉ lệ NXDOMAIN cao — nghi C2 fast-flux. Cảnh báo và theo dõi."),
    ("QUARANTINE", "10.0.0.55",
     "[MITRE: T1021 - Remote Services] [Độ tin cậy: 0.88] Host nội bộ thực hiện di chuyển ngang qua SMB/RDP tới nhiều máy. Cách ly host để chặn lan rộng."),
    ("ALERT", "203.0.113.91",
     "[MITRE: T1595.002 - Vulnerability Scanning] [Độ tin cậy: 0.69] Quét lỗ hổng tự động (nuclei/nikto) dò các đường dẫn nhạy cảm. Cảnh báo và chặn ở edge."),
    ("BLOCK_IP", "198.51.100.23",
     "[MITRE: T1110.003 - Password Spraying] [Độ tin cậy: 0.90] Một mật khẩu phổ biến thử trên hàng chục tài khoản (dưới ngưỡng khóa từng account). Phát hiện password spraying, tiến hành chặn."),
    ("LOG", "10.10.10.5",
     "[MITRE: N/A] [Độ tin cậy: 0.20] Lưu lượng từ máy quét Nessus nội bộ đã biết (scheduled scan). Ghi log, không hành động — false positive hợp lệ."),
    ("AWAIT_HITL", "172.16.5.200",
     "[MITRE: T1210 - Exploitation of Remote Services] [Độ tin cậy: 0.58] Dấu hiệu khai thác dịch vụ từ xa (SMB) giữa các host nội bộ. Mơ hồ — chuyển HITL để phân tích sâu."),
    ("ALERT", "62.210.105.116",
     "[MITRE: T1071 - Application Layer Protocol] [Độ tin cậy: 0.75] Beacon HTTPS định kỳ tới endpoint đáng ngờ (JA3 bất thường). Nghi C2 mã hóa kênh, cảnh báo điều tra."),
]


# =========================================================================
# 2) THREAT MEMORY — IP reputation, known entities, APT chains
# =========================================================================
INCIDENTS = [
    # (ip, action, mitre) — lặp lại để đẩy reputation lên cao (high-risk)
    ("45.155.205.233", "BLOCK_IP", "T1190 - Exploit Public-Facing Application"),
    ("45.155.205.233", "BLOCK_IP", "T1190 - SQL Injection"),
    ("45.155.205.233", "ALERT", "T1595.002 - Vulnerability Scanning"),
    ("185.220.101.47", "BLOCK_IP", "T1110.004 - Credential Stuffing"),
    ("185.220.101.47", "BLOCK_IP", "T1110.003 - Password Spraying"),
    ("91.219.236.166", "BLOCK_IP", "T1486 - Data Encrypted for Impact"),
    ("91.219.236.166", "BLOCK_IP", "T1071 - C2 beacon"),
    ("103.97.176.12", "BLOCK_IP", "T1505.003 - Web Shell"),
    ("198.51.100.23", "BLOCK_IP", "T1110.003 - Password Spraying"),
    ("10.1.1.45", "ALERT", "T1498.001 - Direct Network Flood"),
    ("172.16.0.88", "ALERT", "T1046 - Network Service Discovery"),
    ("62.210.105.116", "ALERT", "T1071 - Application Layer Protocol"),
]

KNOWN_ENTITIES = [
    ("scanner", "10.10.10.5", "Nessus Vulnerability Scanner (scheduled weekly scan)", "admin"),
    ("pentest_ip", "192.168.50.10", "Red Team pentest VM - authorized engagement Q2/2026", "manager"),
    ("admin_tool", "192.168.1.20", "Ansible automation controller", "admin"),
    ("scanner", "10.10.10.6", "Qualys Cloud Agent scanner", "admin"),
    ("backup_server", "192.168.1.30", "Veeam backup server (large outbound is normal)", "admin"),
]

# Chuỗi APT nhiều ngày cho 1 attacker IP (Tab 3: APT chain detection)
APT_IP = "45.83.64.1"
APT_EVENTS = [
    # (apt_phase, apt_day)
    ("Reconnaissance", 1),
    ("Initial_Compromise", 2),
    ("Establish_Foothold", 2),
    ("Lateral_Movement", 3),
    ("Privilege_Escalation", 4),
    ("Data_Exfiltration", 5),
]


def seed_audit():
    for action, target, reason in AUDIT_EVENTS:
        _log_to_db(action, target, reason)
    print(f"[AUDIT] seeded {len(AUDIT_EVENTS)} alerts/decisions (HMAC-chained)")


def seed_threat_memory():
    s = ThreatMemoryStore()
    for ip, action, mitre in INCIDENTS:
        s.record_incident(ip, action, mitre)
    print(f"[THREAT] seeded {len(INCIDENTS)} incidents")

    added_e = 0
    for etype, val, desc, by in KNOWN_ENTITIES:
        if not s.is_known_entity(val):
            s.add_known_entity(etype, val, desc, by)
            added_e += 1
    print(f"[THREAT] +{added_e} known entities")

    # APT multi-day chain
    for phase, day in APT_EVENTS:
        s.record_apt_event(APT_IP, dst_ip="192.168.1.10", apt_phase=phase, apt_day=day)
    s.record_apt_indicator(
        "persistent_ip", APT_IP, 0.93,
        related_ips=APT_IP,
        mitre_chain="T1595→T1190→T1078→T1021→T1068→T1041",
    )
    chain = s.check_apt_chain(APT_IP)
    print(f"[THREAT] APT chain for {APT_IP}: is_apt={chain['is_apt']} chain_length={chain['chain_length']} severity={chain.get('severity_escalation')}")

    # vài APT event lẻ cho IP khác để Tab threat events phong phú
    s.record_apt_event("185.220.101.47", apt_phase="Credential_Access", apt_day=1)
    s.record_apt_event("91.219.236.166", apt_phase="Impact_Ransomware", apt_day=1)
    print(f"[THREAT] stats: {s.get_stats()} | threat_events={len(s.get_all_threat_events())}")


def seed_rules():
    fl = FeedbackListener()
    # Pending rules — chờ L3 Manager phê duyệt (HITL approval workflow, Tab 2)
    pending = [
        ("Source IP", "45.155.205.233", 100, "SQLi attacker — đề xuất chặn vĩnh viễn"),
        ("Source IP", "185.220.101.47", 100, "Credential stuffing botnet IP"),
        ("URI", "/shell.jsp", 90, "Web shell access path — chặn pattern"),
        ("User-Agent", "(?i)(nikto|nuclei|sqlmap)", 80, "Công cụ quét tấn công đã biết"),
    ]
    added_p = 0
    for field, pat, score, reason in pending:
        res = fl.receive_new_rule(field, pat, score=score, source="langgraph_agent", reason=reason)
        if res.get("status") in ("APPLIED", "SKIPPED"):
            added_p += 1
    print(f"[RULES] {added_p}/{len(pending)} pending rules submitted (status PENDING_APPROVAL)")

    # Approve 2 cái -> ACTIVE (để Tab 'Active Rules' có data)
    fl.approve_rule(pattern="45.155.205.233", field="Source IP")
    fl.approve_rule(pattern="/shell.jsp", field="URI")
    print("[RULES] approved 2 rules -> ACTIVE")

    # Whitelist pentest/internal IPs
    for ip in ["192.168.50.10", "10.10.10.6"]:
        fl.add_to_whitelist(ip)
    print(f"[RULES] whitelisted: {fl.get_whitelisted_ips()}")


if __name__ == "__main__":
    print("=== Seeding SENTINEL Dashboard demo data ===")
    seed_audit()
    seed_threat_memory()
    seed_rules()
    print("\n✅ Done. Mở http://localhost:8501 — các tab Alerts / HITL Rules / APT & Reputation / Blocklist đã có dữ liệu.")
