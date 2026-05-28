import json
from src.agent.threat_memory import ThreatMemoryStore

print("==========================================================")
print("🧠 DEMO 10: APT CHAIN DETECTION (THREAT MEMORY)")
print("==========================================================\n")

# Khởi tạo Threat Memory
store = ThreatMemoryStore()

target_ip = "10.0.0.99"
print(f"1. Ghi nhận chuỗi hành vi của IP {target_ip} diễn ra rải rác:")

# Ghi nhận 2 sự kiện APT cùng IP, khác ngày
store.record_apt_event(target_ip, apt_phase="Reconnaissance", apt_day=1)
print(f"   - Ngày 1: IP thực hiện thăm dò mạng (Reconnaissance) -> Đã ghi nhận.")

store.record_apt_event(target_ip, apt_phase="Initial_Compromise", apt_day=2)
print(f"   - Ngày 2: IP thực hiện xâm nhập ban đầu (Initial Compromise) -> Đã ghi nhận.\n")

# Kiểm tra chuỗi APT
result = store.check_apt_chain(target_ip)
print("2. Kết quả kiểm tra liên kết chuỗi APT:")
print(f"   - IP: {target_ip}")
print(f"   - Phát hiện chuỗi APT: {result['is_apt']}")
print(f"   - Số lượng sự kiện: {result['chain_length']}")
print(f"   - Các giai đoạn phát hiện: {result.get('phases_seen', '')}")
print(f"   - Ngày cuối hoạt động: Ngày {result.get('max_day_seen', 0)}")
print(f"   - Mức độ cảnh báo: {result.get('severity_escalation', 'NORMAL')}\n")

# Xem dataset DAPT2020 đã xử lý
chains = [json.loads(l) for l in open("data/processed/dapt2020_chains.jsonl")]
multi_day = [c for c in chains if len(c["days_spanned"]) >= 2]
print("3. Thống kê tập dữ liệu APT thực tế DAPT2020:")
print(f"   - Tổng số chuỗi tấn công: {len(chains)}")
print(f"   - Số chuỗi kéo dài qua nhiều ngày (Multi-day): {len(multi_day)}")
print("==========================================================")
