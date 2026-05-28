from src.tier1_filter.rule_engine import RuleEngine

# Khởi tạo bộ lọc Tier 1
engine = RuleEngine()

print("==========================================================")
print("🛡️ DEMO 3: TIER 1 — RULE ENGINE & SESSION BASELINE")
print("==========================================================\n")

# 1. Log an toàn (DROP) -> Loại bỏ ngay lập tức ở Tier 1, không làm phiền LLM
safe_log = {"Source IP": "10.0.0.50", "Destination Port": 8080, "Total Fwd Packets": 1}
result = engine.evaluate(safe_log)
print(f"1. Log an toàn (DROP):")
print(f"   - Input log: {safe_log}")
print(f"   - Action: {result['tier1_action']} (Reasons: {result.get('tier1_reasons')})\n")

# 2. Log truy cập SSH port 22 nguy hiểm (ESCALATE) -> Chuyển tiếp lên Tier 2
ssh_log = {"Source IP": "192.168.1.100", "Destination Port": 22, "Total Fwd Packets": 5}
result_ssh = engine.evaluate(ssh_log)
print(f"2. Log truy cập SSH (ESCALATE):")
print(f"   - Input log: {ssh_log}")
print(f"   - Action: {result_ssh['tier1_action']} (Score: {result_ssh['tier1_score']})\n")

# 3. Phát hiện Port Scanning qua trượt cửa sổ thời gian (Stateful Session tracking)
print(f"3. Giả lập IP 10.99.99.99 quét liên tiếp 15 cổng khác nhau:")
result_scan = {}
for port in range(1, 16):
    result_scan = engine.evaluate({"Source IP": "10.99.99.99", "Destination Port": port, "Total Fwd Packets": 1})
print(f"   - Action sau 15 cổng: {result_scan['tier1_action']} (Reasons: {result_scan['tier1_reasons']})\n")

# 4. IP Whitelist (WHITELIST_DROP) -> Tự động bỏ qua nhanh
wl_log = {"Source IP": "127.0.0.1", "Destination Port": 22, "Total Fwd Packets": 9999}
result_wl = engine.evaluate(wl_log)
print(f"4. Log từ IP trong Whitelist (WHITELIST_DROP):")
print(f"   - Input log: {wl_log}")
print(f"   - Action: {result_wl['tier1_action']} (Reasons: {result_wl['tier1_reasons']})")
print("==========================================================")
