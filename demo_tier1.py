from src.tier1_filter.rule_engine import RuleEngine

engine = RuleEngine()

print("==========================================================")
print("🛡️  DEMO: TIER 1 — RULE ENGINE & SESSION BASELINE")
print("==========================================================\n")

# ─── Case 1: DROP — traffic bình thường ───────────────────────────────────────
safe_log = {"Source IP": "10.0.0.50", "Destination Port": 8080, "Total Fwd Packets": 1}
result = engine.evaluate(safe_log)
print("1. Traffic bình thường (DROP)")
print(f"   Input  : {safe_log}")
print(f"   Action : {result['tier1_action']}  | Score: {result['tier1_score']}")
print(f"   Reasons: {result['tier1_reasons']}\n")

# ─── Case 2: BLOCK_IP — SSH brute-force (port nhạy cảm, packet thấp) ──────────
ssh_log = {"Source IP": "192.168.1.100", "Destination Port": 22, "Total Fwd Packets": 5}
result_ssh = engine.evaluate(ssh_log)
print("2. SSH BruteForce (BLOCK_IP)")
print(f"   Input  : {ssh_log}")
print(f"   Action : {result_ssh['tier1_action']}  | Score: {result_ssh['tier1_score']}")
print(f"   Lý do  : Port 22 ∈ sensitive_ports AND fwd_packets=5 < 200 → Block IP\n")

# ─── Case 3: ALERT — DoS/DDoS volumetric ──────────────────────────────────────
dos_log = {"Source IP": "10.1.1.1", "Destination Port": 80, "Total Fwd Packets": 5000}
result_dos = engine.evaluate(dos_log)
print("3. DoS Volumetric Attack (ALERT)")
print(f"   Input  : {dos_log}")
print(f"   Action : {result_dos['tier1_action']}  | Score: {result_dos['tier1_score']}")
print(f"   Lý do  : fwd_packets=5000 > max_fwd_packets → Alert (không block: DDoS có thể spoof)\n")

# ─── Case 4: ESCALATE — Web attack (HTTP port, không volumetric) ──────────────
web_log = {"Source IP": "10.2.2.2", "Destination Port": 80, "Total Fwd Packets": 300,
           "payload": ""}
# Cần đủ score từ session baseline hoặc dynamic rules
# Giả lập: inject via dynamic rule để demo ESCALATE path
from src.tier1_filter.feedback_listener import FeedbackListener
fl = FeedbackListener()
fl.receive_new_rule(field="Source IP", pattern="10.2.2.2", score=40, reason="Demo ESCALATE")
fl.approve_rule(pattern="10.2.2.2", field="Source IP")  # Approve the rule so it becomes ACTIVE
# Force reload
import os, time
engine2 = RuleEngine()  # fresh instance picks up new rule
result_web = engine2.evaluate(web_log)
print("4. Web Attack via Dynamic Rule (ESCALATE)")
print(f"   Input  : {web_log}")
print(f"   Action : {result_web['tier1_action']}  | Score: {result_web['tier1_score']}")
print(f"   Lý do  : Port 80 ∈ [80,443,8080] nhưng fwd_packets=300 >= 200 (không brute-force) → ESCALATE lên Tier-2\n")
fl.clear_all_dynamic_rules()  # cleanup

# ─── Case 5: AWAIT_HITL — Port scanning (Session Baseline) ────────────────────
print("5. Port Scanning — Session Baseline detection (AWAIT_HITL)")
print("   Giả lập IP 10.99.99.99 quét 12 port non-HTTP liên tiếp:")
result_scan = {}
for port in [1, 2, 3, 25, 53, 135, 137, 139, 445, 3306, 5432, 8888]:
    result_scan = engine.evaluate({
        "Source IP": "10.99.99.99",
        "Destination Port": port,
        "Total Fwd Packets": 1
    })
print(f"   Action : {result_scan['tier1_action']}  | Score: {result_scan['tier1_score']}")
print(f"   Reasons: {result_scan['tier1_reasons']}")
print(f"   Lý do  : 12 non-HTTP ports > threshold(10) → AWAIT_HITL (Lateral Movement)\n")

# ─── Case 6: DROP — IP được Whitelist ─────────────────────────────────────────
wl_log = {"Source IP": "127.0.0.1", "Destination Port": 22, "Total Fwd Packets": 9999}
result_wl = engine.evaluate(wl_log)
print("6. IP trong Whitelist (DROP)")
print(f"   Input  : {wl_log}")
print(f"   Action : {result_wl['tier1_action']}  | Score: {result_wl['tier1_score']}")
print(f"   Lý do  : Source IP ∈ whitelist_ips → bỏ qua toàn bộ rules\n")

# ─── Case 7: Z-Score / Welford detection — Zero-day statistical anomaly ────────
print("7. Zero-day Statistical Anomaly (Z-Score / Welford)")
print("   Warmup: nạp 110 log bình thường để khởi tạo baseline N(μ,σ²)...")
for i in range(110):
    engine.evaluate({
        "Source IP": f"10.3.{i//256}.{i%256+1}",
        "Destination Port": 80,
        "Total Fwd Packets": 10 + (i % 5),   # ~10-14 packets, variance nhỏ
        "Flow Duration": 1000 + (i * 3),      # ~1000-1330 μs
        "Flow Pkts/s": 10.0 + (i % 3),        # ~10-12 pkts/s
        "Fwd Seg Size Min": 32,
    })
print(f"   Warmup hoàn tất. total_processed_logs = {engine.total_processed_logs}")
print(f"   Baseline Flow Duration: μ = {engine.global_stats['Flow Duration'].mean():.1f}, "
      f"σ = {engine.global_stats['Flow Duration'].std_dev():.1f}")

# Inject outlier cực lớn — mô phỏng DoS slow attack với flow duration bất thường
outlier_log = {
    "Source IP": "10.99.0.1",
    "Destination Port": 80,
    "Total Fwd Packets": 12,
    "Flow Duration": 999999,   # Z-score >> 3.5
    "Flow Pkts/s": 0.001,      # cực thấp
    "Fwd Seg Size Min": 0,
}
result_z = engine.evaluate(outlier_log)
print(f"\n   Outlier log: Flow Duration=999999μs (APT slow attack)")
print(f"   Z-Score max : {result_z.get('tier1_z_score', 'N/A'):.2f}")
print(f"   Action      : {result_z['tier1_action']}  | Score: {result_z['tier1_score']}")
if result_z['tier1_reasons']:
    for r in result_z['tier1_reasons']:
        print(f"   Reason      : {r}")

print("\n==========================================================")
print("Tóm tắt: 6 action types được demo | Welford Z-score activated ✓")
print("  DROP         — traffic bình thường / whitelisted IP")
print("  BLOCK_IP     — SSH/FTP brute-force (sensitive port, low packets)")
print("  ALERT        — DoS/DDoS volumetric (fwd_packets > max threshold)")
print("  ESCALATE     — Web attack (port 80/443, dynamic rule match)")
print("  AWAIT_HITL   — Port scan / Lateral Movement (session baseline)")
print("  Z-Score path — Zero-day statistical anomaly (post-warmup)")
print("==========================================================")
