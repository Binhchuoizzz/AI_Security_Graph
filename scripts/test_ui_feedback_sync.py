import os
import sys
import time

# Đảm bảo đường dẫn import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.response.executor import unblock_ip
from src.tier1_filter.feedback_listener import FeedbackListener
from src.tier1_filter.rule_engine import RuleEngine


def simulate_log(ip: str):
    # Trả về 1 log đơn giản
    return {
        "Source IP": ip,
        "Destination IP": "10.0.0.1",
        "Source Port": 12345,
        "Destination Port": 80,
        "Protocol": 6,
        "Total Length of Fwd Packets": 100,
        "Total Fwd Packets": 1,
        "URI": "/test",
    }


def print_result(step: str, ip: str, action: str, reasons: list):
    print(f"[{step}] IP: {ip} -> Action: {action} | Reasons: {reasons}")


def main():
    print("=== BẮT ĐẦU TEST E2E FEEDBACK LOOP & TIER-1 SYNC ===")

    # Khởi tạo các thành phần
    engine = RuleEngine()
    listener = FeedbackListener()

    # Fake IPs for testing
    IP_A = "99.99.99.1"  # Block -> test -> block tier 1
    IP_B = "99.99.99.2"  # Whitelist -> test -> whitelist_drop
    IP_C = "99.99.99.3"  # Block -> unblock -> test -> không bị block

    print("\n--- 1. TEST BLOCK IP A ---")
    log_a1 = simulate_log(IP_A)
    res_a1 = engine.evaluate(log_a1)
    print_result("Lần 1 (Chưa Block)", IP_A, res_a1["tier1_action"], res_a1["tier1_reasons"])

    print(">>> (UI) Analyst Bấm Block IP A...")
    listener.receive_new_rule(
        "Source IP", IP_A, score=100, source="manual_ui", reason="Block từ UI"
    )

    # Approve rule IP A
    listener.approve_rule(IP_A, "Source IP")

    # Ép RuleEngine load lại config ngay lập tức (giả lập mtime thay đổi)
    time.sleep(0.1)
    engine.last_config_check_time = 0

    log_a2 = simulate_log(IP_A)
    res_a2 = engine.evaluate(log_a2)
    print_result("Lần 2 (Đã Block)", IP_A, res_a2["tier1_action"], res_a2["tier1_reasons"])
    assert res_a2["tier1_action"] == "BLOCK_IP", (
        f"Lỗi: IP A không bị chặn ở Tier-1. Hành động: {res_a2['tier1_action']}"
    )

    print("\n--- 2. TEST WHITELIST IP B ---")
    log_b1 = simulate_log(IP_B)
    res_b1 = engine.evaluate(log_b1)
    print_result("Lần 1 (Chưa Whitelist)", IP_B, res_b1["tier1_action"], res_b1["tier1_reasons"])

    print(">>> (UI) Analyst Bấm Whitelist IP B...")
    listener.add_to_whitelist(IP_B)

    engine.last_config_check_time = 0

    log_b2 = simulate_log(IP_B)
    log_b2["payload"] = "SELECT * FROM users"  # Payload bẩn
    res_b2 = engine.evaluate(log_b2)
    print_result(
        "Lần 2 (Đã Whitelist có payload SQLi)",
        IP_B,
        res_b2["tier1_action"],
        res_b2["tier1_reasons"],
    )
    assert res_b2["tier1_action"] == "WHITELIST_DROP", (
        f"Lỗi: IP B không được Whitelist_drop. Hành động: {res_b2['tier1_action']}"
    )
    assert any("SQLi" in str(r) for r in res_b2["tier1_reasons"]) or any(
        "WAF" in str(r) for r in res_b2["tier1_reasons"]
    ), "Lỗi: Whitelist không phân tích tiếp log (không thấy SQLi reason)."

    print("\n--- 3. TEST UNBLOCK IP C ---")
    print(">>> (UI) Analyst Block IP C...")
    listener.receive_new_rule("Source IP", IP_C, score=100, source="manual_ui", reason="Block C")
    listener.approve_rule(IP_C, "Source IP")

    engine.last_config_check_time = 0
    log_c1 = simulate_log(IP_C)
    res_c1 = engine.evaluate(log_c1)
    print_result("Lần 1 (Đã Block C)", IP_C, res_c1["tier1_action"], res_c1["tier1_reasons"])
    assert res_c1["tier1_action"] == "BLOCK_IP"

    print(">>> (UI) Analyst UNBLOCK IP C...")
    listener.reject_rule(IP_C, "Source IP")
    unblock_ip(IP_C)  # Gỡ khỏi Redis/Threat memory nếu có

    engine.last_config_check_time = 0
    log_c2 = simulate_log(IP_C)
    res_c2 = engine.evaluate(log_c2)
    print_result("Lần 2 (Đã Unblock C)", IP_C, res_c2["tier1_action"], res_c2["tier1_reasons"])
    assert res_c2["tier1_action"] != "BLOCK_IP", (
        f"Lỗi: IP C vẫn bị block. Hành động: {res_c2['tier1_action']}"
    )

    print("\n--- 4. TEST UNWHITELIST IP B ---")
    print(">>> (UI) Analyst Bỏ Whitelist IP B...")
    listener.remove_from_whitelist(IP_B)
    engine.last_config_check_time = 0

    log_b3 = simulate_log(IP_B)
    log_b3["payload"] = "SELECT * FROM users"  # Payload bẩn
    res_b3 = engine.evaluate(log_b3)
    print_result(
        "Lần 3 (Đã Bỏ Whitelist, có payload bẩn)",
        IP_B,
        res_b3["tier1_action"],
        res_b3["tier1_reasons"],
    )
    assert res_b3["tier1_action"] != "WHITELIST_DROP", (
        f"Lỗi: IP B vẫn pass whitelist. Hành động: {res_b3['tier1_action']}"
    )

    # Dọn dẹp test
    print("\n--- Dọn dẹp dữ liệu test ---")
    listener.reject_rule(IP_A, "Source IP")
    listener.reject_rule(IP_B, "Source IP")
    listener.reject_rule(IP_C, "Source IP")
    listener.remove_from_whitelist(IP_A)
    listener.remove_from_whitelist(IP_B)
    listener.remove_from_whitelist(IP_C)

    print("\n=== TẤT CẢ TEST ĐỀU PASSED, LOGIC TIER-1 VÀ UI ĐÃ ĐỒNG BỘ HOÀN HẢO ===")


if __name__ == "__main__":
    main()
