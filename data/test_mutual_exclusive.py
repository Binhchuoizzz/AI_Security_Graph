import sys

sys.path.append("/app")
from src.tier1_filter.feedback_listener import FeedbackListener

feedback_mgr = FeedbackListener()
# 1. Block an IP
ip = "192.168.1.100"
feedback_mgr.receive_new_rule("Source IP", ip)
feedback_mgr.approve_rule(ip, "Source IP")

# Check if it's active
rules = feedback_mgr.get_active_dynamic_rules()
print("After Block:")
print("Active rules:", [r for r in rules if r.get("pattern") == ip])
print("Whitelist:", ip in feedback_mgr.get_whitelisted_ips())

# 2. Add to Whitelist
feedback_mgr.add_to_whitelist(ip)

print("After Whitelist:")
rules = feedback_mgr.get_active_dynamic_rules()
print("Active rules:", [r for r in rules if r.get("pattern") == ip])
print("Whitelist:", ip in feedback_mgr.get_whitelisted_ips())

# 3. Block again
feedback_mgr.receive_new_rule("Source IP", ip)
feedback_mgr.approve_rule(ip, "Source IP")

print("After Re-Block:")
rules = feedback_mgr.get_active_dynamic_rules()
print("Active rules:", [r for r in rules if r.get("pattern") == ip])
print("Whitelist:", ip in feedback_mgr.get_whitelisted_ips())
