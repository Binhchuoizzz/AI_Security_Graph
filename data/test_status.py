import sys
sys.path.append("/app")
from src.tier1_filter.feedback_listener import FeedbackListener

feedback_mgr = FeedbackListener()
ip = "192.168.1.100"

print("Initial:")
print(feedback_mgr.get_whitelisted_ips())
rules = feedback_mgr.get_all_dynamic_rules()
print([r for r in rules if r.get('pattern') == ip])

feedback_mgr.receive_new_rule("Source IP", ip)
feedback_mgr.approve_rule(ip, "Source IP")

print("\nAfter Block:")
print(feedback_mgr.get_whitelisted_ips())
rules = feedback_mgr.get_all_dynamic_rules()
print([r for r in rules if r.get('pattern') == ip])

feedback_mgr.add_to_whitelist(ip)

print("\nAfter Whitelist:")
print(feedback_mgr.get_whitelisted_ips())
rules = feedback_mgr.get_all_dynamic_rules()
print([r for r in rules if r.get('pattern') == ip])
