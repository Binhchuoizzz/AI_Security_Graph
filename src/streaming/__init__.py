"""
Module Streaming: Redis-based Message Queue cho kien truc SIEM Multi-source.

Bao gom cac thanh phan:
- Publisher: doc CSV THO theo chunk va day vao MOT Redis Stream (queue_waf) —
  load test production-scale. (Multi-queue routing nam o scripts/simulate_traffic.py
  va experiments/stream_unified_online.py — publisher cua luong gop online.)
- Subscriber: lang nghe NHIEU Redis Stream qua consumer group, goi Tier-1 RuleEngine,
  ghi chuoi APT EMERGENT tu metadata DAPT (luong gop online) va gom batch ESCALATE
  chuyen len Tier-2 Agent.
"""
