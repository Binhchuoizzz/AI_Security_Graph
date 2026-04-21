"""
Module Streaming: Redis-based Message Queue cho kien truc SIEM Multi-source.

Bao gom cac thanh phan:
- Publisher: Doc CSV va day log vao Redis Queue (multi-queue routing).
- Subscriber: Lang nghe Redis Queue, gom batch va chuyen len Tier 1.
"""
