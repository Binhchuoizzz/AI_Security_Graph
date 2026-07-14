"""Bằng chứng an toàn đa luồng cho đường Tier-2 song song (agent_workers>=2).

Khi nhiều worker Tier-2 chạy song song, 4 vùng trạng thái dùng chung phải an toàn:
  1. Chuỗi audit HMAC (executor._log_to_db) — read-modify-write prev_hash: KHÔNG được rẽ nhánh.
  2. loop_detector (state_monitor) — bộ đếm phải THREAD-LOCAL (mỗi invoke cô lập).
  3. SemanticCache (OrderedDict) — get/put đồng thời KHÔNG được vỡ.
  4. threat_memory.record_incident — reputation RMW không mất cập nhật (serialize).

Các test này chạy N luồng đồng thời; nếu thiếu khóa/thread-local, chúng sẽ FAIL.
"""

import sqlite3
import threading


def test_audit_hmac_chain_intact_under_concurrency(tmp_path, monkeypatch):
    """Hammer _log_to_db từ 4 luồng -> chuỗi HMAC vẫn liền mạch (verify PASS)."""
    from src.response import executor

    db = tmp_path / "audit_trail.db"
    monkeypatch.setattr(executor, "DB_PATH", str(db))
    with sqlite3.connect(str(db)) as c:
        c.execute(
            "CREATE TABLE audit_trail (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, "
            "action TEXT, target TEXT, reason TEXT, integrity_hash TEXT, raw_log TEXT)"
        )

    n_threads, per_thread = 4, 25

    def worker(w):
        for j in range(per_thread):
            executor._log_to_db("ALERT", f"10.0.0.{w}", f"reason {w}-{j}")

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with sqlite3.connect(str(db)) as c:
        count = c.execute("SELECT COUNT(*) FROM audit_trail").fetchone()[0]
    assert count == n_threads * per_thread, "mất dòng audit (database is locked?)"

    ok, msg = executor.verify_audit_trail_integrity()
    assert ok, f"Chuỗi HMAC BỊ GÃY khi ghi song song (rẽ nhánh prev_hash): {msg}"


def test_loop_detector_is_thread_local():
    """Mỗi luồng reset+đếm riêng: phải thấy đúng bộ đếm của MÌNH, không lẫn."""
    from src.guardrails.state_monitor import LoopDetector

    ld = LoopDetector(max_iterations=1000)
    results: dict[str, int] = {}
    barrier = threading.Barrier(4)

    def worker(name):
        ld.reset()
        barrier.wait()  # ép các luồng đan xen tối đa
        for _ in range(5):
            ld.record_visit("node_x")
        results[name] = ld.node_counter.get("node_x", -1)

    threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(v == 5 for v in results.values()), (
        f"loop_detector bị chia sẻ (không thread-local): {results}"
    )


def test_semantic_cache_concurrent_no_corruption():
    """get/put đồng thời trên OrderedDict không vỡ + LRU giữ đúng trần."""
    from src.rag.semantic_cache import SemanticCache

    cache = SemanticCache(max_size=50, ttl_seconds=1800)

    def worker(i):
        for j in range(200):
            cache.put(f"q{i % 8}-{j % 30}", {"r": j})
            cache.get(f"q{i % 8}-{j % 30}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(cache.cache) <= 50, "LRU vượt trần khi truy cập song song"


def test_threat_memory_reputation_no_lost_updates(tmp_path):
    """record_incident đồng thời cùng 1 IP: tổng số incident phải KHỚP (không mất cập nhật)."""
    from src.agent.threat_memory import ThreatMemoryStore

    store = ThreatMemoryStore(db_path=str(tmp_path / "tm.db"))
    n_threads, per_thread = 4, 25

    def worker():
        for _ in range(per_thread):
            store.record_incident("10.9.9.9", "ALERT")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rep = store.get_ip_reputation("10.9.9.9")
    assert rep is not None
    assert rep["total_incidents"] == n_threads * per_thread, (
        f"mất cập nhật reputation (RMW race): {rep['total_incidents']}"
    )
