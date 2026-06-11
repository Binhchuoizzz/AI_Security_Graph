"""
Integration tests cho Unified Streaming Evaluation.

Kiểm chứng 2 thuộc tính cốt lõi của phương pháp luồng gộp (thay cho 3 luồng cũ):
  1. Luồng gộp dùng DATA THẬT và được TRỘN xen kẽ (không xếp khối theo nguồn).
  2. Phát hiện APT là EMERGENT — bản án chỉ bật sau khi tích lũy đủ sự kiện
     đa-ngày, KHÔNG phải nạp-sẵn đáp án (đã loại bỏ tính circular).

Các test này offline + sạch (dùng DB tạm, KHÔNG ghi đè file kết quả tracked).
"""

import os
import sqlite3
import tempfile

import pytest  # type: ignore

from experiments.evaluate_unified_stream import build_stream
from src.agent.threat_memory import ThreatMemoryStore


def test_stream_merges_real_sources_interleaved():
    """3 nguồn thật được gộp + trộn xen kẽ trong cùng một luồng."""
    warmup, main, apt_truth, n_chains = build_stream()

    sources = {ev["source"] for ev in main}
    assert {"cicids", "dapt", "zeroday"}.issubset(sources)

    # Warmup đủ cho Welford (warmup_count=100) + có IP APT đa-ngày thật
    assert len(warmup) >= 100
    assert len(apt_truth) >= 1
    assert n_chains >= 5

    # Trộn thật sự: nhiều lần đổi nguồn liên tiếp (xếp khối => gần như không đổi)
    switches = sum(
        1 for i in range(1, len(main)) if main[i]["source"] != main[i - 1]["source"]
    )
    assert switches >= 50, f"Luồng chưa trộn xen kẽ (chỉ {switches} lần đổi nguồn)"

    # DAPT giữ thứ tự đa-ngày: với mỗi IP, các 'day' xuất hiện không giảm
    # theo thứ tự luồng (điều kiện cần để phát hiện emergent đúng).
    seen_day = {}
    for ev in main:
        if ev["source"] != "dapt":
            continue
        ip, day = ev["ip"], ev["day"]
        assert day >= seen_day.get(ip, 0), f"DAPT {ip} bị đảo ngày: {day} < {seen_day[ip]}"
        seen_day[ip] = day


def test_apt_detection_is_emergent_not_preseeded():
    """Trên bộ nhớ SẠCH: 1 sự kiện ngày-1 CHƯA phải APT; chỉ khi có sự kiện
    ngày khác cho cùng IP thì check_apt_chain mới BẬT (nổi lên dần)."""
    db_path = os.path.join(tempfile.gettempdir(), "test_unified_emergent.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    store = ThreatMemoryStore(db_path=db_path)
    with sqlite3.connect(db_path) as c:
        c.execute("DELETE FROM threat_events")

    ip = "203.0.113.77"
    try:
        # Sau sự kiện NGÀY 1 đầu tiên: CHƯA đủ bằng chứng đa-ngày -> chưa APT
        store.record_apt_event(ip, apt_phase="Reconnaissance", apt_day=1)
        assert store.check_apt_chain(ip)["is_apt"] is False

        # Thêm sự kiện cùng ngày 1: vẫn 1 ngày -> vẫn CHƯA APT
        store.record_apt_event(ip, apt_phase="Reconnaissance", apt_day=1)
        assert store.check_apt_chain(ip)["is_apt"] is False

        # Sự kiện NGÀY 2 cho cùng IP -> đủ đa-ngày -> bản án BẬT (emergent)
        store.record_apt_event(ip, apt_phase="Lateral_Movement", apt_day=2)
        verdict = store.check_apt_chain(ip)
        assert verdict["is_apt"] is True
        assert verdict["chain_length"] >= 2
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
