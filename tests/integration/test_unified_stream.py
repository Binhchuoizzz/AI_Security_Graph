"""
Integration tests cho Unified Streaming Evaluation (offline) + ONLINE publisher.

Kiểm chứng 3 thuộc tính cốt lõi của phương pháp luồng gộp (thay cho 3 luồng cũ):
  1. Luồng gộp dùng DATA THẬT và được TRỘN xen kẽ (không xếp khối theo nguồn).
  2. Phát hiện APT là EMERGENT — bản án chỉ bật sau khi tích lũy đủ sự kiện
     đa-ngày, KHÔNG phải nạp-sẵn đáp án (đã loại bỏ tính circular).
  3. Publisher ONLINE phát CÙNG luồng gộp đó, enrich đủ metadata để subscriber
     ghi chuỗi APT + định tuyến đúng queue (đường demo realtime end-to-end).

Các test này offline + sạch (dùng DB tạm, KHÔNG ghi đè file kết quả tracked,
KHÔNG cần Redis).
"""

import json
import os
import sqlite3
import tempfile

import pytest  # type: ignore

from experiments.stream_unified_online import build_sequence, determine_queue, enrich
from experiments.unified_dataset import build_stream
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
    switches = sum(1 for i in range(1, len(main)) if main[i]["source"] != main[i - 1]["source"])
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


def test_online_publisher_enriches_and_routes():
    """Publisher ONLINE phát CÙNG luồng gộp, enrich đủ metadata theo nguồn và định
    tuyến mọi event vào queue hợp lệ — điều kiện để subscriber ghi APT + agent xử lý."""
    seq, warmup, main, apt_truth, n_chains = build_sequence()

    srcs, queues = set(), set()
    dapt_attack_meta = 0
    zd_total = zd_meta = 0
    for ev in seq:
        log = enrich(ev)
        srcs.add(ev["source"])
        queues.add(determine_queue(log))
        # dataset_source phải được gắn để Tier-1/Tier-2 phân biệt ngữ cảnh
        assert log.get("dataset_source") == "unified_stream"
        assert log.get("unified_source") == ev["source"]
        if ev["source"] == "dapt" and log.get("apt_is_attack"):
            if log.get("apt_phase") and log.get("apt_day") is not None:
                dapt_attack_meta += 1
        if ev["source"] == "zeroday":
            zd_total += 1
            if log.get("zd_id") and log.get("zd_mitre"):
                zd_meta += 1

    assert {"cicids", "dapt", "zeroday"}.issubset(srcs)
    # Định tuyến chỉ rơi vào các queue đã khai báo (không lạc queue)
    assert queues.issubset({"queue_waf", "queue_firewall"}), f"Queue lạ: {queues}"
    # DAPT attack PHẢI mang apt metadata, nếu không subscriber sẽ không ghi chuỗi APT
    assert dapt_attack_meta > 0
    # Mọi zero-day phải mang đủ marker
    assert zd_meta == zd_total and zd_total >= 1


def test_online_apt_recording_contract_matches_subscriber():
    """Mô phỏng đúng nhánh subscriber: ghi từng sự kiện DAPT-attack (mang metadata)
    của một IP vào bộ nhớ SẠCH theo thứ tự luồng -> bản án APT phải NỔI LÊN đúng
    thời điểm đủ đa-ngày (giống cơ chế offline, không nạp sẵn)."""
    seq, *_ = build_sequence()

    # Chọn IP DAPT có sự kiện tấn công ở >= 2 ngày trong luồng
    by_ip_days = {}
    for ev in seq:
        if ev.get("source") == "dapt" and ev.get("is_attack"):
            by_ip_days.setdefault(ev["ip"], set()).add(ev["day"])
    multi_day_ip = next((ip for ip, days in by_ip_days.items() if len(days) >= 2), None)
    assert multi_day_ip is not None, "Không có IP DAPT đa-ngày để kiểm chứng"

    db_path = os.path.join(tempfile.gettempdir(), "test_online_apt_contract.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    store = ThreatMemoryStore(db_path=db_path)
    with sqlite3.connect(db_path) as c:
        c.execute("DELETE FROM threat_events")

    try:
        fired_day = None
        days_recorded = set()
        for ev in seq:
            if ev.get("source") != "dapt" or not ev.get("is_attack") or ev["ip"] != multi_day_ip:
                continue
            before = store.check_apt_chain(multi_day_ip)
            store.record_apt_event(
                src_ip=multi_day_ip,
                dst_ip=ev.get("dst_ip", ""),
                apt_phase=ev.get("phase"),
                apt_day=ev.get("day"),
                label=ev.get("label", ""),
                timestamp=ev.get("timestamp", ""),
            )
            days_recorded.add(ev["day"])
            after = store.check_apt_chain(multi_day_ip)
            if (not before["is_apt"]) and after["is_apt"] and fired_day is None:
                fired_day = ev["day"]
                # Tại thời điểm BẬT phải đã thấy >= 2 ngày khác nhau (emergent thật)
                assert len(days_recorded) >= 2

        assert fired_day is not None, "APT không bao giờ bật dù IP đa-ngày"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_zerodays_real_derived_invariants():
    """Bất biến của zero-day REAL-DERIVED (thay 3 mẫu hardcode cũ):

    1. Đủ 7 mẫu theo ZD_SPECS, id duy nhất, RẢI qua ngày 2-5 (không dồn 1 ngày).
    2. Mỗi mẫu: ĐÚNG feature trong spec bị đặt giá trị cực trị.
    3. Nền là flow benign 'static-clean' (cổng KHÔNG nhạy cảm, fwd <= max_fwd_packets)
       => luật TĨNH (đối chứng) phải BỎ SÓT (DROP) toàn bộ — tính signature-less.
    """
    from experiments.unified_dataset import (
        GT_PATH,
        ZD_SPECS,
        _build_zerodays,
        static_only_action,
    )
    from src.tier1_filter.rule_engine import RuleEngine

    with open(GT_PATH, encoding="utf-8") as f:
        gt = json.load(f)
    zds = _build_zerodays(gt, tkey=lambda day: float(day))

    assert len(zds) == len(ZD_SPECS) == 7
    assert len({z["id"] for z in zds}) == 7, "id zero-day bị trùng"
    assert {z["day"] for z in zds} == {2, 3, 4, 5}, "zero-day phải rải ngày 2-5"

    engine = RuleEngine()
    for z, (zid, _name, feat, val, _dst, _mitre, day) in zip(zds, ZD_SPECS, strict=False):
        log = z["log"]
        assert z["id"] == zid and z["day"] == day
        assert log[feat] == val, f"{zid}: feature {feat} không được đẩy cực trị"
        port = int(log.get("Destination Port", 0) or 0)
        assert port not in engine.sensitive_ports, f"{zid}: nền KHÔNG static-clean (port {port})"
        assert float(log.get("Total Fwd Packets", 0) or 0) <= engine.max_fwd_packets
        assert static_only_action(engine, log) == "DROP", (
            f"{zid}: luật tĩnh PHẢI bỏ sót (signature-less) nhưng lại bắt được"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
