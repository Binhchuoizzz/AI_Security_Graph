"""
Unit tests cho LỚP-2 feature-fingerprint của ExactMatchResponseCache
(src/agent/response_cache.py).

Mục tiêu: các flow CÙNG BẢN CHẤT (khác mỗi IP/timestamp) phải GỘP về 1 khoá -> 1 lần
gọi LLM, còn flow KHÁC bản chất (khác payload/dịch vụ) phải TÁCH khoá. Đây là cách hạ
backlog LLM mà KHÔNG bỏ sót tấn công.
"""

from src.agent.response_cache import ExactMatchResponseCache


def _cache():
    return ExactMatchResponseCache(max_size=100, ttl_seconds=60)


def test_identical_flows_differing_only_by_ip_collapse():
    """2 log DAPT nền chỉ khác IP/timestamp -> CÙNG fingerprint -> gộp 1 verdict."""
    c = _cache()
    a = {"Source IP": "10.0.0.1", "Destination Port": 443, "timestamp": "t1"}
    b = {"Source IP": "10.0.0.2", "Destination Port": 443, "timestamp": "t2"}
    assert c.feature_fingerprint(a) == c.feature_fingerprint(b)
    c.set_by_features(a, {"action": "LOG", "confidence": 0.9})
    assert c.get_by_features(b) == {"action": "LOG", "confidence": 0.9}


def test_different_payload_stays_separate():
    """Khác nội dung app-layer (payload/message) -> fingerprint KHÁC -> KHÔNG gộp nhầm."""
    c = _cache()
    a = {"Destination Port": 443, "message": "[Threat-Intel] MITRE T1046"}
    b = {"Destination Port": 443, "message": "[Threat-Intel] MITRE T1087"}
    assert c.feature_fingerprint(a) != c.feature_fingerprint(b)
    c.set_by_features(a, {"action": "BLOCK_IP"})
    assert c.get_by_features(b) is None  # b chưa có -> miss (không mượn verdict của a)


def test_different_service_stays_separate():
    """Zero-day khác 'service' (PORT_x) -> tách khoá -> mỗi cái vẫn được xét riêng."""
    c = _cache()
    a = {"service": "PORT_52581", "Destination Port": 52581}
    b = {"service": "PORT_55341", "Destination Port": 55341}
    assert c.feature_fingerprint(a) != c.feature_fingerprint(b)


def test_wellknown_port_kept_but_ephemeral_bucketed():
    """Cổng well-known giữ số (định danh dịch vụ); cổng ephemeral cao gộp 'hi'."""
    c = _cache()
    assert c._port_token(22) == "22"
    assert c._port_token(443) == "443"
    assert c._port_token(52581) == "hi"
    assert c._port_token(55341) == "hi"  # cùng bucket 'hi' với 52581
    assert c._port_token(0) == "0"


def test_tier1_signal_separates_benign_from_attack():
    """tier1_action/tier1_reasons vào fingerprint -> benign vs attack cùng cổng KHÔNG gộp."""
    c = _cache()
    benign = {"Destination Port": 80, "tier1_action": "LOG", "tier1_reasons": []}
    attack = {
        "Destination Port": 80,
        "tier1_action": "ESCALATE",
        "tier1_reasons": ["Bất thường về dung lượng"],
    }
    assert c.feature_fingerprint(benign) != c.feature_fingerprint(attack)
