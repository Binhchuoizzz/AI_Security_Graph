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


# ==============================================================================
# XUẤT XỨ CỦA PHẦN LẬP LUẬN KHI CACHE HIT TRÊN MỘT IP KHÁC
# ==============================================================================
#
# Lỗi thật, phát hiện bằng cách đọc `config/system_settings.yaml` do hệ thống SỐNG ghi ra
# trong lượt chạy 2026-07-28: luật chặn `172.20.0.122` mang phần lý do nói về
# `10.200.4.164`; hai luật chặn `192.168.41.100` / `192.168.41.5` cùng mang lý do viết cho
# `192.168.42.174`. Cache lớp-2 gộp theo ĐẶC TRƯNG (cố ý bỏ IP khỏi khoá) nên `reasoning`
# của IP gốc đi thẳng vào nhật ký kiểm toán, lý do luật động và giao diện analyst.
# `target` thực thi thì vẫn đúng — chỉ phần GIẢI THÍCH là sai địa chỉ.


def test_cached_reasoning_declares_its_origin_ip():
    from src.agent.nodes import _annotate_reused_verdict

    decision = {"extracted_iocs": [{"ioc_type": "ip", "value": "10.200.4.164"}]}
    reasoning = "This log shows a single source IP (10.200.4.164) making 2 HTTP requests."

    out = _annotate_reused_verdict(reasoning, decision, "172.20.0.122")
    assert "TÁI SỬ DỤNG" in out
    assert "10.200.4.164" in out and "172.20.0.122" in out
    # Nguyên văn của LLM phải được GIỮ, không bị viết lại thành tên IP mới.
    assert reasoning in out


def test_same_ip_reasoning_is_left_untouched():
    from src.agent.nodes import _annotate_reused_verdict

    decision = {"extracted_iocs": [{"ioc_type": "ip", "value": "10.0.0.1"}]}
    r = "Traffic from 10.0.0.1 looks volumetric."
    assert _annotate_reused_verdict(r, decision, "10.0.0.1") == r
    assert _annotate_reused_verdict(r, decision, "UNKNOWN_TARGET") == r


def test_cache_get_returns_a_copy_not_the_stored_object():
    """Sửa verdict lấy ra KHÔNG được làm hỏng mục trong cache."""
    from src.agent.response_cache import ExactMatchResponseCache

    c = ExactMatchResponseCache()
    c.set("payload-x", {"action": "ALERT", "nested": {"k": 1}})
    got = c.get("payload-x")
    assert got is not None
    got["action"] = "BLOCK_IP"
    got["nested"]["k"] = 999

    again = c.get("payload-x")
    assert again is not None
    assert again["action"] == "ALERT", "cache bị ghi đè bởi thao tác ở hạ nguồn"
    assert again["nested"]["k"] == 1, "deepcopy không sâu — dict lồng vẫn bị chia sẻ"


# ==============================================================================
# BỘ NHỚ ĐE DOẠ DÀI HẠN PHẢI THỰC SỰ TỚI ĐƯỢC LLM
# ==============================================================================
#
# Lỗi thật: `node_llm_triage` truy vấn SQLite dựng `threat_memory_context` mỗi lô rồi cất
# vào state, nhưng `build_triage_prompt` chỉ nhận (log_data, rag_context) và
# `SentinelState.get_memory_for_prompt()` KHÔNG có nơi nào gọi. Bộ nhớ Đe doạ dài hạn —
# đóng góp chính của RQ3 — chưa bao giờ tới được LLM: mô hình luôn phán quyết như thể mỗi
# IP là lần đầu gặp.


def test_threat_memory_reaches_the_prompt():
    from src.agent.prompts import build_triage_prompt

    msgs = build_triage_prompt(
        log_data="LOG", rag_context="RAG", threat_memory_context="IP 1.2.3.4: 5 sự cố trước đó"
    )
    user = msgs[-1]["content"]
    assert "5 sự cố trước đó" in user, "tiền sử KHÔNG vào prompt"
    assert "PRIOR HISTORY" in user

    # Không có tiền sử -> KHÔNG chèn khối rỗng gây nhiễu prompt.
    plain = build_triage_prompt(log_data="LOG", rag_context="RAG")[-1]["content"]
    assert "PRIOR HISTORY" not in plain


def test_feature_cache_separates_hosts_with_and_without_history():
    """Nếu không tách rổ, verdict của IP sạch sẽ bị tái dùng cho kẻ tái phạm."""
    from src.agent.response_cache import ExactMatchResponseCache

    c = ExactMatchResponseCache()
    log = {"service": "HTTP", "Destination Port": 80, "tier1_action": "ESCALATE"}
    c.set_by_features(log, {"action": "ALERT"}, has_history=False)

    got = c.get_by_features(log, has_history=False)
    assert got is not None and got["action"] == "ALERT"
    assert c.get_by_features(log, has_history=True) is None, (
        "IP có tiền sử dùng lại verdict của IP sạch — tác dụng của Threat Memory bị xoá"
    )
