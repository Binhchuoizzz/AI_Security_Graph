"""
Unit tests — Học "kỹ thuật" (Behavioral Signature Learning).

Kiểm chứng tính năng: khi Tier-2 (LLM) chặn một IP, ngoài luật theo IP nó còn
trích một CHỮ KÝ HÀNH VI (công cụ trên User-Agent / token tấn công trên URI) để
Tier-1 bắt nhanh một IP KHÁC dùng CÙNG kỹ thuật — không chỉ "nhớ mặt" IP cũ.

Bao phủ:
  1. `_derive_behavioral_rule` trích đúng chữ ký an toàn (và loại benign/quá-phổ-biến).
  2. Tier-1 `_KEY_ALIASES` normalize `user_agent`/`uri` (để luật khớp log lowercase).
  3. Tier-1 với luật hành vi ACTIVE CỜ một IP HOÀN TOÀN MỚI cùng ngón đòn.
  4. Không over-block: traffic benign KHÔNG dính luật hành vi.

Không cần LLM server (thuần Tier-1 + hàm trích chữ ký).
"""

import pytest

from src.agent.nodes import _derive_behavioral_rule
from src.tier1_filter.rule_engine import _KEY_ALIASES, RuleEngine


# ── 1. Trích chữ ký hành vi ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "log_entry,expected",
    [
        # Công cụ tấn công rõ ràng trên User-Agent (chuẩn hoá key khác nhau)
        ({"user_agent": "sqlmap/1.5.2 (http://sqlmap.org)"}, ("User-Agent", "sqlmap", 50)),
        ({"User-Agent": "Nikto/2.1.6"}, ("User-Agent", "nikto", 50)),
        ({"user_agent": "Mozilla/5.0 nmap-scan"}, ("User-Agent", "nmap", 50)),
        # Token tấn công trên URI
        ({"uri": "/p?id=1 UNION SELECT pass FROM users"}, ("URI", "union select", 50)),
        ({"URI": "/cgi-bin/../../../etc/passwd"}, ("URI", "../../", 50)),
        # KHÔNG có chữ ký an toàn -> None (chỉ giữ luật IP)
        ({"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64)"}, None),  # browser benign
        ({"user_agent": "curl/8.1.2", "uri": "/health"}, None),  # curl CỐ Ý loại
        ({"user_agent": "python-requests/2.31", "uri": "/api/v1"}, None),  # loại
        ({"Source IP": "10.0.0.5", "Destination Port": 22}, None),  # không có field chữ ký
    ],
)
def test_derive_behavioral_rule(log_entry, expected):
    assert _derive_behavioral_rule(log_entry) == expected


def test_derive_returns_valid_field_for_feedback_validator():
    """Field trả về phải nằm trong tập FeedbackValidator cho phép (URI/User-Agent)."""
    from src.guardrails.feedback_validator import FeedbackValidator

    fv = FeedbackValidator()
    for log in [{"user_agent": "sqlmap/1.6"}, {"uri": "x UNION SELECT y"}]:
        field, pattern, score = _derive_behavioral_rule(log)
        is_valid, errors = fv.validate_rule(field, pattern, score)
        assert is_valid, f"Behavioral rule bị FeedbackValidator từ chối: {errors}"


# ── 2. Tier-1 alias chuẩn hoá field lớp-ứng-dụng ──────────────────────────
def test_tier1_aliases_cover_application_fields():
    """Sau vá: Tier-1 phải normalize user_agent/uri (đồng bộ Guardrails)."""
    assert _KEY_ALIASES.get("user_agent") == "User-Agent"
    assert _KEY_ALIASES.get("uri") == "URI"


# ── 3. Tier-1 bắt IP MỚI cùng kỹ thuật ────────────────────────────────────
def _engine_with_behavioral_rule():
    e = RuleEngine()
    # Mô phỏng luật hành vi ĐÃ được HITL duyệt (ACTIVE) — inject trực tiếp,
    # KHÔNG ghi vào config thật. Sau refactor: luật KHÔNG-phải-Source-IP nằm ở
    # dynamic_behavioral_rules (list tuple field/pattern/score); luật Source IP
    # nằm ở dynamic_ip_blocks (set) để tra O(1).
    e.dynamic_behavioral_rules = [("User-Agent", "sqlmap", 50)]
    return e


def test_new_ip_same_technique_is_caught():
    """IP HOÀN TOÀN MỚI dùng User-Agent 'sqlmap' -> Tier-1 CỜ (không DROP)."""
    e = _engine_with_behavioral_rule()
    new_log = {
        "Source IP": "203.0.113.77",  # IP chưa từng thấy
        "Destination Port": 80,
        "Protocol": 6,
        "Total Fwd Packets": 12,
        "User-Agent": "sqlmap/1.6#dev",
    }
    res = e.evaluate(new_log)
    assert res["tier1_action"] != "DROP"
    assert res["tier1_score"] >= 15  # vượt risk_threshold
    assert any("Luật động" in r for r in res["tier1_reasons"])


def test_new_ip_lowercase_key_is_caught():
    """Log nguồn viết thường 'user_agent' vẫn khớp nhờ alias vá."""
    e = _engine_with_behavioral_rule()
    low = {
        "src_ip": "203.0.113.88",
        "dst_port": 80,
        "protocol": 6,
        "fwd_packets": 9,
        "user_agent": "sqlmap/1.6",
    }
    res = e.evaluate(low)
    assert any("Luật động" in r for r in res["tier1_reasons"])


# ── 4. Không over-block traffic benign ────────────────────────────────────
def test_benign_not_over_blocked_by_behavioral_rule():
    """Trình duyệt benign KHÔNG dính luật 'sqlmap' -> DROP/LOG."""
    e = _engine_with_behavioral_rule()
    benign = {
        "Source IP": "192.168.100.5",
        "Destination Port": 443,
        "Protocol": 6,
        "Total Fwd Packets": 4,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    }
    res = e.evaluate(benign)
    assert not any("Luật động" in r for r in res["tier1_reasons"])
    assert res["tier1_action"] in ("DROP", "LOG")
