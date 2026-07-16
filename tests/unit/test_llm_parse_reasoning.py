"""Regression: parse_llm_response phải LUÔN mang `reasoning` (không để trống thành thẻ
"No reasoning provided / tin cậy 0%" trên Dashboard) và vớt được trường từ JSON bị cắt cụt.

Bug gốc: khi output LLM không parse được JSON (thường do max_tokens cắt cụt), hard-fallback
trả dict KHÔNG có key `reasoning` -> UI hiện "No reasoning provided" + 0% + MITRE gây hiểu lầm.
"""

from src.agent.llm_client import llm_client


def test_valid_json_passthrough():
    d = llm_client.parse_llm_response(
        '{"action":"BLOCK_IP","confidence":0.9,"reasoning":"SQLi detected"}'
    )
    assert d["action"] == "BLOCK_IP"
    assert d["confidence"] == 0.9
    assert d["reasoning"] == "SQLi detected"
    assert "error" not in d  # đường JSON hợp lệ không gắn cờ lỗi


def test_truncated_json_salvages_reasoning():
    """JSON bị cắt cụt giữa reasoning (max_tokens) -> vẫn vớt action/confidence/reasoning."""
    raw = (
        '{"action": "ALERT", "confidence": 0.7, "mitre_technique": "T1046", '
        '"reasoning": "Nhiều IP quét cổng liên tục cho thấy trinh sát mạng và'
    )
    d = llm_client.parse_llm_response(raw)
    assert d["action"] == "ALERT"
    assert d["confidence"] == 0.7
    assert d["mitre_technique"] == "T1046"
    assert d.get("reasoning"), "reasoning bị mất khi JSON cắt cụt"
    assert "trinh sát mạng" in d["reasoning"]
    assert d.get("error") == "parse_salvaged"


def test_unparseable_fallback_has_reasoning():
    """Output rác hoàn toàn -> fallback AWAIT_HITL nhưng PHẢI có reasoning trung thực."""
    d = llm_client.parse_llm_response("Sorry, I cannot help with that request.")
    assert d["action"] == "AWAIT_HITL"
    assert d["confidence"] == 0.0
    assert d.get("error") == "parse_failed"
    assert d.get("reasoning"), "BUG: fallback không có reasoning -> thẻ 'No reasoning provided'"
    assert "không đọc được" in d["reasoning"].lower()


def test_markdown_fenced_json():
    d = llm_client.parse_llm_response('```json\n{"action":"LOG","reasoning":"benign"}\n```')
    assert d["action"] == "LOG"
    assert d["reasoning"] == "benign"
