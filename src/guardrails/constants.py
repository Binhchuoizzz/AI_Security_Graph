"""
Guardrails Central Constants and Helper Functions
"""

# --------------------------------------------------------------------------- #
# TẦNG RA QUYẾT ĐỊNH — ghi tường minh vào cột `audit_trail.tier`
# --------------------------------------------------------------------------- #
# VÌ SAO TỒN TẠI: Dashboard từng xếp cảnh báo vào 3 tab bằng cách DÒ CHUỖI trong câu lý do
# ("Cổng ML" -> tab ML, "Tier-1" -> tab luật, còn lại -> tab LLM). Câu lý do khi LLM hỏng có
# chứa cụm "Tier-1 (xác định) vẫn bảo vệ độc lập", nên một sự cố của Tier-2 rơi nhầm sang tab
# Tier-1 ngay khi action không phải AWAIT_HITL. Phân loại phải đến từ nơi BIẾT sự thật.
#
# Bản ghi TRƯỚC migration có `tier = ''` -> UI rơi về heuristic cũ, không mất dữ liệu.
TIER_RULE = "tier1_rule"  # bộ máy luật Tier-1 (chữ ký, Welford, luật tĩnh/động)
TIER_ML = "tier1_ml"  # Cổng ML (LightGBM) — vẫn thuộc Tier-1
TIER_LLM = "tier2_llm"  # tác tử LangGraph Tier-2
TIER_MANUAL = "manual"  # analyst thao tác tay trên Dashboard
# Dòng do CHÍNH bộ tự kiểm ghi ra (`scripts/audit_ui_functions.py`), không phải sự kiện thật.
#
# VÌ SAO CẦN MỘT NHÃN RIÊNG. Bộ tự kiểm phải gọi đúng `block_ip` thật thì mới kiểm được đường
# thật, nên nó ĐỂ LẠI dòng trong `audit_trail`. Mà `audit_trail` là sổ móc xích HMAC — xoá một
# dòng là gãy chuỗi, nên không dọn được. Đo ngày 12/08/2026: sau một lượt tự kiểm, Dashboard
# có 2 lệnh `BLOCK_IP` của IP thử nghiệm 203.0.113.254 nằm lẫn với lệnh chặn thật, không thẻ
# nào đếm chúng nên tổng trên thẻ phễu lệch tổng trong sổ. Gắn nhãn thì dòng vẫn còn (chuỗi
# nguyên vẹn) nhưng không còn giả dạng một lệnh chặn thật.
TIER_SELFTEST = "selftest"

KEY_ALIASES = {
    "src_ip": "Source IP",
    "source_ip": "Source IP",
    "source ip": "Source IP",
    "dst_port": "Destination Port",
    "destination_port": "Destination Port",
    "destination port": "Destination Port",
    "protocol": "Protocol",
    "total_fwd_pkts": "Total Fwd Packets",
    "total fwd packets": "Total Fwd Packets",
    "flow_dur": "Flow Duration",
    "flow_duration": "Flow Duration",
    "flow duration": "Flow Duration",
    "timestamp": "Timestamp",
    "uri": "URI",
    "user-agent": "User-Agent",
    "user_agent": "User-Agent",
    "user agent": "User-Agent",
}


def normalize_log_keys(log_entry: dict) -> dict:
    """
    Normalize log keys to match canonical uppercase schema.
    Returns a new dict with canonical keys.
    """
    normalized = {}
    for k, v in log_entry.items():
        canonical_key = KEY_ALIASES.get(k.lower(), k)
        normalized[canonical_key] = v
    return normalized
