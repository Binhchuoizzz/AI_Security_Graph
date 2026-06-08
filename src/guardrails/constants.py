"""
Guardrails Central Constants and Helper Functions
"""

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
