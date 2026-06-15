"""
Cấu hình dùng chung và các hằng số cho DAPT2020.
"""

import pandas as pd  # type: ignore

# Các giai đoạn APT theo từng ngày của DAPT2020 (đã sửa ánh xạ dựa trên cột Stage thực tế)
APT_PHASES = {
    "day1": "Benign",
    "day2": "Reconnaissance",
    "day3": "Establish Foothold",
    "day4": "Lateral Movement",
    "day5": "Data Exfiltration",
}

DAPT_RAW_DIR = "data/raw/dapt2020/"
DAPT_PROCESSED_FILE = "data/processed/dapt2020_chains.jsonl"

# Nhãn đại diện cho hành vi an toàn (benign)
BENIGN_LABELS = {"Normal", "BENIGN", "Benign", "normal", "benign"}


# Các hàm hỗ trợ chuẩn hóa
def normalize_stage(stage_val):
    if pd.isna(stage_val) or stage_val is None:
        return "Unknown"
    s = str(stage_val).strip()
    if s.upper() in ("BENIGN", "NORMAL"):
        return "Benign"
    return s


def normalize_label(label_val):
    if pd.isna(label_val) or label_val is None:
        return "Unknown"
    lbl = str(label_val).strip()
    if lbl.upper() in ("BENIGN", "NORMAL"):
        return "Normal"
    return lbl


# Ánh xạ các nhãn tấn công DAPT2020 sang MITRE ATT&CK TTPs
DAPT_LABEL_TO_MITRE = {
    "Network Scan": "T1046",
    "Web Vulnerability Scan": "T1595.002",
    "Directory Bruteforce": "T1083",
    "Account Bruteforce": "T1110.001",
    "Account Discovery": "T1087",
    "SQL Injection": "T1190",
    "CSRF": "T1185",
    "Malware Download": "T1105",
    "Backdoor": "T1543",
    "Privilege Escalation": "T1068",
    "Command Injection": "T1059",
    "Data Exfiltration": "T1041",
}

# Danh sách đầy đủ 85 cột trong tập dữ liệu thô DAPT2020
DAPT2020_HEADERS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWR Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "FWD Init Win Bytes",
    "Bwd Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "label",
    "Stage",
]
