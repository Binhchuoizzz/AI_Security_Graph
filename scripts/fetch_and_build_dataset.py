import os
import pandas as pd
import json
from huggingface_hub import hf_hub_download

# Mapping của user
LABEL_MAP = {
    "SSH-Patator":        {"mitre": "T1110", "sub": "T1110.001", "action": "BLOCK_IP",    "severity": "HIGH"},
    "FTP-Patator":        {"mitre": "T1110", "sub": "T1110.001", "action": "BLOCK_IP",    "severity": "HIGH"},
    "DoS Hulk":           {"mitre": "T1499", "sub": "T1499.002", "action": "ALERT",       "severity": "HIGH"},
    "DoS GoldenEye":      {"mitre": "T1499", "sub": "T1499.002", "action": "ALERT",       "severity": "HIGH"},
    "DoS slowloris":      {"mitre": "T1499", "sub": "T1499.001", "action": "ALERT",       "severity": "MEDIUM"},
    "Heartbleed":         {"mitre": "T1203", "sub": None,        "action": "BLOCK_IP",    "severity": "CRITICAL"},
    "Web Attack \u2013 XSS":   {"mitre": "T1059", "sub": "T1059.007","action": "ALERT",        "severity": "MEDIUM"}, # Đã update dấu dash của dataset thật
    "Web Attack \u2013 Sql Injection": {"mitre": "T1190", "sub": None,"action": "ALERT",       "severity": "HIGH"},
    "Web Attack \u2013 Brute Force":   {"mitre": "T1110", "sub": None,"action": "BLOCK_IP",    "severity": "HIGH"},
    "PortScan":           {"mitre": "T1046", "sub": None,        "action": "LOG",         "severity": "LOW"},
    "Bot":                {"mitre": "T1071", "sub": None,        "action": "ALERT",       "severity": "HIGH"},
    "Infiltration":       {"mitre": "T1078", "sub": None,        "action": "AWAIT_HITL",  "severity": "CRITICAL"},
    "BENIGN":             {"mitre": None,    "sub": None,        "action": "LOG",         "severity": "INFO"},
}

# Có một số file raw CSV dùng "Web Attack  XSS" (dash thay vì hyphen), nên sẽ support map linh hoạt
ALT_LABELS = {
    "Web Attack - XSS": "Web Attack \u2013 XSS",
    "Web Attack - Sql Injection": "Web Attack \u2013 Sql Injection",
    "Web Attack - Brute Force": "Web Attack \u2013 Brute Force"
}

FEATURE_COLS = [
    " Source IP", " Destination IP", " Source Port", " Destination Port",
    " Protocol", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    " Total Length of Fwd Packets", " Total Length of Bwd Packets", " Label"
]

REPO_ID = "c01dsnap/CIC-IDS2017"
CSV_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]

def _infer_service(port: int) -> str:
    return {22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}.get(port, f"PORT_{port}")

def fetch_and_build(n_per_label: int = 10, output_path: str = "experiments/ground_truth.json"):
    print("[*] Bắt đầu tải và lọc dataset CICIDS2017 trực tiếp từ Hugging Face...")
    
    all_data = []
    
    for filename in CSV_FILES:
        print(f"  -> Tải {filename}...")
        try:
            filepath = hf_hub_download(repo_id=REPO_ID, filename=filename, repo_type="dataset")
            # Đọc CSV với error_bad_lines=False để an toàn
            df = pd.read_csv(filepath, usecols=lambda c: c.strip() in [col.strip() for col in FEATURE_COLS], low_memory=False, encoding='utf-8', on_bad_lines='skip')
            df.columns = df.columns.str.strip()
            
            # Chuẩn hóa nhãn bị lỗi font chữ (dấu dash dài)
            df["Label"] = df["Label"].replace(ALT_LABELS)
            
            # Chỉ lấy những nhãn nằm trong LABEL_MAP
            valid_labels = list(LABEL_MAP.keys())
            df_filtered = df[df["Label"].isin(valid_labels)]
            all_data.append(df_filtered)
            print(f"     Tìm thấy {len(df_filtered)} mẫu thuộc danh sách cần tìm.")
        except Exception as e:
            print(f"[!] Lỗi khi xử lý file {filename}: {e}")
            
    if not all_data:
        print("[!] Không có dữ liệu nào được trích xuất!")
        return
        
    combined_df = pd.concat(all_data, ignore_index=True)
    print(f"[*] Đã gộp thành công. Tổng số mẫu sau lọc: {len(combined_df)}")
    
    samples = []
    gt_counter = 1
    
    for label, mapping in LABEL_MAP.items():
        subset = combined_df[combined_df["Label"] == label]
        if len(subset) == 0:
            print(f"[WARN] Label '{label}' không tìm thấy trong bộ dữ liệu.")
            continue
            
        chosen = subset.sample(min(n_per_label, len(subset)), random_state=42)
        
        for _, row in chosen.iterrows():
            sample = {
                "id": f"GT-{gt_counter:03d}",
                "description": f"{label} attack sample from CICIDS2017",
                "logs": [{
                    "timestamp": "2026-04-18T10:00:00Z", # Mock timestamp cho schema cũ
                    "src_ip": str(row.get("Source IP", "0.0.0.0")),
                    "dst_ip": str(row.get("Destination IP", "0.0.0.0")),
                    "src_port": int(row.get("Source Port", 0)),
                    "dst_port": int(row.get("Destination Port", 0)),
                    "protocol": int(row.get("Protocol", 6)),
                    "flow_duration_ms": int(row.get("Flow Duration", 0)),
                    "fwd_packets": int(row.get("Total Fwd Packets", 0)),
                    "bwd_packets": int(row.get("Total Backward Packets", 0)),
                    "fwd_bytes": int(row.get("Total Length of Fwd Packets", 0)),
                    "bwd_bytes": int(row.get("Total Length of Bwd Packets", 0)),
                    "service": _infer_service(int(row.get("Destination Port", 0)))
                }],
                "expected_mitre_technique": mapping["sub"] if mapping["sub"] else mapping["mitre"],
                "expected_action": mapping["action"]
            }
            # Add raw network layout
            sample["input"] = {
                "network_layer": sample["logs"][0].copy(),
                "application_layer": {
                    "service": _infer_service(int(row.get("Destination Port", 0))),
                    "payload_snippet": None,
                    "user_agent": None,
                },
                "cicids_label": label
            }
            samples.append(sample)
            gt_counter += 1
            
    # Thêm lại 1 mẫu Adversarial để test Guardrails (giữ lại tính chất của Phase 4)
    samples.append({
        "id": f"GT-{gt_counter:03d}",
        "description": "SQL Injection in User-Agent with Zero-width joiner (Evasion Attempt - Adversarial)",
        "logs": [
            {"timestamp": "2026-04-18T10:05:00Z", "src_ip": "192.168.1.100", "payload": "SELECT * FROM users WHERE id=1", "user_agent": "Mozilla/5.0 <script>alert(1)</script> \u200d"}
        ],
        "expected_mitre_technique": "T1190",
        "expected_action": "ALERT"
    })
            
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding='utf-8') as f:
        json.dump(samples, f, indent=2, ensure_ascii=False)
        
    print(f"\n[OK] Đã generate {len(samples)} samples ra file {output_path}")
    
    from collections import Counter
    dist = Counter(s.get("input", {}).get("cicids_label", "Adversarial") for s in samples)
    print("\nPhân bổ nhãn (Label distribution):")
    for label, count in dist.most_common():
        print(f"  {label}: {count}")

if __name__ == "__main__":
    fetch_and_build(n_per_label=10)
