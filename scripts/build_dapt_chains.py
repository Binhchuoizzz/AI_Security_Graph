"""
Xây dựng các chuỗi phiên APT (APT session chains) từ DAPT2020.

Mỗi chuỗi = một chuỗi các sự kiện từ cùng một IP tấn công qua nhiều ngày.
Đầu ra: data/processed/dapt2020_chains.jsonl

Các chuỗi kéo dài ≥ 2 ngày và chứa ít nhất một sự kiện tấn công
đại diện cho hành vi APT thực tế (kẻ tấn công kiên trì).
"""

import os
import glob
import json
from pathlib import Path
from datetime import datetime
import pandas as pd  # type: ignore

# Các công cụ phân tích tĩnh sẽ phân giải scripts.dapt2020_config
# Fallback xử lý khi chạy trực tiếp trong thư mục scripts/
try:
    from scripts.dapt2020_config import (
        APT_PHASES, DAPT_RAW_DIR, DAPT_PROCESSED_FILE,
        BENIGN_LABELS, normalize_stage, normalize_label,
        DAPT_LABEL_TO_MITRE
    )
except ImportError:
    from dapt2020_config import (  # type: ignore  # noqa: E402
        APT_PHASES, DAPT_RAW_DIR, DAPT_PROCESSED_FILE,
        BENIGN_LABELS, normalize_stage, normalize_label,
        DAPT_LABEL_TO_MITRE
    )


def safe_int(val):
    """Ép kiểu giá trị sang số nguyên một cách an toàn."""
    try:
        return int(val) if pd.notna(val) else 0
    except (ValueError, TypeError):
        return 0


def build_chains():
    all_events = []

    for day_file, phase in APT_PHASES.items():
        path = os.path.join(DAPT_RAW_DIR, f"{day_file}.csv")
        if not Path(path).exists():
            # Thử tìm theo mẫu
            matches = glob.glob(os.path.join(DAPT_RAW_DIR, f"*{day_file[-1]}*"))
            if not matches:
                print(f"WARNING: {path} not found, skipping")
                continue
            path = matches[0]

        df = pd.read_csv(path, low_memory=False)
        df["apt_day"] = int(day_file[-1])

        # Chuẩn hóa tên cột (DAPT2020 sử dụng nhiều định dạng khác nhau)
        col_map = {}
        for col in df.columns:
            col_lower = col.lower()
            if "src" in col_lower and "ip" in col_lower:
                col_map[col] = "src_ip"
            elif "dst" in col_lower and "ip" in col_lower:
                col_map[col] = "dst_ip"
            elif col_lower == "label":
                col_map[col] = "label"
            elif col_lower == "stage":
                col_map[col] = "Stage"
            elif "timestamp" in col_lower or "time" in col_lower:
                col_map[col] = "timestamp"
        df = df.rename(columns=col_map)

        # Chuẩn hóa nhãn và Stage/phase nếu tồn tại
        if "label" in df.columns:
            df["label"] = df["label"].apply(normalize_label)
        else:
            df["label"] = "Normal"

        if "Stage" in df.columns:
            df["apt_phase"] = df["Stage"].apply(normalize_stage)
        else:
            df["apt_phase"] = phase

        # Chỉ chọn các cột cần thiết để tiết kiệm bộ nhớ
        cols_to_keep = [c for c in ["src_ip", "dst_ip", "label", "apt_phase", "apt_day", "timestamp"] if c in df.columns]
        df = df[cols_to_keep]

        all_events.append(df)
        print(f"  Loaded {len(df)} events from {day_file} (canonical phase: {phase})")

    if not all_events:
        raise RuntimeError(f"No DAPT2020 files loaded. Check {DAPT_RAW_DIR}")

    combined = pd.concat(all_events, ignore_index=True)
    print(f"\nTotal combined events: {len(combined)}")

    # Đảm bảo src_ip tồn tại, nếu không có thì tạo IP giả lập
    if "src_ip" not in combined.columns:
        print("WARNING: src_ip not found. Using mock IP from index.")
        combined["src_ip"] = (combined.index % 50).apply(
            lambda x: f"192.168.{x // 256}.{x % 256}"
        )

    # Xây dựng các chuỗi theo IP kẻ tấn công
    chains = {}
    for _, row in combined.iterrows():
        ip = str(row.get("src_ip", "unknown"))
        if ip not in chains:
            chains[ip] = []
        
        lbl_val = str(row.get("label", "Normal"))
        chains[ip].append({
            "day": safe_int(row.get("apt_day", 0)),
            "phase": str(row.get("apt_phase", "Unknown")),
            "label": lbl_val,
            "mitre_ttp": DAPT_LABEL_TO_MITRE.get(lbl_val, None),
            "src_ip": ip,
            "dst_ip": str(row.get("dst_ip", "10.0.0.1")),
            "timestamp": str(row.get("timestamp", "")),
        })

    def parse_dapt_timestamp(ts_str):
        try:
            return datetime.strptime(ts_str, "%d/%m/%Y %I:%M:%S %p")
        except Exception:
            try:
                return datetime.fromisoformat(ts_str)
            except Exception:
                return datetime.min

    # Sắp xếp mỗi chuỗi theo trình tự thời gian
    for ip in chains:
        chains[ip].sort(key=lambda x: (x["day"], parse_dapt_timestamp(x.get("timestamp", ""))))

    # Chỉ giữ các chuỗi kéo dài nhiều ngày thể hiện hành vi APT thực (yêu cầu >= 2 ngày và ít nhất một cuộc tấn công)
    apt_chains = {
        ip: events
        for ip, events in chains.items()
        if len(set(e["day"] for e in events)) >= 2
        and any(e["label"] not in BENIGN_LABELS for e in events)
    }

    print(f"Multi-day APT chains found (with attack events): {len(apt_chains)} attacker IPs")
    assert len(apt_chains) >= 5, \
        f"Need >= 5 multi-day chains, got {len(apt_chains)}"

    # Write to JSONL
    output_path = Path(DAPT_PROCESSED_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for ip, events in apt_chains.items():
            if len(events) > 20:
                print(f"  [INFO] {ip}: {len(events)} events -> sampling 10 attack + 10 benign events")
                # Chọn tối đa 10 sự kiện tấn công và 10 sự kiện bình thường để giữ tín hiệu
                attack_evts = [e for e in events if e["label"] not in BENIGN_LABELS]
                benign_evts = [e for e in events if e["label"] in BENIGN_LABELS]
                sampled = attack_evts[:10] + benign_evts[:10]
            else:
                sampled = events
            
            # Sắp xếp lại để duy trì trình tự thời gian
            sampled.sort(key=lambda x: (x["day"], parse_dapt_timestamp(x.get("timestamp", ""))))

            f.write(json.dumps({
                "attacker_ip": ip,
                "chain_length": len(events),
                "days_spanned": sorted(set(e["day"] for e in events)),
                "phases": list(dict.fromkeys(e["phase"] for e in events)),
                "events": sampled,
            }) + "\n")

    # Thống kê tóm tắt
    chain_lengths = [len(v) for v in apt_chains.values()]
    print(f"Chain stats: min={min(chain_lengths)}, "
          f"max={max(chain_lengths)}, "
          f"avg={sum(chain_lengths) / len(chain_lengths):.1f}")

    print("\nPASS: DAPT2020 APT chains built successfully")
    print(f"Output: {DAPT_PROCESSED_FILE}")

    return len(apt_chains)


if __name__ == "__main__":
    build_chains()
