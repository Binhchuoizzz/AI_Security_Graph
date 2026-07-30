"""Nạp CSIC 2010 HTTP -> tập L7 THẬT cho luồng `queue_waf`.

VÌ SAO CẦN. Đo được trên luồng hiện tại: trong 5.000 sự kiện chỉ có ~180 mang bằng chứng
tầng ứng dụng, và 69 trong số đó là payload do TÁC GIẢ TỰ SOẠN. Mọi chỉ số "quy kết kỹ thuật"
của đồ án vì thế đứng trên một tập tự soạn cỡ 69 mẫu — quá nhỏ và không khách quan. CSIC 2010
là ~61.000 request HTTP THẬT đánh vào một ứng dụng thương mại điện tử thật, tấn công nằm lẫn
trong lưu lượng bình thường.

CẢNH BÁO PHƯƠNG PHÁP — ĐỌC TRƯỚC KHI DÙNG SỐ:
CSIC chỉ gán nhãn `normal` / `anomalous`. Nó KHÔNG gán loại tấn công, càng không gán mã
ATT&CK. Việc suy ra loại tấn công là một BƯỚC DIỄN GIẢI của người làm đồ án, và phải khai
báo đúng như vậy trong luận văn.

Bộ phân loại ở đây CỐ Ý viết ĐỘC LẬP với `_WAF_PATTERNS` của Tier-1. Nếu dùng chính chữ ký
của hệ thống để sinh đáp án rồi chấm hệ thống bằng đáp án đó thì là lập luận vòng tròn: hệ
thống sẽ đạt gần 100% và con số vô nghĩa. Mẫu dưới đây bắt nguồn từ mô tả tấn công của chính
bộ CSIC và từ định nghĩa OWASP, KHÔNG chép từ mã nguồn dự án.

Bản ghi KHÔNG khớp họ nào -> `wa_mitre` để TRỐNG: vẫn dùng được để chấm PHÁT HIỆN
(tấn công/lành), nhưng bị loại khỏi phần chấm QUY KẾT KỸ THUẬT. Thà bỏ trống còn hơn gán bừa.

Chạy:
    .venv/bin/python scripts/build_csic_dataset.py --limit 4000
    .venv/bin/python scripts/build_csic_dataset.py --limit 4000 --out data/csic.json
"""

import argparse
import json
import os
import random
import re
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

BASE = "https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/raw/master/csic_2010"
FILES = {
    "normal_train": f"{BASE}/normalTrafficTraining.txt",
    "normal_test": f"{BASE}/normalTrafficTest.txt",
    "anomalous": f"{BASE}/anomalousTrafficTest.txt",
}
CACHE = os.path.join(ROOT, "data", "raw", "csic2010")

# ── Bộ phân loại ĐỘC LẬP (OWASP / mô tả bộ CSIC), KHÔNG lấy từ src/tier1_filter ──
# Thứ tự CÓ ý nghĩa: mẫu đặc hiệu đứng trước mẫu tổng quát.
FAMILIES: tuple[tuple[str, str, str], ...] = (
    (
        "SQL Injection",
        "T1190",
        r"(?:'|%27)\s*(?:;|\)|\s)\s*(?:drop|union|select|insert|update|delete)\b"
        r"|\bunion\s+(?:all\s+)?select\b|\bdrop\s+table\b|\bor\s+1\s*=\s*1\b|--\s*$",
    ),
    (
        "Cross-Site Scripting",
        "T1059.007",
        r"&lt;\s*script|%3cscript|javascript:|onerror\s*=|onload\s*=|&lt;\s*img[^&]*onerror",
    ),
    (
        "Path Traversal",
        "T1083",
        r"\.\./|%2e%2e[/%]|\.\.\\|/etc/passwd|boot\.ini",
    ),
    (
        "Command Injection",
        "T1059",
        r"(?:;|\||&&|%3b|%7c)\s*(?:cat|ls|id|whoami|ping|wget|curl|nc|bash|sh)\b",
    ),
    (
        "CRLF Injection",
        "T1071.001",
        r"%0d%0a|%0a%0d|\r\n(?:set-cookie|location)\s*:",
    ),
    (
        "Buffer Overflow",
        "T1499.004",
        r"[A-Za-z0-9]{400,}|(?:%41){100,}",
    ),
    # Hai họ dưới đây chiếm phần LỚN nhóm "anomalous" của CSIC. Chúng không phải tiêm nhiễm
    # nhưng vẫn là tấn công thật, và ánh xạ ATT&CK bảo vệ được: dò tệp sao lưu/mã nguồn và
    # duyệt ép tới ứng dụng mẫu đều là Active Scanning bằng danh sách từ (T1595.003).
    (
        "Backup/Source File Probing",
        "T1595.003",
        r"\.(?:old|bak|inc|orig|save|swp|tar|zip|log)\b|~$|\.(?:jsp|php|asp)\.(?:old|bak|txt)\b",
    ),
    (
        "Forced Browsing",
        "T1595.003",
        r"/(?:WebSphereSamples|examples|manager|admin|phpmyadmin|test|backup|conf|WEB-INF)/",
    ),
)
_COMPILED = [(n, t, re.compile(p, re.I)) for n, t, p in FAMILIES]


def classify(text: str) -> tuple[str, str]:
    """(tên họ, mã ATT&CK) hoặc ('', '') nếu không khớp họ nào — KHÔNG đoán."""
    for name, tech, rx in _COMPILED:
        if rx.search(text):
            return name, tech
    return "", ""


def fetch(url: str, dest: str) -> str:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest) and os.path.getsize(dest) > 1000:
        return open(dest, encoding="latin-1").read()
    print(f"[*] tải {url}")
    with urllib.request.urlopen(url, timeout=180) as r:  # noqa: S310
        data = r.read().decode("latin-1")
    open(dest, "w", encoding="latin-1").write(data)
    return data


def parse_requests(blob: str) -> list[dict]:
    """Tách các request HTTP thô (phân cách bằng dòng trống, body nằm sau Content-Length)."""
    out: list[dict] = []
    cur: dict = {}
    headers: dict = {}
    body_len = 0
    lines = blob.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP/", line)
        if m:
            if cur:
                out.append({**cur, "headers": headers})
            cur = {"method": m.group(1), "url": m.group(2), "body": ""}
            headers, body_len = {}, 0
            i += 1
            while i < len(lines) and lines[i].strip():
                if ":" in lines[i]:
                    k, v = lines[i].split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                    if k.strip().lower() == "content-length":
                        body_len = int(v.strip() or 0)
                i += 1
            if body_len:
                while i < len(lines) and not lines[i].strip():
                    i += 1
                if i < len(lines):
                    cur["body"] = lines[i]
                    i += 1
            continue
        i += 1
    if cur:
        out.append({**cur, "headers": headers})
    return out


def to_event(req: dict, is_attack: bool, idx: int, rnd: random.Random) -> dict:
    parsed = urllib.parse.urlparse(req["url"])
    uri = parsed.path + (("?" + parsed.query) if parsed.query else "")
    decoded = urllib.parse.unquote_plus(uri + " " + req.get("body", ""))
    fam, tech = classify(decoded) if is_attack else ("", "")
    # IP nguồn: dải TEST-NET-2 (RFC 5737) để KHÔNG đụng bất kỳ IP nào của CICIDS/DAPT —
    # trùng dải sẽ làm trí nhớ/reputation của hai tập trộn vào nhau và bẩn cả hai phép đo.
    ip = f"198.51.100.{rnd.randint(1, 254)}" if is_attack else f"198.51.100.{rnd.randint(1, 254)}"
    return {
        "Source IP": ip,
        "Destination Port": 8080,
        "Protocol": 6,
        "service": "http",
        "method": req["method"],
        "uri": uri,
        "payload": req.get("body", ""),
        "user_agent": req["headers"].get("user-agent", ""),
        "message": f"HTTP {req['method']} {uri}"[:500],
        "Total Fwd Packets": rnd.randint(3, 12),
        "Total Length of Bwd Packets": rnd.randint(500, 8000),
        "Flow Duration": rnd.randint(1000, 90000),
        "csic_index": idx,
        # nhãn -> sidecar, KHÔNG nằm trong sự kiện (bộ đóng dấu sẽ tách ra)
        "_label": {
            "unified_source": "csic",
            "expected_threat": is_attack,
            "gt_label": fam or ("Anomalous (unclassified)" if is_attack else "Benign"),
            "wa_mitre": tech,
            "wa_expected_action": "BLOCK_IP" if tech else ("ALERT" if is_attack else "LOG"),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=4000, help="tổng số sự kiện xuất ra")
    ap.add_argument("--out", default="data/csic.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    normal = parse_requests(fetch(FILES["normal_test"], os.path.join(CACHE, "normal_test.txt")))
    anom = parse_requests(fetch(FILES["anomalous"], os.path.join(CACHE, "anomalous.txt")))
    print(f"[+] phân tích được: {len(normal)} bình thường · {len(anom)} bất thường")

    half = args.limit // 2
    rnd.shuffle(normal)
    rnd.shuffle(anom)
    events = [to_event(r, False, i, rnd) for i, r in enumerate(normal[:half])]
    events += [to_event(r, True, i, rnd) for i, r in enumerate(anom[: args.limit - half])]
    rnd.shuffle(events)

    from collections import Counter

    fams = Counter(e["_label"]["gt_label"] for e in events)
    n_tech = sum(1 for e in events if e["_label"]["wa_mitre"])
    print(
        f"[+] {len(events)} sự kiện · {n_tech} có mã kỹ thuật suy ra được "
        f"({100 * n_tech / len(events):.1f}%)"
    )
    for k, v in fams.most_common():
        print(f"      {k:32s} {v}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(events, f, ensure_ascii=False, indent=1)
    print(f"\n[+] -> {args.out}")
    print("[i] Bước sau: scripts/stamp_demo_ids.py để tách nhãn `_label` sang sidecar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
