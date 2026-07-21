"""Ánh xạ chữ ký WAF của Tier-1 sang phân loại CHUẨN CÔNG NGHIỆP.

MỤC ĐÍCH (câu hỏi phản biện): "29 họ chữ ký này do các anh tự nghĩ ra, lấy gì bảo đảm nó
phủ đúng thứ cần phủ?" Bảng dưới neo từng họ vào hai khung tham chiếu công khai:

  * **OWASP CRS 3.3** — bộ luật WAF chuẩn công nghiệp, tổ chức theo file `REQUEST-9xx-*`.
    Tên file là định danh ỔN ĐỊNH của CRS 3.x (không phải số hiệu luật riêng lẻ, vốn thay
    đổi giữa các bản vá — cố ý neo ở mức FILE để không trích dẫn số hiệu không kiểm chứng).
  * **OWASP Top 10:2021** — phân loại rủi ro ứng dụng web.

TRUNG THỰC VỀ PHẠM VI: một số họ chữ ký **không có** đối ứng trong CRS, và đó KHÔNG phải
thiếu sót của CRS — CRS là bộ luật cho **giao dịch HTTP**, còn các họ đó là hành vi
endpoint/mạng (ransomware, đào tiền, đánh cắp credential AD, LOLBin, reverse shell, rò rỉ
ra dịch vụ ngoài). Khung đối ứng cho chúng là **Sigma** (luật phát hiện trên log endpoint)
và MITRE ATT&CK. Việc ghi rõ điều này chính là bằng chứng bộ chữ ký phủ RỘNG HƠN phạm vi
một WAF, chứ không phải bịa ra danh mục cho đủ.

Xem thêm: `tests/unit/test_crs_mapping.py` bắt buộc MỌI họ trong `_WAF_PATTERNS` phải có
mục ở đây — thêm chữ ký mà quên ánh xạ thì CI đỏ, không trôi được.
"""

from typing import NamedTuple

CRS_VERSION = "OWASP CRS 3.3"
TOP10_VERSION = "OWASP Top 10:2021"

# Giá trị dùng khi một họ nằm NGOÀI phạm vi CRS (không phải tấn công tầng HTTP).
OUT_OF_CRS_SCOPE = "—"


class CrsRef(NamedTuple):
    """Một dòng ánh xạ: họ chữ ký Tier-1 -> khung tham chiếu công khai."""

    crs_file: str  # file luật CRS 3.3, hoặc OUT_OF_CRS_SCOPE
    owasp_top10: str  # hạng mục OWASP Top 10:2021
    note: str  # vì sao ánh xạ như vậy / khung thay thế nếu ngoài CRS


# Khoá PHẢI khớp CHÍNH XÁC khoá trong `rule_engine._WAF_PATTERNS`.
CRS_MAPPING: dict[str, CrsRef] = {
    # ── Tấn công tiêm nhiễm tầng ứng dụng (CRS phủ trực tiếp) ────────────────────
    "SQL Injection (SQLi)": CrsRef(
        "REQUEST-942-APPLICATION-ATTACK-SQLI", "A03 Injection", "Đối ứng trực tiếp."
    ),
    "SQLi nâng cao (blind/stacked/OS)": CrsRef(
        "REQUEST-942-APPLICATION-ATTACK-SQLI",
        "A03 Injection",
        "Cùng file CRS; ta tách riêng biến thể blind/stacked để log rõ hơn cho analyst.",
    ),
    "Cross-Site Scripting (XSS)": CrsRef(
        "REQUEST-941-APPLICATION-ATTACK-XSS", "A03 Injection", "Đối ứng trực tiếp."
    ),
    "XSS nâng cao (khung/thuộc tính)": CrsRef(
        "REQUEST-941-APPLICATION-ATTACK-XSS",
        "A03 Injection",
        "Cùng file CRS; biến thể qua thuộc tính/khung.",
    ),
    "Path Traversal / LFI": CrsRef(
        "REQUEST-930-APPLICATION-ATTACK-LFI", "A01 Broken Access Control", "Đối ứng trực tiếp."
    ),
    "Sensitive File Access": CrsRef(
        "REQUEST-930-APPLICATION-ATTACK-LFI",
        "A01 Broken Access Control",
        "Truy cập tệp nhạy cảm là biểu hiện của LFI/đọc tệp trái phép.",
    ),
    "Command Injection": CrsRef(
        "REQUEST-932-APPLICATION-ATTACK-RCE", "A03 Injection", "Đối ứng trực tiếp."
    ),
    "Web Shell / Code Execution": CrsRef(
        "REQUEST-933-APPLICATION-ATTACK-PHP",
        "A03 Injection",
        "CRS tách web shell PHP riêng; RCE tổng quát ở 932.",
    ),
    "Web shell qua tệp tải lên": CrsRef(
        "REQUEST-933-APPLICATION-ATTACK-PHP",
        "A08 Software and Data Integrity Failures",
        "Tải lên tệp thực thi được — CRS phủ phần payload PHP.",
    ),
    "XXE Injection": CrsRef(
        "REQUEST-944-APPLICATION-ATTACK-JAVA",
        "A05 Security Misconfiguration",
        "XXE thường qua parser XML (Java/PHP); CRS phủ trong nhóm 944 và 920.",
    ),
    "SSTI (Template Injection)": CrsRef(
        "REQUEST-934-APPLICATION-ATTACK-GENERIC", "A03 Injection", "Nhóm tiêm nhiễm tổng quát."
    ),
    "SSRF / Cloud Metadata": CrsRef(
        "REQUEST-934-APPLICATION-ATTACK-GENERIC",
        "A10 Server-Side Request Forgery",
        "SSRF có hạng mục Top 10 RIÊNG (A10) — bằng chứng ta phủ đúng rủi ro trọng yếu.",
    ),
    "NoSQL Injection": CrsRef(
        "REQUEST-934-APPLICATION-ATTACK-GENERIC", "A03 Injection", "Nhóm tiêm nhiễm tổng quát."
    ),
    "LDAP Injection": CrsRef(
        "REQUEST-921-PROTOCOL-ATTACK", "A03 Injection", "Tiêm nhiễm theo giao thức."
    ),
    "CRLF / Response Splitting": CrsRef(
        "REQUEST-921-PROTOCOL-ATTACK",
        "A03 Injection",
        "CRS xếp response-splitting vào nhóm tấn công giao thức.",
    ),
    "Log4Shell / JNDI Injection": CrsRef(
        "REQUEST-944-APPLICATION-ATTACK-JAVA",
        "A06 Vulnerable and Outdated Components",
        "CVE-2021-44228; CRS phủ ở nhóm Java.",
    ),
    "Insecure Deserialization": CrsRef(
        "REQUEST-944-APPLICATION-ATTACK-JAVA",
        "A08 Software and Data Integrity Failures",
        "Chuỗi gadget deserialization (Java/PHP).",
    ),
    "Prototype Pollution": CrsRef(
        "REQUEST-934-APPLICATION-ATTACK-GENERIC",
        "A03 Injection",
        "Nhóm Node.js/JavaScript trong CRS 3.3.",
    ),
    "JWT / xác thực yếu": CrsRef(
        "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION",
        "A07 Identification and Authentication Failures",
        "alg=none / thao túng token phiên.",
    ),
    "GraphQL lạm dụng": CrsRef(
        "REQUEST-934-APPLICATION-ATTACK-GENERIC",
        "A04 Insecure Design",
        "Introspection / truy vấn lồng sâu — CRS 3.3 phủ hạn chế; là điểm mở rộng của ta.",
    ),
    "Mã hoá né tránh (encoding evasion)": CrsRef(
        "REQUEST-920-PROTOCOL-ENFORCEMENT",
        "A03 Injection",
        "CRS chuẩn hoá đầu vào trước khi khớp luật; ta bắt trực tiếp dấu hiệu né tránh.",
    ),
    "Scanner / Attack Tooling": CrsRef(
        "REQUEST-913-SCANNER-DETECTION", "A05 Security Misconfiguration", "Đối ứng trực tiếp."
    ),
    # ── NGOÀI phạm vi CRS: hành vi endpoint/mạng, khung đối ứng là Sigma ─────────
    "Reverse Shell": CrsRef(
        OUT_OF_CRS_SCOPE,
        "A03 Injection (hậu quả)",
        "Hành vi SAU khai thác, không phải giao dịch HTTP. Khung: Sigma + ATT&CK T1059.",
    ),
    "Encoded PowerShell": CrsRef(
        OUT_OF_CRS_SCOPE,
        OUT_OF_CRS_SCOPE,
        "Thực thi endpoint. Khung: Sigma (process creation) + ATT&CK T1059.001.",
    ),
    "Living-off-the-land (LOLBin)": CrsRef(
        OUT_OF_CRS_SCOPE,
        OUT_OF_CRS_SCOPE,
        "Lạm dụng nhị phân hệ thống hợp lệ. Khung: Sigma + ATT&CK T1218.",
    ),
    "Đánh cắp thông tin xác thực (AD)": CrsRef(
        OUT_OF_CRS_SCOPE,
        "A07 Identification and Authentication Failures",
        "Tấn công Active Directory. Khung: Sigma + ATT&CK TA0006.",
    ),
    "Ransomware / phá huỷ": CrsRef(
        OUT_OF_CRS_SCOPE, OUT_OF_CRS_SCOPE, "Tác động endpoint. Khung: Sigma + ATT&CK TA0040."
    ),
    "Đào tiền mã hoá": CrsRef(
        OUT_OF_CRS_SCOPE, OUT_OF_CRS_SCOPE, "Chiếm dụng tài nguyên. Khung: ATT&CK T1496."
    ),
    "Rò rỉ ra dịch vụ ngoài": CrsRef(
        OUT_OF_CRS_SCOPE,
        "A01 Broken Access Control (hậu quả)",
        "Exfiltration ra dịch vụ ngoài. Khung: Sigma + ATT&CK TA0010.",
    ),
}


def coverage_summary() -> dict[str, int]:
    """Thống kê độ phủ để trích vào luận văn (đếm từ chính bảng, không nhập tay)."""
    in_crs = sum(1 for r in CRS_MAPPING.values() if r.crs_file != OUT_OF_CRS_SCOPE)
    return {
        "total": len(CRS_MAPPING),
        "mapped_to_crs": in_crs,
        "beyond_crs_scope": len(CRS_MAPPING) - in_crs,
        "distinct_crs_files": len(
            {r.crs_file for r in CRS_MAPPING.values() if r.crs_file != OUT_OF_CRS_SCOPE}
        ),
        "distinct_top10": len(
            {r.owasp_top10 for r in CRS_MAPPING.values() if r.owasp_top10 != OUT_OF_CRS_SCOPE}
        ),
    }
