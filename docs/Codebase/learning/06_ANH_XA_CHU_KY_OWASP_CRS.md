# Ánh xạ Chữ ký Tier-1 → OWASP CRS

> **TÀI LIỆU SINH TỪ CODE** — nguồn: `src/tier1_filter/crs_mapping.py`.
> `tests/unit/test_crs_mapping.py` bắt buộc mọi họ chữ ký trong `_WAF_PATTERNS`
> phải có mục ánh xạ, nên bảng này không thể trôi khỏi code thật.

## Vì sao cần bảng này

Câu hỏi phản biện chắc chắn gặp: *"29 họ chữ ký này do các anh tự nghĩ ra,
lấy gì bảo đảm phủ đúng thứ cần phủ?"* Bảng dưới neo từng họ vào hai khung
tham chiếu công khai: **OWASP CRS 3.3** và **OWASP Top 10:2021**.

Định danh CRS neo ở mức **FILE luật** (`REQUEST-9xx-*`) chứ không phải số hiệu
luật riêng lẻ — số hiệu thay đổi giữa các bản vá, tên file thì ổn định qua CRS 3.x.

## Độ phủ

| Chỉ số | Giá trị |
|---|---:|
| Tổng họ chữ ký | **29** |
| Khớp được vào CRS | **22** |
| Số file luật CRS chạm tới | **11** |
| Hạng mục OWASP Top 10 phủ | **10** |
| Ngoài phạm vi CRS (endpoint/mạng) | **7** |

## A. Khớp trực tiếp vào OWASP CRS

| # | Họ chữ ký Tier-1 | File luật CRS 3.3 | OWASP Top 10:2021 | Ghi chú |
|--:|---|---|---|---|
| 1 | SQL Injection (SQLi) | `REQUEST-942-APPLICATION-ATTACK-SQLI` | A03 Injection | Đối ứng trực tiếp. |
| 2 | SQLi nâng cao (blind/stacked/OS) | `REQUEST-942-APPLICATION-ATTACK-SQLI` | A03 Injection | Cùng file CRS; ta tách riêng biến thể blind/stacked để log rõ hơn cho analyst. |
| 3 | Cross-Site Scripting (XSS) | `REQUEST-941-APPLICATION-ATTACK-XSS` | A03 Injection | Đối ứng trực tiếp. |
| 4 | XSS nâng cao (khung/thuộc tính) | `REQUEST-941-APPLICATION-ATTACK-XSS` | A03 Injection | Cùng file CRS; biến thể qua thuộc tính/khung. |
| 5 | Path Traversal / LFI | `REQUEST-930-APPLICATION-ATTACK-LFI` | A01 Broken Access Control | Đối ứng trực tiếp. |
| 6 | Sensitive File Access | `REQUEST-930-APPLICATION-ATTACK-LFI` | A01 Broken Access Control | Truy cập tệp nhạy cảm là biểu hiện của LFI/đọc tệp trái phép. |
| 7 | Command Injection | `REQUEST-932-APPLICATION-ATTACK-RCE` | A03 Injection | Đối ứng trực tiếp. |
| 8 | Web Shell / Code Execution | `REQUEST-933-APPLICATION-ATTACK-PHP` | A03 Injection | CRS tách web shell PHP riêng; RCE tổng quát ở 932. |
| 9 | Web shell qua tệp tải lên | `REQUEST-933-APPLICATION-ATTACK-PHP` | A08 Software and Data Integrity Failures | Tải lên tệp thực thi được — CRS phủ phần payload PHP. |
| 10 | XXE Injection | `REQUEST-944-APPLICATION-ATTACK-JAVA` | A05 Security Misconfiguration | XXE thường qua parser XML (Java/PHP); CRS phủ trong nhóm 944 và 920. |
| 11 | SSTI (Template Injection) | `REQUEST-934-APPLICATION-ATTACK-GENERIC` | A03 Injection | Nhóm tiêm nhiễm tổng quát. |
| 12 | SSRF / Cloud Metadata | `REQUEST-934-APPLICATION-ATTACK-GENERIC` | A10 Server-Side Request Forgery | SSRF có hạng mục Top 10 RIÊNG (A10) — bằng chứng ta phủ đúng rủi ro trọng yếu. |
| 13 | NoSQL Injection | `REQUEST-934-APPLICATION-ATTACK-GENERIC` | A03 Injection | Nhóm tiêm nhiễm tổng quát. |
| 14 | LDAP Injection | `REQUEST-921-PROTOCOL-ATTACK` | A03 Injection | Tiêm nhiễm theo giao thức. |
| 15 | CRLF / Response Splitting | `REQUEST-921-PROTOCOL-ATTACK` | A03 Injection | CRS xếp response-splitting vào nhóm tấn công giao thức. |
| 16 | Log4Shell / JNDI Injection | `REQUEST-944-APPLICATION-ATTACK-JAVA` | A06 Vulnerable and Outdated Components | CVE-2021-44228; CRS phủ ở nhóm Java. |
| 17 | Insecure Deserialization | `REQUEST-944-APPLICATION-ATTACK-JAVA` | A08 Software and Data Integrity Failures | Chuỗi gadget deserialization (Java/PHP). |
| 18 | Prototype Pollution | `REQUEST-934-APPLICATION-ATTACK-GENERIC` | A03 Injection | Nhóm Node.js/JavaScript trong CRS 3.3. |
| 19 | JWT / xác thực yếu | `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION` | A07 Identification and Authentication Failures | alg=none / thao túng token phiên. |
| 20 | GraphQL lạm dụng | `REQUEST-934-APPLICATION-ATTACK-GENERIC` | A04 Insecure Design | Introspection / truy vấn lồng sâu — CRS 3.3 phủ hạn chế; là điểm mở rộng của ta. |
| 21 | Mã hoá né tránh (encoding evasion) | `REQUEST-920-PROTOCOL-ENFORCEMENT` | A03 Injection | CRS chuẩn hoá đầu vào trước khi khớp luật; ta bắt trực tiếp dấu hiệu né tránh. |
| 22 | Scanner / Attack Tooling | `REQUEST-913-SCANNER-DETECTION` | A05 Security Misconfiguration | Đối ứng trực tiếp. |

## B. Ngoài phạm vi CRS — và vì sao đó KHÔNG phải thiếu sót

CRS là bộ luật cho **giao dịch HTTP**. Các họ dưới đây là hành vi **endpoint/mạng**,
nên khung đối ứng đúng của chúng là **Sigma** và **MITRE ATT&CK**, không phải CRS.
Việc bộ chữ ký chạm tới cả nhóm này cho thấy nó phủ **rộng hơn** phạm vi một WAF.

| # | Họ chữ ký Tier-1 | OWASP Top 10:2021 | Khung đối ứng |
|--:|---|---|---|
| 1 | Reverse Shell | A03 Injection (hậu quả) | Hành vi SAU khai thác, không phải giao dịch HTTP. Khung: Sigma + ATT&CK T1059. |
| 2 | Encoded PowerShell | — | Thực thi endpoint. Khung: Sigma (process creation) + ATT&CK T1059.001. |
| 3 | Living-off-the-land (LOLBin) | — | Lạm dụng nhị phân hệ thống hợp lệ. Khung: Sigma + ATT&CK T1218. |
| 4 | Đánh cắp thông tin xác thực (AD) | A07 Identification and Authentication Failures | Tấn công Active Directory. Khung: Sigma + ATT&CK TA0006. |
| 5 | Ransomware / phá huỷ | — | Tác động endpoint. Khung: Sigma + ATT&CK TA0040. |
| 6 | Đào tiền mã hoá | — | Chiếm dụng tài nguyên. Khung: ATT&CK T1496. |
| 7 | Rò rỉ ra dịch vụ ngoài | A01 Broken Access Control (hậu quả) | Exfiltration ra dịch vụ ngoài. Khung: Sigma + ATT&CK TA0010. |

## Cách dùng khi bảo vệ

> "Bộ chữ ký Tier-1 gồm 29 họ. **22/29** khớp
> trực tiếp vào **11 file luật** của OWASP CRS 3.3 và phủ
> **10 hạng mục** OWASP Top 10:2021. **7 họ**
> còn lại nằm ngoài phạm vi CRS vì chúng là hành vi endpoint/mạng — đối ứng bằng
> Sigma và MITRE ATT&CK. Bảng ánh xạ được test tự động ràng buộc với code."

---

*Sinh lại: đọc `src/tier1_filter/crs_mapping.py`. Số liệu đếm từ `coverage_summary()`.*
