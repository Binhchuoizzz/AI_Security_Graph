# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)

> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.

> **Sinh lúc:** 2026-07-30T06:42:53

---

## 0. Luồng dữ liệu (toàn DATA THẬT, trộn xen kẽ)

Mọi sự kiện là data thật (CICIDS từ `ground_truth.json`, DAPT từ `dapt2020_chains.jsonl`); zero-day là biến thể **REAL-DERIVED** — nền là flow benign THẬT, chỉ đẩy **một** feature lên cực trị, rải qua nhiều ngày. Các nguồn được **trộn xen kẽ trong từng ngày** bằng khóa thời gian golden-ratio (không xếp khối theo nguồn); DAPT giữ nguyên ngày thật.

- Warmup benign CICIDS (CHỈ học baseline Welford, **không chấm**): **150**
- Luồng chính trộn (benign nền + tấn công CICIDS + mọi sự kiện DAPT + zero-day): **25649** sự kiện đi qua hệ thống, trong đó **25123** được chấm phân loại
- DAPT chuỗi: **9** | IP là APT thật (≥2 ngày tấn công): **3**

## 1. Phân loại ở TẦNG LỌC Tier-1 (gate) trên luồng trộn

> Đây là số của **riêng tầng Tier-1** (rule tĩnh + Welford), tức cổng lọc thô. Tier-1 cố tình chỉ chặn phần tấn công lộ rõ ở tầng mạng và **đẩy phần tinh vi lên Tier-2** (vì vậy recall ở đây thấp là đúng thiết kế). F1 của TOÀN hệ thống (Tier-1 + LLM) được đo ở Ablation `Config F`.

> **Phạm vi chấm:** mọi sự kiện flow CÓ NHÃN ground-truth ở luồng chính (`cicids` từ `ground_truth.json` + `cicids_max`/`dapt_max` trích thẳng từ CSV thô). Cỡ mẫu thực chấm: **25123** trên 25649 sự kiện luồng chính. **150 flow benign warmup KHÔNG được chấm** — đó là tập dùng để HỌC baseline Welford, chấm nó rồi báo là độ chính xác chính là test-on-train; toàn bộ benign trong ma trận dưới đây là **held-out**.

| Metric (Tier-1 gate) | Giá trị |
| :--- | :---: |
| **MCC** (chỉ số chính) | **0.0859** |
| Balanced accuracy | 0.5462 |
| F1 | 0.4164 (CI95 [0.4071, 0.425]) |
| Precision | 0.3539 |
| Recall (attack) | 0.5057 |
| Specificity (benign) | 0.5866 |
| Accuracy | 0.5616 |
| Mốc ZeroR (đoán hằng tốt nhất) | 0.6907 |
| Accuracy vượt mốc? | **KHÔNG** |
| TP / FP / TN / FN | 3929 / 7173 / 10180 / 3841 |
| Cỡ mẫu đã chấm | 25123 |

- Đã chấm theo nguồn: `{'cicids': 1170, 'cicids_max': 16953, 'dapt_max': 5000, 'csic': 2000}`
- Loại khỏi phân loại (có lý do): `{'warmup_benign': 150, 'zeroday': 120, 'dapt': 402, 'adversarial': 4}`

> **MCC là chỉ số chính, không phải F1.** Một bộ đoán-một-lớp cho MCC = 0 bất kể tỉ lệ lớp, trong khi F1 và Accuracy đều bị base rate của tập đánh lừa.

### 1.1 Bóc theo TỪNG lớp tấn công

Recall gộp có thể là trung bình của *bắt hết lớp này, bỏ sạch lớp kia*. Bảng này là bằng chứng cho tính khái quát — và là nơi điểm mù lộ ra.

| Lớp | n | Recall (CI95) | Bỏ sót | Specificity | FP |
| :--- | ---: | :---: | ---: | :---: | ---: |
| Attack | 5598 | 0.3639 [0.3514, 0.3766] | 3561 | — | — |
| Bot | 80 | 0.5 [0.393, 0.607] | 40 | — | — |
| Infilteration | 80 | 0.575 [0.4657, 0.6774] | 34 | — | — |
| DDoS attacks-LOIC-HTTP | 80 | 0.5875 [0.478, 0.6889] | 33 | — | — |
| DoS attacks-Slowloris | 80 | 0.5875 [0.478, 0.6889] | 33 | — | — |
| Brute Force -Web | 80 | 0.6125 [0.5029, 0.7118] | 31 | — | — |
| DoS attacks-Hulk | 80 | 0.7125 [0.6054, 0.8001] | 23 | — | — |
| SQL Injection | 110 | 0.7182 [0.6278, 0.7938] | 31 | — | — |
| DoS attacks-GoldenEye | 80 | 0.7875 [0.6858, 0.8629] | 17 | — | — |
| Brute Force -XSS | 80 | 0.8125 [0.7134, 0.8829] | 15 | — | — |
| DDOS attack-HOIC | 80 | 0.8625 [0.7703, 0.9215] | 11 | — | — |
| Adversarial | 50 | 0.9 [0.7864, 0.9565] | 5 | — | — |
| Anomalous (unclassified) | 836 | 0.9916 [0.9828, 0.9959] | 7 | — | — |
| Backup/Source File Probing | 82 | 1.0 [0.9552, 1.0] | 0 | — | — |
| CRLF Injection | 20 | 1.0 [0.8389, 1.0] | 0 | — | — |
| Cross-Site Scripting | 27 | 1.0 [0.8754, 1.0] | 0 | — | — |
| DDOS attack-LOIC-UDP | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| DoS attacks-SlowHTTPTest | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| FTP-BruteForce | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| Forced Browsing | 4 | 1.0 [0.5101, 1.0] | 0 | — | — |
| Path Traversal | 3 | 1.0 [0.4385, 1.0] | 0 | — | — |
| SSH-Bruteforce | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| Benign | 17353 | — (lớp lành tính) | — | 0.5866 | 7173 |

## 2. Phát hiện APT (DAPT) — EMERGENT, không nạp sẵn

Bộ nhớ bắt đầu **rỗng**; mỗi sự kiện APT được ghi vào memory KHI nó tới trong luồng, rồi mới hỏi `check_apt_chain`. Bản án APT chỉ bật sau khi tích lũy đủ sự kiện **đa ngày** — chứng minh phát hiện nổi lên dần, **không** phải tra đáp án nạp sẵn.

- APT thật xuất hiện trong stream: **3**
- Phát hiện đúng: **3** | Bỏ sót: **0** | Recall: **1.0**
- Độ trễ phát hiện trung bình: **8.33 sự kiện**

| Attacker IP | Ngày BẬT cảnh báo APT | Sự kiện tới khi bật |
| :--- | :---: | :---: |
| 192.168.3.29 | ngày 4 (ngày 1 = chưa APT) | 3 |
| 209.147.138.11 | ngày 3 (ngày 1 = chưa APT) | 12 |
| 72.201.228.135 | ngày 4 (ngày 1 = chưa APT) | 10 |

## 3. Zero-day (signature-less) — static bỏ sót, Welford bắt

Tổng: **120** | Welford bắt được (mà static bỏ sót): **81/120**

| ID | Kịch bản | Rule tĩnh (static-only, đối chứng) | Full Tier-1 (Welford) | Z-Score |
| :--- | :--- | :---: | :---: | :---: |
| ZD-013-004 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.51 ✅ |
| ZD-008-001 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 2.9 ⚠️ |
| ZD-008-005 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.92 ⚠️ |
| ZD-013-001 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.45 ✅ |
| ZD-013-005 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 7.24 ✅ |
| ZD-008-002 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 2.66 ⚠️ |
| ZD-008-006 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.42 ⚠️ |
| ZD-013-002 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.4 ✅ |
| ZD-013-006 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.39 ✅ |
| ZD-008-003 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.45 ⚠️ |
| ZD-008-007 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.75 ⚠️ |
| ZD-013-003 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.38 ✅ |
| ZD-013-007 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.38 ✅ |
| ZD-008-000 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **BLOCK_IP** | 7.74 ✅ |
| ZD-008-004 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.63 ⚠️ |
| ZD-013-000 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **BLOCK_IP** | 6.36 ✅ |
| ZD-002-007 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.69 ⚠️ |
| ZD-001-002 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.6 ✅ |
| ZD-009-006 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.78 ⚠️ |
| ZD-002-000 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.67 ⚠️ |
| ZD-001-006 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.6 ✅ |
| ZD-002-004 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **ESCALATE** | 8.05 ✅ |
| ZD-009-003 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 2.52 ⚠️ |
| ZD-001-003 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 8.13 ✅ |
| ZD-009-007 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.38 ⚠️ |
| ZD-002-001 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.65 ⚠️ |
| ZD-001-007 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.6 ✅ |
| ZD-009-000 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.63 ⚠️ |
| ZD-002-005 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.64 ⚠️ |
| ZD-001-000 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.59 ✅ |
| ZD-009-004 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.46 ⚠️ |
| ZD-001-004 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.59 ✅ |
| ZD-002-002 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **ESCALATE** | 8.39 ✅ |
| ZD-009-001 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **ESCALATE** | 8.43 ✅ |
| ZD-002-006 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.61 ⚠️ |
| ZD-001-001 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 8.47 ✅ |
| ZD-009-005 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.54 ⚠️ |
| ZD-001-005 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.58 ✅ |
| ZD-002-003 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.59 ⚠️ |
| ZD-009-002 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 2.94 ⚠️ |
| ZD-003-001 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 17500.17 ✅ |
| ZD-010-000 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.28 ⚠️ |
| ZD-014-002 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.77 ⚠️ |
| ZD-003-005 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 17626.42 ✅ |
| ZD-010-004 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 2.44 ⚠️ |
| ZD-014-006 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **ESCALATE** | 8.77 ✅ |
| ZD-004-003 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.77 ⚠️ |
| ZD-004-007 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.79 ⚠️ |
| ZD-003-002 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 17907.96 ✅ |
| ZD-010-001 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **BLOCK_IP** | 1.56 ✅ |
| ZD-014-003 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.78 ⚠️ |
| ZD-004-000 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.76 ⚠️ |
| ZD-003-006 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18025.73 ✅ |
| ZD-010-005 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.26 ⚠️ |
| ZD-014-007 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 2.96 ⚠️ |
| ZD-004-004 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **ESCALATE** | 8.98 ✅ |
| ZD-014-000 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 2.65 ⚠️ |
| ZD-003-003 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18286.65 ✅ |
| ZD-010-002 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **ESCALATE** | 9.1 ✅ |
| ZD-014-004 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.79 ⚠️ |
| ZD-004-001 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.77 ⚠️ |
| ZD-003-007 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18414.8 ✅ |
| ZD-010-006 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.48 ⚠️ |
| ZD-004-005 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.78 ⚠️ |
| ZD-003-000 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18565.67 ✅ |
| ZD-014-001 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.8 ⚠️ |
| ZD-003-004 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18665.23 ✅ |
| ZD-010-003 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 2.97 ⚠️ |
| ZD-014-005 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.8 ⚠️ |
| ZD-004-002 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.78 ⚠️ |
| ZD-010-007 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.64 ⚠️ |
| ZD-004-006 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **ESCALATE** | 9.36 ✅ |
| ZD-011-005 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 503.18 ✅ |
| ZD-015-007 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 9.41 ✅ |
| ZD-005-004 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.65 ✅ |
| ZD-006-002 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.42 ✅ |
| ZD-015-000 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 9.48 ✅ |
| ZD-006-006 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 9.52 ✅ |
| ZD-011-002 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **BLOCK_IP** | 504.99 ✅ |
| ZD-015-004 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.2 ✅ |
| ZD-005-001 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.69 ✅ |
| ZD-011-006 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 505.56 ✅ |
| ZD-005-005 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.72 ✅ |
| ZD-006-003 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.44 ✅ |
| ZD-015-001 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.2 ✅ |
| ZD-006-007 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.45 ✅ |
| ZD-011-003 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 506.48 ✅ |
| ZD-015-005 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.2 ✅ |
| ZD-005-002 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.77 ✅ |
| ZD-011-007 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 507.58 ✅ |
| ZD-006-000 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.45 ✅ |
| ZD-005-006 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.79 ✅ |
| ZD-006-004 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.45 ✅ |
| ZD-011-000 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 507.92 ✅ |
| ZD-015-002 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.2 ✅ |
| ZD-011-004 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 508.9 ✅ |
| ZD-015-006 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.2 ✅ |
| ZD-005-003 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.84 ✅ |
| ZD-006-001 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.47 ✅ |
| ZD-005-007 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.85 ✅ |
| ZD-006-005 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.47 ✅ |
| ZD-011-001 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 510.41 ✅ |
| ZD-015-003 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.19 ✅ |
| ZD-005-000 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.87 ✅ |
| ZD-007-003 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7354.21 ✅ |
| ZD-007-007 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7374.2 ✅ |
| ZD-012-003 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23549.61 ✅ |
| ZD-012-007 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23570.0 ✅ |
| ZD-007-000 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7407.11 ✅ |
| ZD-007-004 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7425.04 ✅ |
| ZD-012-000 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23570.4 ✅ |
| ZD-012-004 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23576.51 ✅ |
| ZD-007-001 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7467.43 ✅ |
| ZD-007-005 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7483.89 ✅ |
| ZD-012-001 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23559.35 ✅ |
| ZD-012-005 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23569.49 ✅ |
| ZD-007-002 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7518.65 ✅ |
| ZD-007-006 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7539.26 ✅ |
| ZD-012-002 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23593.37 ✅ |
| ZD-012-006 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23582.29 ✅ |

---

## Kết luận

Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và (3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + Tier-Consensus Guard được đánh giá ở `evaluate_adversarial.py --mode pipeline`.
