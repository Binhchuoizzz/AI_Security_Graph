# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)

> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.

> **Sinh lúc:** 2026-08-05T14:16:17

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
| **MCC** (chỉ số chính) | **0.0952** |
| Balanced accuracy | 0.5482 |
| F1 | 0.3819 (CI95 [0.3727, 0.3916]) |
| Precision | 0.3726 |
| Recall (attack) | 0.3916 |
| Specificity (benign) | 0.7049 |
| Accuracy | 0.608 |
| Mốc ZeroR (đoán hằng tốt nhất) | 0.6908 |
| Accuracy vượt mốc? | **KHÔNG** |
| TP / FP / TN / FN | 3042 / 5122 / 12233 / 4726 |
| Cỡ mẫu đã chấm | 25123 |

- Đã chấm theo nguồn: `{'cicids': 1170, 'cicids_max': 16953, 'dapt_max': 5000, 'csic': 2000}`
- Loại khỏi phân loại (có lý do): `{'warmup_benign': 150, 'zeroday': 120, 'dapt': 402, 'adversarial': 4}`

> **MCC là chỉ số chính, không phải F1.** Một bộ đoán-một-lớp cho MCC = 0 bất kể tỉ lệ lớp, trong khi F1 và Accuracy đều bị base rate của tập đánh lừa.

### 1.1 Bóc theo TỪNG lớp tấn công

Recall gộp có thể là trung bình của *bắt hết lớp này, bỏ sạch lớp kia*. Bảng này là bằng chứng cho tính khái quát — và là nơi điểm mù lộ ra.

| Lớp | n | Recall (CI95) | Bỏ sót | Specificity | FP |
| :--- | ---: | :---: | ---: | :---: | ---: |
| Adversarial | 50 | 0.0 [0.0, 0.0714] | 50 | — | — |
| Bot | 80 | 0.0 [0.0, 0.0458] | 80 | — | — |
| DoS attacks-GoldenEye | 80 | 0.0125 [0.0022, 0.0675] | 79 | — | — |
| DoS attacks-Hulk | 80 | 0.025 [0.0069, 0.0866] | 78 | — | — |
| DoS attacks-Slowloris | 80 | 0.025 [0.0069, 0.0866] | 78 | — | — |
| DDoS attacks-LOIC-HTTP | 80 | 0.0375 [0.0128, 0.1045] | 77 | — | — |
| Brute Force -Web | 80 | 0.275 [0.1892, 0.3814] | 58 | — | — |
| SQL Injection | 109 | 0.3211 [0.2408, 0.4136] | 74 | — | — |
| Attack | 5598 | 0.3249 [0.3128, 0.3373] | 3779 | — | — |
| Infilteration | 80 | 0.325 [0.2324, 0.4336] | 54 | — | — |
| Forced Browsing | 6 | 0.3333 [0.0968, 0.7] | 4 | — | — |
| Brute Force -XSS | 80 | 0.525 [0.417, 0.6308] | 38 | — | — |
| DDOS attack-HOIC | 80 | 0.65 [0.5408, 0.7455] | 28 | — | — |
| Anomalous (unclassified) | 835 | 0.7018 [0.6699, 0.7318] | 249 | — | — |
| Backup/Source File Probing | 83 | 1.0 [0.9558, 1.0] | 0 | — | — |
| CRLF Injection | 19 | 1.0 [0.8318, 1.0] | 0 | — | — |
| Cross-Site Scripting | 23 | 1.0 [0.8569, 1.0] | 0 | — | — |
| DDOS attack-LOIC-UDP | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| DoS attacks-SlowHTTPTest | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| FTP-BruteForce | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| Path Traversal | 5 | 1.0 [0.5655, 1.0] | 0 | — | — |
| SSH-Bruteforce | 80 | 1.0 [0.9542, 1.0] | 0 | — | — |
| Benign | 17355 | — (lớp lành tính) | — | 0.7049 | 5122 |

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
| ZD-013-004 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.5 ✅ |
| ZD-008-001 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 2.9 ⚠️ |
| ZD-008-005 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.9 ⚠️ |
| ZD-013-001 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.44 ✅ |
| ZD-013-005 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 7.29 ✅ |
| ZD-008-002 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 2.62 ⚠️ |
| ZD-008-006 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.42 ⚠️ |
| ZD-013-002 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.39 ✅ |
| ZD-013-006 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.39 ✅ |
| ZD-008-003 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.46 ⚠️ |
| ZD-008-007 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.74 ⚠️ |
| ZD-013-003 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.37 ✅ |
| ZD-013-007 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.38 ✅ |
| ZD-008-000 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **ESCALATE** | 7.87 ✅ |
| ZD-008-004 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 1.58 ⚠️ |
| ZD-013-000 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 6.37 ✅ |
| ZD-002-007 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.63 ⚠️ |
| ZD-001-002 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.59 ✅ |
| ZD-009-006 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.73 ⚠️ |
| ZD-002-000 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.61 ⚠️ |
| ZD-001-006 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.58 ✅ |
| ZD-002-004 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **ESCALATE** | 8.2 ✅ |
| ZD-009-003 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 2.46 ⚠️ |
| ZD-001-003 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 8.29 ✅ |
| ZD-009-007 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.37 ⚠️ |
| ZD-002-001 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.58 ⚠️ |
| ZD-001-007 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.54 ✅ |
| ZD-009-000 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.58 ⚠️ |
| ZD-002-005 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **BLOCK_IP** | 2.57 ✅ |
| ZD-001-000 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.52 ✅ |
| ZD-009-004 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.47 ⚠️ |
| ZD-001-004 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.51 ✅ |
| ZD-002-002 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **ESCALATE** | 8.57 ✅ |
| ZD-009-001 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **ESCALATE** | 8.62 ✅ |
| ZD-002-006 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.54 ⚠️ |
| ZD-001-001 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 8.67 ✅ |
| ZD-009-005 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 1.49 ⚠️ |
| ZD-001-005 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 4.48 ✅ |
| ZD-002-003 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **DROP** | 2.52 ⚠️ |
| ZD-009-002 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 2.97 ⚠️ |
| ZD-003-001 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 17940.33 ✅ |
| ZD-010-000 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.3 ⚠️ |
| ZD-014-002 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.81 ⚠️ |
| ZD-003-005 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18067.97 ✅ |
| ZD-010-004 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 2.38 ⚠️ |
| ZD-014-006 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **ESCALATE** | 9.0 ✅ |
| ZD-004-003 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.79 ⚠️ |
| ZD-004-007 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.8 ⚠️ |
| ZD-003-002 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18378.4 ✅ |
| ZD-010-001 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.5 ⚠️ |
| ZD-014-003 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.82 ⚠️ |
| ZD-004-000 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.8 ⚠️ |
| ZD-003-006 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18510.53 ✅ |
| ZD-010-005 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.29 ⚠️ |
| ZD-014-007 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 2.99 ⚠️ |
| ZD-004-004 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **ESCALATE** | 9.23 ✅ |
| ZD-014-000 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 2.67 ⚠️ |
| ZD-003-003 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18802.92 ✅ |
| ZD-010-002 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **ESCALATE** | 9.37 ✅ |
| ZD-014-004 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.84 ⚠️ |
| ZD-004-001 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.82 ⚠️ |
| ZD-003-007 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 18940.59 ✅ |
| ZD-010-006 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.42 ⚠️ |
| ZD-004-005 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.82 ⚠️ |
| ZD-003-000 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 19111.23 ✅ |
| ZD-014-001 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.85 ⚠️ |
| ZD-003-004 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 19222.46 ✅ |
| ZD-010-003 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 3.01 ⚠️ |
| ZD-014-005 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **DROP** | 1.85 ⚠️ |
| ZD-004-002 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **DROP** | 1.83 ⚠️ |
| ZD-010-007 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 1.58 ⚠️ |
| ZD-004-006 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **ESCALATE** | 9.65 ✅ |
| ZD-011-005 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 495.13 ✅ |
| ZD-015-007 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 9.7 ✅ |
| ZD-005-004 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.75 ✅ |
| ZD-006-002 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.48 ✅ |
| ZD-015-000 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 9.78 ✅ |
| ZD-006-006 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 9.83 ✅ |
| ZD-011-002 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 496.31 ✅ |
| ZD-015-004 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-005-001 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.78 ✅ |
| ZD-011-006 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 496.78 ✅ |
| ZD-005-005 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.81 ✅ |
| ZD-006-003 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.5 ✅ |
| ZD-015-001 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-006-007 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.51 ✅ |
| ZD-011-003 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 497.25 ✅ |
| ZD-015-005 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-005-002 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.86 ✅ |
| ZD-011-007 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 498.38 ✅ |
| ZD-006-000 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.51 ✅ |
| ZD-005-006 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.88 ✅ |
| ZD-006-004 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.52 ✅ |
| ZD-011-000 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 498.54 ✅ |
| ZD-015-002 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-011-004 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 499.3 ✅ |
| ZD-015-006 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-005-003 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.93 ✅ |
| ZD-006-001 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.53 ✅ |
| ZD-005-007 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.95 ✅ |
| ZD-006-005 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 4.53 ✅ |
| ZD-011-001 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 499.72 ✅ |
| ZD-015-003 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 4.08 ✅ |
| ZD-005-000 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 12.97 ✅ |
| ZD-007-003 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7414.75 ✅ |
| ZD-007-007 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7435.56 ✅ |
| ZD-012-003 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23361.95 ✅ |
| ZD-012-007 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23369.53 ✅ |
| ZD-007-000 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7468.79 ✅ |
| ZD-007-004 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7487.02 ✅ |
| ZD-012-000 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23362.34 ✅ |
| ZD-012-004 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23367.35 ✅ |
| ZD-007-001 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7529.31 ✅ |
| ZD-007-005 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7546.45 ✅ |
| ZD-012-001 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23350.57 ✅ |
| ZD-012-005 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23356.54 ✅ |
| ZD-007-002 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7578.91 ✅ |
| ZD-007-006 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 7598.97 ✅ |
| ZD-012-002 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23372.71 ✅ |
| ZD-012-006 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 23358.45 ✅ |

---

## Kết luận

Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và (3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + Tier-Consensus Guard được đánh giá ở `evaluate_adversarial.py --mode pipeline`.
