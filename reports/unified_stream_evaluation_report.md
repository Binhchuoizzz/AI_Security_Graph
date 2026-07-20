# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)

> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.

> **Sinh lúc:** 2026-07-20T00:10:01

---

## 0. Luồng dữ liệu (toàn DATA THẬT, trộn xen kẽ)

Mọi sự kiện là data thật (CICIDS từ `ground_truth.json`, DAPT từ `dapt2020_chains.jsonl`); zero-day là biến thể **REAL-DERIVED** — nền là flow benign THẬT, chỉ đẩy **một** feature lên cực trị, rải qua nhiều ngày. Các nguồn được **trộn xen kẽ trong từng ngày** bằng khóa thời gian golden-ratio (không xếp khối theo nguồn); DAPT giữ nguyên ngày thật.

- Warmup benign CICIDS (học baseline Welford): **150**
- Luồng chính trộn (benign nền + tấn công CICIDS + mọi sự kiện DAPT + zero-day): **26521** sự kiện
- DAPT chuỗi: **9** | IP là APT thật (≥2 ngày tấn công): **3**

## 1. Phân loại ở TẦNG LỌC Tier-1 (gate) trên luồng trộn

> Đây là số của **riêng tầng Tier-1** (rule tĩnh + Welford), tức cổng lọc thô. Tier-1 cố tình chỉ chặn phần tấn công lộ rõ ở tầng mạng và **đẩy phần tinh vi lên Tier-2** (vì vậy recall ở đây thấp là đúng thiết kế). F1 của TOÀN hệ thống (Tier-1 + LLM) được đo ở Ablation `Config F`.

| Metric (Tier-1 gate) | Giá trị |
| :--- | :---: |
| F1 | **0.5311** |
| Accuracy | 0.4167 |
| Precision | 0.9237 |
| Recall (attack) | 0.3726 |
| TP / FP / TN / FN | 436 / 36 / 114 / 734 |

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

Tổng: **15** | Welford bắt được (mà static bỏ sót): **12/15**

| ID | Kịch bản | Rule tĩnh (static-only, đối chứng) | Full Tier-1 (Welford) | Z-Score |
| :--- | :--- | :---: | :---: | :---: |
| ZD-008 | Zero-Day C2 Beacon cực nhỏ và ẩn | DROP (bỏ sót) | **DROP** | 2.96 ⚠️ |
| ZD-013 | Zero-Day Burst Fwd packets đột biến | DROP (bỏ sót) | **ESCALATE** | 120.57 ✅ |
| ZD-002 | Zero-Day Beacon tần suất gói cực cao | DROP (bỏ sót) | **ESCALATE** | 5.66 ✅ |
| ZD-009 | Zero-Day Cửa sổ Fwd âm (anomaly) | DROP (bỏ sót) | **DROP** | 0.85 ⚠️ |
| ZD-001 | Zero-Day Exfil khối lượng Bwd cực lớn | DROP (bỏ sót) | **ESCALATE** | 3450.15 ✅ |
| ZD-004 | Zero-Day Phiên kéo dài bất thường (low&slow) | DROP (bỏ sót) | **ESCALATE** | 260.01 ✅ |
| ZD-014 | Zero-Day Time delay khổng lồ | DROP (bỏ sót) | **ESCALATE** | 290.35 ✅ |
| ZD-003 | Zero-Day Tunnel cửa sổ Bwd bất thường | DROP (bỏ sót) | **ESCALATE** | 4342.1 ✅ |
| ZD-010 | Zero-Day Gói SYN liên tục siêu nhỏ | DROP (bỏ sót) | **DROP** | 2.44 ⚠️ |
| ZD-015 | Zero-Day Exfil gián đoạn Bwd burst | DROP (bỏ sót) | **ESCALATE** | 1231.89 ✅ |
| ZD-006 | Zero-Day Payload Fwd khổng lồ | DROP (bỏ sót) | **ESCALATE** | 124287.28 ✅ |
| ZD-011 | Zero-Day Mảnh payload Bwd quá to | DROP (bỏ sót) | **ESCALATE** | 403.28 ✅ |
| ZD-005 | Zero-Day Bùng nổ gói Bwd (volumetric mới) | DROP (bỏ sót) | **ESCALATE** | 94253.08 ✅ |
| ZD-007 | Zero-Day Cửa sổ Fwd dị thường | DROP (bỏ sót) | **ESCALATE** | 3411.99 ✅ |
| ZD-012 | Zero-Day C2 PSH Flag chìm | DROP (bỏ sót) | **ESCALATE** | 20053.69 ✅ |

---

## Kết luận

Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và (3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + Tier-Consensus Guard được đánh giá ở `evaluate_adversarial.py --mode pipeline`.
