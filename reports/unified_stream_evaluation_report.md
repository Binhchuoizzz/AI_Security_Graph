# Báo Cáo: Đánh Giá Luồng Gộp Thống Nhất (Unified Streaming Evaluation)

> **Thay thế** phương pháp 3 luồng tách rời. Gộp CICIDS + DAPT2020 + Zero-day vào **một luồng sắp theo thời gian**, stream tăng dần qua hệ thống thật (Tier-1 + Welford + Threat Memory) với **bộ nhớ khởi tạo sạch**.

> **Sinh lúc:** 2026-06-11T10:00:26

---

## 0. Luồng dữ liệu

- Warmup benign (học baseline Welford): **300**
- Sự kiện luồng chính (CICIDS tấn công + DAPT + zero-day): **4294**
- DAPT chuỗi: **9** | IP là APT thật (≥2 ngày tấn công): **3**

## 1. Phân loại ở TẦNG LỌC Tier-1 (gate) trên luồng trộn

> Đây là số của **riêng tầng Tier-1** (rule tĩnh + Welford), tức cổng lọc thô. Tier-1 cố tình chỉ chặn phần tấn công lộ rõ ở tầng mạng và **đẩy phần tinh vi lên Tier-2** (vì vậy recall ở đây thấp là đúng thiết kế). F1 của TOÀN hệ thống (Tier-1 + LLM) được đo ở Ablation `Config F`.

| Metric (Tier-1 gate) | Giá trị |
| :--- | :---: |
| F1 | **0.6487** |
| Accuracy | 0.506 |
| Precision | 0.9572 |
| Recall (attack) | 0.4905 |
| TP / FP / TN / FN | 1946 / 87 / 213 / 2021 |

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

Tổng: **3** | Welford bắt được (mà static bỏ sót): **3/3**

| ID | Kịch bản | Rule tĩnh (Config A) | Full Tier-1 (Welford) | Z-Score |
| :--- | :--- | :---: | :---: | :---: |
| ZD-001 | Zero-Day Exfil (Flow-Duration outlier) | DROP (bỏ sót) | **ESCALATE** | 25815.06 ✅ |
| ZD-002 | Zero-Day Beacon (Flow-Pkts/s outlier) | DROP (bỏ sót) | **ESCALATE** | 30470.55 ✅ |
| ZD-003 | Zero-Day Tunnel (Bwd-volume outlier) | DROP (bỏ sót) | **ESCALATE** | 40627.62 ✅ |

---

## Kết luận

Một luồng thống nhất chứng minh đồng thời 3 năng lực trên cùng dòng thời gian thực tế: (1) phân loại Tier-1, (2) phát hiện APT **nổi lên dần** từ bộ nhớ sạch (đã loại bỏ tính circular của phương pháp nạp-sẵn cũ), và (3) bắt zero-day outlier mà luật tĩnh bỏ sót. Tầng LLM (Tier-2) + Tier-Consensus Guard được đánh giá ở `evaluate_adversarial_pipeline.py`.
