# Chạy & Demo SENTINEL

> Cập nhật 11/08/2026. Tệp này là **cách vận hành từ đầu tới cuối**.
> Chỉ số đo đạc xem [DEMO_BY_RQ.md](DEMO_BY_RQ.md); luồng nghiệp vụ xem [DEMO_FLOWS.md](DEMO_FLOWS.md).

---

## 1. Cài một lần

```bash
uv venv && uv pip install -r requirements.txt
cp .env.example .env          # điền SENTINEL_LOG_SECRET, NEO4J_PASSWORD
python -m src.rag.embedder    # dựng chỉ mục FAISS + BM25
```

`.env` **phải** có `SENTINEL_LOG_SECRET`. Thiếu nó thì chuỗi HMAC ký bằng khoá mặc định công
khai — vẫn chạy, nhưng chỉ chứng minh *tính nhất quán*, không phải *chống giả mạo*.

---

## 2. Chạy demo — MỘT lệnh

`data/demo.json` nặng ~830 MB nên không track git. Chưa có thì dựng trước, **đúng thứ tự** —
`build_demo.py` đọc `data/csic.json`, chạy ngược thì luồng ra đời với 0 bản ghi CSIC:

```bash
.venv/bin/python scripts/build_csic_dataset.py --limit 36000   # ~1 phút
.venv/bin/python scripts/build_demo.py                         # ~4 phút, ~4 GB RAM
```

Rồi:

```bash
./scripts/run_demo.sh --fresh
```

Lệnh này dựng hạ tầng Docker → chờ LLM cục bộ → `reset_all` → bật Dashboard → đẩy luồng.
Mở **<http://localhost:8501>**, đăng nhập `manager`.

| cờ | tác dụng |
| :-- | :-- |
| `--fresh` | `reset_all` trước khi đẩy: dọn danh tiếng IP, chuỗi APT, luật động, Redis stream |
| `--small` | đẩy `data/demo_small.json` (~10.000 sự kiện) thay vì luồng đầy đủ |
| `--no-push` | chỉ dựng hạ tầng + UI, không đẩy |
| `SENTINEL_LITE=0` | ctx 32.768 / 2 khe (đúng cấu hình đã đo) thay vì 16.384 / 1 khe |

Đẩy một lát ngắn để soi UI nhanh:

```bash
UNIFIED_STREAM_LIMIT=20000 .venv/bin/python scripts/demo.py
```

Tắt để giải phóng RAM:

```bash
pkill -f "main.py --mode server" ; pkill -f "streamlit run" ; docker-compose stop
```

Tier-1 và Cổng ML tiêu thụ luồng ở tốc độ đường truyền; nút cổ chai là Tier-2 (mỗi lô LLM
~13 giây, 2 worker song song). Producer **tự điều tiết**: `demo.py` tạm dừng đẩy khi độ trễ
consumer-group vượt 5.000 hoặc backlog LLM vượt 2.000. Cứ để chạy nền, Dashboard điền dần.

---

## 3. Phân bổ dữ liệu tập demo

`data/demo.json` — **496.885 sự kiện, 100% bản ghi THẬT** (không sinh dữ liệu giả).

### Theo nguồn

| Nguồn | Sự kiện | Tấn công | Vai trò trong demo |
| :-- | --: | --: | :-- |
| `cicids_max` — CSE-CIC-IDS2018, 10 ngày | 456.849 | 6.304 | Nền NetFlow. Phần lớn benign để Tier-1 xử lý tại chỗ |
| `csic` — CSIC 2010 HTTP | 36.000 | 18.000 | **Tầng bằng chứng ứng dụng**: payload thật để chấm quy kết kỹ thuật |
| `dapt_max` — DAPT2020 khối lượng | 1.500 | 345 | Nền chiến dịch |
| `cicids` — lát ground_truth | 1.250 | 1.170 | Phủ đủ 15 lớp CICIDS có nhãn |
| `adv_llm` — deepset + jackhhao | 730 | 730 | Tiêm nhiễm câu lệnh / jailbreak công khai (AML.T0051) |
| `dapt` — chuỗi DAPT2020 thật | 402 | 324 | **9 chuỗi APT đa ngày** cho panel kill-chain |
| `zeroday` — real-derived | 150 | 150 | Probe không chữ ký, Welford bắt |
| `adversarial` — OWASP | 4 | 4 | Payload đối kháng gốc |
| **Tổng** | **496.885** | **26.019** | **5,24% tấn công · 94,76% benign** |

### Theo lớp tấn công (24 nhãn phân biệt)

| Nhóm | Các lớp |
| :-- | :-- |
| Web (CSIC 2010) | Anomalous unclassified 14.762 · Backup/Source File Probing 1.545 · SQL Injection 648 · Cross-Site Scripting 396 · CRLF Injection 390 · Path Traversal 145 · Forced Browsing 114 |
| Mạng (CICIDS2018) | Bot · FTP-BruteForce · SSH-Bruteforce · Infilteration · Brute Force -Web · Brute Force -XSS · SQL Injection · DoS GoldenEye/Hulk/Slowloris/SlowHTTPTest · DDoS LOIC-HTTP/LOIC-UDP/HOIC — mỗi lớp 80 ca |
| Đối kháng AI | Adversarial 50 · prompt injection + jailbreak 730 |
| Chưa nhãn lớp | DAPT 402 (mang nhãn giai đoạn kill-chain thay vì lớp tấn công) |

### Ba điều cần biết trước khi demo

**CSIC xuất hiện từ vị trí ~92.000.** Luồng sắp theo thời gian thật và CSIC nằm ở ngày 2–5,
nên cắt lát đầu (`UNIFIED_STREAM_LIMIT` nhỏ) sẽ **không thấy web attack nào**. Muốn xem tầng
ứng dụng nhanh thì dùng `--small` — `data/demo_small.json` là tập con phân tầng giữ đủ cả 8
nguồn lẫn chuỗi APT.

**Trần dữ liệu đã chạm.** CSIC 2010 còn 36.000 normal / 25.065 anomalous nên 36.000 là mức cao
nhất giữ được cân bằng 50/50. Kho tiêm nhiễm có đúng 730 mẫu (203 deepset + 527 jackhhao) và
`_build_adv_llm` không lặp lại mẫu — xin nhiều hơn cũng chỉ nhận về 730.

**Chặn nhiều hơn drop là bình thường trên tập này.** Đo ở lượt chạy 11/08/2026: `BLOCK_IP` vượt
`DROP` vì trong 100.000 sự kiện đầu có 4.319 IP riêng biệt mà **1.792 IP (41%) từng có ít nhất
một sự kiện tấn công**. CICIDS2018 dùng chung dải IP cho cả lưu lượng lành lẫn tấn công, nên
block-on-sight theo danh tiếng chặn luôn lưu lượng lành sau đó của cùng IP. Tỷ lệ xả tải vẫn
đúng vì cả `BLOCK_IP` lẫn `DROP` đều không tốn token — nhưng nên chủ động nói ra khi trình bày.
