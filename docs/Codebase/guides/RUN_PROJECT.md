# Chạy & Demo SENTINEL

> Cập nhật 11/08/2026. Tệp này là **cách vận hành từ đầu tới cuối**.
> Chỉ số đo đạc xem [DEMO_BY_RQ.md](DEMO_BY_RQ.md); luồng nghiệp vụ xem [DEMO_FLOWS.md](DEMO_FLOWS.md).

---

## 1. Cài một lần

```bash
uv venv && uv pip install -r requirements.txt
cp .env.example .env          # điền SENTINEL_LOG_SECRET, NEO4J_PASSWORD, REDIS_PASSWORD
python -m src.rag.embedder    # dựng chỉ mục FAISS + BM25
```

`.env` **phải** có `SENTINEL_LOG_SECRET`. Thiếu nó thì chuỗi HMAC ký bằng khoá mặc định công
khai — vẫn chạy, nhưng chỉ chứng minh *tính nhất quán*, không phải *chống giả mạo*.

---

## 2. Chạy demo

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
| `--fresh` | `reset_all` trước khi đẩy: dừng producer cũ, dọn danh tiếng IP, chuỗi APT, luật động, Redis stream |
| `--small` | đẩy `data/demo_small.json` (~10.000 sự kiện) thay vì luồng đầy đủ |
| `--no-push` | chỉ dựng hạ tầng + UI, không đẩy |
| `SENTINEL_LITE=0` | ctx 32.768 / 2 khe (đúng cấu hình đã đo) thay vì 16.384 / 1 khe |

Đẩy một lát ngắn để soi UI nhanh:

```bash
UNIFIED_STREAM_LIMIT=20000 .venv/bin/python scripts/demo.py
```

Dừng và dọn: xem [§5 Xoá sạch](#5-xoá-sạch-ba-mức).

### Núm điều tiết thông lượng

Mặc định trong mã giữ nguyên giá trị của mọi phép đo đã công bố. Bốn biến dưới đây chỉ đổi
**tốc độ**, không đổi phán quyết:

| biến | mặc định | cho luồng 500k | tác dụng |
| :-- | --: | --: | :-- |
| `UNIFIED_STREAM_DELAY` | `0.3` | `0.0` | Độ trễ giữa hai lô đẩy. Mặc định khoá cứng producer ở ~166 sự kiện/giây bất kể consumer nhanh cỡ nào |
| `UNIFIED_STREAM_BATCH` | `50` | `1000` | Số sự kiện mỗi lượt `xadd` pipeline |
| `SENTINEL_READ_COUNT` | `500` | `500` | Số message mỗi lượt `xreadgroup`. **Tách khỏi** kích thước lô Tier-2 |
| `SENTINEL_BATCH_TIMEOUT` | `5` | `30` | Giây im lặng trước khi xả lô đang gom. Quá ngắn thì lô toàn 1–2 phần tử, nhân số lượt gọi LLM lên nhiều lần |

Backpressure tự bảo vệ: producer dừng khi độ trễ consumer-group vượt `UNIFIED_STREAM_MAX_LAG`
(5.000) hoặc backlog LLM vượt `UNIFIED_STREAM_MAX_LLM_BACKLOG` (2.000). Cứ để chạy nền.

### Kiến trúc ML-trước (bật cho buổi diễn)

Ba cờ trong `config/system_settings.yaml`. **Mặc định TẮT trong mã** — mọi số RQ1/Tier-2 của
luận văn đo theo kiến trúc phễu cũ, nên phải tắt lại trước khi chạy benchmark:

| cờ | tác dụng |
| :-- | :-- |
| `tier1.ml_gate_all_events` | Cổng ML chấm **mọi** sự kiện trước Tier-2, và phán quyết chặn suy-từ-luồng của luật tĩnh phải qua nó thay vì chốt cứng |
| `tier2.require_application_evidence` | Lô không có payload/URI/User-Agent dừng ở ALERT, không lên LLM. Đồng thời cấm Cổng ML dùng `DROP` phủ quyết bằng chứng tầng ứng dụng |
| `tier1.demo_escalate_waf_prefixes` | Dải `198.19.` được **leo thang** thay vì chặn, để Tier-2 có ca payload quy kết được. Chỉ đổi đích đến, không đụng payload/nhãn/mã |

### Sửa mã mà UI không đổi?

Dashboard chạy trong container. Streamlit chạy lại `app.py` khi tệp đổi nhưng **giữ nguyên
module đã import**, nên sửa bất cứ thứ gì ngoài `app.py` sẽ cho UI chạy nửa mới nửa cũ (biểu
hiện điển hình: `TypeError: ... takes from 0 to 1 positional arguments but 2 were given`).
Mã được mount vào container nên chỉ cần:

```bash
docker restart sentinel_dashboard
```

---

## 3. Phân bổ dữ liệu tập demo

`data/demo.json` — **496.885 sự kiện, 100% bản ghi THẬT** (không sinh dữ liệu giả).

### Theo nguồn

| Nguồn | Sự kiện | Tấn công | Vai trò trong demo |
| :-- | --: | --: | :-- |
| `cicids_max` — CSE-CIC-IDS2018, 10 ngày | 456.849 | 6.304 | Nền NetFlow. Phần lớn benign để Tier-1 + Cổng ML xử lý tại chỗ |
| `csic` — CSIC 2010 HTTP | 36.000 | 18.000 | **Tầng bằng chứng ứng dụng**: payload thật để chấm quy kết kỹ thuật |
| `dapt_max` — DAPT2020 khối lượng | 1.500 | 345 | Nền chiến dịch |
| `cicids` — lát ground_truth | 1.250 | 1.170 | Phủ đủ 15 lớp CICIDS có nhãn |
| `adv_llm` — deepset + jackhhao | 730 | 730 | Tiêm nhiễm câu lệnh / jailbreak công khai (AML.T0051) |
| `dapt` — chuỗi DAPT2020 thật | 402 | 324 | **9 chuỗi APT đa ngày** cho panel kill-chain |
| `zeroday` — real-derived | 150 | 150 | Probe không chữ ký, Welford bắt |
| `adversarial` — OWASP | 4 | 4 | Payload đối kháng gốc |
| **Tổng** | **496.885** | **26.019** | **5,24% tấn công · 94,76% benign** |

### Theo lớp tấn công (22 nhãn phân biệt)

| Nhóm | Các lớp |
| :-- | :-- |
| Web (CSIC 2010) | Anomalous unclassified 14.762 · Backup/Source File Probing 1.545 · SQL Injection 648 · Cross-Site Scripting 396 · CRLF Injection 390 · Path Traversal 145 · Forced Browsing 114 |
| Mạng (CICIDS2018) | Bot · FTP-BruteForce · SSH-Bruteforce · Infilteration · Brute Force -Web · Brute Force -XSS · SQL Injection · DoS GoldenEye/Hulk/Slowloris/SlowHTTPTest · DDoS LOIC-HTTP/LOIC-UDP/HOIC — mỗi lớp 80 ca |
| Đối kháng AI | Adversarial 50 · prompt injection + jailbreak 730 |
| Chưa nhãn lớp | DAPT 402 (mang nhãn giai đoạn kill-chain thay vì lớp tấn công) |

### Thứ tự và gom IP — hai thứ quyết định trải nghiệm demo

**80% benign chạy đệm trước**, 20% còn lại trộn đều với toàn bộ tấn công; sự kiện tấn công đầu
tiên ở vị trí **#376.725 (75,8% luồng)**. Tách đôi cứng thì ca tấn công đầu tiên rơi xuống tận
vị trí #470.866 (94,8%) — demo trống trơn rồi một bức tường tấn công dồn ở cuối.

**Lát dàn dựng gom vào 90 IP (`198.19.x`), nhóm tiêm nhiễm vào 65 IP (`198.18.x`).** Tier-2
gộp lô **theo IP nguồn**: xả khi đủ 10 log, *hoặc* khi IP đó im lặng quá
`SENTINEL_BATCH_TIMEOUT` giây. Cấp mỗi mẫu một IP riêng thì 1.500 mẫu thành 1.500 lô
một-phần-tử — mỗi lô một lượt gọi LLM ~18 giây, tức ~2,8 giờ GPU cho đúng một lát dữ liệu.

**Trần cứng 1 lô/IP/60 giây.** Khi một IP xả lô, hệ thống cắm cờ `pending_ai:{ip}` sống 60
giây; trong cửa sổ đó MỌI sự kiện tiếp theo của IP ấy bị **nén thẳng**, không vào bộ đệm.
Nên số lô tối đa của một đợt dồn = **số IP**, không phải số mẫu ÷ 10. Đo ở lượt chạy
11/08/2026: 90 IP dàn dựng × 100 mẫu chỉ ra **91 lô** (8.166 mẫu bị nén), trong khi 65 IP
tiêm nhiễm × **đúng 10 mẫu** ra trọn 64 lô — không mẫu nào bị nén. Muốn N lô thì cấp N IP,
mỗi IP 10 mẫu.

**Bộ đệm gom lô không có trần.** Mỗi IP đang leo thang giữ tối đa 9 log (log thứ 10 xả
ngay), đo được 11,5 KB/log, nên 10.000 IP leo thang đồng thời ≈ 1 GB. Kịch bản demo không
chạm tới (chỉ ~0,2% lưu lượng leo thang), nhưng một triển khai thật gặp DDoS phân tán
nguồn thì có.

### Ba điều cần biết trước khi demo

**CSIC xuất hiện từ vị trí ~92.000.** Luồng sắp theo thời gian thật và CSIC nằm ở ngày 2–5,
nên cắt lát đầu (`UNIFIED_STREAM_LIMIT` nhỏ) sẽ **không thấy web attack nào**. Muốn xem tầng
ứng dụng nhanh thì dùng `--small`.

**Trần dữ liệu đã chạm.** CSIC 2010 còn 36.000 normal / 25.065 anomalous nên 36.000 là mức cao
nhất giữ được cân bằng 50/50. Kho tiêm nhiễm có đúng 730 mẫu (203 deepset + 527 jackhhao) và
`_build_adv_llm` không lặp lại mẫu — xin nhiều hơn cũng chỉ nhận về 730.

**Chặn nhiều hơn drop, và nên chủ động nói ra.** CICIDS2018 dùng chung dải IP cho cả lưu lượng
lành lẫn tấn công. Một lệnh chặn đúng vào IP tấn công sẽ chặn luôn lưu lượng lành sau đó của
cùng IP — đo ở lượt chạy 11/08/2026, hệ số khuếch đại là **~19 gói lành cho mỗi lệnh chặn**.
Tỷ lệ xả tải vẫn đúng vì cả `BLOCK_IP` lẫn `DROP` đều không tốn token, nhưng đây là hạn chế
của **tập dữ liệu**, không phải của hệ thống, và trình bày thì nên nêu thẳng.

---

## 4. Số đo của lượt chạy tham chiếu

Lượt 11/08/2026, `ml_gate_all_events` + `require_application_evidence` bật, 2 worker Tier-2,
llama.cpp 2 khe. **Đây là số vận hành của buổi diễn, KHÔNG phải số benchmark của luận văn** —
benchmark chạy theo kiến trúc phễu mặc định, xem `experiments/results/`.

| Chỉ số | Giá trị |
| :-- | --: |
| Sự kiện xử lý | 496.885 / 496.885 (100,00%) |
| Thông lượng ổn định | ~327 sự kiện/giây (~25 phút cho trọn luồng) |
| Xả tải LLM | **99,58%** — 2.084 sự kiện thật sự tới LLM |
| Lô Tier-2 | 553 (trung bình 3,8 log/lô) |
| Lô mang bằng chứng ứng dụng | **301/301 (100%)** |
| Tier-2: chặn / chuyển người / cảnh báo | 351 / 183 / 19 — **63,5% / 33,1% / 3,4%** |
| Thời gian trung vị mỗi lô Tier-2 | 17,7 giây (p95 22,3) |
| Tràn ngữ cảnh | 0/300 lô |
| Redis: khoá bị đuổi | **0** |

### Chất lượng quy kết của lượt này — và bốn bản vá sau đó

Đối chiếu với nhãn thật CSIC (nối bằng khoá **nội dung**, không nối bằng `csic_index` —
trường đó **trùng**: 36.000 bản ghi chỉ có 18.000 chỉ số, mỗi chỉ số dùng lại cho một bản
ghi lành và một bản ghi bất thường):

- **T1571 "Non-Standard Port" chiếm 139/327 quy kết (42,5%)**, trong đó 136 lệnh chặn ở độ
  tin cậy 0,93. Nhãn thật của chúng: **254 bản ghi Benign**.
- **136 lô một-log bị chặn — 0 đúng, 136 nhầm (0,0%).** Lô một-log chấm được tuyệt đối vì
  log đại diện chính là cả lô.
- Nguyên nhân gốc nằm ở **truy vấn RAG**, không ở LLM: 336 lô chỉ sinh 44 truy vấn phân
  biệt, 187 lô (55,7%) dùng chung một chuỗi không mang tín hiệu tấn công nào. RAG chỉ trả
  về được kỹ thuật tầng mạng; **T1190 không có mặt để LLM chọn**. Lá chắn "neo bằng chứng"
  đóng dấu hợp lệ 139/139 vì T1571 *có* trong tài liệu đã truy xuất — nó xác nhận model
  chọn đúng trong thực đơn, không biết thực đơn sai.

Bốn bản vá đã vào mã sau lượt chạy này (`nodes.py`, `attack_mapper.py`, `rule_engine.py`):

1. `match_waf_family` tách ra mức module — Tier-2 **soi lại chữ ký WAF của Tier-1** trên
   chính lô khi `tier1_reasons` không mang từ vựng tấn công (đường z-score).
2. Từ vựng "brute force" chỉ sinh khi có **≥3 lần** gửi thông tin xác thực trong một lô;
   mẫu cũ khớp mọi biểu mẫu đăng ký hợp lệ.
3. Lô không suy ra được từ vựng tấn công đặc trưng bị **chặn trần tự-tin xuống dải ALERT**
   — không chặn, không chất việc cho người, và `raise_alert` vẫn tự leo thang lên `BLOCK_IP`
   nếu IP đó quay lại.
4. Lá chắn T1571 hỏi "có dấu hiệu kênh điều khiển không?" thay vì "payload có rỗng không?".

Phát lại ngoại tuyến trên CSIC thật, cỡ lô 10 (đúng cỡ Tier-2 dùng):

| | giữ quyền chặn |
| :-- | --: |
| lô 10 log **tấn công** | 1.756/1.800 = **97,6%** |
| lô 10 log **lành** | 0/1.800 = **0,0%** |

Trên chính 553 lô của lượt chạy: **229/229 lệnh chặn nhầm ở dải `198.51.x` bị hạ xuống
ALERT**, và 0 lệnh chặn đúng nào bị mất ở đó (vì không có lệnh nào đúng).

**Số Tier-2 trong bảng trên là TRƯỚC bản vá.** Phân bố phán quyết sẽ đổi ở lượt sau — chạy
lại rồi mới trích dẫn.

Hàng đợi Tier-2 tiêu hoá tiếp sau khi đẩy xong — đó là thiết kế: vòng đọc Redis và Tier-1
không bao giờ bị LLM chậm chặn lại.

---

## 5. Xoá sạch: ba mức

Ba mức tách nhau vì chúng tốn ba khoảng thời gian rất khác nhau để dựng lại. Chọn mức thấp
nhất giải quyết được việc đang cần.

| mức | xoá gì | dựng lại tốn |
| :-- | :-- | :-- |
| 1 — reset giữa hai lượt | trạng thái ứng dụng | vài giây |
| 2 — thu hồi đĩa | mức 1 + dung lượng tệp `.db` và log | vài giây |
| 3 — xoá sạch | mức 2 + `demo.json`, container, volume Docker | ~10 phút + ~5 phút dựng luồng |

### Mức 1 — reset giữa hai lượt chạy

```bash
.venv/bin/python scripts/reset_all.py               # dọn xong bật lại subscriber
.venv/bin/python scripts/reset_all.py --no-restart  # chỉ dọn, không bật lại
.venv/bin/python scripts/reset_all.py --dry-run     # in ra sẽ xoá gì, KHÔNG đụng dữ liệu
```

Trình tự **producer → subscriber → dữ liệu** là bắt buộc, không phải thẩm mỹ: một lượt đẩy
còn sống sẽ bơm sự kiện vào giữa lúc đang xoá bảng, và nếu nó sống sót qua reset thì chạy song
song với lượt sau — đúng lỗi đã làm hỏng trọn một lượt đo (516.885/496.885 = 104% sự kiện).

Xoá: bảng `audit_trail` + `login_attempts` · `ip_reputation` + `known_entities` +
`apt_indicators` + `threat_events` · `guardrails_audit.db` · `tier2_trace.jsonl` ·
`pipeline_stats.json` · `tier1_blocks.json` · luật động + whitelist trong
`system_settings.yaml` · 5 khoá Redis (`queue_waf`, `queue_firewall`, `queue_sysmon`,
`queue_decisions`, `queue_hitl`) · toàn bộ `blacklist:*`.

Giữ: `data/demo.json` · container Docker · chỉ mục FAISS · đồ thị Neo4j · **kích thước** tệp
`.db`.

Thêm `--keep-trace` để giữ `logs/tier2_trace.jsonl` khi cần so nhiều lượt trong cùng một
chiến dịch audit. Mặc định là xoá, và đó là chủ ý: hai sink Tier-2 này từng không nằm trong
danh sách dọn nên mọi thống kê Tier-2 đều trộn lẫn các lượt chạy.

### Mức 2 — thu hồi dung lượng đĩa

`reset_all` dùng `DELETE`, và cả ba cơ sở dữ liệu đều `auto_vacuum=0`, nên **tệp không co
lại**. Đo trên bản sao `guardrails_audit.db`:

```text
trước DELETE : 59 MB  (298.247 dòng)
sau   DELETE : 59 MB  (0 dòng)      <- bảng rỗng, đĩa y nguyên
sau   VACUUM : 12 KB
```

Muốn lấy lại đĩa thì phải `VACUUM` tường minh:

```bash
.venv/bin/python scripts/reset_all.py --no-restart
for db in config/audit_trail.db config/threat_memory.db logs/guardrails_audit.db; do
  [ -f "$db" ] && sqlite3 "$db" "VACUUM;"
done
rm -f logs/*.log            # log chạy tích luỹ; hiện ~425 MB
```

Chạy `VACUUM` khi subscriber còn sống sẽ kẹt ở `database is locked` — dừng trước
(`--no-restart`), vacuum, rồi bật lại bằng `reset_all` không cờ.

### Mức 3 — xoá sạch tất cả

```bash
.venv/bin/python scripts/reset_all.py --no-restart
pkill -f "streamlit run"
docker-compose down -v                        # -v xoá LUÔN volume mlflow_data + neo4j_data
rm -f data/demo.json data/demo_small.json     # 830 MB
rm -f logs/*.log logs/*.jsonl
rm -f config/audit_trail.db config/threat_memory.db logs/guardrails_audit.db
```

Ba điều dễ mất mà không nhận ra:

**`down -v` xoá đồ thị Neo4j và lịch sử MLflow.** Chúng nằm trong volume có tên, không nằm
trong thư mục dự án. Dựng lại đồ thị bằng `.venv/bin/python main.py --mode scan` — lệnh này
chạy Trivy + Bandit rồi nạp kết quả vào Neo4j. Neo4j ngoại tuyến thì `graph_builder` ghi
`status: "unavailable"` chứ **không** bịa số đếm nút/cạnh.

**Dùng `docker-compose` (có gạch nối).** Máy này không có plugin `docker compose`.

**`.env` và chỉ mục FAISS không bị đụng** ở cả ba mức. Chỉ dựng lại FAISS
(`python -m src.rag.embedder`) khi đã sửa `knowledge_base/*.json`.

Dựng lại từ số không: [§1](#1-cài-một-lần) rồi [§2](#2-chạy-demo).
