# Chạy & Demo SENTINEL

> Cập nhật 14/08/2026. Tệp này chỉ trả lời: **chạy cái gì, nó làm gì, và dữ liệu của lượt đó
> phân bổ ra sao**. Chỉ số đo đạc xem [DEMO_BY_RQ.md](DEMO_BY_RQ.md); chạy tay từng luồng xem
> [DEMO_FLOWS.md](DEMO_FLOWS.md).
>
> **Đặt `SENTINEL_FREEZE_DYNAMIC_RULES=1` cho MỌI lệnh dưới đây.** Không đặt thì Cổng ML ghi
> hàng trăm luật động thẳng vào `config/system_settings.yaml`, làm bẩn cấu hình dùng chung và
> khiến lượt sau không so được với lượt trước.

---

## 2. Kịch bản demo trước hội đồng

Mỗi luồng chạy độc lập: **chạy → xem → xoá → chạy luồng kế**. Không chồng hai luồng, vì Tier-1
nhớ mặt IP của lượt trước (danh tiếng ≥70 là chặn thẳng, không lên LLM).

### 2.0. Khởi động từ trạng thái sạch

```bash
cd ~/Projects/Thesis/AI_Security_Graph
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --fresh
```

Một lệnh lo hết: bật 4 container, chờ LLM sẵn sàng, `reset_all`, bật đúng 1 subscriber, bật
Dashboard, rồi đẩy trọn luồng. Mở <http://localhost:8501>, đăng nhập `manager`.

Muốn xem lại lượt cũ mà không chạy lại từ đầu thì khôi phục ảnh chụp:

```bash
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --no-push    # chỉ dựng hạ tầng
cp ~/demo_snapshot/audit_trail.db ~/demo_snapshot/threat_memory.db config/
cp ~/demo_snapshot/pipeline_stats.json config/
cp ~/demo_snapshot/guardrails_audit.db ~/demo_snapshot/tier2_trace.jsonl logs/
cp ~/demo_snapshot/system_settings.yaml.demo config/system_settings.yaml   # 145 phiếu HITL
SENTINEL_FREEZE_DYNAMIC_RULES=1 SENTINEL_TIER2_APP_EVIDENCE_ONLY=1 \
  nohup .venv/bin/python main.py --mode server --log-level INFO >> logs/subscriber.log 2>&1 &
```

Khôi phục snapshot xong thì **đừng chạy `reset_all`** — lệnh đó xoá sạch đúng cái vừa khôi phục.

### 2.1. Luồng tổng

```bash
UNIFIED_STREAM_DELAY=0 UNIFIED_STREAM_BATCH=500 \
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --fresh

watch -n2 'jq -c "{raw:.raw_logs_total, llm:.pending_llm_queue}" config/pipeline_stats.json'
```

Đẩy trọn `data/demo.json` qua Tier-1 → Cổng ML → Tier-2. **Xong** = producer in
`[+] Finished streaming …` **và** `pending_llm_queue` về 0 (Tier-2 tiêu hoá hết backlog).

> **Hai biến môi trường ở dòng đầu không phải trang trí.** `scripts/demo.py` mặc định
> `BATCH_SIZE=50` + `BATCH_DELAY=0.3`, tức trần cứng ~167 sự kiện/giây bất kể consumer khoẻ
> đến đâu. Đo ngày 17/08/2026 trên chính máy demo:
>
> | cấu hình | nhịp đẩy đo được | riêng khâu đẩy 496.885 sự kiện |
> | :-- | --: | --: |
> | mặc định (`delay=0,3` · `batch=50`) | 164,8 sk/s | ~50 phút |
> | `delay=0` · `batch=500` | **1.454 sk/s** | **~6 phút** |
>
> Bỏ phanh KHÔNG mất an toàn: `_wait_for_capacity()` đã gác trước mỗi lô bằng vòng phản hồi
> thật — dừng đẩy khi lag consumer-group ≥ 5.000 hoặc backlog LLM ≥ 2.000. `time.sleep(0.3)`
> là cái phanh thứ hai, mù, chồng lên một cái phanh đã biết nhìn. `maxlen=10.000` của stream
> vẫn lớn hơn trần lag 5.000 nên Redis chỉ cắt entry đã ack, không mất sự kiện chưa đọc.
>
> Nghịch lý phải biết: nhánh `--small` (§2.2) đặt sẵn `delay=0,1`, nhánh đầy đủ thì không đặt
> gì nên rơi về `0,3` — bản demo NGẮN đang chạy nhanh gấp 3 lần mỗi sự kiện so với bản đầy đủ.
>
> ⚠️ **Con số "3 giờ 30 phút" trong bản trước là của cấu hình CÓ phanh** và chưa đo lại sau khi
> bỏ. Riêng khâu đẩy giảm từ ~50 phút xuống ~6 phút; tổng thời gian lượt chạy còn phụ thuộc
> Tier-2 tiêu hoá backlog, phần đó chưa đo. Đừng trích một con số tổng nào cho tới khi đo.
>
> ❌ **Đừng dùng lại lệnh theo dõi cũ** `grep -oP 'qsize~\K[0-9]+' logs/subscriber.log`. Chuỗi
> `qsize~` chỉ được in khi có một lô ĐƯỢC ĐẨY SANG TIER-2, mà ~95% luồng là benign nên phần đầu
> lượt chạy không sinh dòng nào. Kết quả rỗng bị đọc nhầm thành "hàng đợi đã về 0, chạy xong" —
> trong khi thực tế mới nạp được vài chục nghìn sự kiện. Đo 17/08/2026 sau 30.650 sự kiện:
> 0 dòng `Enqueue lô`, 0 lượt Tier-2.

`run_demo.sh` đặt sẵn `SENTINEL_TIER2_APP_EVIDENCE_ONLY=1`: Tier-2 chỉ nhận lô có
payload/URI/User-Agent, NetFlow thuần dừng ở ALERT tại Tier-1 (Cổng ML vẫn chặn bình thường).
Cờ đặt bằng biến môi trường, `config/system_settings.yaml` giữ nguyên cả ba cờ demo `false`.
Muốn tái lập benchmark: `SENTINEL_TIER2_APP_EVIDENCE_ONLY=0 ./scripts/run_demo.sh --fresh`.

Xong thì sao lưu để lỡ nghịch hỏng giữa buổi còn khôi phục trong 10 giây:

```bash
mkdir -p ~/demo_snapshot && cp config/audit_trail.db config/threat_memory.db \
   config/pipeline_stats.json logs/tier2_trace.jsonl ~/demo_snapshot/
```

**Phân bổ dữ liệu — `data/demo.json`, 496.885 sự kiện, 100% bản ghi THẬT.** Bảng dưới đếm
thẳng trên tệp theo khoá `unified_source` (14/08/2026), không chép lại từ tài liệu cũ:

| Nguồn | Sự kiện | Tấn công | Vai trò |
| :-- | --: | --: | :-- |
| `cicids_max` — CSE-CIC-IDS2018, 10 ngày | 456.849 | 5.296 | Nền NetFlow, phần lớn benign |
| `csic` — CSIC 2010 HTTP | 36.000 | 18.000 | Tầng bằng chứng ứng dụng (payload thật) |
| `dapt_max` — DAPT2020 khối lượng | 1.500 | 345 | Nền chiến dịch |
| `cicids` — lát ground_truth | 1.250 | 1.170 | Phủ đủ 15 lớp CICIDS có nhãn |
| `adv_llm` — deepset + jackhhao | 730 | 730 | Tiêm nhiễm câu lệnh / jailbreak (AML.T0051) |
| `dapt` — chuỗi DAPT2020 thật | 402 | 324 | 3 chuỗi APT đa ngày |
| `zeroday` — real-derived | 150 | 150 | Probe không chữ ký, Welford bắt |
| `adversarial` — OWASP | 4 | 4 | Payload đối kháng gốc |
| **Tổng** | **496.885** | **26.019** | **5,24% tấn công · 94,76% benign** |

> Hàng `dapt` trước đây ghi **0** tấn công, kèm lý giải "bản án APT nổi lên từ Threat Memory chứ
> không từ nhãn từng sự kiện". Lý giải đó đúng về *cách hệ kết luận*, nhưng sai về *dữ liệu*:
> 324/402 bản ghi có mang `expected_threat`/`apt_is_attack`. Sai số đó kéo tổng xuống 25.695 và
> tỉ lệ xuống 5,17% — lệch với 5,24% mà README ghi. Số trong bảng này là số đếm được.

22 lớp tấn công phân biệt. CSIC nằm ở ngày 2–5 nên **xuất hiện từ vị trí ~92.000** — cắt lát
đầu sẽ không thấy web attack nào; muốn xem tầng ứng dụng nhanh thì dùng `--small` (§2.2).

> 🔴 **Tệp này MỚI HƠN lượt đo xả tải.** Bản 496.885 sự kiện được dựng **12/08/2026**; con số
> xả tải **97,47%** đang trích trong luận văn đo ngày **05/08** trên bản cũ 99.717 sự kiện
> **chưa có CSIC**. `measure_offload_vs_baserate.py --source demo` đọc thẳng tệp này, nên chạy
> lại hôm nay ra số khác — đó là hành vi đúng, không phải lỗi. Chi tiết:
> [DEMO_BY_RQ.md §0](DEMO_BY_RQ.md).

### 2.2. Lát nhỏ

```bash
.venv/bin/python scripts/reset_all.py     # xoá lượt cũ + bật lại đúng 1 subscriber
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --small   # ~10.000 sự kiện, vài phút
```

Dùng khi hội đồng bảo "chạy lại xem". Thiếu tệp thì `run_demo.sh` tự dựng. Dựng tay thì phải
đóng dấu ngay sau đó, đúng thứ tự — không có `gt_id` thì không con số nào đối chiếu được:

```bash
.venv/bin/python scripts/build_demo_small.py
.venv/bin/python scripts/stamp_demo_ids.py --files data/demo_small.json --remint
```

**Phân bổ dữ liệu — `data/demo_small.json`:**

| Nguồn | Tập nhỏ | % nhỏ | % luồng đầy |
| :-- | --: | --: | --: |
| `cicids_max` | 5.659 | 56,6% | 91,9% |
| `csic` | 3.500 | 35,0% | 7,2% |
| `adv_llm` | 500 | 5,0% | 0,15% |
| `cicids` | 122 | 1,2% | 0,25% |
| `dapt` | 115 | 1,2% | 0,08% |
| `dapt_max` | 50 | 0,5% | 0,30% |
| `zeroday` | 50 | 0,5% | 0,03% |
| `adversarial` | 4 | 0,04% | 0,001% |
| **Tổng** | **10.000** | | |

Đây là **tập con phân tầng**, không phải mẫu ngẫu nhiên: các lớp hiếm được bơm thừa có chủ
đích để panel APT và panel quy kết có dữ liệu. Hệ quả phải nói ra nếu bị hỏi — tỉ lệ tấn công
là **30,8%** so với **5,2%** của luồng đầy, nên hồ sơ tải thật nằm ở §2.1 chứ không ở đây.

Giữ được: 22 lớp tấn công · 3 IP APT đa ngày · 250 mẫu CSIC mang mã kỹ thuật.

### 2.3. Đối kháng — tấn công vào chính LLM

```bash
.venv/bin/python scripts/push_flow.py --source adversarial --real-only
```

Nạp payload thẳng vào đường ống để xem lớp bọc dữ liệu chống tiêm nhiễm hoạt động. Mỗi payload
đi từ một IP TEST-NET riêng; log thô được bọc giữa hai data-marker sinh ngẫu nhiên mỗi lượt, nên
nội dung giữa hai mốc là **dữ liệu để phân tích, không phải mệnh lệnh để tuân theo**.

**Phân bổ dữ liệu — kho có 723 mẫu, `--real-only` lấy 603:**

| Nhóm | Số mẫu | Xuất xứ |
| :-- | --: | :-- |
| AdvBench | 200 | công khai |
| jackhhao | 200 | công khai |
| deepset | 203 | công khai |
| **Tổng `--real-only`** | **603** | **dữ liệu thật** |
| `encoding_bypass` · `structural` · `semantic` · `jailbreak` · `rag_poisoning` | 120 | tác giả tự soạn — **bị loại** |

Luôn dùng `--real-only`. **Đừng dùng `--limit 120`**: bộ nạp `sorted(glob)` rồi cắt tiền tố nên
`--limit` chọn theo thứ tự chữ cái, thực tế lấy trọn 120 mẫu AdvBench chứ không phải 120 mẫu
tự soạn như tài liệu cũ ghi.

### 2.4. Sổ kiểm toán chống giả mạo

```bash
# 1. sạch
.venv/bin/python -c "from src.response.executor import verify_audit_trail_integrity as v; print(v())"

# 2. sửa một dòng GIỮA sổ như kẻ tấn công muốn xoá dấu vết
sqlite3 config/audit_trail.db "UPDATE audit_trail SET target='1.1.1.1' \
  WHERE id=(SELECT id FROM audit_trail ORDER BY id LIMIT 1 OFFSET (SELECT COUNT(*)/2 FROM audit_trail));"

# 3. chuỗi gãy, và chỉ đúng dòng gãy
.venv/bin/python -c "from src.response.executor import verify_audit_trail_integrity as v; print(v())"

# 4. khôi phục
cp ~/demo_snapshot/audit_trail.db config/
```

Mỗi dòng ký HMAC và móc vào chữ ký dòng trước, nên sửa một dòng làm hỏng mọi dòng sau. Sửa dòng
**giữa sổ** chứ đừng sửa dòng đầu — nó chứng minh chuỗi chỉ đúng vị trí bị đụng. Khoá lấy từ
`SENTINEL_LOG_SECRET` trong `.env`, không nằm trong mã.

Hai giới hạn phải tự nêu: chuỗi bắt được **sửa** và **chèn** nhưng không bắt được **cắt đuôi**;
và sổ ghi quyết định của **Cổng ML và tác tử LLM**, không ghi lệnh chặn do luật tĩnh Tier-1.

### 2.5. Xoá giữa hai luồng

```bash
.venv/bin/python scripts/reset_all.py                # xoá + bật lại subscriber, vài giây
.venv/bin/python scripts/reset_all.py --dry-run      # xem sẽ xoá gì, KHÔNG đụng dữ liệu
```

Xoá: `audit_trail` · danh tiếng IP · chuỗi APT · `guardrails_audit.db` · `tier2_trace.jsonl` ·
`pipeline_stats.json` · luật động + whitelist · 5 stream Redis · toàn bộ `blacklist:*`.
Giữ: `demo.json` · container · chỉ mục FAISS · đồ thị Neo4j.

Muốn lấy lại dung lượng đĩa thì phải `VACUUM` tường minh — `reset_all` dùng `DELETE` và cả ba DB
đều `auto_vacuum=0` nên tệp không co lại:

```bash
.venv/bin/python scripts/reset_all.py --no-restart   # phải dừng trước, không thì "database is locked"
for db in config/audit_trail.db config/threat_memory.db logs/guardrails_audit.db; do
  [ -f "$db" ] && sqlite3 "$db" "VACUUM;"
done
find logs -maxdepth 1 -type f \( -name '*.log' -o -name '*.jsonl' \) -delete
.venv/bin/python scripts/reset_all.py                # bật lại
```
