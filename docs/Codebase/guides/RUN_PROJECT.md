# Chạy & Demo SENTINEL

> Cập nhật 12/08/2026. Tệp này là **phân bổ dữ liệu** + **kịch bản demo**.
> Chỉ số đo đạc xem [DEMO_BY_RQ.md](DEMO_BY_RQ.md); chạy tay từng luồng xem
> [DEMO_FLOWS.md](DEMO_FLOWS.md).

---

## 1. Phân bổ dữ liệu tập demo

`data/demo.json` — **496.885 sự kiện, 100% bản ghi THẬT** (không sinh dữ liệu giả).

### Theo nguồn

| Nguồn | Sự kiện | Tấn công | Vai trò trong demo |
| :-- | --: | --: | :-- |
| `cicids_max` — CSE-CIC-IDS2018, 10 ngày | 456.849 | 5.296 | Nền NetFlow. Phần lớn benign để Tier-1 + Cổng ML xử lý tại chỗ |
| `csic` — CSIC 2010 HTTP | 36.000 | 18.000 | **Tầng bằng chứng ứng dụng**: payload thật để chấm quy kết kỹ thuật |
| `dapt_max` — DAPT2020 khối lượng | 1.500 | 345 | Nền chiến dịch |
| `cicids` — lát ground_truth | 1.250 | 1.170 | Phủ đủ 15 lớp CICIDS có nhãn |
| `adv_llm` — deepset + jackhhao | 730 | 730 | Tiêm nhiễm câu lệnh / jailbreak công khai (AML.T0051) |
| `dapt` — chuỗi DAPT2020 thật | 402 | 0 | **9 chuỗi APT đa ngày**; bản án `is_apt` nổi lên từ Threat Memory khi một IP xuất hiện ở ≥2 ngày, không từ nhãn từng sự kiện |
| `zeroday` — real-derived | 150 | 150 | Probe không chữ ký, Welford bắt |
| `adversarial` — OWASP | 4 | 4 | Payload đối kháng gốc |
| **Tổng** | **496.885** | **25.695** | **5,17% tấn công · 94,83% benign** |

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

**Lát dàn dựng gom vào 549 IP (`198.19.x`), nhóm tiêm nhiễm vào 65 IP (`198.18.x`).** Tier-2
gộp lô **theo IP nguồn**: xả khi đủ 10 log, *hoặc* khi IP đó im lặng quá
`SENTINEL_BATCH_TIMEOUT` giây. Cấp mỗi mẫu một IP riêng thì 1.500 mẫu thành 1.500 lô
một-phần-tử — mỗi lô một lượt gọi LLM ~18 giây, tức ~2,8 giờ GPU cho đúng một lát dữ liệu.

**Trần cứng 1 lô/IP/60 giây.** Khi một IP xả lô, hệ thống cắm cờ `pending_ai:{ip}` sống 60
giây; trong cửa sổ đó MỌI sự kiện tiếp theo của IP ấy bị **nén thẳng**, không vào bộ đệm.
Nên số lô tối đa của một đợt dồn = **số IP**, không phải số mẫu ÷ 10. Đo ở lượt chạy
11/08/2026: 90 IP dàn dựng × 100 mẫu chỉ ra **91 lô** (8.166 mẫu bị nén), trong khi 65 IP
tiêm nhiễm × **đúng 10 mẫu** ra trọn 64 lô — không mẫu nào bị nén. Muốn N lô thì cấp N IP,
mỗi IP 10 mẫu.

**Lát dàn dựng THUẦN một họ kỹ thuật.** 5.486 mẫu CSIC mang chữ ký WAF được gom **theo họ**
trước khi cắt lô, nên cả 549 lô đều thuần một họ và **310 lô chấm được quy kết theo luật
CHẶT** (T1595.003 154 · T1190 64 · T1059.007 39 · T1071.001 39 · T1083 14). Trước khi gom, lô
trộn 3–5 họ nên không lô nào chấm chặt được — chỉ chấm nới ("kỹ thuật gán có nằm trong lô"),
mà lô 4 họ thì luật đó tặng sẵn 4 cơ hội đúng.

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

## 2. Kịch bản demo trước hội đồng

Mỗi luồng chạy **độc lập**: chạy → xem → xoá → chạy luồng kế. Không chồng hai luồng lên nhau,
vì Tier-1 nhớ mặt IP của lượt trước (danh tiếng ≥70 là chặn thẳng, không lên LLM) nên lượt
sau sẽ không tái hiện được hành vi lượt đầu.

> **Đặt `SENTINEL_FREEZE_DYNAMIC_RULES=1` cho MỌI lệnh chạy dưới đây.** Không đặt thì Cổng ML
> ghi luật động thẳng vào `config/system_settings.yaml` — đo lượt 12/08/2026 trên lát 10.000
> sự kiện: **531 luật, 7.910 dòng YAML** chen vào tệp cấu hình, kèm nguyên văn lời biện giải
> của LLM. Hai hậu quả: lượt sau chạy với hàng trăm luật ACTIVE nên không so được với lượt
> trước, và tệp cấu hình bẩn rất dễ bị commit nhầm. Dọn bằng
> `git checkout config/system_settings.yaml` (bản đã commit vốn sạch, hai cờ demo đã `false`).

### 2.1. Luồng tổng — chạy HÔM TRƯỚC, không chạy tại chỗ

```bash
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --fresh
grep -oP 'qsize~\K[0-9]+' logs/subscriber.log | tail -1     # đợi về 0 mới xong
```

Đẩy trọn 496.885 sự kiện qua Tier-1 → Cổng ML → Tier-2. Đẩy xong ~25 phút, nhưng hàng đợi
Tier-2 còn tiêu hoá tiếp nên **tổng ~3,3 giờ** — đó là lý do không chạy live.

Xong thì sao lưu lại, để lỡ nghịch hỏng giữa buổi thì khôi phục trong 10 giây:

```bash
mkdir -p ~/demo_snapshot && cp config/audit_trail.db config/threat_memory.db \
   config/pipeline_stats.json logs/tier2_trace.jsonl ~/demo_snapshot/
```

**Hôm demo chỉ bật hạ tầng, không đẩy:**

```bash
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --no-push
```

**Xem ở đâu:** tab **🎬 Executive Overview** cho phễu xả tải (bao nhiêu sự kiện vào, bao nhiêu
thật sự tốn một lượt gọi LLM) · tab **📊 SIEM Logs & Audit Trail** cho từng phán quyết kèm lý
do và kỹ thuật MITRE đã gán.

### 2.2. Lát nhỏ — khi hội đồng bảo "chạy lại xem"

```bash
.venv/bin/python scripts/reset_all.py     # xoá lượt cũ + bật lại đúng 1 subscriber
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --small   # ~10.000 sự kiện, vài phút
```

Dùng `--small` chứ **đừng** cắt lát đầu của luồng đầy: CSIC nằm ở ngày 2–5 nên xuất hiện từ vị
trí ~92.000, cắt lát đầu sẽ không thấy web attack nào. Thiếu tệp thì `run_demo.sh` tự dựng
(lần đầu chậm thêm ~1 phút).

**Dựng tay thì phải đóng dấu ngay sau đó** — hai bước, đúng thứ tự:

```bash
.venv/bin/python scripts/build_demo_small.py
.venv/bin/python scripts/stamp_demo_ids.py --files data/demo_small.json --remint
```

Dựng lại tập nhỏ thì **phải có `--remint`**: bản ghi được chọn lại từ `demo.json` nên nhiều
sự kiện mang sẵn `gt_id` cũ và đụng nhau (đo: 51 ID trùng). Script từ chối ghi khi phát hiện
trùng — đó là chủ ý, vì khoá nối hỏng thì mọi phép chấm sau đó vô nghĩa.

Không đóng dấu thì `gt_id` rỗng, `batch.gt_ids` trong tracer cũng rỗng, và **không con số nào
của lượt chạy đối chiếu được với sự thật**. Sidecar `*.labels.json` giữ **bản sao** đáp án
ngoài luồng — `src/` không bao giờ đọc nó, nên hệ thống vẫn chạy mù và người chấm nối kết quả
lại sau. Đóng dấu là idempotent, chạy lại không hỏng gì.

**Phân bổ — đo trên `data/demo_small.json` ngày 12/08/2026:**

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

Giữ được: **22 lớp tấn công** · **3 IP APT đa-ngày** (đủ để panel kill-chain có dữ liệu) ·
**250 mẫu CSIC dàn dựng** mang mã kỹ thuật (T1595.003 120 · T1190 47 · T1071.001 40 ·
T1059.007 25 · T1083 18).

**Vì sao KHÔNG lấy đúng tỉ lệ luồng đầy.** Đây là **tập con phân tầng**, không phải mẫu ngẫu
nhiên. Ép đúng tỉ lệ trên 10.000 sự kiện thì còn **8 sự kiện DAPT · 3 zero-day · 15 đối
kháng** — chuỗi APT cần một IP xuất hiện ở ≥2 ngày nên 9 chuỗi biến mất và ba panel trống
trơn. Các lớp hiếm được bơm thừa **có chủ đích**.

Hệ quả phải nói ra nếu bị hỏi: tỉ lệ tấn công của tập nhỏ là **30,8%** so với **5,2%** của
luồng đầy. Con số đại diện cho **hồ sơ tải thật** nằm ở luồng đầy, không phải ở đây — script
in cả hai cạnh nhau ở dòng cuối chính vì lý do đó.

### 2.3. Đối kháng — tấn công vào chính LLM

```bash
.venv/bin/python scripts/push_flow.py --source adversarial --real-only
# 603 payload THẬT: AdvBench 200 · jackhhao 200 · deepset 203
```

**Dùng `--real-only`.** Kho có 723 mẫu, trong đó **120 mẫu do tác giả tự soạn** bằng template
Python tất định (`scripts/build_adversarial_suite.py` → `encoding_bypass` 45 · `structural_attacks`
20 · `semantic_confusion` 20 · `jailbreak` 20 · `rag_poisoning` 15). Cờ này loại chúng, chỉ giữ
**603 mẫu thật** lấy từ ba tập công khai.

> **Đừng dùng `--limit 120`.** Bộ nạp `sorted(glob)` rồi cắt tiền tố, nên `--limit` chọn theo
> thứ tự chữ cái của tên thư mục chứ không theo xuất xứ. Tài liệu cũ ghi `--limit 120` =
> "encoding 45 · structural 20 · semantic 20 · jailbreak 20 · rag_poison 15" — đúng khi kho
> mới chỉ có 120 mẫu tự soạn, nhưng sau khi thêm 603 mẫu thật thì `advbench_gcg` sắp lên đầu
> và `--limit 120` thực ra lấy trọn 120 mẫu AdvBench. Số cũ không đỏ lên ở đâu cả.

Mỗi payload là một IP TEST-NET riêng (`198.51.100.x` / `203.0.113.x`) tải một đòn tầng ứng
dụng. Mọi log đi qua TẤT CẢ các lớp Tier-1, không tách theo loại. Log là dữ liệu do kẻ tấn công viết mà lại
được đưa vào prompt, nên hệ thống bọc log thô giữa hai data-marker sinh ngẫu nhiên mỗi lượt:
nội dung giữa hai mốc là **dữ liệu để phân tích, không phải mệnh lệnh để tuân theo**.

**Xem:** tab **🎬 Executive Overview** → "Vòng phản hồi Hai tầng" và *Live Threat Feed*.

Hai con số bổ sung nhau, không thay thế nhau — lớp tĩnh mạnh ở `encoding_bypass` nhưng **mù
trước tấn công ngữ nghĩa**:

| lớp | tệp | phạm vi | xuất xứ mẫu |
| :-- | :-- | :-- | :-- |
| Guardrail **tĩnh** | `robustness_results.json` | 120 mẫu, 5 nhóm | **tác giả tự soạn** |
| **Tier-2** (LLM) | `adversarial_pipeline_results.json` | 75 mẫu, 4 nhóm ngữ nghĩa | **tác giả tự soạn** |

Hai tệp kết quả này đo trên **đúng 120 mẫu tự soạn**, không phải 603 mẫu thật — chúng tồn tại
để đo *từng lớp phòng thủ* trên các vector được thiết kế riêng cho lớp đó. Lượt demo
`--real-only` là phép thử **độc lập** trên dữ liệu thật; đừng trộn hai con số vào một câu.

> **Phải nói thẳng khi demo end-to-end:** một phần payload bị Tier-1 **DROP** trước khi tới
> Guardrail — lọt bằng cách bị bỏ qua, không phải bị chặn có chủ đích. Con số kháng tiêm nhiễm
> đo bằng cách nạp **thẳng** vào đường ống, và phải nói rõ như vậy.

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

Sửa dòng **giữa sổ** chứ đừng sửa dòng đầu — nó chứng minh chuỗi chỉ ĐÚNG vị trí bị đụng,
mạnh hơn hẳn việc chỉ báo "có gì đó sai". Kiểm 12/08/2026 trên bản sao 36.169 dòng: sửa
`id=18087` thì thông báo trả về đúng ID đó, kèm mốc thời gian và giá trị đã bị thay.

Mỗi dòng ký HMAC và **móc vào chữ ký dòng trước**, nên sửa một dòng làm hỏng mọi dòng sau.
Khoá lấy từ `SENTINEL_LOG_SECRET` trong `.env`, không nằm trong mã. Giới hạn phải tự nêu:
chuỗi bắt được **sửa** và **chèn**, nhưng **cắt đuôi** thì không.

### 2.5. Xoá giữa hai luồng

```bash
.venv/bin/python scripts/reset_all.py                # xoá + bật lại subscriber, vài giây
.venv/bin/python scripts/reset_all.py --dry-run      # xem sẽ xoá gì, KHÔNG đụng dữ liệu
```

Xoá: `audit_trail` · danh tiếng IP · chuỗi APT · `guardrails_audit.db` · `tier2_trace.jsonl` ·
`pipeline_stats.json` · luật động + whitelist · 5 stream Redis · toàn bộ `blacklist:*`.
Giữ: `demo.json` · container · chỉ mục FAISS · đồ thị Neo4j.

Trình tự **producer → subscriber → dữ liệu** là bắt buộc: một lượt đẩy còn sống sẽ bơm sự kiện
vào giữa lúc đang xoá bảng — đúng lỗi đã làm hỏng trọn một lượt đo (104% sự kiện).

**Muốn lấy lại dung lượng đĩa** thì phải `VACUUM` tường minh — `reset_all` dùng `DELETE` và cả
ba DB đều `auto_vacuum=0` nên tệp **không co lại** (đo: 146 MB → 36 KB sau VACUUM):

```bash
.venv/bin/python scripts/reset_all.py --no-restart   # phải dừng trước, không thì "database is locked"
for db in config/audit_trail.db config/threat_memory.db logs/guardrails_audit.db; do
  [ -f "$db" ] && sqlite3 "$db" "VACUUM;"
done
find logs -maxdepth 1 -type f \( -name '*.log' -o -name '*.jsonl' \) -delete
.venv/bin/python scripts/reset_all.py                # bật lại
```

> `rm -f logs/*.jsonl` trong zsh sẽ **huỷ cả lệnh** nếu không có tệp nào khớp (`nomatch`) —
> dùng `find … -delete` như trên.

**Xoá sạch tất cả** (thêm `docker-compose down -v` + `rm data/demo*.json`): `down -v` xoá LUÔN
volume Neo4j và MLflow — chúng nằm ngoài thư mục dự án. Dựng lại đồ thị bằng
`.venv/bin/python main.py --mode scan` (cần `trivy`). Máy này dùng `docker-compose` có gạch
nối, không có plugin `docker compose`.
