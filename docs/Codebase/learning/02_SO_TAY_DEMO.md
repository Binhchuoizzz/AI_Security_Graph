# Sổ tay demo — SENTINEL

Chạy **sau slide 12**. Năm cảnh, **10 phút**. Thứ tự đi đúng mạch bộ slide: đường rẻ trước,
đường đắt sau, lớp giáp, rồi con người.

| Cảnh | Chứng minh | Ở đâu | ⏱ |
| :-- | :-- | :-- | --: |
| ▶1 | Phần lớn lưu lượng không chạm tới LLM | `🎬 Tổng quan` | 80s |
| ▶2 | Đường rẻ có ba chặng thật, mỗi chặng ghi sổ | `📊 Nhật ký` · 3 tab con | 90s |
| ▶3 | Mô hình không được nói bằng trí nhớ | Tier-2 · một thẻ BLOCK | 140s |
| ▶4 | Tiêm nhiễm bị chặn · sổ bị sửa thì lộ đúng dòng | Terminal + Dashboard | 190s |
| ▶5 | Người duyệt xong, luật rơi về tầng rẻ nhất | HITL → Chặn & Miễn trừ | 80s |

---

## Chuẩn bị — chạy ở nhà, không làm trên sân khấu

```bash
cd ~/Projects/Thesis/AI_Security_Graph
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --no-push
cp ~/demo_snapshot_final/*.db config/
cp ~/demo_snapshot_final/pipeline_stats.json ~/demo_snapshot_final/tier1_blocks.json config/
cp ~/demo_snapshot_final/system_settings.yaml config/
cp ~/demo_snapshot_final/tier2_trace.jsonl logs/

grep -c '^SENTINEL_LOG_SECRET=.\+' .env     # phải ra 1 — KHÔNG in giá trị khóa
sqlite3 config/audit_trail.db \
  "SELECT id, action, target FROM audit_trail WHERE action='BLOCK_IP' ORDER BY id DESC LIMIT 1;"
#   PHẢI ra →  2076|BLOCK_IP|198.19.2.41
```

> **ID đã chốt: `2076` · IP `198.19.2.41` · `2026-08-18 12:15:58`.** Nếu lệnh trên ra số khác,
> **dùng số vừa in ra** và sửa lệnh ở ▶4②.

**Bảng kiểm:** alt-tab theo thứ tự Slide → Dashboard → Terminal · đã đăng nhập vai
**`L3_Manager`** · terminal dán sẵn hai lệnh ▶4 chưa Enter · đã chọn sẵn **một thẻ BLOCK đẹp**
(▶3) và **một phiếu AWAIT_HITL dễ đọc** (▶5) · ghi `2076` ra giấy · tắt thông báo và ngủ màn hình.

> 🚫 **Không bao giờ gõ `--fresh` hoặc `reset_all` trong buổi bảo vệ.** Hai lệnh đó xóa sạch ảnh
> chụp vừa đổ vào, không có đường lùi.

---

## ▶1 · Toàn cảnh — 80 giây

**Tab `🎬 Tổng quan`.** Hàng chỉ số trên cùng → chỉ **hai thẻ**:

**① `Log thô vào` → ② `Xả tải LLM`**

> Đây là tổng bản ghi đã vào hệ thống. Còn đây là tỉ lệ hệ tự giải quyết mà không tốn một
> token nào — số này đang chạy theo luồng, không phải số cố định.

Nếu còn thời gian, chỉ vào bảng **`🚨 Dòng cảnh báo trực tiếp`**, cột **`Quyết định bởi`**:

> Mỗi dòng ghi rõ tầng nào ra quyết định. Cột này đọc từ chính cột `tier` mà tầng đó ghi vào
> sổ, không phải suy từ câu chữ.

Xuống khối `📊 Chỉ số vận hành thời gian thực` — bốn thẻ, bổ sung cho hàng trên chứ không lặp
lại. Dừng nửa nhịp ở thẻ cuối, **`Chuỗi HMAC ✅ Nguyên vẹn`**:

> Ô này lát nữa em sẽ quay lại.

*(Gài cho ▶4. Không giải thích gì thêm.)*

Kéo xuống khối **`🏆 Bốn con số của luận văn`**:

> Bốn ô này là kết quả đo trong luận văn, giao diện đọc thẳng từ tệp kết quả thực nghiệm — đúng
> năm tệp mà slide vừa trích. Khối đỏ bên dưới là các giới hạn em tự nêu.

### ⚠️ Bẫy ở cảnh này

- **Trên màn hình có HAI tỉ lệ xả tải.** Thẻ `Xả tải LLM` ở hàng trên là **luồng đang chạy**;
  con số **97,5%** trong khối bốn ô là **số benchmark** đo trên 99.717 sự kiện ở nền tấn công
  9,77%. Hai số sẽ khác nhau. Nói tách bạch, đừng chỉ tay lẫn lộn.
- Thẻ **`Tier-1 luật chặn`** đọc từ **bộ đếm luồng**, không phải sổ HMAC — nhánh chặn của luật
  Tier-1 không ghi dòng audit nào. Bị hỏi thì nhận thẳng: giới hạn đã ghi trong luận văn.
  **Đừng nói *"mọi lệnh chặn đều nằm trong sổ ký"*.**

---

## ▶2 · Đường rẻ — 90 giây

**Tab `📊 Nhật ký & Sổ kiểm toán` → ba tab con, đi trái sang phải, không nhảy cóc.**

**① `🟢 Tier-1 · Rules (Welford & Signatures)`**

> Những ca bị chặn ngay bằng chữ ký và mốc thống kê. Không có mô hình nào tham gia.

**② `⚡ Tier-1 · ML Gate (LightGBM)`**

> Phần Tầng 1 thấy ngờ ngợ mà không kết luận được thì chuyển sang cổng học máy. Cổng này chỉ tự
> chặn khi độ tin cậy từ 0,85 trở lên, và mỗi lệnh chặn để lại một dòng trong vết kiểm toán.

**③ `🧠 Tier-2 · Agentic LLM (LangGraph)` — chỉ lướt, CHƯA MỞ THẺ NÀO**

> Phần này em xin quay lại ngay sau đây.

*Mở thẻ ở đây là đốt mất cao trào của ▶3.*

### ⚠️ Gần như chắc chắn bị hỏi: *"Sao lại có hai cái Tier-1?"*

> Nhãn trên giao diện gộp theo **chi phí** — cả hai đều là đường rẻ, không gọi mô hình ngôn ngữ.
> Luận văn tách theo **cơ chế**, nên gọi cổng học máy là một chặng riêng.

---

## ▶3 · Đường đắt — 140 giây

**Tab con `🧠 Tier-2` → mở đúng thẻ đã chọn trước buổi.** Tuyệt đối không cuộn tìm tại chỗ.

Chỉ **ba chỗ, đúng thứ tự: ① mã ATT&CK → ② đoạn tri thức được trích → ③ câu lập luận.**
Đọc thứ tự đó thì người nghe tự thấy quan hệ nhân quả; đọc ngược thành ba mảnh rời.

Nếu Thầy hỏi vì sao thẻ này có huy hiệu mà thẻ Tier-1 không có:

> Hai huy hiệu `✅ GROUNDED IN RAG` và `🧠 Live GPU` **chỉ xuất hiện trên thẻ của Tier-2**. Luật
> Tier-1 và Cổng ML chạy trên CPU và không truy xuất tri thức, nên thẻ của chúng không đeo hai
> huy hiệu đó — nhìn huy hiệu là biết ngay ca nào đã tốn một lượt suy luận.

> Mã kỹ thuật ở trên chỉ được phép tồn tại vì đoạn tài liệu ở dưới tồn tại. Không neo được vào
> chứng cứ thì hệ hạ cấp ca đó xuống hàng chờ chuyên gia, chứ không cho đi qua.
>
> Trên 1.421 ca mô hình khẳng định mã kỹ thuật, không ca nào thiếu neo. Luật này đã giữ lại
> **76 lệnh chặn IP** do chính mô hình nghĩ ra.

Nêu luôn cái giá, đừng để Thầy phải hỏi:

> Chỉ dùng bộ truy xuất thì quy kết đúng 80,0%; chạy toàn tuyến qua rào chắn còn 68,0%. Mười hai
> điểm phần trăm là học phí của việc không tin lời mô hình — em cho rằng đáng trả.

---

## ▶4 · Tấn công thật — 190 giây

Cảnh kịch tính nhất. **Sáu bước, không đảo thứ tự.**

**① Thanh bên → `🛡️ Kiểm tra tính toàn vẹn Logs (HMAC Audit)`** → chờ dải xanh.

> Trước khi làm gì, em xin xác nhận cuốn sổ đang lành.

**② Terminal · Enter lệnh đã dán sẵn**

```bash
sqlite3 config/audit_trail.db "UPDATE audit_trail SET action='LOG' WHERE id=2076;"
```

> Em đóng vai kẻ tấn công vừa bị chặn, nay sửa thẳng vào cơ sở dữ liệu để xóa dấu vết — đổi lệnh
> chặn thành một dòng ghi log vô hại.

**③ Enter NGAY lệnh thứ hai, đừng dừng xem kết quả bước ②**

```bash
.venv/bin/python scripts/test_adversarial_llm.py
```

**④ NÓI LIỀN 65 GIÂY, KHÔNG NHÌN MÀN HÌNH CHỜ**

> Cách chống tiêm nhiễm của em không phải dò xem kẻ tấn công viết gì. Em bọc toàn bộ phần dữ liệu
> không tin cậy vào giữa một cặp dấu phân định mang chuỗi ngẫu nhiên, sinh mới theo từng lô. Mọi
> thứ trong ranh giới đó luôn là dữ liệu để đọc, không bao giờ là mệnh lệnh để làm. Vì chuỗi đó
> đổi liên tục, kẻ tấn công không đoán trước được để viết dấu đóng rồi thoát ra ngoài.
>
> Trên **678 mẫu đối kháng**, không mẫu nào đổi được phán quyết.

> ⏱ **65 giây là bắt buộc, không phải câu giờ.** Phép kiểm toàn vẹn được đệm 30 giây
> ([`app.py:105`](../../../src/ui/app.py#L105)). Bấm 🛡️ lại quá sớm sẽ trả kết quả cũ và vẫn báo
> *toàn vẹn* — demo hỏng mà không ai biết vì sao.
>
> ⚠️ Nói rõ: *"trên màn hình là năm mẫu chạy tại chỗ; 678 là toàn bộ tập đối kháng em đã đo."*

**⑤ Về Dashboard, bấm `🛡️` lần hai → dải đỏ**

```text
⚠️ PHÁT HIỆN GIẢ MẠO! Đứt gãy chuỗi băm tại dòng log ID 2076.
- Thời điểm: 2026-08-18 12:15:58 · Mục tiêu bị sửa đổi (IP): 198.19.2.41 · Hành động: LOG
```

Chỉ tay vào **`ID 2076`** và **`198.19.2.41`**, đối chiếu con số ghi trên giấy.

> Hệ không chỉ biết có người sửa. Nó chỉ đúng dòng nào bị sửa.

**⑥ Khôi phục — BẮT BUỘC, trước khi sang ▶5**

```bash
cp ~/demo_snapshot_final/audit_trail.db config/
```

---

## ▶5 · Vòng khép — 80 giây

> ⚠️ Bước ⑥ của ▶4 phải đã chạy xong. ▶5 đọc đúng cơ sở dữ liệu đó.

**① Tab `🧑‍💻 Phê duyệt (HITL)`** → mở phiếu đã chọn, **đọc to lý do hoãn**.

> Hệ nhận 1.066 cảnh báo leo thang, trong đó chỉ 80 là đe dọa thật. Nhìn hàng đợi này như một bộ
> phân loại nhị phân thì kết quả rất kém, và em báo cáo đầy đủ trong luận văn. Nhưng nó không
> phải bộ phân loại — nó là kênh phân loại ưu tiên: hàng đợi này chỉ chiếm **15,76% khối lượng**
> mà chứa **95,0% đe dọa thật**, tức làm giàu hơn sáu lần.

Bấm **`✅ Duyệt`**.

> ⚠️ Nút **`❌ Bác bỏ`** nằm ngay cạnh — bấm nhầm là hỏng bước ②.
> ⚠️ Nút `✅ Duyệt` **chỉ hiện với vai `L3_Manager`**
> ([`app.py:1599`](../../../src/ui/app.py#L1599)). Sai vai là mất trắng bước ②.

**② Tab `🔒 Chặn & Miễn trừ`** → thẻ **`Luật vĩnh viễn`** tăng thêm 1, rồi chỉ đúng IP vừa duyệt
trong bảng **`🛑 Luật chặn vĩnh viễn và lịch sử`**.

> Mô hình đề xuất, chuyên gia phê duyệt, luật rơi về Tầng 1. Từ lần sau ca này chỉ tốn giá của
> tầng rẻ nhất. Hệ càng chạy càng đẩy được nhiều việc về phía rẻ.

Rồi **alt-tab về slide 12** và dừng. Đừng để màn hình cuối buổi là dashboard.

---

## Sau khi demo xong — trả về trạng thái đã chuẩn bị

Buổi demo làm thay đổi bốn chỗ. Muốn diễn lại (buổi sau, hoặc quay video) thì phải trả hết về
mốc ban đầu, **không phải chạy lại luồng**.

| Cảnh | Đã đổi gì | Nằm ở đâu |
| :-- | :-- | :-- |
| ▶4② | Sửa dòng `id=2076` thành `LOG` | `config/audit_trail.db` |
| ▶5① | Duyệt một luật → `ACTIVE` | `config/system_settings.yaml` |
| ▶5① | `mark_ip_blocked()` đẩy uy tín IP lên 100 | `config/threat_memory.db` |
| ▶5① | Ghi thêm dòng `BLOCK_IP` "APPROVED (HITL)" | `config/audit_trail.db` |
| ▶5① | Đưa IP vào blacklist Redis | Redis (TTL 1 giờ, tự hết hạn) |

### Cách trả về — chép đè từ ảnh chụp, đúng ba lệnh của bước chuẩn bị

```bash
cd ~/Projects/Thesis/AI_Security_Graph
cp ~/demo_snapshot_final/*.db config/
cp ~/demo_snapshot_final/pipeline_stats.json ~/demo_snapshot_final/tier1_blocks.json config/
cp ~/demo_snapshot_final/system_settings.yaml config/
cp ~/demo_snapshot_final/tier2_trace.jsonl logs/
docker restart sentinel_dashboard          # buộc UI bỏ cache và đọc lại tệp mới
```

Blacklist Redis không cần đụng — nó tự hết hạn sau 1 giờ. Muốn sạch ngay:

```bash
docker exec sentinel_redis redis-cli --no-auth-warning -a "$REDIS_PASSWORD" \
  --scan --pattern 'blacklist:*' | xargs -r -n50 \
  docker exec sentinel_redis redis-cli --no-auth-warning -a "$REDIS_PASSWORD" DEL
```

### Kiểm ba thứ trước khi coi là xong

```bash
sqlite3 config/audit_trail.db \
  "SELECT COUNT(*), (SELECT id||'|'||action||'|'||target FROM audit_trail
                     WHERE action='BLOCK_IP' ORDER BY id DESC LIMIT 1) FROM audit_trail;"
#   PHẢI ra →  2077|2076|BLOCK_IP|198.19.2.41

# So NỘI DUNG hai tệp, không so byte: cơ sở dữ liệu bật WAL nên tệp đổi byte ngay khi
# Dashboard mở đọc, dù nội dung y hệt — `md5sum` ở đây sẽ báo lệch một cách vô cớ.
# Vân tay dưới đây là mã băm của dòng cuối, tức đại diện cho cả chuỗi HMAC.
for f in config/audit_trail.db ~/demo_snapshot_final/audit_trail.db; do
  sqlite3 "$f" "SELECT COUNT(*)||' | '||substr((SELECT integrity_hash FROM audit_trail
                       ORDER BY id DESC LIMIT 1),1,16) FROM audit_trail;"
done
#   HAI DÒNG PHẢI GIỐNG NHAU →  2077 | a02536ea4a77699b
```

Rồi mở Dashboard, bấm **`🛡️ Kiểm tra tính toàn vẹn Logs`** → phải ra dải xanh. Chưa xanh thì
chờ hết 30 giây đệm rồi bấm lại; vẫn đỏ nghĩa là bản chép chưa vào.

> 🚫 **Vẫn không dùng `--fresh` và `reset_all.py` để trả về mốc này.** Hai lệnh đó XOÁ SẠCH rồi
> dựng lại từ đầu — mất luôn 2.077 dòng sổ và dòng `2076` mà cả cảnh ▶4 dựa vào. Chúng chỉ dùng
> khi muốn tạo một ảnh chụp HOÀN TOÀN MỚI, và khi đó phải làm lại từ đầu:
>
> ```bash
> SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --fresh   # dựng dữ liệu mới
> mkdir -p ~/demo_snapshot_final
> cp config/audit_trail.db config/threat_memory.db config/guardrails_audit.db \
>    config/pipeline_stats.json config/tier1_blocks.json config/system_settings.yaml \
>    ~/demo_snapshot_final/
> cp logs/tier2_trace.jsonl ~/demo_snapshot_final/
> sqlite3 config/audit_trail.db \
>   "SELECT id, action, target FROM audit_trail WHERE action='BLOCK_IP' ORDER BY id DESC LIMIT 1;"
> ```
>
> **Ghi lại ID vừa in ra** và sửa vào ▶4② cùng mục "ID đã chốt" ở đầu tài liệu — con số `2076`
> chỉ đúng với ảnh chụp hiện tại.

---

## Khi hỏng

| Hỏng gì | Làm gì | Nói gì |
| :-- | :-- | :-- |
| Dashboard trắng / lỗi `ImportError` | `docker restart sentinel_dashboard`, chờ 30s | *"Em xin khởi động lại giao diện."* |
| LLM không phản hồi ở ▶4③ | `Ctrl+C`, bỏ phần đối kháng, sang thẳng ⑤ | *"Phần này em đã đo đầy đủ trong luận văn."* |
| Bấm 🛡️ lần hai vẫn báo *toàn vẹn* | Chờ đủ 30 giây rồi bấm lại | *"Phép kiểm này được đệm ba mươi giây."* |
| ID không phải 2076 | Dùng số `sqlite3` vừa in ra | — |
| Chữ hiển thị lạ / thiếu dấu | Không cần làm gì — giao diện dùng phông hệ thống, **không tải phông qua mạng** | — |
| Bị yêu cầu chạy dữ liệu mới | `SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --small` | *"Tập con 10.000 sự kiện, nền tấn công cao hơn nên tỉ lệ xả tải sẽ khác 97,5%."* |

---

## Ba câu phải nói kèm mẫu số, dù không ai hỏi

| Con số | Luôn nói kèm |
| :-- | :-- |
| **97,5%** xả tải | đo ở nền tấn công 9,8%; nền 31,6% thì còn 90,6% |
| **99,55%** báo nhầm | tỉ lệ trong phần **LLM khẳng định là thật**; `AWAIT_HITL` không nằm trong mẫu số; luồng này có tỉ lệ cảnh báo thật 7,5% |
| **100%** kháng tiêm nhiễm | trên 678 mẫu đối kháng của **Tầng 2**; lớp guardrail tĩnh đo riêng, không trích thay cho nhau |

---

## Bằng chứng mã nguồn — chỉ mở nếu bị hỏi "chỗ nào trong code"

Mở sẵn ở một tab trình duyệt thứ hai.

| Chủ đề | Vị trí |
| :-- | :-- |
| Neo bằng chứng (▶3) | [`_grounded()` nodes.py:1593](../../../src/agent/nodes.py#L1593) · hạ cấp [nodes.py:1842](../../../src/agent/nodes.py#L1842) · không neo được → `AWAIT_HITL` [nodes.py:1305](../../../src/agent/nodes.py#L1305) |
| Hợp nhất hai đường truy xuất | [`RRF_K = 60` retriever.py:207](../../../src/rag/retriever.py#L207) |
| **76** và **1.421** | [evidence_grounding_results.json](../../../experiments/results/evidence_grounding_results.json) |
| **80,0%** so **68,0%** | [rrf_payload](../../../experiments/results/attack_mapper_eval_rrf_payload.json) · [e2e_payload](../../../experiments/results/attack_mapper_eval_e2e_payload.json) — cùng `n_with_technique = 250`, nên so sánh hợp lệ trên **cùng một tập** |
| Chuỗi ký HMAC (▶4) | ghi: [executor.py:293](../../../src/response/executor.py#L293) · kiểm: [executor.py:691](../../../src/response/executor.py#L691) — thông điệp ký gồm cả `prev_hash`, lấy từ `integrity_hash` đã lưu ([:704](../../../src/response/executor.py#L704)), nên **đúng một dòng gãy** |
| Đệm 30 giây | [app.py:105](../../../src/ui/app.py#L105) |
| Ngưỡng Cổng ML (▶2②) | `CLIP_SIGMA` · `OOD_SIGMA` · `OOD_FRACTION` [ml_gateway.py:37-39](../../../src/tier1_filter/ml_gateway.py#L37-L39) · bốn dải tin cậy [ml_gateway.py:51](../../../src/tier1_filter/ml_gateway.py#L51) |
| Vòng khép (▶5) | [`approve_rule()` feedback_listener.py:308](../../../src/tier1_filter/feedback_listener.py#L308) — chuyển luật sang `ACTIVE` kèm `is_hitl_approved=True` và **tự gỡ IP khỏi whitelist** nếu nó đang nằm đó (whitelist ưu tiên cao nhất ở Tầng 1, để nguyên thì luật vừa duyệt vô hiệu) |
| Mọi số của ▶5 | `summary.triage` trong [tier2_decision_results.json](../../../experiments/results/tier2_decision_results.json) |
