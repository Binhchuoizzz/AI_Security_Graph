# Sổ tay demo — SENTINEL

Chạy **sau khi trình bày xong slide 12**. Năm cảnh, **10 phút**.

Thứ tự cảnh đi đúng mạch của bộ slide — đường rẻ trước, đường đắt sau, lớp giáp, rồi con người —
để Quý Thầy Cô tự khớp được cái đang nhìn với cái vừa nghe. Cảnh ▶4 đặt gần cuối vì nó là cao
trào, và vì khoảng chờ kỹ thuật trong đó vừa đúng bằng thời gian nói phần chống tiêm nhiễm.

| Cảnh | Chứng minh điều gì | Ở đâu | ⏱ | Cộng dồn |
| :-- | :-- | :-- | --: | --: |
| ▶1 | Phần lớn lưu lượng không chạm tới LLM | Executive Overview | 80s | 1:20 |
| ▶2 | Đường rẻ có ba chặng thật, mỗi chặng ghi sổ | SIEM Logs · 3 tab con | 90s | 2:50 |
| ▶3 | Mô hình không được nói bằng trí nhớ | Tier-2 · một thẻ BLOCK | 140s | 5:10 |
| ▶4 | Tiêm nhiễm bị chặn · sổ bị sửa thì lộ đúng dòng | Terminal + Dashboard | 190s | 8:20 |
| ▶5 | Người duyệt xong, luật rơi về tầng rẻ nhất | HITL → Blocklist | 80s | 9:40 |

---

# Chuẩn bị trước buổi

Chạy ở nhà, **không làm trên sân khấu**.

```bash
cd ~/Projects/Thesis/AI_Security_Graph
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --no-push
cp ~/demo_snapshot_final/*.db ~/demo_snapshot_final/pipeline_stats.json config/
cp ~/demo_snapshot_final/system_settings.yaml config/
cp ~/demo_snapshot_final/tier2_trace.jsonl logs/
```

Kiểm ba thứ, theo đúng thứ tự này:

```bash
grep -c '^SENTINEL_LOG_SECRET=.\+' .env        # phải in ra đúng 1 — KHÔNG in giá trị khóa
ls -la ~/demo_snapshot_final/audit_trail.db    # bản sổ sạch để bước ⑥ khôi phục
sqlite3 config/audit_trail.db \
  "SELECT id, action, target FROM audit_trail WHERE action='BLOCK_IP' ORDER BY id DESC LIMIT 1;"
#   PHẢI ra →  2076|BLOCK_IP|198.19.2.41
```

> **ID đã chốt: `2076` · IP `198.19.2.41` · dấu thời gian `2026-08-18 12:15:58`.**
> Đây là dòng `BLOCK_IP` cuối trong ảnh chụp `~/demo_snapshot_final/audit_trail.db` (2.077 dòng,
> chuỗi HMAC đã kiểm: **toàn vẹn**). Lệnh `cp` ở trên ghi đè bản `config/` hiện có, nên sau khi
> `cp` thì đúng nó là dòng cuối.
> Nếu lệnh trên ra số **khác 2076**, nghĩa là có luồng chạy thêm sau bước `cp` — **dùng số vừa in
> ra, đừng dùng 2076**, và sửa lại lệnh ở ▶4②.

### Bảng kiểm trước khi lên

- [ ] Thứ tự alt-tab: **Slide → Dashboard → Terminal**
- [ ] Dashboard đã đăng nhập với vai **`L3_Manager`**, đang ở tab *Executive Overview*
- [ ] Terminal đã dán sẵn hai lệnh của ▶4, **chưa Enter**
- [ ] Đã chọn sẵn **một thẻ BLOCK đẹp** ở Tier-2 (cho ▶3) và **một phiếu AWAIT_HITL dễ đọc** (cho ▶5)
- [ ] Đã ghi ID `2076` và IP `198.19.2.41` ra giấy, để cạnh máy
- [ ] Tắt thông báo hệ thống, tắt ngủ màn hình

> 🚫 **Luật sắt: không bao giờ gõ `--fresh` hoặc `reset_all` trong buổi bảo vệ.**
> Hai lệnh đó xóa sạch ảnh chụp vừa đổ vào, và không có đường lùi.

---

# ▶1 · Toàn cảnh — 80 giây

**Tab `🎬 Executive Overview` → khối `📊 Real-Time Operational Metrics`** (hàng 8 thẻ số liệu).

Chỉ **ba thẻ**, đúng thứ tự:

**① `Log thô vào` → ② `Hàng đợi LLM (lô) ⏳` → ③ `Chuỗi HMAC`**

> Đây là tổng số bản ghi đã đi vào hệ thống. Còn đây là số lô phải nhờ tới mô hình ngôn ngữ.
> Khoảng cách giữa hai con số đó chính là phần hệ thống tự giải quyết mà không cần AI — đó là
> tỉ lệ xả tải em vừa báo cáo.

Tới thẻ **`Chuỗi HMAC ✅ Nguyên vẹn`** thì dừng nửa nhịp:

> Ô này lát nữa em sẽ quay lại.

*(Gài sẵn cho ▶4. Đừng giải thích gì thêm ở đây.)*

Kéo xuống khối **`🏆 Empirical Thesis Benchmark Results`**, chỉ hai thẻ **`Giảm độ trễ đầu-cuối`**
và **`Cổng ML giảm tải LLM`**, không đọc số, chỉ nói:

> Đây là các số benchmark trong luận văn, hệ thống đọc thẳng từ tệp kết quả thực nghiệm.

### ⚠️ Hai cái bẫy ở cảnh này

- **Không có thẻ nào trên màn hình in ra "97,5%".** Đó là số benchmark, không phải số đang chạy.
  Chỉ tay vào một thẻ rồi đọc 97,5% là tự tạo ra một lỗi không cần thiết. Nói tách bạch: *"trên
  màn hình là luồng đang chạy; 97,5% là con số em đo trong luận văn."*
- Thẻ **`Tier-1 luật chặn`** đọc từ **bộ đếm luồng**, không phải từ sổ HMAC — nhánh chặn của luật
  Tier-1 không ghi dòng audit nào. Nếu bị hỏi thì nhận thẳng: đây là giới hạn đã ghi trong luận
  văn. **Tuyệt đối đừng nói *"mọi lệnh chặn đều nằm trong sổ ký"*.**

---

# ▶2 · Đường rẻ — 90 giây

**Tab `📊 SIEM Logs & Audit Trail` → hàng ba tab con, đi trái sang phải, không nhảy cóc.**

### ① `🟢 Tier-1 · Rules (Welford & Signatures)`

> Đây là những ca bị chặn ngay bằng chữ ký và mốc thống kê. Không có mô hình nào tham gia.

### ② `⚡ Tier-1 · ML Gate (LightGBM)`

> Đây là phần Tầng 1 thấy ngờ ngợ mà không kết luận được, chuyển sang cổng học máy. Cổng này chỉ
> tự chặn khi độ tin cậy từ 0,85 trở lên — và mỗi lệnh chặn đều để lại một dòng trong vết kiểm toán.

### ③ `🧠 Tier-2 · Agentic LLM (LangGraph)` — **chỉ lướt qua, CHƯA MỞ THẺ NÀO**

> Phần này em xin quay lại ngay sau đây.

*Mở thẻ ở đây là đốt mất cao trào của ▶3.*

### ⚠️ Câu hỏi gần như chắc chắn sẽ bị hỏi

*"Sao lại có hai cái Tier-1?"* — Trả lời ngay, đừng để treo:

> Nhãn trên giao diện gộp theo **chi phí** — cả hai đều là đường rẻ, không gọi mô hình ngôn ngữ.
> Còn luận văn tách theo **cơ chế**, nên gọi cổng học máy là một chặng riêng.

---

# ▶3 · Đường đắt — 140 giây

**Tab con `🧠 Tier-2 · Agentic LLM (LangGraph)` → mở đúng thẻ đã chọn từ trước buổi.**

> Tuyệt đối không cuộn tìm tại chỗ. Thẻ đẹp và thẻ khó đọc nằm lẫn nhau.

Chỉ **ba chỗ trên thẻ, đúng thứ tự này**:

**① mã ATT&CK → ② đoạn tri thức được trích dẫn → ③ câu lập luận**

Đọc theo thứ tự đó thì người nghe tự thấy quan hệ nhân quả. Đọc ngược lại thì thành ba mảnh rời.

Câu chốt:

> Mã kỹ thuật ở trên chỉ được phép tồn tại vì đoạn tài liệu ở dưới tồn tại. Không neo được vào
> chứng cứ thì hệ hạ cấp ca đó xuống hàng chờ chuyên gia, chứ không cho đi qua.
>
> Trên 1.421 ca mô hình khẳng định mã kỹ thuật, không ca nào thiếu neo. Và luật này đã giữ lại
> **76 lệnh chặn địa chỉ IP** do chính mô hình nghĩ ra.

Rồi nêu luôn cái giá, đừng để Thầy phải hỏi:

> Em xin nói cả cái giá phải trả. Chỉ dùng bộ truy xuất thì quy kết đúng 80,0%; chạy toàn tuyến
> qua rào chắn thì còn 68,0%. Mười hai điểm phần trăm là học phí của việc không tin lời mô hình —
> em cho rằng đáng trả.

---

# ▶4 · Tấn công thật — 190 giây

Cảnh kịch tính nhất. **Sáu bước, không được đảo thứ tự.**

### ① Dashboard · thanh bên → nút `🛡️ Kiểm tra tính toàn vẹn Logs (HMAC Audit)`

Chờ dải xanh: `✅ Hệ thống nhật ký toàn vẹn (0 phát hiện sửa đổi hay giả mạo).`

> Trước khi làm gì, em xin xác nhận cuốn sổ đang lành.

### ② Terminal · Enter lệnh đã dán sẵn

```bash
sqlite3 config/audit_trail.db "UPDATE audit_trail SET action='LOG' WHERE id=2076;"
```

> Em xin đóng vai kẻ tấn công vừa bị hệ ra lệnh chặn, nay sửa thẳng vào cơ sở dữ liệu để xóa dấu
> vết — đổi lệnh chặn thành một dòng ghi log vô hại.

### ③ Enter NGAY lệnh thứ hai, đừng dừng lại xem kết quả bước ②

```bash
.venv/bin/python scripts/test_adversarial_llm.py
```

### ④ NÓI LIỀN 65 GIÂY, KHÔNG NHÌN MÀN HÌNH CHỜ

> Cách chống tiêm nhiễm của em không phải là dò xem kẻ tấn công viết gì. Em bọc toàn bộ phần dữ
> liệu không tin cậy vào giữa một cặp dấu phân định mang chuỗi ngẫu nhiên, sinh mới theo từng lô.
> Mọi thứ nằm trong ranh giới đó luôn bị coi là dữ liệu để đọc, không bao giờ là mệnh lệnh để làm.
> Và vì chuỗi đó đổi liên tục, kẻ tấn công không đoán trước được để viết dấu đóng rồi thoát ra ngoài.
>
> Trên **678 mẫu đối kháng**, không mẫu nào đổi được phán quyết.

> ⏱ **65 giây của ③④ là bắt buộc, không phải để câu giờ.** Phép kiểm toàn vẹn được cache 30 giây
> ([`app.py:105`](../../../src/ui/app.py#L105)). Bấm 🛡️ lại quá sớm sẽ trả kết quả cũ và vẫn báo
> *toàn vẹn* — demo hỏng mà không ai biết vì sao.

> ⚠️ Nói rõ hai thứ khác nhau: *"trên màn hình là năm mẫu chạy tại chỗ; 678 là toàn bộ tập đối
> kháng em đã đo trong luận văn."* Đừng để hiểu nhầm terminal đang chạy 678 mẫu.

### ⑤ Quay lại Dashboard, bấm `🛡️` lần hai → dải đỏ

```
⚠️ PHÁT HIỆN GIẢ MẠO! Đứt gãy chuỗi băm tại dòng log ID 2076.
- Thời điểm: 2026-08-18 12:15:58 · Mục tiêu bị sửa đổi (IP): 198.19.2.41 · Hành động đang hiển thị: LOG
```

Chỉ tay vào **`ID 2076`** và **`198.19.2.41`**, đối chiếu với con số đã ghi ra giấy.

> Hệ không chỉ biết là có người sửa. Nó chỉ đúng dòng nào bị sửa.

### ⑥ Khôi phục — BẮT BUỘC, trước khi sang ▶5

```bash
cp ~/demo_snapshot_final/audit_trail.db config/
```

---

# ▶5 · Vòng khép — 80 giây

> ⚠️ Bước ⑥ của ▶4 phải đã chạy xong. ▶5 đọc đúng cơ sở dữ liệu đó.

### ① Tab `🧑‍💻 HITL Approvals` → mục `Phê duyệt Phân tích từ LLM (AWAIT_HITL)`

Mở **phiếu đã chọn từ trước buổi**, **đọc to lý do hoãn**.

> Hệ nhận 1.066 cảnh báo leo thang, trong đó chỉ 80 là đe dọa thật. Nhìn hàng đợi này như một bộ
> phân loại nhị phân thì kết quả rất kém, và em báo cáo đầy đủ trong luận văn. Nhưng nó không phải
> bộ phân loại — nó là một kênh phân loại ưu tiên: hàng đợi này chỉ chiếm **15,76% khối lượng** mà
> chứa tới **95,0% đe dọa thật**, tức là làm giàu hơn sáu lần.

Bấm **`✅ Approve`**.

> ⚠️ Nút **`❌ Reject`** nằm ngay cạnh. Bấm nhầm là hỏng cả bước ②.
> ⚠️ Nút **`✅ Approve` chỉ hiện với vai `L3_Manager`** ([`app.py:1599`](../../../src/ui/app.py#L1599)).
> Đăng nhập sai vai là mất trắng bước ②.

### ② Tab `🔒 Blocklist & Whitelist Management` → chỉ đúng IP vừa duyệt

> Mô hình đề xuất, chuyên gia phê duyệt, luật rơi về Tầng 1. Từ lần sau, ca này chỉ tốn giá của
> tầng rẻ nhất. Hệ thống càng chạy càng đẩy được nhiều việc về phía rẻ.

Rồi **alt-tab về slide 12** và dừng.

> Đừng để màn hình cuối buổi là dashboard.

---

# Khi hỏng

| Hỏng gì | Làm gì | Nói gì |
| :-- | :-- | :-- |
| Dashboard trắng | `docker restart sentinel_dashboard` | *"Em xin khởi động lại giao diện."* |
| LLM không phản hồi ở ▶4③ | `Ctrl+C`, bỏ phần đối kháng, đi thẳng bước ⑤ | *"Phần này em đã đo đầy đủ trong luận văn."* |
| Bấm 🛡️ lần hai vẫn báo *toàn vẹn* | Chờ đủ 30 giây rồi bấm lại | *"Phép kiểm này được đệm ba mươi giây."* |
| ID không phải 2076 | Dùng số `sqlite3` vừa in ra | — |
| Bị yêu cầu chạy dữ liệu mới | `SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --small` | *"Đây là tập con 10.000 sự kiện, nền tấn công cao hơn nên tỉ lệ xả tải sẽ khác 97,5%."* |

---

# Bằng chứng mã nguồn — chỉ mở nếu bị hỏi "chỗ nào trong code"

Mở sẵn ở một tab trình duyệt thứ hai.

**Neo bằng chứng (▶3)**
- Lá chắn: [`_grounded()` — nodes.py:1593](../../../src/agent/nodes.py#L1593) — mã chỉ được nhận nếu
  nằm trong ngữ cảnh RAG của **chính lô đó**; hạ cấp tại [nodes.py:1806](../../../src/agent/nodes.py#L1806).
- Ca mô hình nói tấn công mà lô không có bằng chứng: [nodes.py:1305](../../../src/agent/nodes.py#L1305) → `AWAIT_HITL`.
- Hợp nhất hai đường truy xuất: [`RRF_K = 60` — retriever.py:207](../../../src/rag/retriever.py#L207).
- **76** và **1.421** nằm trong [evidence_grounding_results.json](../../../experiments/results/evidence_grounding_results.json).
- **80,0%** ở [attack_mapper_eval_rrf_payload.json](../../../experiments/results/attack_mapper_eval_rrf_payload.json)
  và **68,0%** ở [attack_mapper_eval_e2e_payload.json](../../../experiments/results/attack_mapper_eval_e2e_payload.json);
  cả hai cùng `n_with_technique = 250`, nên 12 điểm là so sánh hợp lệ trên **cùng một tập**.

**Niêm phong HMAC (▶4)**
- Chuỗi ký: [executor.py:691](../../../src/response/executor.py#L691) — thông điệp ký gồm cả
  `prev_hash`; [executor.py:704](../../../src/response/executor.py#L704) — `prev_hash` lấy từ
  `integrity_hash` đã lưu, nên **đúng một dòng gãy**.
- Cache 30 giây: [app.py:105](../../../src/ui/app.py#L105).

**Ngưỡng Cổng ML (▶2②)**
- `CLIP_SIGMA = 8.0` · `OOD_SIGMA = 6.0` · `OOD_FRACTION = 0.30`:
  [ml_gateway.py:37-39](../../../src/tier1_filter/ml_gateway.py#L37-L39); bốn dải tin cậy ở
  [ml_gateway.py:51](../../../src/tier1_filter/ml_gateway.py#L51).

**Vòng khép (▶5)**
- Nút duyệt gọi [`approve_rule()` — feedback_listener.py:308](../../../src/tier1_filter/feedback_listener.py#L308):
  chuyển luật sang `ACTIVE` kèm `is_hitl_approved=True`, và **tự gỡ IP khỏi whitelist** nếu nó đang
  nằm đó — vì whitelist ưu tiên cao nhất ở Tầng 1, để nguyên thì luật vừa duyệt vô hiệu.
- Mọi số của ▶5 nằm trong `summary` của [tier2_decision_results.json](../../../experiments/results/tier2_decision_results.json).

---

# Ba câu phải nói kèm mẫu số, dù không ai hỏi

| Con số | Luôn nói kèm |
| :-- | :-- |
| **97,5%** xả tải | đo ở nền tấn công 9,8%; nền 31,6% thì còn 90,6% |
| **99,55%** báo nhầm | là tỉ lệ trong phần **LLM khẳng định là thật**; `AWAIT_HITL` không nằm trong mẫu số; luồng này có tỉ lệ cảnh báo thật 7,5% |
| **100%** kháng tiêm nhiễm | trên 678 mẫu đối kháng của **Tầng 2**; lớp guardrail tĩnh đo riêng, không được trích thay cho nhau |
