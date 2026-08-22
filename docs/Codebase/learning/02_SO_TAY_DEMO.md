# Sổ tay demo — SENTINEL

Chạy sau slide 12. Năm cảnh, 10 phút. Làm đúng thứ tự dưới đây.

---

## 0 · Chuẩn bị (chạy ở nhà)

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

Ra số khác `2076` thì dùng số vừa in và sửa lệnh ở **▶4②**.

Trước khi lên sân khấu:

1. Đăng nhập vai **`L3_Manager`**.
2. Mở sẵn ba cửa sổ theo thứ tự alt-tab: Slide → Dashboard → Terminal.
3. Dán sẵn hai lệnh của ▶4 vào terminal, **chưa Enter**.
4. Chọn sẵn một thẻ BLOCK (cho ▶3) và một phiếu AWAIT_HITL (cho ▶5).
5. Ghi `2076` và `198.19.2.41` ra giấy.
6. Tắt thông báo, tắt ngủ màn hình.

> 🚫 Không gõ `--fresh` hoặc `reset_all` trong buổi bảo vệ.

---

## ▶1 · Tổng quan — 80 giây

Tab **`🎬 Tổng quan`**:

1. Chỉ thẻ **`Log thô vào`**.
2. Chỉ thẻ **`Xả tải LLM`**.
3. Chỉ bảng **`🚨 Dòng cảnh báo trực tiếp`**, cột **`Quyết định bởi`**.
4. Xuống khối **`📊 Chỉ số vận hành thời gian thực`**, dừng ở thẻ **`Chuỗi HMAC`** — nói *"ô này lát nữa em quay lại"*.
5. Kéo xuống khối **`🏆 Bốn con số của luận văn`**.

---

## ▶2 · Đường rẻ — 90 giây

Tab **`📊 Nhật ký & Sổ kiểm toán`** → ba tab con, trái sang phải:

1. **`🟢 Tier-1 · Rules (Welford & Signatures)`**
2. **`⚡ Tier-1 · ML Gate (LightGBM)`**
3. **`🧠 Tier-2 · Agentic LLM (LangGraph)`** — chỉ lướt, **không mở thẻ nào**.

---

## ▶3 · Đường đắt — 140 giây

Vẫn ở tab con **`🧠 Tier-2`** → mở đúng thẻ đã chọn sẵn. Chỉ ba chỗ, đúng thứ tự:

1. Mã ATT&CK.
2. Đoạn tri thức được trích.
3. Câu lập luận.

Rồi chỉ hai huy hiệu **`✅ GROUNDED IN RAG`** và **`🧠 Live GPU`**.

---

## ▶4 · Tấn công thật — 190 giây

1. Thanh bên → **`🛡️ Kiểm tra tính toàn vẹn Logs (HMAC Audit)`** → chờ dải xanh.
2. Terminal, Enter lệnh 1:

   ```bash
   sqlite3 config/audit_trail.db "UPDATE audit_trail SET action='LOG' WHERE id=2076;"
   ```

3. Enter ngay lệnh 2, không dừng xem kết quả:

   ```bash
   .venv/bin/python scripts/test_adversarial_llm.py
   ```

4. **Nói liền ≥65 giây, không nhìn màn hình chờ.**
5. Về Dashboard → bấm **`🛡️`** lần hai → dải đỏ, chỉ vào `ID 2076` và `198.19.2.41`.
6. Khôi phục — **bắt buộc, trước khi sang ▶5**:

   ```bash
   cp ~/demo_snapshot_final/audit_trail.db config/
   ```

---

## ▶5 · Vòng khép — 80 giây

1. Tab **`🧑‍💻 Phê duyệt (HITL)`** → mở phiếu đã chọn, đọc to lý do hoãn.
2. Bấm **`✅ Duyệt`** — không bấm nhầm **`❌ Bác bỏ`** ngay cạnh.
3. Tab **`🔒 Chặn & Miễn trừ`** → thẻ **`Luật vĩnh viễn`** tăng 1.
4. Chỉ IP vừa duyệt trong bảng **`🛑 Luật chặn vĩnh viễn và lịch sử`**.
5. Alt-tab về slide 12 và dừng.

---

## 6 · Sau khi demo xong

```bash
cd ~/Projects/Thesis/AI_Security_Graph
cp ~/demo_snapshot_final/*.db config/
cp ~/demo_snapshot_final/pipeline_stats.json ~/demo_snapshot_final/tier1_blocks.json config/
cp ~/demo_snapshot_final/system_settings.yaml config/
cp ~/demo_snapshot_final/tier2_trace.jsonl logs/
docker restart sentinel_dashboard
```

Blacklist Redis tự hết hạn sau 1 giờ. Muốn sạch ngay:

```bash
docker exec sentinel_redis redis-cli --no-auth-warning -a "$REDIS_PASSWORD" \
  --scan --pattern 'blacklist:*' | xargs -r -n50 \
  docker exec sentinel_redis redis-cli --no-auth-warning -a "$REDIS_PASSWORD" DEL
```
