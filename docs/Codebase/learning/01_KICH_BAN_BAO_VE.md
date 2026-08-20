# Kịch bản Bảo vệ SENTINEL — Bảng vận hành + Lời thoại

> **Văn trình bày nằm trong slide.** Mở `docs/Thesis/slides/index.html`, bật panel
> *LỜI THOẠI THUYẾT TRÌNH* — mỗi slide đã có sẵn lời nói, mốc thời gian, và chỉ dẫn demo
> ngay tại slide cần chuyển màn hình. Bản sao đầy đủ nằm ở **Phần 5** của tài liệu này.
>
> **Tài liệu này trả lời đúng một câu hỏi: slide nào thì chạy gì, show gì.**
>
> Tổng: **30 phút** — nói 18:30 · màn hình 11:30. Còn lại dành cho hỏi đáp.

---

## 1. Trục thời gian

| Từ | Đến | Ở đâu | Làm gì |
| --: | --: | :-- | :-- |
| 0:00 | 6:00 | Slide 1–7 | mở đầu · ba vướng mắc · ba câu hỏi · kiến trúc |
| 6:00 | 7:30 | **▶1 Màn hình** | Executive Overview |
| 7:30 | 10:00 | Slide 8–10 | Welford · Cổng ML · bộ đệm |
| 10:00 | 12:00 | **▶2 Màn hình** | SIEM Logs, ba tab con |
| 12:00 | 14:30 | Slide 11–12 | tác tử 6 nút · Dual-RAG |
| 14:30 | 17:00 | **▶3 Màn hình** | mở một thẻ BLOCK của Tầng 2 |
| 17:00 | 18:30 | Slide 13 | rào chắn AI · HMAC |
| 18:30 | 21:30 | **▶4 Terminal + Dashboard** | giả mạo sổ + tấn công LLM |
| 21:30 | 25:00 | Slide 14–16 | dữ liệu · 5D · ablation |
| 25:00 | 27:30 | **▶5 Màn hình** | HITL + Blocklist |
| 27:30 | 30:00 | Slide 18–20 | đóng góp · giới hạn · kết |

Ba mốc tự kiểm: **6:00 sang màn hình lần đầu** · **17:00 xong slide 13** · **27:30 về slide 18**.
Trễ quá 1 phút thì bỏ slide 6 và rút ▶5 còn mỗi tab HITL.

---

## 2. BẢNG VẬN HÀNH — slide nào, chạy gì, show gì

| Slide | ⏱ | Chuyển màn hình? | Chạy gì / mở gì | Show cái gì | 🔴 Số đóng đinh |
| :-- | --: | :-- | :-- | :-- | :-- |
| 1 Bìa | 25s | — | — | — | — |
| 2 Cảm ơn | 15s | — | — | — | — |
| 3 Cấu trúc | 20s | — | — | — | — |
| 4 Ba vướng mắc | 90s | — | — | — | — |
| 5 Ba câu hỏi | 60s | — | — | — | — |
| 6 So sánh | 45s | — | — | — | *(cắt đầu tiên nếu trễ)* |
| **7 Kiến trúc** | 120s | **➜ ▶1** | Dashboard (đã mở sẵn) | Tab **🎬 Executive Overview** | **97,5% + 90,6%** — luôn nói cặp |
| 8 Welford | 60s | — | — | — | — |
| 9 Cổng ML | 60s | — | — | — | 962 / 0 FP |
| **10 Bộ đệm** | 30s | **➜ ▶2** | Dashboard | Tab **📊 SIEM Logs** → 3 tab con, **trái sang phải**: `Tier-1 Rules` → `ML Gate` → `Tier-2 LLM` (tab 3 chỉ lướt) | **0,182 ms** · **962 / 0** |
| 11 Tác tử | 90s | — | — | *(nói câu ĐÓNG RQ1 trước khi vào slide)* | — |
| **12 Dual-RAG** | 60s | **➜ ▶3** | Dashboard | Tab **🧠 Tier-2 · Agentic LLM** → **mở 1 thẻ BLOCK**; chỉ mã ATT&CK · đoạn tri thức trích dẫn · câu lập luận | **76** lệnh ảo giác bị chặn · **80,0% → 68,0%** |
| **13 Rào chắn** | 90s | **➜ ▶4** | **Terminal + Dashboard** — sáu bước ở §3 | ① nút 🛡️ toàn vẹn → ② sửa SQL → ③④ chạy đối kháng → ⑤ nút 🛡️ bắt giả mạo → ⑥ khôi phục | **678 → 0** · **ID dòng bị sửa** |
| 14 Dữ liệu | 45s | — | — | *(nói câu ĐÓNG RQ2 cuối ▶4)* | — |
| 15 Kết quả 5D | 120s | — | — | — | mỗi chiều **một** số |
| **16 Ablation** | 45s | **➜ ▶5** | Dashboard | Tab **🧑‍💻 HITL Approvals** → mở 1 phiếu, đọc lý do hoãn, **bấm duyệt**; rồi tab **🔒 Blocklist** → chỉ IP vừa duyệt | **15,76% ↔ 95,0%** · lặp lại **0,182 ms** |
| 17 Dashboard | 5s | — | *(bàn đạp, bấm lướt)* | — | — |
| 18 Đóng góp | 60s | — | — | *(nói câu ĐÓNG RQ3 trước khi vào slide)* | — |
| 19 Giới hạn | 60s | — | — | — | — |
| 20 Kết | 30s | — | — | — | — |

**Ba số TUYỆT ĐỐI KHÔNG nhấn trong lúc demo** — chúng có chỗ riêng kèm sẵn câu giải thích,
rơi ra một mình là hội đồng tưởng hệ đang hỏng:

| Đừng nhấn giữa demo | Chỗ đúng của nó |
| :-- | :-- |
| `MCC 0,0` · `99,55% FP` | slide 15 và ▶5, **kèm ngay cách nhìn thứ hai** |
| `18,8%` lọc tĩnh | slide 13, kèm ngay câu *"sức chống chịu đến từ cơ chế đóng gói"* |
| `31,13%` nhánh luật tĩnh | slide 19 (giới hạn) |

---

## 3. Sáu bước của ▶4 — nhịp duy nhất có ghi vào cơ sở dữ liệu

Lấy ID trước buổi, **ghi ra giấy**:

```bash
sqlite3 config/audit_trail.db \
  "select id,action,target from audit_trail where action='BLOCK_IP' order by id desc limit 1;"
```

| # | Ở đâu | Làm gì | ⏱ |
| :-- | :-- | :-- | --: |
| ① | Dashboard · thanh bên | bấm **🛡️ Kiểm tra tính toàn vẹn Logs** → *Hệ thống toàn vẹn* | 10s |
| ② | Terminal | `sqlite3 config/audit_trail.db "UPDATE audit_trail SET action='LOG' WHERE id=<ID>;"` | 15s |
| ③ | Terminal | `.venv/bin/python scripts/test_adversarial_llm.py` | 5s |
| ④ | — | **NÓI LIỀN 65 GIÂY, ĐỪNG NHÌN MÀN HÌNH CHỜ** | 65s |
| ⑤ | Dashboard | bấm **🛡️** lần hai → *PHÁT HIỆN GIẢ MẠO tại dòng ID …* | 20s |
| ⑥ | Terminal | `cp ~/demo_snapshot_final/audit_trail.db config/` | 5s |

> Bước ④ lấp đúng bộ đệm 30 giây của bộ kiểm tra toàn vẹn — nên bước ⑤ mới tính lại thật.
> **Bước ⑥ bắt buộc chạy trước ▶5**, vì ▶5 đọc cùng cơ sở dữ liệu đó.

---

## 4. Chuẩn bị trước buổi

```bash
cd ~/Projects/Thesis/AI_Security_Graph
SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --no-push
cp ~/demo_snapshot_final/*.db ~/demo_snapshot_final/pipeline_stats.json config/
cp ~/demo_snapshot_final/system_settings.yaml config/
cp ~/demo_snapshot_final/tier2_trace.jsonl logs/
```

**Thứ tự alt-tab: Slide → Dashboard → Terminal.**

- [ ] Dashboard **đã đăng nhập**, đang ở tab *Executive Overview*
- [ ] Terminal đã gõ sẵn lệnh đối kháng, **chưa Enter**
- [ ] Slide ở slide 1, toàn màn hình, **panel lời thoại đã bật**
- [ ] Đã ghi ID bản ghi `BLOCK_IP` ra giấy
- [ ] Đã chọn trước **một thẻ BLOCK đẹp** (▶3) và **một phiếu AWAIT_HITL dễ đọc** (▶5)
- [ ] Tắt thông báo hệ thống, tắt ngủ màn hình

> 🚫 **Luật sắt: không bao giờ gõ `--fresh` hoặc `reset_all` trong buổi bảo vệ.**
> Hai lệnh đó xoá sạch ảnh chụp vừa đổ vào.

### Ba nhánh hỏng

| Hỏng | Gỡ |
| :-- | :-- |
| Dashboard trắng / lỗi lạ | `docker restart sentinel_dashboard` — 10 giây. Nói: *"em khởi động lại giao diện."* |
| LLM không phản hồi ở ▶4 | `Ctrl+C`, bỏ nửa đối kháng, đi thẳng bước ⑤ — nửa toàn vẹn vẫn chứng minh trọn vẹn RQ2 |
| Hội đồng bắt chạy dữ liệu mới | `SENTINEL_FREEZE_DYNAMIC_RULES=1 ./scripts/run_demo.sh --small` — nói rõ đây là tập con 10.000 sự kiện nền tấn công 30,8%, **khác hỗn hợp** luồng đầy nên tỉ lệ sẽ khác 97,5% |

---

## 5. Lời thoại từng slide

> **Đây là bản sao sinh tự động từ `speakerNotes` trong** `docs/Thesis/slides/index.html`.
> Bản gốc nằm trong slide — sửa ở đó, đừng sửa ở đây.
>
> Phần nói trên slide: **≈ 3.566 âm tiết ≈ 19,8 phút** ở nhịp 180 âm tiết/phút.
> Ngân sách 18:30 — nếu trễ thì **bỏ slide 6** (khoảng 58 giây) là vừa khít.
>
> Ký hiệu trong lời thoại: `⏱` mốc thời gian · `▶` chỉ dẫn demo · `🔴` con số phải đóng đinh
> · `🔒` câu đóng câu hỏi nghiên cứu (nói lúc chuyển màn hình, tính vào giờ demo).

---

### Slide 1 — Bìa

> Kính thưa Quý Thầy Cô trong Hội đồng.
>
> Em là Nguyễn Đức Bình, học viên lớp MSE23HN, ngành Kỹ thuật Phần mềm, Viện Quản trị và Công nghệ FSB.
>
> Đề tài của em: SENTINEL — Kiến trúc Nhận thức Hai tầng cho Phát hiện và Phản hồi Mối đe doạ Tự động sử dụng AI Tác tử, dưới sự hướng dẫn của TS. Bùi Văn Hiệu và TS. Đặng Văn Hiếu.
>
> Toàn hệ chạy cục bộ trên một GPU 16GB, không phụ thuộc dịch vụ đám mây. Em xin phép bắt đầu.
>
> ⏱ 25 giây

---

### Slide 2 — Lời cảm ơn

> Em xin trân trọng cảm ơn hai Thầy hướng dẫn; Quý Thầy Cô Viện FSB và Trường Đại học FPT; Ban Lãnh đạo và đồng nghiệp tại Trung tâm Dữ liệu Quốc gia; cùng gia đình em.
>
> Nội dung đã ghi đầy đủ trên slide, em xin phép không đọc lại để dành thời gian cho phần chuyên môn.
>
> ⏱ 15 giây — NÓI NHANH, TRANG TRỌNG.

---

### Slide 3 — Cấu trúc 4 phần

> Báo cáo của em gồm bốn phần: đặt vấn đề và mục tiêu; kiến trúc hai tầng; thực nghiệm và đánh giá năm chiều; đóng góp, hạn chế và hướng phát triển.
>
> Em xin phép Hội đồng một điều: ở những chỗ thích hợp, em sẽ mở hệ thống đang vận hành để Hội đồng quan sát trực tiếp, thay vì dồn phần minh hoạ về cuối buổi.
>
> ⏱ 20 giây — CÂU XIN PHÉP ĐAN XEN LÀ BẢN LỀ CẢ BUỔI. ĐỪNG BỎ.

---

### Slide 4 — Ba nút thắt SOC

> Kính thưa Hội đồng, em xin bắt đầu từ ba nút thắt trong vận hành thực tế.
>
> NÚT THẮT MỘT — QUY MÔ LOG VÀ KHỦNG HOẢNG ĐỘ TRỄ. Một trung tâm giám sát nhận hàng trăm nghìn đến hàng triệu bản ghi mỗi ngày, mà phần lớn cảnh báo lại là hoạt động lành tính, gây quá tải cảnh báo — hiện tượng AlAhmadi và cộng sự đã ghi nhận tại USENIX Security 2022. Đẩy toàn bộ log thô qua AI thì chính AI thành điểm nghẽn. Cần một bộ lọc tốc độ cao ở vành ngoài.
>
> NÚT THẮT HAI — BỀ MẶT TẤN CÔNG AI VÀ GIẢ MẠO NHẬT KÝ. Nút thắt này sinh ra do chính việc đưa AI vào tuyến phòng thủ. Kẻ tấn công chèn câu lệnh vào Syslog hoặc User-Agent để chiếm quyền điều khiển mô hình; bóp méo đặc trưng để né mô hình học máy; và sửa xoá nhật ký sau xâm nhập, làm mất tính chống chối bỏ. Cần rào chắn cô lập đầu vào và niêm phong vết kiểm toán.
>
> NÚT THẮT BA — SOAR CỨNG NHẮC, ẢO GIÁC VÀ TẢI CHUYÊN GIA. Playbook cố định không phán quyết được theo ngữ cảnh mới. Nhưng AI để tự do thì ảo giác, tự bịa mã kỹ thuật và chặn vô căn cứ. Cần tác tử có tra cứu để giảm ảo giác, và phân loại thông minh để giảm tải chuyên gia.
>
> Ba nút thắt này không giải quyết riêng lẻ được. Đó là bài toán trung tâm của luận văn: một kiến trúc phân tầng hai lớp.
>
> ⏱ 90 giây — Ba nút thắt ánh xạ MỘT-MỘT sang ba câu hỏi ở slide sau. Tách rõ ba khối.

---

### Slide 5 — Ba câu hỏi nghiên cứu

> Ba nút thắt vừa nêu dẫn thẳng tới ba câu hỏi nghiên cứu, theo đúng thứ tự.
>
> CÂU HỎI MỘT — HIỆU NĂNG VÀ CHI PHÍ SUY LUẬN. Làm thế nào xả tải log thô ngay ở tốc độ đường truyền để giảm độ trễ và chi phí GPU. Chỗ khó: lọc rẻ thì bỏ sót, lọc kỹ thì lại phải gọi mô hình.
>
> CÂU HỎI HAI — PHÒNG THỦ ĐA VECTOR VÀ VẾT KIỂM TOÁN. Cơ chế nào chống đỡ được cả chèn câu lệnh, né tránh cổng học máy, lẫn giả mạo nhật ký. Chỗ khó: nhật ký chính là dữ liệu do kẻ tấn công viết, nên lọc theo từ khoá thì hắn chỉ cần đổi câu chữ.
>
> CÂU HỎI BA — SUY LUẬN TÁC TỬ VÀ QUY KẾT MITRE. Làm sao quy kết đúng mã ATT&CK và giảm tải chuyên gia mà vẫn hạn chế ảo giác. Chỗ khó: một mô hình lượng tử hoá thì luôn có câu trả lời, kể cả khi không biết. Làm sao buộc nó im lặng khi thiếu bằng chứng.
>
> Ba nút thắt, ba câu hỏi, ba đóng góp — gắn một-một. Mọi con số em báo cáo hôm nay đều thuộc một trong ba trục này.
>
> ⏱ 60 giây

---

### Slide 6 — So sánh đối chiếu

> Em xin đặt SENTINEL cạnh hai nhóm giải pháp hiện hành.
>
> SIEM và SOAR truyền thống dùng luật tương quan tĩnh: một tầng, rẻ và nhanh, nhưng báo động giả cao vì không suy luận ngữ cảnh, và không có cơ chế chống chèn câu lệnh.
>
> Các hệ tác tử một tầng như CyberRAG hay LanG suy luận tốt, nhưng chạy mô hình cho từng sự kiện nên độ trễ tính bằng giây.
>
> SENTINEL đi hướng lai: định tuyến theo chi phí phán quyết, chỉ phần dư mới chạm mô hình; và chống chèn câu lệnh bằng cơ chế bọc theo cấu trúc, độc lập với nội dung.
>
> Em xin nói rõ một điểm cho công bằng: con số F1 chín tám phẩy một của LanG là số nhóm tác giả đó tự công bố trên dữ liệu của họ, còn số của em đo trên 678 mẫu đối kháng của luận văn này. Hai bên đo trên hai tập khác nhau, nên em không đặt cạnh nhau để tuyên bố hơn kém.
>
> ⏱ 45 giây — CẮT ĐẦU TIÊN NẾU TRỄ. Nhưng phải giữ đoạn cuối về LanG, nói khi bước sang slide 7.

---

### Slide 7 — Kiến trúc hai tầng

> Đây là kiến trúc tổng thể. Em xin đi theo hành trình của một bản ghi, không liệt kê từng khối.
>
> Đầu vào là luồng hợp nhất 99.717 sự kiện, ghép từ CSE-CIC-IDS2018 và CSIC 2010.
>
> CHẶNG MỘT — TẦNG 1, đường nhanh: luật WAF tất định cộng điểm Z theo Welford, ngưỡng ba phẩy năm sigma, chi phí hằng số.
>
> CHẶNG HAI — CỔNG HỌC MÁY: LightGBM trên 76 đặc trưng, chia bốn dải độ tin cậy.
>
> CHẶNG BA — BỘ ĐỆM PHÁN QUYẾT TẦNG MỘT PHẨY BẢY LĂM: khoá băm SHA-256 trên payload và headers; ca trùng khít thì dùng lại phán quyết cũ, bỏ qua hoàn toàn mô hình.
>
> Ba chặng xếp đúng thứ tự rẻ trước, đắt sau, và mỗi chặng chỉ nhận phần chặng trước không kết luận nổi.
>
> CHẶNG BỐN — TẦNG 2 chỉ tiếp nhận phần dư: đồ thị LangGraph điều phối Foundation-Sec 8B, kết hợp Dual-RAG trên 433 mã MITRE ATT&CK, bộ nhớ đe doạ, và rào chắn Đóng gói Dữ liệu kèm HMAC. Vận hành tại chỗ trên một GPU 16GB.
>
> Nguyên tắc của toàn hệ nằm ở một câu: PHÁN QUYẾT RẺ PHẢI ĐỨNG TRƯỚC PHÁN QUYẾT ĐẮT.
>
> Phần dư lớn tới đâu, Phần Ba sẽ đo. Nhưng xin nêu trước hai mỏ neo: Tầng 1 xử lý một sự kiện trung bình 0,182 mili giây; Tầng 2 xử lý một lô mất 13,438 giây.
>
> Em xin phép mở hệ thống để Hội đồng quan sát phễu xả tải đang vận hành.
>
> ⏱ 120 giây — SLIDE QUAN TRỌNG NHẤT.
>
> ━━━━━━━━━━━━━━━━━━━━━━━━
> ▶ DEMO 1 — Tab Executive Overview (1 phút 30)
> Chỉ ba số: tổng log thô · tỉ lệ xả tải · hàng đợi LLM.
> 🔴 ĐÓNG ĐINH: 97,5% — LUÔN NÓI KÈM 90,6%, KHÔNG NÓI LẺ.
> Câu chốt: 97,5% đo ở tỉ lệ tấn công nền 9,8%. Khi nền lên 31,56% thì xả tải còn 90,6%, và vai tầng gánh tải đảo chiều. Xả tải là thuộc tính của hỗn hợp lưu lượng, không phải hằng số của hệ. Em công bố cả hai điểm đo, vì nếu chỉ trưng một số thì câu hỏi hiển nhiên của Hội đồng — trên hạ tầng khác có giữ được không — không có chỗ nào trả lời.

---

### Slide 8 — RuleEngine & Welford

> Đây là chi tiết Tầng 1.
>
> Cốt lõi là THUẬT TOÁN TRỰC TUYẾN WELFORD: cập nhật liên tục trung bình và tổng bình phương độ lệch trên luồng vô hạn mà không cần lưu lịch sử, thời gian và bộ nhớ hằng số. Điểm Z tính từ đó, ngưỡng ba phẩy năm sigma.
>
> Ý nghĩa: hệ phát hiện bất thường mà không cần mẫu tấn công, tức là có khả năng với biến thể chưa từng biết.
>
> Em có hai biện pháp bảo vệ đường nền. Thứ nhất, CẬP NHẬT KHOÁ THEO PHÁN QUYẾT: chỉ luồng đã kết luận lành tính mới được cập nhật, chống đầu độc kiểu nước sôi từ từ. Thứ hai, GIEO ĐƯỜNG NỀN CHUẨN từ trước, tránh báo động nhầm khi khởi động lạnh.
>
> Ngoài ra RuleEngine còn ba rào chắn bộ nhớ: tra cứu cổng bằng cấu trúc Set thay cho biểu thức chính quy; bộ đệm uy tín IP có giới hạn dung lượng chống cạn kiệt bộ nhớ; và bảng phiên tự dọn theo thời gian sống.
>
> Kết quả: Tầng 1 xử lý trung bình 0,182 mili giây và không tiêu tốn VRAM.
>
> ⏱ 60 giây

---

### Slide 9 — Cổng ML LightGBM

> Ca nào Tầng 1 không kết luận được sẽ sang Cổng học máy.
>
> Mô hình LightGBM huấn luyện trên 949.535 mẫu NetFlow với 76 đặc trưng. Trên 2.534 sự kiện Cổng trực tiếp phán quyết, hệ số Matthews đạt 0,6667 và F1 đạt 0,8248.
>
> Chính sách chia bốn dải: từ 0,85 trở lên thì tự động chặn IP; từ 0,65 đến 0,85 thì đẩy lên Tầng 2; từ 0,40 đến 0,65 thì cảnh báo ưu tiên thấp; dưới 0,40 thì bỏ qua.
>
> Kết quả đáng chú ý nhất: ở ngưỡng từ 0,85 trở lên, Cổng đã tự động chặn 962 ca và KHÔNG CÓ CA BÁO NHẦM NÀO.
>
> Phần thứ hai là chống né tránh, nhằm vô hiệu hoá kỹ thuật bóp méo đặc trưng đối kháng. Lớp một: KẸP ĐIỂM Z TẠI TÁM SIGMA, giá trị dị biệt cực đoan bị kẹp, giá trị thiếu điền bằng trung bình. Lớp hai: TỰ TỪ CHỐI — nếu quá 30 phần trăm đặc trưng vượt sáu sigma, mô hình không phán quyết mà đẩy thẳng lên Tầng 2.
>
> Em xin nhấn mạnh lớp thứ hai: một mô hình chịu thừa nhận đầu vào nằm ngoài vùng nó đã học thì an toàn hơn một mô hình luôn có câu trả lời. Bóp méo đặc trưng có lật nổi phán quyết không, Phần Ba đo.
>
> ⏱ 60 giây

---

### Slide 10 — Semantic Cache (Tầng 1.75)

> Giữa Cổng học máy và Tầng 2 còn một chặng, em gọi là Tầng một phẩy bảy lăm.
>
> Khi bị tấn công bùng nổ, hàng nghìn bản ghi trùng payload đổ về cùng lúc; gọi mô hình cho từng bản ghi lặp lại là lãng phí GPU nghiêm trọng. Em ép toàn bộ payload, URI, User-Agent và headers vào một khoá băm SHA-256; trùng khoá thì dùng lại phán quyết cũ. Khoá chặt cả headers còn loại bỏ nguy cơ đầu độc bộ đệm giữa các máy khách.
>
> Kết quả đo: trúng đệm 1.220 trên 1.500; độ trễ khi trúng là 9,8 mili giây so với 87,7 — nhanh hơn 8,9 lần.
>
> Ba chặng lọc vừa trình bày chính là ba tab em xin mở ra đây.
>
> ⏱ 30 giây
>
> ━━━━━━━━━━━━━━━━━━━━━━━━
> ▶ DEMO 2 — Tab SIEM Logs, ba tab con, TRÁI SANG PHẢI (2 phút)
> ① Tier-1 Rules — 🔴 0,182 ms: "đây là quyết định giá 0,182 mili giây."
> ② ML Gate — 🔴 962 / 0 FP: "962 lệnh chặn tự động, không có ca báo nhầm, và mỗi dòng đều nằm trong vết kiểm toán."
> ③ Tier-2 LLM — chỉ lướt, CHƯA MỞ THẺ NÀO, để dành cho demo 3.

---

### Slide 11 — Tác tử LangGraph & Foundation-Sec 8B

> 🔒 NÓI TRƯỚC KHI VÀO SLIDE — ĐÓNG CÂU HỎI THỨ NHẤT:
> Đến đây em xin khép lại câu hỏi thứ nhất. Kiến trúc phân tầng xả tải 97,5% ở tỉ lệ tấn công nền 9,8%, và 90,6% ở nền 31,56%. Mỗi con số đều công bố kèm tỉ lệ nền mà nó được đo trên đó. Câu hỏi thứ nhất đã được trả lời bằng số đo.
> ━━━━━━━━━━━━━━━━━━━━━━━━
>
> Tầng 2 không phải một lời gọi mô hình. Nó là máy trạng thái hữu hạn trên LangGraph, gồm sáu nút: rào chắn kiểm nonce và whitelist; tra cứu ngữ cảnh bằng Dual-RAG; phân loại bằng Foundation-Sec 8B; quy kết kỹ thuật sang MITRE chuẩn STIX; thi hành lệnh chặn có chữ ký HMAC; và chuyển người xử lý.
>
> Mô hình phục vụ cục bộ qua llama.cpp trên CUDA, cửa sổ 16.384 token, nhiệt độ 0,1. Lượng tử hoá Q4_K_M giữ mô hình ở 7 đến 8 GB VRAM, vừa một GPU 16GB.
>
> Ba cơ chế bảo đảm đầu ra. Một, ÉP CẤU TRÚC: mô hình bắt buộc xuất JSON theo lược đồ Pydantic, chỉ ba hành động hợp lệ. Hai, GỠ NHÃN TỰ ĐỘNG: mọi nhãn nội bộ bị gỡ khỏi prompt trước khi gọi, tránh lộ đáp án. Ba, CHỊU LỖI: JSON méo thì bóc tách dự phòng; thất bại hoàn toàn thì tự chuyển về chờ chuyên gia.
>
> Điểm em muốn nhấn nhất là NÚT THỨ SÁU: tác tử được phép không đưa ra phán quyết. Thiếu căn cứ thì ca đó sang hàng đợi chờ chuyên gia. Trong an ninh, một hệ thống buộc phải trả lời mọi câu hỏi là một hệ thống nguy hiểm.
>
> ⏱ 90 giây

---

### Slide 12 — Dual-RAG & Bộ nhớ đe doạ

> Tác tử không suy luận trong chân không. Nó tra cứu song song hai kênh theo hai nguyên lý khác nhau.
>
> KÊNH DÀY dùng FAISS với mô hình nhúng all-MiniLM-L6-v2, mạnh ở ngữ nghĩa. KÊNH THƯA dùng BM25, mạnh ở khớp chính xác mã CVE, số cổng, địa chỉ IP. Hai bảng xếp hạng dung hợp bằng Reciprocal Rank Fusion với k bằng 60 — hợp nhất theo THỨ HẠNG nên không phải cân hai thang điểm khác nhau. Kho tri thức gồm 433 mã STIX MITRE ATT&CK và NIST SP 800-61r2.
>
> Trên nền đó em đặt hai rào chắn. NEO BẰNG CHỨNG: mọi mã kỹ thuật mô hình khẳng định phải hiện diện trong tài liệu đã truy xuất của chính lô đó — cơ chế này đã chặn 76 lệnh chặn IP ảo giác. KHỬ ĐỘC TÀI LIỆU: vô hiệu hoá cấu trúc mệnh lệnh trong tài liệu trước khi chèn vào prompt.
>
> Song song là bộ nhớ đe doạ SQLite: uy tín IP suy giảm theo hàm mũ khi IP im lặng, để không chặn vĩnh viễn một địa chỉ đã sạch; ngược lại IP đạt điểm nguy hiểm tối đa bị Tầng 1 chặn tức thì.
>
> Em xin mở một quyết định thật của tác tử.
>
> ⏱ 60 giây
>
> ━━━━━━━━━━━━━━━━━━━━━━━━
> ▶ DEMO 3 — Tab Tier-2, MỞ MỘT THẺ BLOCK (2 phút 30) — TRÁI TIM BUỔI BẢO VỆ
> Chỉ ba chỗ: mã ATT&CK · đoạn tri thức được trích dẫn · câu lập luận.
> 🔴 ĐÓNG ĐINH: 76 lệnh chặn ảo giác đã bị lá chắn neo giữ lại.
> Câu chốt: mọi mã kỹ thuật đều phải hiện diện trong tài liệu truy xuất của chính lô đó; không neo được thì hạ cấp an toàn xuống hàng đợi chờ chuyên gia. Trên 1.421 ca khẳng định mã kỹ thuật, không ca nào thiếu neo.
> NÊU LUÔN CÁI GIÁ: trần truy xuất 80,0%, toàn tuyến chỉ 68,0%. Mười hai điểm phần trăm là cái giá của việc không tin lời mô hình — em cho rằng đáng trả.

---

### Slide 13 — Rào chắn AI & niêm phong HMAC

> Phần vừa rồi là giữ cho mô hình không khẳng định sai. Slide này là giữ cho mô hình không bị chiếm quyền, và giữ sổ kiểm toán không bị giả mạo — chính là câu hỏi thứ hai.
>
> CƠ CHẾ MỘT — ĐÓNG GÓI DỮ LIỆU PHÂN ĐỊNH. Nhật ký là dữ liệu do kẻ tấn công viết, nên ghép thẳng vào prompt thì hắn viết được chỉ dẫn cho mô hình. Em bọc toàn bộ payload không tin cậy vào giữa cặp dấu phân định mang nonce mật mã ngẫu nhiên. Mọi token câu lệnh nằm trong ranh giới đó bị ép xử lý như văn bản thụ động.
>
> Mấu chốt là nonce sinh động theo từng lô, nên kẻ tấn công không đoán trước được dấu phân định để thoát ra — điều mà dấu phân định cố định không làm được. Bản chất cơ chế là BỌC THEO CẤU TRÚC, KHÔNG DÒ TỪ KHOÁ, nên hiệu lực không phụ thuộc kẻ tấn công viết gì.
>
> CƠ CHẾ HAI — NIÊM PHONG MẬT MÃ. Mỗi bản ghi phán quyết được băm liên hoàn bằng HMAC-SHA256, chữ ký tính trên cả nội dung của nó lẫn chữ ký bản ghi liền trước. Sửa một dòng làm gãy mọi chữ ký sau nó, nên hệ không chỉ phát hiện mà còn ĐỊNH VỊ đúng dòng bị đụng.
>
> Bổ trợ là ba bộ thẩm định: thẩm định dữ liệu lọc log dị dạng; thẩm định quyết định bác bỏ lệnh chặn nhắm vào hạ tầng nội bộ; thẩm định phản hồi áp nguyên tắc không tin mặc định lên luật do AI đề xuất.
>
> Phần Ba sẽ đo cả phần cơ chế này KHÔNG bắt được. Nhưng trước đó, em xin phép thử tấn công trực tiếp, ngay bây giờ.
>
> ⏱ 90 giây
>
> ━━━━━━━━━━━━━━━━━━━━━━━━
> ▶ DEMO 4 — SÁU BƯỚC, TERMINAL + DASHBOARD (3 phút)
> ① Dashboard, thanh bên, bấm Kiểm tra tính toàn vẹn Logs — hiện Hệ thống toàn vẹn.
> ② Terminal: sqlite3 config/audit_trail.db "UPDATE audit_trail SET action='LOG' WHERE id=<ID>;"
>    Nói: em đóng vai kẻ tấn công đã bị ra lệnh chặn, nay sửa thẳng cơ sở dữ liệu để xoá dấu vết.
> ③ Enter ngay: .venv/bin/python scripts/test_adversarial_llm.py
> ④ NÓI LIỀN 65 GIÂY, KHÔNG NHÌN MÀN HÌNH CHỜ. Giải thích nonce theo lô.
>    🔴 ĐÓNG ĐINH: 678 mẫu đối kháng, không mẫu nào đổi được phán quyết.
> ⑤ Quay lại Dashboard, bấm lần hai — hiện PHÁT HIỆN GIẢ MẠO, định vị đúng dòng ID.
> ⑥ Khôi phục: cp ~/demo_snapshot_final/audit_trail.db config/
>
> 🔒 ĐÓNG CÂU HỎI THỨ HAI (cuối demo 4):
> Như vậy câu hỏi thứ hai đã được trả lời trên cả hai vế, ngay trước Hội đồng. Vế một: 678 mẫu đối kháng không mẫu nào chiếm được quyền điều khiển mô hình. Vế hai: sổ bị sửa thì hệ phát hiện và định vị đúng dòng. Đây không phải em thuật lại — Hội đồng vừa quan sát trực tiếp.

---

### Slide 14 — Môi trường & dữ liệu

> Em xin trình bày môi trường thực nghiệm trước khi vào kết quả.
>
> Hạ tầng: một máy trạm cục bộ, NVIDIA RTX 4060 Ti 16GB VRAM, Intel Core i7-14700KF, 32GB RAM DDR5. Máy chủ mô hình llama.cpp trên CUDA, trọng số Q4_K_M nặng 4,6GB, chiếm 7 đến 8GB VRAM khi nạp ngữ cảnh. Đóng gói bằng Docker Compose với Redis Stream và SQLite. Vận hành tại chỗ hoàn toàn.
>
> Dữ liệu: hai tập chuẩn quốc tế. CSE-CIC-IDS2018 cho log xâm nhập mạng; CSIC 2010 cho tấn công tầng ứng dụng web. Hai tập ghép thành luồng 99.717 sự kiện, tỉ lệ tấn công nền 9,8%. Tập nhãn chuẩn 1.700 mẫu, ánh xạ tự động từ nhãn gốc.
>
> Phương pháp: đo trên năm chiều — xả tải, độ trễ, độ chính xác, kháng chèn câu lệnh, chi phí tài nguyên. Đối chứng với SIEM/SOAR và hệ tác tử một tầng. Và dùng một mô hình độc lập khác họ chấm định tính chất lượng lập luận.
>
> ⏱ 45 giây

---

### Slide 15 — Kết quả 5D

> Đây là kết quả trên năm chiều. Em xin không đọc toàn bảng, mỗi chiều chỉ nêu một con số cùng mẫu số của nó.
>
> CHIỀU MỘT — HIỆU NĂNG. Xả tải 97,5% trên luồng 99.717 sự kiện. Độ trễ trung vị giảm từ 17,18 giây xuống 0,88 mili giây. Phân rã theo tầng: Tầng 1 là 0,182 mili giây, Tầng 2 là 13,438 giây.
>
> CHIỀU HAI — AN TOÀN AI VÀ MẬT MÃ. Trên 678 mẫu đối kháng, không mẫu nào đổi được phán quyết. Kháng né tránh học máy 98,75%. Toàn vẹn HMAC 100%.
>
> CHIỀU BA — QUY KẾT VÀ TRUY XUẤT. Tài liệu đúng nằm trong ba kết quả đầu đạt 93,0% trên 243 truy vấn. Trần truy xuất của RRF là 80,0%. Lá chắn neo giữ tỉ lệ ca thiếu neo ở mức không trên 1.421 ca.
>
> CHIỀU BỐN — PHÂN LOẠI SỰ CỐ. Giảm 84,24% khối lượng cho chuyên viên, trên 1.066 cảnh báo. Hàng đợi hoãn chứa 95,0% đe doạ thật.
>
> CHIỀU NĂM — CHẤT LƯỢNG SUY LUẬN. Trọng tài là mô hình khác họ, chấm độc lập, đạt 3,78 trên 5.
>
> Em xin chủ động nêu điểm yếu: trong bốn trục chấm, trục độ sạch tài liệu truy xuất chỉ đạt 2,54 — thấp nhất, do bộ truy xuất còn kéo về tài liệu nhiễu. Hạn chế này em ghi ở Chương 5, có hướng khắc phục ở slide cuối.
>
> Và về con số 97,5%: nó đo ở tỉ lệ tấn công nền 9,8%. Khi nền lên 31,56%, xả tải còn 90,6% và vai tầng gánh tải đảo chiều. MỘT CON SỐ XẢ TẢI KHÔNG KÈM TỈ LỆ TẤN CÔNG NỀN LÀ MỘT CON SỐ KHÔNG ĐỌC ĐƯỢC — nên em công bố cả hai.
>
> ⏱ 120 giây

---

### Slide 16 — Ablation & Trọng tài độc lập

> Hai phân tích chuyên sâu.
>
> Thứ nhất, ABLATION so Cấu hình A chỉ có Tầng 1 với Cấu hình F hoàn chỉnh, trên cùng 1.700 mẫu. Độ chính xác hành động: A đạt 28,29%, F đạt 35,35%, khoảng tin cậy không chồng lấn.
>
> Nhưng điều đáng nói không phải bảy điểm phần trăm đó, mà là KIỂU SAI ĐÃ THAY ĐỔI. Cấu hình A bỏ ngỏ 59,00% số ca — không được xử lý và cũng không ai biết là có. Cấu hình F bỏ ngỏ 0%, chuyển 44,76% ca nghi ngờ sang hàng đợi hoãn. F triệt tiêu hoàn toàn rủi ro bỏ ngỏ.
>
> Thứ hai, TRỌNG TÀI ĐỘC LẬP chấm trung bình bốn trục 3,78 trên 5, trong đó độ sạch ngữ cảnh 2,54 là trục thấp nhất. Tỉ lệ ảo giác mã kỹ thuật 0,0% trên 1.421 ca.
>
> Em xin nêu thẳng cái giá của lá chắn neo: trần truy xuất 200 trên 250, tức 80,0%; toàn tuyến 170 trên 250, tức 68,0%. Mười hai điểm phần trăm chênh lệch chính là cái giá đó.
>
> Hàng đợi hoãn trông như thế nào, em xin Hội đồng cho phép quan sát trực tiếp.
>
> ⏱ 45 giây
>
> ━━━━━━━━━━━━━━━━━━━━━━━━
> ▶ DEMO 5 — HITL + BLOCKLIST (2 phút 30)
> ① Tab HITL Approvals: mở một phiếu AWAIT_HITL, ĐỌC TO LÝ DO HOÃN.
>    🔴 ĐÓNG ĐINH: 15,76% khối lượng chứa 95,0% đe doạ thật.
>    Câu chốt: hệ nhận 1.066 cảnh báo, chỉ 80 là đe doạ thật. Nhìn như bộ phân loại nhị phân thì kết quả rất kém — Matthews bằng 0, báo nhầm 99,55%, em báo cáo đầy đủ trong luận văn. Nhưng nó là kênh phân loại ưu tiên: hàng đợi hoãn chiếm 15,76% khối lượng mà chứa 95,0% đe doạ thật, làm giàu 6,03 lần.
>    Rồi BẤM DUYỆT MỘT PHIẾU.
> ② Tab Blocklist: chỉ IP vừa duyệt, nay nằm trong luật chặn vĩnh viễn.
>    🔴 LẶP LẠI 0,182 ms — CỐ Ý, KHÉP VÒNG VỚI SLIDE 7.
>    Câu chốt: mô hình đề xuất, chuyên gia phê duyệt, luật nạp về Tầng 1; từ lần sau ca này chỉ tốn 0,182 mili giây.

---

### Slide 17 — Dashboard HITL

> Phần giao diện vận hành và hàng đợi hợp tác người-máy, em xin trình bày trực tiếp trên hệ thống.
>
> ⏱ 5 GIÂY — CHỈ LÀ BÀN ĐẠP SANG DEMO 5. ĐỪNG GIẢNG.

---

### Slide 18 — Đóng góp

> 🔒 NÓI TRƯỚC KHI VÀO SLIDE — ĐÓNG CÂU HỎI THỨ BA:
> Và câu hỏi thứ ba. Tác tử quy kết đúng 68,0%; em không giấu rằng con số này thấp hơn trần truy xuất 80,0%. Nhưng độ tin cậy không nằm ở điểm quy kết, mà ở chỗ không ca nào mô hình khẳng định mà thiếu neo bằng chứng, và 76 lệnh chặn do chính nó sinh ra đã bị giữ lại. Đáng tin không có nghĩa là luôn đúng — đáng tin là biết im lặng khi thiếu bằng chứng.
> ━━━━━━━━━━━━━━━━━━━━━━━━
>
> Em xin tổng kết bốn đóng góp.
>
> MỘT — KIẾN TRÚC LAI HAI TẦNG. Chi phí phán quyết, chứ không phải độ chính xác, mới là thứ quyết định kiến trúc một trung tâm giám sát dùng mô hình ngôn ngữ. Và xả tải là hàm của hỗn hợp lưu lượng, không phải hằng số của hệ.
>
> HAI — BẢO MẬT AI VÀ KIỂM TOÁN MẬT MÃ. Phòng thủ theo cấu trúc thắng phòng thủ theo nội dung. Giá cũng đã đo và nêu, không giấu: lớp tĩnh có báo nhầm trên log lành, và chuỗi HMAC không bắt được cắt cụt đuôi — giới hạn nguyên lý, không phải lỗi cài đặt.
>
> BA — RÀO CHẮN NEO BẰNG CHỨNG. Đây là phát hiện phản trực giác và luận văn giữ nguyên: thêm tầng suy luận làm quy kết XẤU ĐI so với chỉ dùng truy xuất. Đó là đánh đổi có chủ ý. Đóng góp thật không phải điểm quy kết cao, mà là cơ chế buộc mô hình im lặng khi thiếu bằng chứng.
>
> BỐN — SẢN PHẨM THỰC TIỄN. Dùng mô hình ngôn ngữ làm bộ ĐỊNH TUYẾN, không làm bộ phân loại. Cùng một lượt đo, hai khung nhìn cho hai kết luận trái ngược; chọn đúng khung đo cũng là một phần của đóng góp.
>
> ⏱ 60 giây

---

### Slide 19 — Giới hạn & hướng phát triển

> Đây là phần em cho là quan trọng nhất: năm giới hạn kỹ thuật, mỗi giới hạn kèm một hướng phát triển.
>
> MỘT, VỀ MẬT MÃ. HMAC-SHA256 là thuật toán đối xứng nên phải bảo mật khoá cục bộ; và kẻ có quyền quản trị vẫn cắt cụt được đuôi nhật ký. Hướng: chữ ký bất đối xứng Ed25519 và neo băm định kỳ ra ngoài.
>
> HAI, VỀ TRI THỨC. Độ phủ với kỹ thuật hiếm còn lệch 12,0 điểm phần trăm so với trần truy xuất; cá biệt kỹ thuật T1083 đạt tỉ lệ trúng bằng không. Hướng: nạp tình báo mối đe doạ chuẩn STIX/TAXII thời gian thực.
>
> BA, VỀ NHIỄU TRUY XUẤT. Độ sạch ngữ cảnh mới đạt 2,54 trên 5, tỉ lệ trích dẫn trực tiếp log thô mới 11,2%. Hướng: tinh chỉnh mô hình cục bộ để ép trích dẫn trọn vẹn.
>
> BỐN, VỀ ĐƠN TÁC TỬ. Tầng 2 hiện là một đồ thị đơn lẻ, chưa phân vai chuyên biệt. Hướng: kiến trúc đa tác tử.
>
> NĂM, VỀ QUY MÔ HẠ TẦNG. Thực nghiệm mới trên một máy trạm đơn GPU. Hướng: nâng cấp cổng Tầng 1 bằng ngôn ngữ biên dịch và áp dụng vLLM cho Tầng 2.
>
> ⏱ 60 giây — CHỖ ĂN ĐIỂM, ĐỪNG LƯỚT. NÓI THẲNG, KHÔNG RÀO ĐÓN.
> Nếu trễ: nói kỹ ba giới hạn đầu, hai cái cuối gộp một câu.

---

### Slide 20 — Kết & Q&A

> Kính thưa Hội đồng.
>
> Tóm lại, luận văn cho thấy mô hình ngôn ngữ lớn ứng dụng được trong trung tâm giám sát an ninh, với hai điều kiện: đặt nó đứng SAU các tầng lọc rẻ hơn, và không tin lời nó khi nó không đưa ra được bằng chứng truy xuất.
>
> Em xin chân thành cảm ơn TS. Bùi Văn Hiệu, TS. Đặng Văn Hiếu cùng Quý Thầy Cô trong Hội đồng.
>
> Em xin hết phần trình bày, kính mời Hội đồng đặt câu hỏi.
>
> ⏱ 30 giây — DỪNG Ở ĐÂY. KHÔNG ĐỂ MÀN HÌNH CUỐI LÀ DASHBOARD.
