# Những chỗ phải sửa trong luận văn

> Lập ngày 30/07/2026, sau đợt vá 6 lỗi đo lường + rà toàn bộ script/dữ liệu.
> Mọi vị trí đều có ở **cả hai bản VI và EN** trừ khi ghi rõ khác.

---

## A. SAI SỰ THẬT — phải sửa, không thể biện hộ

### A1. Tên model suy luận — 14 chỗ

Luận văn ghi tên model cũ. Hệ thống thực tế chạy **Foundation-Sec-8B-Instruct Q4_K_M**.

| tệp | dòng |
| :-- | :-- |
| `ch1_introduction.tex` | 38 (Phạm vi & Đối tượng) |
| `ch2_theoretical_background.tex` | 21 (tính toán bộ nhớ FP16) |
| `ch3_system_design.tex` | 20, 40 |
| `ch4_experiments_evaluation.tex` | 25 (bảng phần cứng) |

Kèm theo: mọi chỗ ghi `n_ctx 8192` phải thành **32768** (`-np 2` → 16.384 token/khe).

> Model cũ **không phục vụ nổi** prompt hiện tại: `-c 8192 -np 2` = 4.096 token/khe, prompt
> thật p50 ≈ 7.700 token → hỏng 60/60 lượt trong 0,02 giây.
> Đã đổi tên model khắp nơi và đo lại ở ctx 32768.

### A2. "25.799 sự kiện CSE-CIC-IDS2018" — 15 chỗ

`ch4:11, 28` · `ch5:9` (cả hai bản).

Con số này đến từ `build_stream()` với bộ mặc định cũ, mà bộ đó **chỉ nạp một ngày**
`Thursday-01-03` = **chỉ lớp Infiltration**, và **không có CSIC**. Tức nó không phải
"CSE-CIC-IDS2018" theo nghĩa người đọc hiểu.

Sau khi sửa mặc định: **25.799 sự kiện · 22 lớp tấn công · 2.000 CSIC · 120 zero-day**.

### A3. Xả tải 92,2% (389/5000) — 8 chỗ

`ch4:54, 59, 64` · `ch5:11`. Đứng trên nền dữ liệu ở A2 nên phải tính lại.

Số đo sống hiện có: **92,2%** (chỉ 389/5.000 chạm LLM). Phân bổ cơ chế có bằng chứng:
điểm tĩnh 1.913 · Cổng ML 1.175 · tiền sử IP 697 · Z-score 383 · chữ ký WAF 337 ·
trí nhớ blacklist 106.

### A4. Quy kết ATT&CK 94,6% — 6 chỗ

`ch4:78` · `ch5:15`. Số cũ đo trên **69 payload do chính tác giả soạn**, đã xoá hẳn.

Số thật trên 300 mẫu CSIC (request HTTP thật):
- `rrf` (tất định): **67,33% exact**
- `e2e` (toàn tuyến): **2,33% exact** ← chưa giải thích được, xem mục C1

### A5. F1 = 98,6% và FPR < 1,2% — 8 chỗ

`ch4:80, 85` · `ch5:15`.

Script tự gắn cờ **`binary_f1_trustworthy: false`** vì `ground_truth.json` có base rate tấn
công **86,9%** — F1 nhị phân xấp xỉ base rate nên không phân biệt được cấu hình nào. Thước
đo chính phải là **chấm-theo-hành-động**:

| | Config A (không LLM) | Config F (đủ LLM) |
| :-- | --: | --: |
| Đúng hành động | 0,333 | 0,391 |
| Bỏ ngỏ | 0,158 | **0** |

### A6. LLM-as-Judge 8,95/10 và RAGAS 0,94 — 14 chỗ

`ch4:78, 80` · `ch5:15`.

Lượt đo cũ là **model tự chấm chính nó** (Foundation-Sec chấm Foundation-Sec) trong khi tệp
kết quả ghi *"Different model family eliminates Self-Enhancement Bias"*. Đã có lượt đo lại
bằng trọng tài thật **Meta-Llama-3-8B**, thang **1–5** (không phải /10):

| trục | tự chấm | trọng tài thật |
| :-- | --: | --: |
| Context precision | 2,88 | **2,68** |
| Answer relevancy | 4,65 | **4,22** |
| Faithfulness | 3,93 | **3,88** |
| Context recall | 3,74 | **4,13** |
| Trích dẫn bằng chứng | 16,5% | **50,2%** |

Ba trong bốn trục tụt khi bị model khác chấm — **đây là bằng chứng thực nghiệm cho chính
Self-Enhancement Bias**, đáng viết thành một đoạn riêng.

> ⚠️ Lượt này có `n_incomplete_schema = 69/277`, script tự tuyên bố không đáng tin. Phải
> truy nguyên trước khi trích.

### A7. Độ trễ 211 ms / nhanh gấp 11,6× / giảm 82,97% — 10 chỗ

`ch4:118` · `ch5:11`.

Đo lại: **SENTINEL CHẬM HƠN LLM-only 7,8%**, Mann-Whitney **p = 1,000** (không khác biệt
thống kê). Nguyên nhân: phép đo ép lấy 50 benign + 50 tấn công nên Tier-1 chỉ loại được
**11/100** — 89 ca vẫn gọi LLM và phải trả thêm chi phí đi qua Tier-1.

**Phải đo lại trên `build_stream()`.** Xem mục C2.

### A8. "432 mục MITRE ATT&CK" — 10 chỗ

Thực tế **433**.

---

## B. PHẢI SỬA CÁCH DIỄN ĐẠT — số đúng nhưng lời sai

### B1. Mục tiêu 3: "loại bỏ hiện tượng hư cấu thông tin"

`ch1` Mục tiêu Nghiên cứu (VI) / Research Objectives (EN).

Không đạt. Đo thật: model chọn kỹ thuật **không có trong tài liệu RAG của chính lô đó** —
Foundation-Sec 6/20 ca (30%), WhiteRabbitNeo 4/25 (16%).

**Câu thay thế, đúng sự thật và mạnh hơn**: *"phát hiện và vô hiệu hoá hư cấu bằng rào chắn
neo-RAG tất định"*. Rào chắn bắt được 93/96 lần, ép về `N/A` + `AWAIT_HITL`. Đây là bảo
chứng **kiến trúc**, không phụ thuộc may mắn của một model — về học thuật còn đáng giá hơn.

### B2. Phạm vi khai THIẾU dữ liệu

`ch1:40` — *"giới hạn trên hai tập benchmark: CSE-CIC-IDS2018 và CSIC 2010"*.

Luồng thật còn có **DAPT2020** và zero-day tổng hợp. Mà chính RQ3 hỏi *"tương quan các sự
kiện xâm nhập phức tạp"* — năng lực đó **chỉ chứng minh được bằng DAPT2020**. Bỏ DAPT khỏi
phạm vi là tự tước bằng chứng cho nửa câu hỏi RQ3, trong khi `ch5` vẫn đang trích DAPT2020.

### B3. Không nói rõ chỉ số nào đo trên tập nào

`ch4:11` gộp chung khiến người đọc hiểu cả hai tập tham gia mọi phép đo. Thực tế:

| tập | dùng cho |
| :-- | :-- |
| `datatest.json` 4.240 (cân bằng, có 1.036 CSIC) | Cổng ML |
| `ground_truth.json` 1.750 (86,9% tấn công) | ablation, quy kết, độ trễ |
| `build_stream()` 25.799 | xả tải, toàn tuyến, APT |

Chi tiết đã viết sẵn ở `docs/BENCHMARK_GUIDE.md`.

### B4. Cổng ML: phải nói rõ vì sao tỉ lệ tự quyết tụt

Sau khi trộn CSIC vào benchmark: F1 **không đổi một chữ số** (0,8248, ma trận nhầm lẫn y
hệt) nhưng tỉ lệ tự quyết **79,1% → 59,8%**.

Lý do phải viết ra: Cổng ML là bộ phân loại LightGBM trên đặc trưng NetFlow; request HTTP
chỉ có 5 trường nên nó **từ chối quyết** và đẩy tiếp — đúng kiến trúc, vì tấn công web là
việc của chữ ký WAF. Không giải thích thì trông như hệ thống kém đi.

### B5. `audit_tier_capability` không phải chỉ số trên tập dữ liệu

Nó chấm **15 ca viết tay**. Là phép thử **chức năng**, hợp lệ — nhưng không được trình bày
cạnh các chỉ số đo trên benchmark.

### B6. Ablation B–E

Ghi chép lần trước: **B ≡ C ≡ D ≡ E giống nhau từng bit** do thước đo nhị phân bão hoà. Nếu
lượt này lặp lại, phải nói thẳng là thước đo không phân giải được, chứ không trình bày 4 cột
số trùng nhau như thể là kết quả.

---

## C. CHƯA GIẢI THÍCH ĐƯỢC — không viết cho tới khi truy ra

### C1. Quy kết e2e 2,33% so với rrf 67,33%

Chênh **29 lần**. T1595.003: rrf 90,8% → e2e **0%**.

Đã loại nghi phạm "rào chắn chặn" (`n_fired_with_technique = 300`, tức mọi ca đều ra mã, chỉ
là sai). Nghi vấn còn lại: **kỹ thuật do LLM tự nêu đè lên bộ ánh xạ tất định**.

Đây là số RQ3 quan trọng nhất vì `e2e` mới là thứ hệ thống triển khai thật sự làm.

### C2. Độ trễ — phải đo lại trên luồng thật

Khi có số, đề xuất trình bày **cả hai** vì cặp số nói lên điều mạnh hơn:

> Lợi thế của kiến trúc hai tầng **có điều kiện** — nó đến từ việc đại đa số lưu lượng SOC là
> vô hại. Trên luồng thật xả tải 92%, hai tầng nhanh hơn nhiều lần. Trên luồng ép cân bằng
> 50/50, nó chậm hơn 7,8% vì phần lọc trở thành chi phí thuần.

### C3. `AWAIT_HITL` = 0 trong ablation

Config F không tạo ra ca chuyển-người nào trên 277 ca lên Tier-2 (trước đây 24,2%). Đường
chuyển-người là một đóng góp được nêu trong luận văn mà ablation **không chứng minh được**.
Chưa rõ do bản vá ưu tiên kỹ thuật con hay do tính chất tập dữ liệu.

---

## D. NÊN THÊM — những thứ đo được mà luận văn chưa có

1. **Chống né tránh Cổng ML tách theo độ khó**: chế độ KHÓ (nhiễu toàn bộ đặc trưng)
   **98,75%**; hai chế độ dễ đều 100%. Gộp trung bình ba chế độ sẽ thổi phồng con số.
2. **Trần độ phủ KB = 100%** — chứng minh mọi thất bại quy kết là do truy xuất/chọn lựa, KHÔNG
   phải thiếu tri thức. Đây là luận cứ mạnh.
3. **30 họ chữ ký WAF** với chuẩn hoá đa vòng kiểu OWASP CRS (giải mã URL/HTML trước khi
   khớp). Luận văn đang chỉ ghi "SQLi/XSS/Path/Cmd-Inj".
4. **Ca T1571 kinh điển** để minh hoạ RQ2: model tự viết *"cổng 443 là cổng chuẩn"* rồi vẫn
   gán nhãn "Non-Standard Port" với **độ tin cậy 99%**. Bằng chứng sống cho luận điểm không
   thể tin vào confidence do LLM tự khai — và rào chắn tất định đã bắt được.
