# Sổ tra nguồn gốc tài liệu tham khảo — SENTINEL

Mục đích: mỗi mục trong `thebibliography` được **tra tận nguồn gốc** (trang xuất bản, DOI, hoặc
trang arXiv), không tin bản ghi cũ. Lần sau muốn kiểm thì đọc bảng này thay vì tra lại từ đầu.

Ngày rà: **06/08/2026**, rà lại **10/08/2026** · Số mục: **38** (34 cũ + 4 mới) · Công cụ kiểm
tự động: `scripts/audit_thesis_refs.py`

## 🔧 Lượt rà lại 10/08/2026 — hai mục còn sai

| khoá | bản trước ghi | sự thật (nguồn) | mức |
| :-- | :-- | :-- | :-- |
| `faiss2019` | *IEEE Trans. Big Data*, **7**(3), pp. 535–547, **2019** | Tập 7 số 3 in **tháng 7–9/2021** (DBLP: 7(1) = tháng 3/2021). Ghép số tập 2021 với năm 2019 là mâu thuẫn nội tại; **2019** chỉ là năm early access nằm trong chuỗi DOI. Sửa năm thành **2021** | 🟡 năm không khớp số tập |
| `jackhhao2023` | **J. Hao**, "Jailbreak Classification Dataset," Hugging Face | Trang tập dữ liệu **không công bố tên thật nào**, chỉ có định danh tài khoản `jackhhao`. Suy "J. Hao" từ định danh là **tự đặt tên cho một người có thật** — đúng loại lỗi đã sửa cho chính khoá này lượt trước. Ghi thẳng định danh làm tác giả (thông lệ IEEE cho kho mã/dữ liệu chỉ có handle) | 🔴 quy sai tác giả (lần 2) |

Ký hiệu: ✅ đã tra, khớp · 🔧 đã tra, **phải sửa** · ➕ mục mới thêm lượt này

---

## 🔧 Bốn mục SAI — sửa lượt này (kèm mục Instruct còn thiếu)

| khoá | bản cũ ghi | sự thật (nguồn) | mức |
| :-- | :-- | :-- | :-- |
| `foundation_sec_2024` | *Cybersecurity Research Team*, "Foundation-Sec: An Open LLM for Cyber Threat Detection," **Security Preprint, 2024** | **Bịa toàn phần.** Thật: *Llama-3.1-FoundationAI-SecurityLLM-Base-8B Technical Report*, Cisco Foundation AI, **arXiv:2504.21039**, 2025 — tác giả đầu P. Kassianik, B. Saglam (18 tác giả, đã đối chiếu trang arXiv) | 🔴 nghiêm trọng |
| `foundation_sec_instruct` | *(chưa có mục)* | ➕ Mục **mới**: bản hệ **thật sự chạy** không phải Base mà là Instruct — *Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct Technical Report*, **arXiv:2508.01059**, 2025, tác giả đầu S. Weerawardhena (17 tác giả, đã đối chiếu trang arXiv). Thiếu mục này thì luận văn đang dẫn nguồn cho một mô hình khác với mô hình đã đo | 🔴 nghiêm trọng |
| `rrf2009` | "…Condorcet and Individual **Bootstrap Product Algorithms**", không số trang | "…Condorcet and Individual **Rank Learning Methods**", SIGIR '09, **pp. 758–759**, DOI 10.1145/1571941.1572114 | 🔴 sai nhan đề |
| `jackhhao2023` | *J. Hao et al.*, "Jailbreak Prompts on Large Language Models," GitHub, `github.com/verazuo/jailbreak_llms` | **Tác giả, nhan đề, URL đều không đúng.** Tệp dự án dùng là `jackhhao_jailbreaks.json` ⇒ nguồn là tập HF `jackhhao/jailbreak-classification`. Kho `verazuo/jailbreak_llms` thuộc **Shen, Chen, Backes, Shen, Zhang — "Do Anything Now", ACM CCS 2024** | 🔴 quy sai tác giả |
| `bm25_2009` | pp. 333–**380** | pp. 333–**389**, DOI 10.1561/1500000019 | 🟡 sai trang |

## ➕ Ba mục mới

| khoá | lý do phải có |
| :-- | :-- |
| `csic2010` | **Bộ dữ liệu chính của tầng ứng dụng** — 500 mẫu quy kết, 910/1.066 cảnh báo của 3.i, 230 log lành đối chứng âm, 1.036 mẫu trong `datatest` — mà trước nay **không có mục nào và không ai trích**. C. Torrano-Giménez, A. Pérez-Villegas, G. Álvarez Marañón, *HTTP DATASET CSIC 2010*, Information Security Institute, CSIC (Spain), 2010, `https://www.isi.csic.es/dataset/HTTP` |
| `alahmadi2022` | Thay con số **">80% báo giả" không nguồn** đang gán cho QRadar. B. A. AlAhmadi, L. Axon, I. Martinovic, "99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms," *Proc. 31st USENIX Security Symposium*, 2022, **pp. 2783–2800** |
| `shen2024dan` | Nguồn thượng nguồn thật của tập jailbreak (xem `jackhhao2023`). X. Shen, Z. Chen, M. Backes, Y. Shen, Y. Zhang, *"Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models*, ACM CCS 2024, DOI 10.1145/3658644.3670388 |

## ➕ Ba mục thêm lượt viết lại Ch1–Ch3 (tra ngày 10/08/2026)

| khoá | xác nhận tận nguồn | ghi chú |
| :-- | :-- | :-- |
| `peffers2007` | K. Peffers, T. Tuunanen, M. A. Rothenberger, S. Chatterjee, *A Design Science Research Methodology for Information Systems Research*, **J. Manag. Inf. Syst. 24(3), pp. 45–77, 2007**, DOI 10.2753/MIS0742-1222240302 | khớp. Một số bản ghi thứ cấp (SCIRP) ghi 45–78; bản của nhà xuất bản Taylor & Francis và ACM DL đều ghi **45–77** |
| `owasp2021` | OWASP Foundation, *OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks*, phát hành **24/09/2021**, `https://owasp.org/Top10/` | khớp |
| `ke2017lightgbm` | G. Ke, Q. Meng, T. Finley, T. Wang, W. Chen, W. Ma, Q. Ye, T.-Y. Liu, *LightGBM: A Highly Efficient Gradient Boosting Decision Tree*, NeurIPS **30**, 2017 | ⚠️ **cố ý KHÔNG ghi số trang.** Kỷ yếu NeurIPS chính thức không đánh số trang cho tập 2017, còn hai nguồn thứ cấp mâu thuẫn: 3146–3154 và 3149–3157. Chọn một trong hai là đoán; bỏ trường trang thì vẫn tra ra bài. Tên tác giả cuối sửa `T. Y. Liu` → **`T.-Y. Liu`** (Tie-Yan) |

---

## ✅ Đã tra, khớp — không đụng

| khoá | xác nhận |
| :-- | :-- |
| `ids2018` | Sharafaldin, Lashkari, Ghorbani · ICISSP 2018 · pp. 108–116 |
| `siem2021` | González-Granadillo, González-Zarzosa, Diaz · *Sensors* **21**(14), art. 4759, 2021 · MDPI |
| `bigdata2019` | Zuech, Khoshgoftaar, Wald · *Journal of Big Data* **2**, art. 3, **2015** (khoá tên 2019 nhưng năm in **đúng** là 2015 — khoá là định danh nội bộ, không in ra) |
| `alertfatigue2022` | Tariq, Baruwal Chhetri, Nepal, Paris · *ACM Comput. Surv.* **57**(9), art. 224, **2025** · DOI 10.1145/3723158 (khoá tên 2022, năm in đúng 2025) |
| `soar2025` | Ismail, Kurnia, Brata, Nelistiani, Heo, Kim, Kim · *Information* **16**(5), art. 365, 2025 · MDPI |
| `welford1962` | *Technometrics* **4**(3), pp. 419–420, 1962 |
| `rag2020` | Lewis et al. · NeurIPS **33**, pp. 9459–9474, 2020 |
| `langgraph2024` | phần mềm, kho GitHub — dạng trích phần mềm hợp lệ |
| `promptinjection2023` | Greshake et al. · arXiv:2302.12173 — nhan đề đang trích là **bản v1**; bản hội nghị AISec'23 đổi thành *"Not what you've signed up for…"*. Ghi chú trong mục |
| `nist80061` | Cichonski, Millar, Grance, Scarfone · NIST SP 800-61 Rev. 2, 2012 |
| `watchtower2026` | Pandey, Bhujang · arXiv:**2605.24421**, 5/2026 — **bản ghi đúng**, nhưng **cách DÙNG ở §2.5 sai** (xem dưới) |
| `cyberrag2025` | Blefari, Cosentino, Pironti, Furfaro, Marozzo · *FGCS* **176**, art. 108186, 2026 · DOI 10.1016/j.future.2025.108186 |
| `autobnb2025` | Liu, Anwar · arXiv:2508.13118, 8/2025 |
| `llmsec_survey2025` | Zhang, Bu, Wen et al. · *Cybersecurity* **8**, **art. 55**, 2025 · DOI 10.1186/s42400-025-00361-w |
| `lang2026` | Abdennebi, Kara, Lahlou, Ould-Slimane · arXiv:**2604.05440**, 07/04/2026 |
| `splunkllm2026` | Sahay et al. · arXiv:**2603.23966**, 25/03/2026 |
| `vaswani2017` | NeurIPS **30**, pp. 5998–6008, 2017 |
| `quantization2021` | Gholami et al. · arXiv:2103.13630 |
| `faiss2019` | Johnson, Douze, Jégou · *IEEE Trans. Big Data* **7**(3), pp. 535–547, **2021** · DOI 10.1109/TBDATA.2019.2921572 (xem lượt rà 10/08 — DOI mang 2019 là năm early access, số 7(3) in tháng 7–9/2021) |
| `he2017drain` | He, Zhu, He, Li, Lyu · ICWS 2017, pp. 33–40 |
| `strom2018mitre` | MITRE, Technical Report MP180360, 2018 |
| `reimers2019sentence` | EMNLP 2019 |
| `zheng2023judge` | NeurIPS **36**, 2023 |
| `dapt2020` | Myneni et al. · MLHat 2020, CCIS **1271**, Springer, pp. 138–163 |
| `ragas2023` | Es, James, Espinosa-Anke, Schockaert · arXiv:2309.15217 (bản hội nghị: EACL 2024 demo) |
| `hmac1997` | Krawczyk, Bellare, Canetti · IETF **RFC 2104**, 1997 |
| `owasp_llm2025` | OWASP GenAI Security Project, Top 10 for LLM Apps, 2025 |
| `nist80207` | Rose, Borchert, Mitchell, Connelly · NIST SP 800-207, 2020 |
| `advbench2023` | Zou, Wang, Kolter, Fredrikson · arXiv:2307.15043 |
| `deepset2023` | tập HF `deepset/prompt-injections` — khớp `data/adversarial_llm/raw/deepset_prompt_injections.json` |

---

## 🔴 §2.5 — năm khẳng định về công trình người khác KHÔNG đứng được

Đây là loại lỗi nặng nhất trong rà trích nguồn: **trích đúng bài, nhưng nói sai bài đó làm gì.**
Giám khảo mở bài gốc ra là thấy ngay. (Cùng họ lỗi đã sửa ở §1.6, commit 80e93de.)

| §2.5 khẳng định | bài gốc thật sự nói |
| :-- | :-- |
| "Watchtower truyền telemetry thô lên LLM đám mây thương mại, độ trễ $\mathcal{O}(N^2)$ **4–26 giây/sự kiện**, vi phạm Zero-Trust" | **Lỗi phạm trù.** `watchtower2026` là **bài tấn công**, không phải hệ thống SOC. Nó tiêm nhiễm qua nội dung log vào trợ lý SOC dùng **gpt-4o-mini** và báo tỉ lệ áp chế: ghi đè trực tiếp (S1) **0% RIÊNG Ở TÁC VỤ PHÂN LOẠI** (tóm tắt 0,07/0,05/**0,15**/0,00; khắc phục 0,09/0,04/0,08/0,01 — bài gốc dành chữ *"fail completely"* cho **S4**, không phải S1), cướp nhân cách **68% khi CHƯA phòng thủ** (nhắc có cấu trúc còn 15%, ràng buộc đầu ra bật lại 33% — không giảm đơn điệu), tóm tắt **96%** khi không phòng thủ / **38%** khi có. **Không có "4–26 s" trong bài.** |
| "AutoBnB, LanG, Policy-Guided SIEM … đơn tầng, mọi sự kiện đều qua nút LLM; độ trễ đã công bố **480–520 ms** trên **16–24 GB VRAM**" | **480–520 ms và 16–24 GB không có trong bài nào cả ba.** LanG báo **≈21 ms** suy luận, MTTD **1,58 s**. |
| "…đều đơn tầng, mọi sự kiện đều qua nút suy luận LLM" | **Sai với `splunkllm2026`**: nó **có** tầng lọc phi-LLM trước LLM (autoencoder tái dựng + DRL hai lớp phân loại sơ bộ). Và **sai phạm trù với `autobnb2025`**: đó là mô phỏng trên trò chơi bàn *Backdoors & Breaches*, không phải tuyến xử lý sự kiện. |
| Bảng: SOTA Agents "bộ lọc ngữ nghĩa xác suất (né được)" | **Đúng về bản chất nhưng phải nói rõ là gì**: LanG có đường rào **hai lớp** regex + **Llama Prompt Guard 2** (F1 **98,1%**). Viết như thể họ không có phòng thủ nào là sai. |
| Bảng, ô *"Kiểm toán Pháp y"* cột hệ tác tử: **"Không thấy công bố"** | **Sai — và do chính lượt sửa này gây ra** (commit 09f655c đổi từ *"Không hỗ trợ niêm phong mật mã"* sang *"Không thấy công bố"*). LanG **có** công bố nhật ký kiểm toán: CSDL SQLite `mcp_audit.db`, có hẳn Bảng VI mô tả lược đồ. Thứ họ **không** có là niêm phong mật mã (bài không nhắc hmac / hash chain / chữ ký số lần nào). Đã sửa lại thành *"Có công bố nhật ký kiểm toán; không niêm phong bằng mật mã"* |
| QRadar "tỉ lệ báo giả **>80%**" | **Không có trong `siem2021` lẫn `soar2025`.** Thay bằng `alahmadi2022` (USENIX Sec '22) và phát biểu về **SOC nói chung**, không gán cho một sản phẩm cụ thể. |

**Hướng sửa:** chuyển `watchtower2026` sang §2.4 (đó mới đúng chỗ — nó là chứng cứ mạnh nhất cho
mô hình đe doạ *tiêm nhiễm qua nền log* của chính luận văn); mô tả nhóm tác tử bằng **số của
chính họ**; dựng lại khoảng trống nghiên cứu theo hướng **SENTINEL khác ở tổ hợp** (định tuyến
theo chi phí + phòng thủ theo **cấu trúc, độc lập nội dung** + niêm phong mật mã), chứ không
theo hướng "họ chẳng có gì".

---

## Ghi chú về đạo văn

Đã đo: thân bài **không có một trích dẫn nguyên văn nào** (0 cặp ` `` … '' ` trong cả 5 chương
bản EN). Bản VI có 9 cụm trong nháy nhưng đều là **chữ của chính tác giả** dùng nháy nhấn giọng.
Không có môi trường `quote`/`quotation`.

⚠️ **Nhan đề trong danh mục tài liệu phải giữ NGUYÊN VĂN.** Diễn giải lại nhan đề một bài báo là
**lỗi trích dẫn** (người đọc không tra ra bài gốc), không phải biện pháp tránh đạo văn. Đây chính
là lý do bốn mục ở bảng 🔧 phải **khôi phục nhan đề đúng**, chứ không phải viết lại cho khác đi.
