# Đối chứng NGOÀI — số đã công bố, đã kiểm từ bài báo gốc

> Tách khỏi `docs/Codebase/guides/DEMO_BY_RQ.md` ngày 04/08/2026 để tài liệu trình diễn chỉ
> còn bảng chỉ số. Nội dung giữ nguyên — đây là câu trả lời cho *"so với hệ khác thì hơn ở
> đâu"*, và mỗi con số đều đã đối chiếu bản gốc chứ không chép lại từ bài thứ cấp.

---

## RQ1 — Đối chứng NGOÀI — số đã công bố trên cùng bộ dữ liệu

Ablation A–F chỉ so SENTINEL với chính nó. Mốc ngoài duy nhất khả thi là **số đã công bố trên
CSE-CIC-IDS2018**, vì chạy Suricata/Snort thật cần PCAP mà `data/raw/` chỉ có CSV đặc trưng luồng.

#### A. Số SOTA thường được trích — và giao thức sinh ra nó

**Saidane, Telch, Shahin, Granelli (2024)**, CS & IT–CSCP, DOI 10.5121/csit.2024.141411 —
CSE-CIC-IDS2018, **15 lớp**, biến thể NetFlow, trung bình theo lớp:

| mô hình | Accuracy | Precision | Recall | F1 |
| :-- | --: | --: | --: | --: |
| VGG19 | **99,22%** | 99,93% | 98,47% | **99,33%** |
| LSTM | 96,83% | 93,27% | 94,53% | 91,40% |
| CNN | 96,56% | 91,40% | 99,00% | 97,33% |
| CNN+LSTM | 95,82% | 98,13% | 96,93% | 97,00% |
| **Random Forest** | **89,94%** | 90,60% | **74,19%** | 93,20% |

Bốn lý do **không so trực tiếp** được với SENTINEL:

1. **SMOTE trước khi chia tập** — K-means+SMOTE rồi mới tách 80/20 **ngẫu nhiên** (§3.4 bản gốc).
   Mẫu tổng hợp sinh từ láng giềng của mẫu test lọt được vào tập train ⇒ rò rỉ.
2. **Chia ngẫu nhiên** trên bộ dữ liệu có luồng trùng lặp ⇒ thổi phồng thêm.
3. **Đa lớp 15 nhãn, trung bình theo lớp** — khác đại lượng với F1/MCC nhị phân.
4. **Biến thể NetFlow**, không phải bộ 80 đặc trưng CICFlowMeter mà `datatest.json` dùng.

⇒ Hàng đáng đặt cạnh nhất là **Random Forest 89,94% / recall 74,19%** — mô hình cổ điển gần Cổng
ML nhất về tinh thần, và ngay cả nó cũng chạy dưới giao thức dễ hơn ta.

#### B. Ba nghiên cứu chứng minh những con số 99% ấy không đáng tin

| nghiên cứu | đo gì | kết quả |
| :-- | :-- | :-- |
| **Cross-dataset generalization** (arXiv 2402.10974) | Train+test **cùng** CSE-CIC-IDS2018, rồi đem sang CIC-IDS2017 | MCC **96–97% → 31–45%** (TB 40,24%) · F1 26–51% · AUROC 58–80% |
| **MAWIFlow** (arXiv 2506.17041) | Cùng mô hình cây trên CIC-IDS vs lưu lượng backbone THẬT (MAWILab) | RF acc **0,9989 → 0,8579** · XGBoost **0,9986 → 0,8535** · DT **0,9990 → 0,8334** |
| **Evaluation Protocol Is the Hidden Variable** (06/2026) | Cùng mô hình, đổi **cách chia tập** | RF/**LightGBM**/MLP macro-F1 **0,79–0,82 (chia ngẫu nhiên) → ≈0,02 (chia theo thời gian)** · 36/45 đặc trưng vượt ngưỡng trôi nặng |

Nguyên văn kết luận của nghiên cứu thứ nhất: *"nearly perfect classification performance when the
models are trained and tested on the same dataset. However, when training and testing the models
in a cross-dataset fashion, the classification accuracy is largely commensurate with random
chance."* Lý do chung: tấn công trong bộ dữ liệu **quá đồng nhất** — vài đặc trưng đã tách được
lớp, nên mô hình học lối tắt của bộ dữ liệu chứ không học hành vi tấn công.

> **Nghiên cứu thứ ba đánh trúng SENTINEL nhất: nó quét đúng LightGBM**, đúng mô hình Cổng ML
> đang dùng. Chia ngẫu nhiên cho macro-F1 0,79–0,82; chia theo thời gian sụp còn **0,02**.
> Đây vừa là vũ khí phản biện, vừa là **rủi ro phải tự nêu**: nếu ai hỏi *"em chia tập thế nào"*
> mà câu trả lời là ngẫu nhiên, thì con số của em nằm đúng vào vùng bài này chỉ trích.

Kèm theo: kiểm toán nhãn báo tới **7,5% luồng bị gán sai nhãn**, cùng luồng trùng lặp và lỗi tính
đặc trưng kế thừa từ CICIDS2017 *(số này lấy từ tóm tắt, chưa đối chiếu bản gốc — đọc trước khi
trích)*.

#### C. Câu trả lời khi bị hỏi *"sao số của em thấp hơn bài báo X"*

> Những con số 99% là **trong-bộ-dữ-liệu, sau khi SMOTE rồi chia ngẫu nhiên**. Chính giao thức đó
> đã bị ba nghiên cứu độc lập chứng minh là không khái quát hoá: MCC 96–97% tụt còn ~40% khi đổi
> bộ dữ liệu; accuracy 0,999 tụt còn 0,86 trên lưu lượng thật; macro-F1 0,80 tụt còn 0,02 khi chia
> tập theo thời gian. Đóng góp của luận văn không phải một điểm F1 cao hơn trên bộ dữ liệu đã bão
> hoà, mà là **kiến trúc phân tầng** — và 1.e–1.n đo đúng thứ đó.

**Chủ động nêu, đừng đợi bị hỏi.** Nó biến *"số của em thấp hơn"* thành *"em biết vì sao số kia
cao và vì sao nó không đáng tin"*.

**Nguồn** *(đã đối chiếu bản gốc trừ chỗ ghi rõ)*:

- [Optimizing Intrusion Detection System Performance through Synergistic Hyperparameter Tuning and Advanced Data Processing](https://arxiv.org/pdf/2408.01792) — Saidane et al., CS & IT–CSCP 2024
- [On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection](https://arxiv.org/html/2402.10974v1)
- [MAWIFlow Benchmark: Realistic Flow-Based Evaluation for Network Intrusion Detection](https://ar5iv.labs.arxiv.org/html/2506.17041)
- [The Evaluation Protocol Is the Hidden Variable: A Drift-Aware Re-Examination of Flow-Based Intrusion Detection Benchmarks](https://www.researchgate.net/publication/406911132_The_Evaluation_Protocol_Is_the_Hidden_Variable_A_Drift-Aware_Re-Examination_of_Flow-Based_Intrusion_Detection_Benchmarks) *(06/2026 — mới nhất, số lấy từ tóm tắt; bản gốc sau tường phí, cần đọc lại)*
- [Network Intrusion Datasets: A Survey, Limitations, and Recommendations](https://arxiv.org/pdf/2502.06688)
- [Deep Learning Methods for Intrusion Detection Systems on the CSE-CIC-IDS2018 Dataset: A Review](https://link.springer.com/chapter/10.1007/978-3-031-89363-6_3) — Springer, tổng quan


---

## RQ3 — Đối chứng NGOÀI — LLM/tác tử làm việc SOC đạt bao nhiêu

Đây là vế đối chứng **quan trọng hơn của RQ1**, vì SENTINEL là hệ tác tử chứ không phải một bộ
phân loại luồng. Câu hỏi thật là: *mô hình biên giới làm việc SOC được bao nhiêu?* — và câu trả
lời cho thấy **suy luận SOC khó hơn nhiều so với cảm nhận thông thường**.

#### CyberSOCEval — Meta + CrowdStrike, arXiv:2509.20166 (11/2025)

Bộ benchmark mã nguồn mở, hai phần, **609 ca** cho phần Malware Analysis:

| tác vụ | mô hình biên giới đạt |
| :-- | :-- |
| **Malware Analysis** (đọc log detonation sandbox, trắc nghiệm) | **23–34%** đúng |
| **Threat Intelligence Reasoning** (đọc báo cáo tình báo, ánh xạ chuỗi tấn công sang MITRE ATT&CK) | **43–53%** (đầu vào ảnh) · cao hơn **5–10 điểm** nếu trích sẵn text |

Ba kết luận của nhóm tác giả, cả ba đều dùng được:

1. **Mô hình hiện tại còn xa mới bão hoà** benchmark — *"a significant hill to climb"*.
2. **Mô hình suy luận (reasoning) KHÔNG có mức tăng như ở code/toán** — chúng chưa được huấn
   luyện để suy luận an ninh mạng.
3. Mô hình **lớn hơn, mới hơn** thì tốt hơn — quy luật scaling vẫn đúng.

**Vì sao quan trọng với SENTINEL:** ánh xạ sang MITRE ATT&CK — đúng việc mà 3.a–3.d đo — là tác
vụ mà **mô hình biên giới của Meta/OpenAI/Google chỉ đạt 43–53%**. SENTINEL chạy
**Foundation-Sec-8B lượng tử hoá Q4\_K\_M trên GPU cục bộ**. Bất kỳ con số quy kết nào cũng phải
đọc trên nền đó, không phải trên kỳ vọng "AI thì phải đúng ~90%".

#### Đối chứng ngành (không bình duyệt — ghi rõ khi trích)

Giải AI SOC Championship (Simbian, 05/2025): mô hình biên giới hoàn thành **61–67%** ca điều tra;
tác tử của hãng ở mức nỗ lực cao đạt **72%**; **chuyên gia người có AI hỗ trợ đạt 73–85%**.
Con số cuối là mốc đáng nhớ: **ngay cả người giỏi nhất có AI trợ giúp cũng không đạt 90%.**

#### Cách trích cho đúng

> Quy kết kỹ thuật ATT&CK là tác vụ mà benchmark mở của Meta+CrowdStrike đo được mô hình biên
> giới chỉ đạt **43–53%**, và ở tác vụ phân tích mã độc chỉ **23–34%**. SENTINEL dùng mô hình 8B
> lượng tử hoá chạy cục bộ, air-gapped. Vì vậy chỉ số đáng nói của luận văn **không phải** tỉ lệ
> quy kết tuyệt đối, mà là: (a) hệ **từ chối khẳng định** khi bằng chứng không đỡ — lá chắn neo
> RAG ở 3.l; (b) phần chênh **`rrf` ↔ `e2e`** cho biết LLM đóng góp bao nhiêu trên nền truy xuất.
>
> ⚠️ **Đừng so trực tiếp con số của mình với 43–53%.** CyberSOCEval là **trắc nghiệm nhiều lựa
> chọn** trên báo cáo tình báo; 3.a–3.d là **sinh mã kỹ thuật tự do** từ log thô. Sinh tự do khó
> hơn trắc nghiệm. Dùng nó làm **bối cảnh về độ khó của tác vụ**, không phải làm thước đo chung.

**Nguồn:**

- [CyberSOCEval: Benchmarking LLMs Capabilities for Malware Analysis and Threat Intelligence Reasoning](https://arxiv.org/pdf/2509.20166) — Meta + CrowdStrike, arXiv:2509.20166v2, 10/11/2025 *(đã đối chiếu bản gốc)*
- [AI-Augmented SOC: A Survey of LLMs and Agents for Security Automation](https://www.mdpi.com/2624-800X/5/4/95) — MDPI *(tổng quan, để định vị công trình)*
- [AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs: A Survey](https://arxiv.org/pdf/2605.08316) *(tổng quan)*
- [OpenSec: Measuring Incident Response Agent Calibration Under Adversarial Evidence](https://arxiv.org/pdf/2601.21083) — liên quan **RQ2** (bằng chứng đối kháng) và hiệu chuẩn độ tin cậy
- [AI in the SOC: Benchmarking LLMs for Autonomous Alert Triage](https://simbian.ai/blog/the-first-ai-soc-llm-benchmark) — **nguồn ngành, không bình duyệt**
