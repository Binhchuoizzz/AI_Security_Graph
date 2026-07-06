---
marp: true
paginate: true
theme: gaia
class: lead
header: 'SENTINEL — Kiến trúc Nhận thức Hai tầng'
footer: 'Nguyễn Đức Bình · FPT University · MSE · 2026'
style: |
  section { font-size: 26px; }
  h1 { color: #1565c0; }
  h2 { color: #0d47a1; }
  strong { color: #c62828; }
  table { font-size: 22px; }
  code { font-size: 20px; }
  section.lead h1 { font-size: 40px; }
  .small { font-size: 20px; color: #555; }
---

<!-- _class: lead -->
# SENTINEL
## Kiến trúc Nhận thức Hai tầng cho Phát hiện & Phản hồi Mối đe dọa Tự động sử dụng AI Tác tử (Agentic AI)

**Học viên:** Nguyễn Đức Bình
**GVHD:** TS. Bùi Văn Hiếu · TS. Đặng Văn Hiếu
**Trường Đại học FPT — Thạc sĩ Kỹ thuật Phần mềm (MSE) · 2026**

<!--
Kính thưa hội đồng, em là Nguyễn Đức Bình. Hôm nay em xin trình bày luận văn "Kiến trúc nhận thức hai tầng SENTINEL cho phát hiện và phản hồi mối đe dọa tự động sử dụng AI tác tử". Bài trình bày khoảng 30 phút gồm: bối cảnh & vấn đề, kiến trúc & đóng góp, phương pháp đánh giá, kết quả thực nghiệm, hạn chế và kết luận.
-->

---

## Bối cảnh & Vấn đề

- **Trung tâm Điều hành An ninh (SOC)** ngập trong cảnh báo → **mệt mỏi cảnh báo (alert fatigue)** → bỏ sót **APT** nguy hiểm.
- Hai hướng tiếp cận hiện có đều có **giới hạn cố hữu**:

| Hướng | Ưu | Nhược |
|---|---|---|
| Luật tĩnh (rule/signature) | Nhanh, tất định | **Bỏ sót zero-day**, không hiểu ngữ cảnh |
| Đưa **mọi** log vào LLM | Suy luận sâu | **Trễ 4–6 giây/log**, không mở rộng, rủi ro bị thao túng |

> **Khoảng trống:** chưa có kiến trúc kết hợp *tốc độ tất định* với *suy luận LLM có kiểm soát & an toàn*.

<!--
Vấn đề cốt lõi: SOC nhận quá nhiều cảnh báo, dẫn tới mệt mỏi cảnh báo và bỏ sót tấn công có chủ đích APT. Luật tĩnh thì nhanh nhưng mù ngữ cảnh và bỏ sót zero-day. Còn đưa mọi log qua LLM thì suy luận tốt nhưng trễ 4-6 giây mỗi log, không thể mở rộng ở tốc độ mạng, và bản thân LLM có thể bị tấn công thao túng. Luận văn giải quyết khoảng trống giữa hai hướng này.
-->

---

## Câu hỏi & Mục tiêu nghiên cứu

**Câu hỏi:** Làm thế nào để tự động hoá SOC vừa **nhanh ở tốc độ mạng**, vừa **suy luận sâu có căn cứ**, mà LLM **không trở thành điểm yếu bảo mật**?

**Mục tiêu:**
1. Lọc lưu lượng lành tính ở **tốc độ mạng, O(1)** — chỉ leo thang phần *thực sự mơ hồ* cho LLM.
2. Suy luận **có nền tảng (grounded)** bằng tri thức chuẩn (MITRE ATT&CK + NIST).
3. **Cô lập LLM** khỏi thao túng đối kháng bằng rào chắn mật mã.
4. Đánh giá **nghiêm ngặt, tái lập, trung thực** (khung 5 chiều + kiểm định thống kê).

<!--
Từ khoảng trống đó, em đặt câu hỏi nghiên cứu và 4 mục tiêu: (1) lọc tốc độ cao O(1) chỉ leo thang phần mơ hồ; (2) suy luận có căn cứ dựa trên MITRE và NIST; (3) cô lập LLM khỏi tấn công đối kháng; (4) đánh giá nghiêm ngặt và trung thực.
-->

---

## Đóng góp chính

1. **Kiến trúc 2 tầng** — Tier-1 lọc tất định tốc độ mạng ↔ Tier-2 tác tử LangGraph.
2. **Bộ lọc Welford trực tuyến** phát hiện zero-day thống kê ở **O(1)** RAM/CPU.
3. **Dual-RAG** (FAISS + BM25 + RRF) nền tảng hoá suy luận trên MITRE + NIST.
4. **Rào chắn AI phòng thủ chiều sâu** + đồng thuận Tier-1/Tier-2 chống thao túng ngữ nghĩa.
5. **Lớp ánh xạ MITRE ATT&CK có cấu trúc** (đóng góp bổ sung — node thứ 6).
6. **Khung đánh giá 5 chiều + kiểm định thống kê** (McNemar, Mann-Whitney U, Wilson CI, LLM-as-Judge liên-họ).

<!--
Sáu đóng góp chính. Ba cái đầu là lõi kiến trúc: hai tầng, Welford O(1), Dual-RAG. Đóng góp 4 là bảo mật phòng thủ chiều sâu. Đóng góp 5 là lớp ánh xạ ATT&CK có cấu trúc mới bổ sung. Đóng góp 6 là phương pháp đánh giá nghiêm ngặt bằng thống kê.
-->

---

## Kiến trúc tổng quan

```
   Log mạng ──►  ┌──────────────── TIER-1 (tốc độ mạng, O(1)) ────────────────┐
                 │  RuleEngine (signature) + Welford online (Z>3.5σ zero-day)  │
                 └───────────────┬───────────────────────────┬────────────────┘
              benign: DROP/LOG ◄─┘                           │ ESCALATE (thiểu số mơ hồ)
                                                             ▼
                 ┌──────────── TIER-2 (Tác tử LangGraph, Gemma-2-9B) ──────────┐
                 │ Guardrails → Dual-RAG → LLM-Triage → ATT&CK-Mapper → Action │
                 │            + Threat Memory (chuỗi APT đa-ngày)              │
                 └───────────────┬────────────────────────────────────────────┘
                                 ▼  BLOCK_IP / ALERT / AWAIT-HITL
                    Audit HMAC-SHA256 ─► Dashboard HITL ─► Feedback về Tier-1
```

- **Tách đường chặn đồng bộ:** Tier-1 đã chặn tấn công rõ ràng ở tốc độ mạng; LLM đóng góp **giải thích + tương quan** *bất đồng bộ* → nghẽn LLM **không** làm chậm bảo vệ.

<!--
Đây là bức tranh tổng thể. Log vào Tier-1: RuleEngine so khớp chữ ký và Welford phát hiện bất thường thống kê, tất cả ở O(1). Lưu lượng lành tính bị loại ngay. Chỉ phần thiểu số thực sự mơ hồ mới leo thang lên Tier-2 — tác tử LangGraph chạy Gemma qua các nút Guardrails, Dual-RAG, LLM-Triage, ATT&CK-Mapper, rồi hành động. Điểm mấu chốt: tầng nhận thức nằm ngoài đường chặn đồng bộ, nên nếu LLM nghẽn thì chỉ chậm phần làm giàu ngữ cảnh, chứ không chậm việc bảo vệ.
-->

---

## Tier-1 — Lọc tốc độ cao (tất định)

- **RuleEngine:** so khớp chữ ký WAF (SQLi/XSS/Path/Cmd-Inj), injection/jailbreak, cổng nhạy cảm, port-scan.
- **Welford online** (`RunningStats`): cập nhật Mean/StdDev **O(1)**; `Z > 3.5σ` ⇒ **zero-day thống kê** (mà signature bỏ sót).
- **Chống Baseline Poisoning:** chỉ nạp flow *lành tính* vào thống kê nền; hot-reload cấu hình mỗi 5s.
- **Session Baseline:** hồ sơ IP, phát hiện port-scan (>10 cổng), TTL eviction chống tràn RAM.

> **Quyết định trong ~0.6 ms** so với **4–6 s** của một lượt suy luận LLM.

<!--
Tier-1 là trái tim tốc độ. RuleEngine so khớp chữ ký các tấn công web đã biết. Quan trọng hơn, thuật toán Welford cập nhật trung bình và độ lệch chuẩn trực tuyến ở O(1) bộ nhớ — khi một luồng lệch quá 3.5 sigma, hệ coi đó là zero-day thống kê mà signature không bắt được. Để chống đầu độc đường cơ sở, chỉ nạp flow lành tính vào thống kê. Kết quả: một quyết định Tier-1 mất khoảng 0.6 mili-giây, so với 4 đến 6 giây của một lượt LLM.
-->

---

## Tier-2 — Tác tử LangGraph (6 nút)

```
guardrails ─► rag_context ─► llm_triage ─►(gate theo ACTION)─► attack_mapper
                                                 │                    │
                                       benign LOG ▼                   ▼
                                                END        action_executor / human_in_the_loop
```

- **State Machine tất định** (`@dataclass SentinelState`) — chống *semantic drift* bằng trường IOC *chỉ-append*.
- **Suy biến an toàn:** LLM chết → tự đẩy về `AWAIT_HITL`, đồ thị **không vỡ** (Tier-1 vẫn bảo vệ độc lập).
- **Tất định:** `temperature=0.1` + `seed=42` → cùng prompt cho **cùng phán quyết** (tái lập).

<!--
Tier-2 là một máy trạng thái hữu hạn do LangGraph biên dịch, gồm sáu nút. Guardrails làm sạch và nén, RAG lấy ngữ cảnh, LLM-Triage ra phán quyết. Nếu là mối đe dọa đáng hành động thì đi qua nút ATT&CK-Mapper để làm giàu, rồi tới nút hành động hoặc hàng đợi con người. Trạng thái là một dataclass với các trường IOC chỉ cho phép ghi thêm để chống trôi dạt ngữ nghĩa. Hệ suy biến an toàn: nếu LLM chết thì tự đẩy về chờ con người duyệt, đồ thị không sập. Và nhờ seed cố định, cùng một prompt luôn cho cùng một quyết định — tái lập được.
-->

---

## Dual-RAG — Suy luận có nền tảng

- Truy xuất **kép**: **MITRE ATT&CK** (299 kỹ thuật) + **NIST SP 800-61r2** (playbook ứng cứu).
- **Hybrid Search:** Dense **FAISS** (ngữ nghĩa) + Sparse **BM25** (từ khoá) → hợp nhất bằng **Reciprocal Rank Fusion (RRF, k=60)**.
- **Semantic Cache** (LRU, TTL 1800s) giảm độ trễ cho truy vấn lặp.
- **Chống RAG Poisoning:** kiểm **checksum SHA-256** tài liệu + `sanitize_retrieve` + gắn *provenance* trước khi vào prompt.

> Ràng buộc LLM vào **ngữ cảnh đã xác thực** ⇒ giảm ảo giác (hallucination).

<!--
Để LLM suy luận có căn cứ, em dùng Dual-RAG: truy xuất song song từ MITRE ATT&CK và NIST. Tìm kiếm lai kết hợp FAISS ngữ nghĩa với BM25 từ khoá, hợp nhất bằng Reciprocal Rank Fusion với hằng số k bằng 60. Có bộ đệm ngữ nghĩa để giảm trễ. Đặc biệt, để chống đầu độc kho tri thức, em kiểm checksum SHA-256 và làm sạch mọi đoạn truy xuất trước khi đưa vào prompt. Việc ràng buộc LLM vào ngữ cảnh đã xác thực giúp giảm ảo giác.
-->

---

## Rào chắn AI — Phòng thủ chiều sâu

- **Delimited Data Encapsulation** — bọc log bằng **nonce một-lần** (`secrets.token_hex`), chống *delimiter smuggling*.
- **Encoding Neutralizer** — giải Base64/Hex/URL/homoglyph trước khi phân tích.
- **Output Sanitizer** — chặn *data exfiltration* qua markdown/HTML/base64 trong đầu ra LLM.
- **Lá chắn Đồng thuận Tier-1/Tier-2** — nếu Tier-1 (tất định) coi là tấn công mà LLM hạ xuống "benign" ⇒ **ép `AWAIT_HITL`** (LLM **không thể** bị "nói chuyện" hạ cấp như con người).
- **Audit HMAC-SHA256 móc-xích** — phát hiện giả mạo log pháp y.

<!--
Vì bản thân LLM là bề mặt tấn công mới, em thiết kế phòng thủ chiều sâu. Dữ liệu log được bọc bằng nonce một lần để LLM phân biệt lệnh với dữ liệu. Bộ trung hoà mã hoá giải các payload bị làm rối. Bộ làm sạch đầu ra chặn rò rỉ dữ liệu. Quan trọng nhất là lá chắn đồng thuận: nếu tầng tất định Tier-1 khẳng định đây là tấn công nhưng LLM lại bị thuyết phục hạ xuống lành tính, hệ sẽ không tin LLM mà ép chờ con người duyệt. Cuối cùng, nhật ký kiểm toán được móc xích bằng HMAC-SHA256 để chống giả mạo.
-->

---

## Đóng góp mới: Lớp ánh xạ MITRE ATT&CK

**Vấn đề:** triage chỉ xuất *nhãn tự do* ("SQLi detected") → khó dùng cho SOC.

**Giải pháp:** node `attack_mapper` biến thành **bản ghi có cấu trúc, kiểm chứng được**:

```json
{ "attack_type": "SQL Injection", "mitre_tactic": "Initial Access",
  "mitre_technique": "T1190 - Exploit Public-Facing Application",
  "mitre_url": "https://attack.mitre.org/techniques/T1190/",
  "recommended_response": "Chặn IP tại WAF + leo thang HITL" }
```

- **3 đường:** curated (web-attack, tất định) → **neo vào verdict triage** → RRF+LLM (fallback).
- **Trung thực:** Prompt Injection → **MITRE ATLAS** (không phải Enterprise); IDOR không có kỹ thuật riêng.

<!--
Đây là đóng góp bổ sung mà em hoàn thiện gần đây. Trước đó, tầng triage chỉ xuất một nhãn tự do như "phát hiện SQLi", rất khó dùng cho quy trình SOC. Node attack_mapper biến nó thành một bản ghi ATT&CK có cấu trúc, kiểm chứng được: tactic, technique, URL chính thức, và phản hồi đề xuất. Nó có ba đường: tra bảng tất định cho web-attack phổ biến, neo vào kỹ thuật mà triage đã gán, và chỉ dùng RRF khi cần. Em cũng giữ tính trung thực: prompt injection thuộc MITRE ATLAS chứ không phải Enterprise, và IDOR thì ATT&CK không có kỹ thuật riêng — em ghi rõ giới hạn này.
-->

---

## Threat Memory & Phát hiện APT đa-ngày

- **Bộ nhớ dài hạn** (SQLite): uy tín IP, thực thể nội bộ, chỉ báo APT — **inject vào prompt** để Agent biết *lịch sử*.
- **Tương quan APT EMERGENT:** IP xuất hiện ở **≥2 NGÀY tấn công** phân biệt ⇒ ghép thành **chuỗi kill-chain đa-ngày**.
- Chống **low-and-slow**: liên kết các hành vi đơn lẻ cách nhau nhiều ngày mà signature đơn-điểm bỏ sót.

> Khôi phục **3/3 chiến dịch APT** (DAPT2020), **recall = 1.0**, **specificity = 1.0** (0 báo nhầm).

<!--
Tấn công APT diễn ra chậm và rải rác nhiều ngày, nên em xây Threat Memory bằng SQLite lưu uy tín IP và chỉ báo APT, rồi inject lịch sử này vào prompt. Cơ chế tương quan emergent: khi một IP xuất hiện ở ít nhất hai ngày tấn công phân biệt, hệ ghép chúng thành một chuỗi kill-chain đa ngày. Nhờ đó phát hiện được tấn công low-and-slow. Trên tập DAPT2020, hệ khôi phục cả ba chiến dịch APT với recall bằng 1, và specificity bằng 1 tức không có báo nhầm.
-->

---

## Phương pháp Đánh giá — Khung 5 chiều (5D)

| Chiều | Chỉ số vận hành |
|---|---|
| **Accuracy** | Precision / Recall / F1 · APT recall · zero-day |
| **Performance** | Độ trễ Tier-1 vs Tier-2 · tỷ lệ leo thang |
| **Security** | Tỷ lệ kháng adversarial (tĩnh vs full-pipeline) |
| **Explainability** | LLM-as-Judge liên-họ (RAGAS) · độ đầy đủ audit |
| **Integrity** | Xác thực chuỗi HMAC |

- **Kiểm định thống kê:** McNemar, **Mann-Whitney U**, **Wilson 95% CI**.
- **Dữ liệu THẬT:** CSE-CIC-IDS2018 + DAPT2020 · **tất định** (seed=42) · **isolation** không đụng dữ liệu luận văn.

<!--
Về phương pháp, em đánh giá theo khung năm chiều: Độ chính xác, Hiệu năng, Bảo mật, Tính giải thích, Tính toàn vẹn. Mỗi chiều gắn với một chỉ số vận hành cụ thể. Em áp dụng kiểm định thống kê phi tham số: McNemar cho khác biệt phân loại, Mann-Whitney U cho độ trễ, và khoảng tin cậy Wilson cho mẫu nhỏ. Toàn bộ chạy trên dữ liệu thật CSE-CIC-IDS2018 và DAPT2020, tất định với seed 42, và cô lập để không làm bẩn dữ liệu luận văn.
-->

---

## Kết quả 1 — Hiệu năng

- **Độ trễ Tier-1: ~0.6 ms** ↔ **Tier-2 (LLM): 4–6 s** — tách biệt được kiểm định **Mann-Whitney U** (**p = 2.8 × 10⁻¹⁷**).
- **Giảm độ trễ đầu-cuối 82.97%**: LLM-only **26.9 s** → Two-Tier **4.6 s** (mục tiêu ≥ 60%).
- **Kiểm soát ngữ cảnh:** nén Drain **bão hoà ~80 token** bất kể số log (RAW vượt cửa sổ 8192 tại N≈100).

> Tier-1 giải quyết **~91%** lưu lượng ⇒ chỉ **~9%** phải gọi LLM.

<!--
Kết quả hiệu năng. Tier-1 quyết định trong khoảng 0.6 mili-giây, còn một lượt LLM mất 4 đến 6 giây. Sự tách biệt này được Mann-Whitney U khẳng định có ý nghĩa thống kê với p rất nhỏ, 2.8 nhân 10 mũ trừ 17. Nhờ Tier-1 giải quyết khoảng 91% lưu lượng, chỉ 9% phải gọi LLM, nên độ trễ đầu cuối giảm gần 83%, từ 26.9 giây xuống 4.6 giây. Bộ nén Drain giữ token đầu vào bão hoà quanh 80 token bất kể số lượng log, tránh tràn cửa sổ ngữ cảnh.
-->

---

## Kết quả 2 — Độ chính xác

- **Phân loại (Unified Stream):** F1 = **0.594** · Precision = **0.939** · Recall = **0.435**.
- **APT đa-ngày:** **3/3** chiến dịch · recall **1.0** · specificity **1.0**.
- **Zero-day:** Welford bắt **7/7** ngoại lệ signature-less mà engine tĩnh **bỏ sót**.

<span class="small">*Ghi chú trung thực:* Precision cao (0.94) nhưng Recall/F1 phản ánh việc Tier-1 ưu-tiên-precision (đánh đổi có chủ đích); giá trị kiến trúc nằm ở suy luận có ngữ cảnh + APT + zero-day, không chỉ ở phân loại nhị phân.*</span>

<!--
Về độ chính xác: trên luồng gộp, F1 đạt 0.594 với precision 0.939 và recall 0.435. Trên APT, phát hiện cả 3 chiến dịch với recall và specificity đều bằng 1. Với zero-day, bộ lọc Welford bắt được cả 7 ngoại lệ không có chữ ký mà engine tĩnh bỏ sót. Em xin nói thẳng: precision cao nhưng đây là thiết kế ưu tiên precision có chủ đích; giá trị thật của kiến trúc nằm ở suy luận có ngữ cảnh, phát hiện APT và zero-day, chứ không chỉ ở phân loại nhị phân.
-->

---

## Kết quả 3 — Bảo mật & Tính giải thích

- **Kháng đối kháng (full-pipeline, LLM + Consensus Guard):** **100%** (0 bị chiếm quyền).
- **Rào chắn tĩnh (120 payload OWASP):** chặn **100% encoding-bypass**; ~**50%** tổng thể — phần *ngữ nghĩa* còn lại được **lá chắn đồng thuận** đẩy về HITL.
- **LLM-as-Judge liên-họ** (Llama-3 chấm Gemma-2): tổng **3.91/5**; **Faithfulness 4.00/5** (kết luận bám chứng cứ RAG).

> Phòng thủ **chiều sâu**, không phải một biểu thức regex đơn lẻ.

<!--
Về bảo mật và tính giải thích: khi tấn công vào toàn pipeline có LLM và lá chắn đồng thuận, tỷ lệ kháng đạt 100% — không payload nào chiếm được quyền. Riêng lớp rào chắn tĩnh chặn 100% payload mã hoá, khoảng 50% tổng thể, phần ngữ nghĩa còn lại được lá chắn đồng thuận đẩy về con người duyệt. Về tính giải thích, em dùng LLM-as-Judge liên họ: dùng Llama-3 của Meta chấm suy luận của Gemma-2 của Google để tránh thiên vị cùng họ — điểm tổng 3.91 trên 5, và Faithfulness 4.0, nghĩa là kết luận bám sát chứng cứ RAG.
-->

---

## Kết quả 4 — Lớp ánh xạ ATT&CK

| Chế độ đánh giá | n | Khớp technique | Tactic |
|---|---|---|---|
| Unit (10 web-attack, curated) | — | **100%** | — |
| **Web-payload — pipeline triển khai** | 50 | **64.0%** | 57.5% |
| Web-payload — chỉ truy xuất (rrf) | 50 | 62.0% | 52.5% |
| Flow-only GT — pipeline triển khai | 160 | **0.0%** | 3.6% |

- **Trung thực:** 0% trên flow-only là **giới hạn của bài toán** (ill-posed) — nhãn cơ học ≠ suy luận LLM; **không phải lỗi mapper**.
- Signature attacks: Prompt-Inj & Cmd-Inj **100%**, XSS & Path-Trav 80%.

<!--
Kết quả của lớp ánh xạ ATT&CK. Kiểm thử đơn vị trên 10 loại web-attack đạt 100% đúng. Trên bộ web-payload thật — đúng miền thiết kế — pipeline triển khai đạt 64% khớp technique. Em xin trung thực về con số 0% trên dữ liệu flow-only: đây là giới hạn của chính bài toán — ánh xạ technique từ đặc trưng luồng thuần là bài toán đặt sai, vì nhãn được gán cơ học khác với điều LLM suy ra hợp lý; đây không phải lỗi của mapper. Với các tấn công có chữ ký rõ như prompt injection và command injection, độ chính xác đạt 100%.
-->

---

## Ablation Study — Đóng góp từng tầng

- Tập **cân bằng 150 benign / 150 tấn công** (tránh base-rate làm mọi cấu hình co về "toàn-dương").

| Cấu hình | Precision | Recall | Độ trễ |
|---|---|---|---|
| **B** — LLM thuần (không lọc/RAG/chắn) | 0.508 | 0.867 | 6.50 s |
| **C** — + cổng Welford | **0.627** | 0.493 | **0.59 s** |

- **Cổng Welford:** precision **0.508→0.627**, độ trễ **giảm ~11 lần** — đánh đổi có chủ đích với recall.
- **McNemar** (B vs mọi cấu hình có cổng): **p < 0.001** (138 phán quyết bất đồng một chiều).

<!--
Nghiên cứu loại trừ để tách đóng góp từng tầng. Em dùng tập cân bằng 150-150 vì tập gốc 93% tấn công khiến mọi cấu hình co về dự đoán toàn dương. So sánh: LLM thuần precision chỉ 0.508 và tốn 6.5 giây mỗi sự kiện. Thêm cổng Welford, precision tăng lên 0.627 và độ trễ giảm khoảng 11 lần xuống 0.59 giây, đổi lại recall giảm — đúng thiết kế ưu tiên precision. Kiểm định McNemar cho thấy khác biệt này có ý nghĩa thống kê với p nhỏ hơn 0.001.
-->

---

## Hạn chế (nêu thẳng)

- **Ánh xạ ATT&CK từ flow-only** là bài toán **ill-posed** — hiệu quả ở miền có payload/ngữ nghĩa, không ở telemetry luồng thuần.
- **Cỡ mẫu APT nhỏ** (n=3) → báo bằng **Wilson 95% CI**, cần dữ liệu APT lớn hơn.
- **Enforcement là `[FIREWALL MOCK]`** (ghi audit) — thực thi thật giao cho luật ACTIVE ở Tier-1; chưa tích hợp firewall sản xuất.
- **Dataset** CSE-CIC-IDS2018 (2018) — cần dữ liệu mối đe dọa mới hơn.

<!--
Em xin nêu thẳng các hạn chế. Thứ nhất, ánh xạ ATT&CK từ dữ liệu luồng thuần là bài toán đặt sai, chỉ hiệu quả ở miền có payload. Thứ hai, cỡ mẫu APT nhỏ chỉ 3 chiến dịch nên em báo kèm khoảng tin cậy Wilson và cần dữ liệu lớn hơn. Thứ ba, hành động chặn hiện là mô phỏng ghi audit, việc thực thi thật giao cho luật ở Tier-1, chưa tích hợp firewall sản xuất. Và dataset từ 2018 cần được cập nhật.
-->

---

## Hướng phát triển

- **Threat intel nội bộ:** nạp TTP nhóm APT thực tế (vd Mustang Panda / PlugX từ MITRE **G0129**) vào RAG.
- **Mở rộng đa-nguồn → Agentic XDR:** thêm DNS / EDR / PAM (đã sẵn kiến trúc Redis Streams đa-queue).
- **Tinh chỉnh (fine-tune) Gemma** trên dữ liệu tấn công đặc thù (LoRA/QLoRA) khi có HPC.
- **Tích hợp SOAR** (XSOAR): SENTINEL *cấp intelligence* cho playbook tự động.

<!--
Hướng phát triển: một là nạp threat intelligence nội bộ như TTP của các nhóm APT thực tế vào RAG. Hai là mở rộng đa nguồn thành Agentic XDR bằng cách thêm log DNS, EDR, PAM — kiến trúc Redis Streams đa hàng đợi đã sẵn sàng cho việc này. Ba là tinh chỉnh Gemma bằng LoRA trên dữ liệu tấn công đặc thù khi có hạ tầng tính toán. Bốn là tích hợp với SOAR như XSOAR, để SENTINEL cấp intelligence cho các playbook tự động.
-->

---

## Kết luận

- **SENTINEL** chứng minh: ghép **bộ lọc tất định tốc độ mạng** với **tầng AI tác tử được cô lập mật mã** cho ra giải pháp **mở rộng được & an ninh hoá**.
- **Số liệu chốt:** độ trễ **−82.97%** (p=2.8×10⁻¹⁷) · APT **3/3** · zero-day **7/7** · suy luận **3.91/5** · ATT&CK mapper **64%** (miền web).
- **Kỹ thuật vững:** **207 test** pass · tất định (seed 42) · đánh giá **trung thực** (nêu cả kết quả âm).

> **Đóng góp:** một khuôn mẫu hai-tầng *có thể mở rộng, giải thích được, an toàn* cho phòng thủ mạng hiện đại.

<!--
Kết luận: SENTINEL chứng minh rằng ghép một bộ lọc tất định tốc độ mạng với một tầng AI tác tử được cô lập mật mã sẽ cho ra một giải pháp tự động hoá vừa mở rộng được vừa an ninh hoá. Các con số chốt: giảm độ trễ gần 83% có ý nghĩa thống kê, phát hiện đủ APT và zero-day, suy luận được chấm 3.91 trên 5, và lớp ánh xạ ATT&CK đạt 64% ở miền web. Về mặt kỹ thuật, 207 test đều pass, hệ tất định, và quan trọng là em đánh giá trung thực, nêu cả kết quả âm. Đóng góp là một khuôn mẫu hai tầng có thể mở rộng, giải thích được và an toàn cho phòng thủ mạng hiện đại.
-->

---

<!-- _class: lead -->
# Xin cảm ơn Hội đồng!
## Em xin lắng nghe câu hỏi & góp ý

**Nguyễn Đức Bình** — MSE, FPT University, 2026
<span class="small">SENTINEL · Kiến trúc Nhận thức Hai tầng · Agentic AI</span>

<!--
Em xin cảm ơn hội đồng đã lắng nghe. Em rất mong nhận được câu hỏi và góp ý từ quý thầy cô để hoàn thiện luận văn. Em xin trân trọng cảm ơn.
-->
