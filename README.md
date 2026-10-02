# 🛡️ SENTINEL: Cognitive Two-Tier SOC Architecture
> **Kiến trúc nhận thức hai tầng cho phát hiện và phản hồi mối đe dọa tự động sử dụng AI tác tử**
> *A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI*

[![Thesis Defense](https://img.shields.io/badge/Thesis%20Defense-8.0%2F10%20(Passed)-success?style=for-the-badge&logo=academia)](docs/Thesis/Fixed/Fix_Thesis_BinhMSE13183.pdf)
[![Degree](https://img.shields.io/badge/Degree-Master%20of%20Software%20Engineering-blue?style=for-the-badge)](docs/Thesis/Fixed/Fixed_Report_BinhMSE13183.pdf)
[![Institution](https://img.shields.io/badge/University-FPT%20University-orange?style=for-the-badge)](https://fpt.edu.vn)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![On-Premises](https://img.shields.io/badge/Deployment-100%25%20On--Premises%20Air--Gapped-purple?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

---

## 📌 Giới thiệu & Bối cảnh (Overview)

**SENTINEL** là công trình Luận văn Thạc sĩ ngành **Kỹ thuật Phần mềm (MSE)** tại Viện Quản trị & Công nghệ FSB — Trường Đại học FPT, đề xuất và hiện thực hóa một kiến trúc Trung tâm Điều hành An ninh mạng (SOC) nhận thức hai tầng, giải quyết triệt để **"Nghịch lý LLM trong An ninh mạng"**:

* **Thực trạng:** Các trung tâm SOC đối mặt với hàng triệu sự kiện/ngày dẫn tới hiện tượng kiệt quệ cảnh báo (*Alert Fatigue*).
* **Nghịch lý LLM:** Nếu đưa thẳng Mô hình Ngôn ngữ Lớn (LLM) vào luồng giám sát thì hệ thống sẽ **Chậm** (độ trễ hàng giây/sự kiện, không tải nổi tốc độ đường truyền), **Đắt** (chi phí tính toán khổng lồ), và **Dễ tổn thương** (ảo giác gán sai quy tắc, rủi ro Prompt Injection).
* **Đột phá của SENTINEL:** Phân tầng theo chi phí tính toán (*Compute-cost Tiering*) — Tầng 1 lọc sạch đại đa số lưu lượng mạng thô ở tốc độ sub-millisecond mà **không tiêu tốn một token LLM nào**; chỉ chuyển các sự kiện thực sự bất thường lên Tầng 2 để AI tác tử phân tích ngữ cảnh chuyên sâu, truy nguyên chứng cứ qua Dual-RAG và phản hồi bán tự động có con người giám sát (*Human-in-the-Loop*).

Hệ thống được thiết kế vận hành **100% nội bộ (on-premises)** trên phần cứng GPU tiêu chuẩn doanh nghiệp (RTX 4060 Ti 16GB), bảo vệ dữ liệu nhạy cảm không thoát ra ngoài đám mây.

---

## 🎓 Thông tin Luận văn Thạc sĩ (Thesis Metadata)

* **Đề tài:** *Kiến trúc nhận thức hai tầng cho phát hiện và phản hồi mối đe dọa tự động sử dụng AI tác tử*
  *(A Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI)*
* **Học viên thực hiện:** **Nguyễn Đức Bình** — MSHV: **24MSE13183** — Lớp: **MSE23HN**
* **Giảng viên hướng dẫn:** **TS. Phan Duy Hùng**, **TS. Bùi Văn Hiếu**
* **Cơ sở đào tạo:** Trường Đại học FPT (Viện Quản trị & Công nghệ FSB)
* **Kết quả bảo vệ:** **8.0 / 10** (Bảo vệ thành công trước Hội đồng Chuyên môn)

### 📂 Tài liệu bảo vệ chính thức (Official Deliverables):
1. 📄 **Báo cáo tiếp thu & giải trình hiệu chỉnh:** [`docs/Thesis/Fixed/Fix_Thesis_BinhMSE13183.pdf`](docs/Thesis/Fixed/Fix_Thesis_BinhMSE13183.pdf)
2. 📘 **Luận văn hoàn thiện (PDF):** [`docs/Thesis/Fixed/Fixed_Report_BinhMSE13183.pdf`](docs/Thesis/Fixed/Fixed_Report_BinhMSE13183.pdf) *(Bản nộp lưu chiểu: [`MSE23HN_NguyenDucBinh_24MSE13183.pdf`](docs/Thesis/MSE23HN_NguyenDucBinh_24MSE13183.pdf))*
3. 📑 **Slide thuyết trình chính thức:** [`docs/Thesis/Fixed/Fixed_Slide_BinhMSE13183.pdf`](docs/Thesis/Fixed/Fixed_Slide_BinhMSE13183.pdf) *(Bản trình chiếu tương tác: [`docs/Thesis/slides/index.html`](docs/Thesis/slides/index.html))*
4. 📝 **Mã nguồn LaTeX:** [`thesis_latex_vi`](docs/Thesis/latex/thesis_latex_vi/) (Tiếng Việt) & [`thesis_latex_en`](docs/Thesis/latex/thesis_latex_en/) (Tiếng Anh)

---

## 🏛️ Kiến trúc hệ thống (System Architecture)

```
                    [ DÒNG SỰ KIỆN MẠNG TỐC ĐỘ CAO ]
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  TẦNG 1: BỘ LỌC ĐỊNH LƯỢNG TỐC ĐỘ CAO (DETERMINISTIC STREAM TRIAGE)     │
│  - Chữ ký ModSecurity WAF + Phân cụm template log Drain3                 │
│  - Thuật toán Welford O(1) thống kê bất thường dòng dữ liệu               │
│  - Bộ phân loại học máy nhẹ LightGBM Gateway (xử lý <1ms)                │
│  ===> Lọc sạch >97.5% lưu lượng rác & tấn công thô (100% KHÔNG DÙNG LLM) │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ Leo thang cảnh báo nghi vấn (~2.5%)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  TẦNG 2: NHẬN THỨC NGỮ CẢNH & PHẢN HỒI BẰNG AI TÁC TỬ (AGENTIC TIER)     │
│  - Rào chắn bảo vệ (Guardrails): Chống Delimiter Smuggling & Prompt Injection│
│  - Dual-RAG: Truy xuất kép MITRE ATT&CK (định danh) + NIST 800-61r2 (ứng phó)│
│  - Agentic FSM (LangGraph + Gemma-2-9B/Llama-3): Lập luận bối cảnh sâu   │
│  - Evidence-Anchoring Shield: Triệt tiêu ảo giác, neo mã kỹ thuật vào log│
│  - Ledger: Niêm phong sổ cái bằng chuỗi HMAC-SHA256 (chống chối bỏ)      │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
          [ Tự động kích hoạt ]           [ Người duyệt AWAIT_HITL ]
          (Cách ly IP, sinh rule)         (Kèm đầy đủ bằng chứng RAG)
                    │                               │
                    └───────────────┬───────────────┘
                                    ▼
                  [ VÒNG LẶP PHẢN HỒI (FEEDBACK LOOP) ]
         Hot-reload luật mới xuống Tầng 1 — Lần sau xử lý tức thì
```

### ⚡ Hai tầng xử lý bổ trợ nhau:

| Thành phần | Công nghệ cốt lõi | Vai trò & Kết quả vận hành |
| :--- | :--- | :--- |
| **Tầng 1 (Triage)** | ModSecurity WAF, Welford Anomaly, Drain3, LightGBM | Xử lý phần lớn lưu lượng ở tốc độ đường truyền (<1ms). Phán quyết: `PASS`, `BLOCK`, hoặc `ESCALATE` không tốn chi phí suy luận. |
| **Tầng 2 (Agentic)** | LangGraph FSM, Local LLM (llama.cpp/vLLM), Dual-RAG | Chỉ kích hoạt khi có leo thang; phân tích biến thể Zero-day, đối chiếu ma trận MITRE ATT&CK và quy trình NIST SP 800-61r2. |
| **Rào chắn bảo vệ** | Nonce Encapsulation, Regex Delimiter Sanitizer | Đóng gói dữ liệu log vào lồng Nonce mật mã; loại bỏ 100% rủi ro Prompt Injection. |
| **Sổ cái pháp y** | HMAC-SHA256 Hash Chaining | Mọi hành động được ký băm liên kết chuỗi; phát hiện tức thì nếu dữ liệu log/audit bị kẻ tấn công sửa đổi hay xóa chèn. |
| **Hồi tiếp luật** | Dynamic Policy Hot-Reload | Luật mới do chuyên viên duyệt được biên dịch đẩy ngược về Tầng 1, biến sự cố mới thành tri thức phòng thủ tức thì. |

---

## 📊 Kết quả thực nghiệm nổi bật (Key Empirical Results)

Toàn bộ chỉ số được trích xuất minh bạch và kiểm chứng độc lập từ các kịch bản đo kiểm chuẩn trong `experiments/results/*.json`:

| Chỉ số đo kiểm | Kết quả đạt được | Ý nghĩa thực tiễn |
| :--- | :---: | :--- |
| **Tỷ lệ giảm tải dòng (Stream Offload)** | **97.5%** | 97.472 trên 99.717 sự kiện được giải quyết triệt để tại Tầng 1; chỉ **2.53%** sự kiện leo thang lên LLM. |
| **Độ trễ trung vị (Median Latency)** | **0.88 ms** | Giảm gần **19.500 lần** so với kiến trúc Single-tier LLM đơn khối (17.174,7 ms), đáp ứng lưu lượng thực tế. |
| **Giảm tải chuyên viên SOC (Analyst Load Cut)** | **84.2%** | Tự động hóa xử lý các cảnh báo thông thường, 15.8% sự kiện cần người duyệt chứa 95.0% mối đe dọa thực tế. |
| **Phòng vệ tiêm nhiễm (Injection Defense)** | **100%** | Ngăn chặn thành công **678/678** mẫu tấn công tiêm nhiễm câu lệnh độc (AdvBench, Jackhhao, Deepset). |
| **Toàn vẹn sổ cái (Audit Tamper Detection)** | **100%** | Chuỗi băm HMAC-SHA256 định vị chính xác **90/90** trường hợp giả mạo, chèn lén hoặc sửa đổi lịch sử quyết định. |
| **Độ chính xác toàn tuyến Tầng 2** | **68.0%** | Đánh đổi có chủ đích từ trần suy diễn RAG (80.0%) thông qua rào chắn neo chứng cứ để bảo đảm **0% quyết định phát ra bị ảo giác**. |

---

## 🚀 Hướng dẫn cài đặt & Khởi chạy (Quick Start)

### Yêu cầu hệ thống (Prerequisites)
* **Hệ điều hành:** Linux (Ubuntu 22.04+ khuyến nghị)
* **Python:** 3.10+
* **Phần cứng:** 32 GB RAM, NVIDIA GPU ≥ 16 GB VRAM (chạy mô hình 9B Q4_K_M).
* **Dịch vụ hỗ trợ:** Redis 7+ (`sudo apt install redis-server` hoặc Docker).

### Bước 1: Khởi tạo môi trường & Cài đặt thư viện
```bash
# Clone repository
git clone https://github.com/Binhchuoiz/AI_Security_Graph.git
cd AI_Security_Graph

# Thiết lập virtual environment
python3.10 -m venv .venv
source .venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt
pip install drain3==0.9.11 --no-deps jsonpickle>=1.5.1

# Cấu hình biến môi trường
cp .env.example .env
# Chỉnh sửa .env để cấu hình SENTINEL_LOG_SECRET và đường dẫn LLM
```

### Bước 2: Khởi tạo dữ liệu & Dựng chỉ mục RAG
```bash
# Dựng chỉ mục tri thức kép MITRE ATT&CK và NIST SP 800-61r2 (FAISS + BM25)
python -m src.rag.embedder

# Xây dựng luồng dữ liệu kiểm thử chuẩn CSIC 2010
python scripts/build_csic_dataset.py --limit 36000
python scripts/build_demo.py
```

### Bước 3: Khởi chạy bảng điều khiển tương tác (Dashboard)
```bash
# Khởi chạy luồng mô phỏng SOC và giao diện điều hành Streamlit
UNIFIED_STREAM_DELAY=0 UNIFIED_STREAM_BATCH=500 ./scripts/run_demo.sh --fresh
```
Truy cập giao diện Web Dashboard tại: **`http://localhost:8501`**

---

## 🧪 Kiểm thử & Đo kiểm (Tests & Quality Assurance)

Toàn bộ hệ thống được bảo vệ bởi bộ kiểm thử tự động toàn diện (666 tests unit, integration và red-teaming):

```bash
# Chạy bộ unit tests & integration tests
SENTINEL_FREEZE_DYNAMIC_RULES=1 MOCK_LLM=1 pytest --cov=src

# Chạy kiểm thử tích hợp toàn tuyến E2E (15/15 kịch bản)
python experiments/e2e_test_runner.py --offline

# Đối soát số liệu thực nghiệm khớp từng con số với luận văn
python scripts/audit_thesis_numbers.py
```

---

## 📁 Cấu trúc thư mục (Repository Structure)

```text
├── src/                        # Mã nguồn ứng dụng runtime
│   ├── streaming/              # Bộ nhận và quản lý dòng sự kiện (Redis/IPC)
│   ├── tier1_filter/           # Tầng 1: WAF signatures, Welford Anomaly, LightGBM
│   ├── guardrails/             # Rào chắn an toàn: Nonce encapsulator, output sanitizer
│   ├── rag/                    # Dual-RAG engine: FAISS + BM25, hybrid retriever
│   ├── agent/                  # Tầng 2: LangGraph FSM, node logic, state management
│   ├── response/               # Bộ thi hành phản hồi, HMAC-SHA256 audit ledger
│   └── ui/                     # Giao diện Web Dashboard Streamlit
├── experiments/                # Bộ khung đo kiểm thực nghiệm & tập kết quả JSON
│   ├── results/                # Kết quả benchmark gốc phục vụ viết luận văn
│   └── adversarial/            # Bộ dữ liệu mẫu tấn công Red-teaming
├── docs/                       # Tài liệu dự án
│   ├── Thesis/                 # Luận văn PDF, Slide báo cáo, LaTeX source, Template
│   │   ├── Fixed/              # Bộ 3 tệp PDF hoàn thiện gửi Hội đồng
│   │   ├── slides/             # Slide thuyết trình HTML tương tác
│   │   └── latex/              # Mã nguồn LaTeX Luận văn (Bản VI & Bản EN)
│   └── Codebase/               # Sổ tay vận hành, hướng dẫn demo chi tiết
├── config/                     # Cấu hình chính sách, rule WAF, ngưỡng phát hiện
├── scripts/                    # Script tiện ích xây dựng dataset, audit số liệu
└── tests/                      # Bộ 666 bài test tự động (Unit, Integration, Red-team)
```

---

## 📜 Trích dẫn & Bản quyền (Citation & License)

Dự án phát hành theo giấy phép mã nguồn mở **[MIT License](LICENSE)**.

Nếu bạn sử dụng kết quả nghiên cứu hoặc mã nguồn của SENTINEL trong các công trình học thuật, vui lòng trích dẫn theo định dạng sau (hoặc xem [`CITATION.cff`](CITATION.cff)):

```bibtex
@mastersthesis{nguyen2026sentinel,
  author       = {Nguyễn Đức Bình},
  title        = {Kiến trúc nhận thức hai tầng cho phát hiện và phản hồi mối đe dọa tự động sử dụng AI tác tử},
  school       = {Trường Đại học FPT},
  year         = {2026},
  month        = {10},
  note         = {Luận văn Thạc sĩ ngành Kỹ thuật Phần mềm (MSE23HN, MSHV 24MSE13183)},
  address      = {Hà Nội, Việt Nam}
}
```

---
*© 2026 Nguyễn Đức Bình — Học viên Cao học ngành Kỹ thuật Phần mềm, Trường Đại học FPT.*
