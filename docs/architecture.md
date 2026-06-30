# Kiến Trúc Hệ Thống (System Architecture)

Hệ thống SENTINEL được thiết kế theo kiến trúc **2-Tier (2 Tầng)** kết hợp luồng dữ liệu thời gian thực (Streaming) và Tác tử suy luận AI (LLM Agent) có hỗ trợ học tích cực Few-shot và phát hiện Outlier không giám sát.

## 1. Biểu Đồ Kiến Trúc Luồng Dữ Liệu

```mermaid
graph TD
    subgraph Data Ingestion
        A[Nguồn Log Mạng / DAPT2020 / CICIDS2018] -->|Streaming| B(Redis Streams)
    end

    subgraph Tier 1: Lọc Sơ Cấp (Rule Engine & Unsupervised)
        B --> C[Subscriber]
        C --> D{Rule Engine: Static, Stateful & Outlier Detector Welford}
        D -->|Benign| E[(Drop/Bỏ qua)]
        D -->|Bất Thường Escalate / Z-Score > 3.5| F[Guardrails: Template Miner + Encapsulator]
    end

    subgraph Khối Tri Thức & Trạng Thái (Storage Layer)
        G[(MITRE FAISS Index)]
        H[(NIST FAISS Index)]
        I[(Threat Memory SQLite)]
        J[(MLflow DB & Artifacts)]
        K[(Audit Trail DB)]
    end

    subgraph Tier 2: LLM Agent & Active Learning (LangGraph)
        F --> L[Triage Node]
        L --> M[RAG Retrieval Node]
        M --> O[Reasoning Node Gemma-2-9B-IT + Few-shot Active Learning]
        O --> P[Action/Routing Node]
    end

    M -.-> G
    M -.-> H
    L -.-> I
    O -.-> J
    P -.-> K

    P -->|Phản hồi/Quyết định| Q[Firewall / Streamlit Dashboard + Live FPR]
    Q -.->|Phê duyệt Rule / Active Learning| R[Feedback Loop (Cập nhật Tier 1)]
    R -.-> D
```

## 2. Các Thành Phần Chính (Components)

1. **Streaming Layer (`src/streaming/`)**: Xử lý dữ liệu đầu vào tốc độ cao. Gồm Publisher đẩy log lên Redis và Subscriber lấy log xuống. Subscriber đếm log thô qua Tier-1 + số bị DROP ghi `config/pipeline_stats.json` để Dashboard hiển thị **Noise Reduction THẬT** (đo trực tiếp, thực đo 550 log → drop 548 → 99.6%). *(Có 3 publisher: `publisher.py` = raw-CSV load-test, `scripts/simulate_traffic.py` = replay ground_truth, `experiments/stream_unified_online.py` = luồng gộp CICIDS+DAPT+zero-day online qua full pipeline.)*
2. **Tier 1 Filter (`src/tier1_filter/`)**: Rule Engine kiểm tra các điều kiện cơ bản (Session Baseline) và chặn nhanh (IP Blacklist, Port rules). Đồng thời tích hợp thuật toán **Welford** online để phát hiện **Unsupervised Anomaly (Zero-day outliers Z-score > 3.5)** dựa trên các metrics lưu lượng mạng thực tế.
3. **Guardrails (`src/guardrails/`)**: Màng bọc an ninh nhiều lớp. Đóng gói dữ liệu đầu vào bằng nonce động (Delimited Data Encapsulation) chống Prompt Injection; phát hiện Jailbreak/DAN; trung hòa Encoding (Base64/Hex/URL + Base32/ROT13/leetspeak/homoglyph NFKC); nén luồng (Drain3 Template Miner). Đầu ra LLM qua **Output Sanitizer** (strip XSS/markdown/base64-hex obfuscation) và **Decision Validator**: (a) **Tier-Consensus Guard** (`enforce_tier_consensus`) chống social-engineering ngữ nghĩa; (b) **Anti-Self-DoS Shield** hạ `BLOCK_IP`→`ALERT` chỉ khi nhắm vào `critical_infrastructure_subnets` (HẸP: loopback + hạ tầng cụ thể — KHÔNG phải toàn RFC1918, nên attacker nội bộ/lateral vẫn bị chặn được).
4. **LangGraph Agent (`src/agent/`)**: Trái tim của hệ thống. Nhận log bất thường, truy xuất lịch sử APT (Threat Memory), gọi RAG và ra quyết định. LLM sử dụng là `Gemma-2-9B-IT` kết hợp **Few-shot Active Learning** tự động tải các luật được phê duyệt/từ chối từ Human làm ví dụ prompt cải thiện độ chính xác. **Độ bền vận hành:** (a) **seed cố định** (`llm.seed=42`) + `temperature=0.1` → cùng prompt cho output TẤT ĐỊNH (tái lập); (b) **suy biến an toàn** — nếu LLM cục bộ chết, `node_llm_triage` bọc `try/except` đẩy về `AWAIT_HITL`, đồ thị KHÔNG vỡ (Tier-1 vẫn bảo vệ độc lập); (c) **quan sát ngữ cảnh** — `token_monitor` ước lượng token TRƯỚC khi gọi (cảnh báo khi sát trần `n_ctx`) và ghi token THẬT sau mỗi call vào `config/llm_token_stats.json` để theo dõi/tinh chỉnh khi log quá dài/nhiều. **(d) ATT&CK Mapper (`attack_mapper.py`):** sau `llm_triage`, mọi threat verdict đi qua nút `attack_mapper` để biến `mitre_technique` dạng văn bản tự do thành bản ghi MITRE CÓ CẤU TRÚC (tactic/technique/sub-technique/URL/`mapping_confidence`/`recommended_response`); web-attack phổ biến tra bảng tất định, còn lại RRF + LLM-select — đồ thị giờ có **6 node**.
5. **RAG Module (`src/rag/`)**: Chịu trách nhiệm nhúng (Embedder) và tìm kiếm lai (Dual-RAG Hybrid: FAISS + BM25) các kịch bản ứng phó từ MITRE ATT&CK và NIST SP 800-61r2.
6. **UI Dashboard (`src/ui/`)**: Giao diện quản trị Streamlit hỗ trợ cơ chế phê duyệt an ninh Human-in-the-Loop, live monitoring và **Live Production FPR Card**. KPI "Logs thô đầu vào" + "Noise Reduction" đọc từ `config/pipeline_stats.json` (số THẬT do Subscriber ghi — không còn ước lượng). Phê duyệt luật trên Dashboard ghi persistent vào `system_settings.yaml` → Tier-1 hot-reload enforce. *(Lưu ý: `block_ip()` ở executor là `[FIREWALL MOCK]` ghi audit; enforcement thật là luật ACTIVE ở Tier-1, KHÔNG chạm firewall OS.)*

## 3. Lớp Lưu Trữ (Storage Layer)

- **`config/`**: Chứa SQLite DB của Hệ thống: `threat_memory.db` (lưu vết APT), `audit_trail.db` (lưu quyết định) và file `system_settings.yaml` lưu trữ whitelist, static rules, dynamic active rules. Ngoài ra: `pipeline_stats.json` (Subscriber ghi số log thô/drop cho Noise Reduction THẬT) và `llm_token_stats.json` (token_monitor ghi mean/p95/max/utilization% ngữ cảnh LLM) — đều cho Dashboard đọc trực tiếp.
- **`mlruns/`**: Chứa Artifacts và SQLite DB của MLflow. Lưu trữ metrics (F1, Latency, Resistance/Block Rate, Reasoning Quality Scores) để đảm bảo tính tái tạo.
- **`knowledge_base/`**:
  - Lưu trữ các tệp tri thức gốc dạng JSON (`mitre_attack.json`, `nist_800_61r2.json`).
  - Thư mục `faiss_index/` chứa các tệp nhúng và chỉ mục BM25.
- **`data/`**: Chứa tập dữ liệu đầu vào chuẩn hóa cho luận văn: CSE-CIC-IDS2018 (CSV) và DAPT2020.
- **`reports/`**: Lưu trữ các báo cáo thực nghiệm an ninh (E2E Integration Validation, Zero-Day Outlier Threat Detection).
- **`scripts/`**: Chứa các script tiện ích quản trị như `switch_model.sh` để hot-swap các model LLM.
