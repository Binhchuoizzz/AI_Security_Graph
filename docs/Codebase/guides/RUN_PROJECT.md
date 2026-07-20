# 🚀 Chạy & Demo SENTINEL — Hướng dẫn nhanh

> **Luận văn Thạc sĩ · Nguyễn Đức Bình** — *Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI.*
> Báo cáo demo đầy đủ: [reports/LIVE_DEMO_REPORT.md](reports/LIVE_DEMO_REPORT.md). Bản đồ mã nguồn: [codebase_summary.md](../learning/codebase_summary.md).

**📊 Số liệu chốt (offline tất định, tái lập — full-ablation 2026-07-20, GPU RTX 4060 Ti; benchmark cân bằng lại: datatest 3204 / ground_truth 1250):**

| Trục | Kết quả |
|---|---|
| **F1 — so sánh trên dữ liệu CÂN BẰNG** (khử base-rate) | luật thô **0.56** (precision cao, recall thấp) → **tầng học 0.80–0.83** (Cổng ML 0.825 · pure-LLM 0.804). *0.967 = 2-tầng phát-hiện+HITL trên tập vận hành 94% attack → base-rate, balanced khử còn 0.559.* |
| Cổng ML (LightGBM 1M, 4 dải) | **giảm tải LLM 83.8%** (761/908) · precision-on-bypass **98.82%** · Test-F1 **0.9635** (190k held-out) · kháng né-tránh **99.58%** |
| Phán xử Tier-2 (escalate, n=800, bỏ qua Cổng ML) | **recall 1.00** (38/38) · **specificity 0.00** (762 benign đều gắn cờ) · acc 0.0475 = base-rate · rel 1.00 · **0 parse-fail** · 353 BLOCK/445 HITL/2 ALERT (lưới an toàn max-recall) |
| APT (DAPT2020) | **3/3** recall · Wilson 95% [0.44, 1.00] · specificity 1.0 · lag ~8 event |
| Zero-day (signature-less) | **12/15** (Welford bắt, rule tĩnh sót) |
| Adversarial | **Tier-2 pipeline 100%** (12/12 resisted, 0% compromise) · guardrail tĩnh: encoding vô hiệu mạnh, semantic/jailbreak khó hơn (chủ đích defense-in-depth) |
| Explainability | **LLM-Judge 3.1/5** (cross-family Llama-3, n=908) |
| Độ trễ | **−82.97%** (2-tier vs LLM-only) · Mann-Whitney p<0.05 |
| Kiểm thử | **pytest 306** · E2E 22/22 (offline 21/22, T19 latency cần LLM) |

> ⚠️ Số **benchmark** lấy từ luồng **OFFLINE tất định**; demo online chỉ để trình diễn end-to-end (phụ thuộc timing/LLM). **Full-ablation đã XONG 13:54.** Bonus: *balanced* (230 mẫu cân bằng, khử base-rate) A≡F **0.559** / pure-LLM B **0.804** (R1.0/P.67) → xác nhận 0.967 là base-rate; *bcde* B–E **0.9655** (150 mẫu).

---

## 0. Chạy FULL demo — **1 LỆNH**

Sau khi setup (§1) 1 lần, mỗi lần demo:

```bash
./scripts/run_demo.sh --fresh --small   # ⭐ KHUYẾN NGHỊ khi bảo vệ: ~5.000 sự kiện, đủ 4 nguồn, xong nhanh
./scripts/run_demo.sh --fresh           # bản đầy đủ: reset sạch → đẩy ~100.000 sự kiện (4 nguồn)
./scripts/run_demo.sh --no-push         # chỉ dựng hạ tầng (containers + subscriber + UI)
# Model: mặc định SENTINEL_LITE=1 (Llama 3 8B, ctx 8192, 1 parallel, Neo4j tắt — máy VRAM thấp).
# Dùng ĐÚNG model luận văn (Gemma-2-9B-IT Q6_K, ctx 16384): SENTINEL_LITE=0 ./scripts/run_demo.sh --fresh --small
```

> ⚠️ **`SENTINEL_LITE` quyết định model:** nếu container LLM đang chạy Gemma mà bạn gọi lệnh mặc định (`LITE=1`), docker-compose sẽ **tạo lại container và đổi sang Llama 3 8B** — sai model luận văn. Kiểm tra: `docker inspect sentinel_llm --format '{{range .Config.Env}}{{println .}}{{end}}' | grep MODEL`.

**`--small` KHÔNG phải "5.000 sự kiện đầu"** mà là **tập con phân tầng** `data/demo_small.json` (tự dựng nếu thiếu, hoặc `scripts/build_demo_small.py`): lấy **nguyên văn** từ `data/demo.json` (không sinh dữ liệu mới) và giữ nguyên thứ tự thời gian gốc, đảm bảo **mọi panel Dashboard đều có dữ liệu thật**:

| Nguồn trong 5.000 sự kiện | Số lượng | Panel được nuôi |
|---|---|---|
| CICIDS2018 (`cicids_max` + `cicids`) | ~4.376 | Tier-1 chặn · Cổng ML · **16 lớp tấn công** · cột MITRE |
| DAPT2020 (`dapt` + `dapt_max`) | ~438 | **Chiến dịch APT — giữ TRỌN 3 IP đa-ngày** |
| Zero-day (real-derived) | 182 | Phát hiện không cần chữ ký (Welford) |
| Adversarial (OWASP) | 4 | Kháng injection/jailbreak |
| **Tấn công / benign** | **751 (15%) / 4.249** | Giảm tải Tier-1 thật |

> Vì sao cần tập con: luồng đầy đủ sắp theo **thời gian thật**, chuỗi APT đa-ngày chỉ hoàn tất quanh vị trí **#46.000–#63.000** → cắt 5.000 sự kiện đầu thì panel APT **luôn trống**.

Mở `http://localhost:8501` (đăng nhập `manager`). Tier-1 lọc phần lớn ở wire-speed; ca ESCALATE qua **Cổng ML** (~0.35ms) tự quyết phần lớn, chỉ ca ML bỏ ngỏ mới trôi qua LLM → **Dashboard điền dần** (đúng thiết kế SOC — LLM là nút cổ chai chủ đích, KHÔNG phải bug).

**Đo thật trên luồng 100k** (offline, không gọi LLM): Tier-1 `DROP 27,3%` + `BLOCK_IP 17,0%` ở tốc độ đường truyền · Cổng ML tự quyết **94,7%** số ca leo thang · **chỉ 2,93% luồng thực sự tới LLM**. LLM ~**9,6 s/quyết định** ⇒ bản 100k cần **~5,5 giờ** rút hết hàng đợi (lý do nên dùng `--small` khi bảo vệ).

Tắt: `pkill -f "main.py --mode server"; docker-compose stop`.

---

## 1. Setup môi trường (1 lần)

```bash
cd ~/Projects/Thesis/AI_Security_Graph
python3.10 -m venv .venv
.venv/bin/pip install --upgrade pip && .venv/bin/pip install -r requirements.txt
.venv/bin/pip install drain3==0.9.11 --no-deps   # drain3 pin cachetools cũ → cài --no-deps
.venv/bin/pip install "jsonpickle>=1.5.1"
cp .env.example .env                             # đã sẵn sàng chạy Local Demo
```

> Nếu Dashboard báo `ModuleNotFoundError: drain3` (image cũ): `docker-compose build agent_ui && docker-compose up -d agent_ui`.
> VS Code báo đỏ import: đặt `python.defaultInterpreterPath` = `${workspaceFolder}/.venv/bin/python` trong `.vscode/settings.json`.

---

## 2. Hạ tầng Docker

```bash
docker-compose up -d          # 5 dịch vụ, tự xếp thứ tự theo healthcheck
docker-compose ps             # kỳ vọng: cả 5 Up/healthy
curl http://localhost:5000/v1/models   # kỳ vọng: JSON model gemma-2-9b-it-Q6_K
```

**5 dịch vụ** (đều có `healthcheck` + `restart: unless-stopped` + resource limits, bind `127.0.0.1`):
`llm` (llama.cpp CUDA, Gemma-2-9B, :5000) · `redis` (:6379) · `mlflow` (:5001) · `neo4j` (:7474, KG V2 tùy chọn) · `agent_ui` (Streamlit :8501, chỉ lên khi redis/mlflow/llm đều healthy).

> **Trước E2E/demo, BẮT BUỘC dựng RAG index:** `.venv/bin/python src/rag/embedder.py` (sinh FAISS/BM25 + checksum).
> **Neo4j crash-loop:** `docker-compose rm -f neo4j && docker volume rm ai_security_graph_neo4j_data && docker-compose up -d neo4j` (KG sinh lại on-demand; luồng lõi không phụ thuộc Neo4j).

---

## 3. Benchmark OFFLINE — số liệu luận văn (tất định, tái lập)

| Lệnh | Chứng minh | Kết quả thực đo |
|---|---|---|
| `experiments/e2e_test_runner.py --offline` | 22 module đúng đặc tả | **22/22 PASSED** (bỏ `--offline` = 22/22 gồm T19 latency, cần LLM) |
| `experiments/evaluate_unified_stream.py` | Phân loại + APT emergent + zero-day, 1 luồng gộp memory SẠCH (không circular) | F1 **0.531** · APT **3/3** (lag ~8) · zero-day **12/15** |
| `experiments/evaluate_ml_gate.py` | Cổng ML LightGBM trên datatest 3204 (4 luồng) | phân loại F1 **0.825** (P.909/R.755) · bypass 79% · kháng né-tránh **99.58%** |
| `experiments/run_ablation.py --mode mlgate` | Cổng ML GIẢM TẢI LLM (Config G, ground_truth 1250) | offload **83.8%** (761/908) · F1(bypass) **0.9739** · precision **98.82%** |
| `experiments/evaluate_tier2_decision.py` | LLM phán quyết khi escalate (bỏ qua Cổng ML; n=800) | recall **1.00** / specificity **0.00** / acc 0.0475=base-rate / **0 parse-fail** — lưới an toàn max-recall |
| `experiments/evaluate_adversarial.py --mode pipeline` | Tier-2 + Consensus Guard kháng social-engineering *(cần LLM)* | **100% resisted** (12/12, 0% compromise) |
| `experiments/evaluate_adversarial.py --mode static` | Guardrails tĩnh (6 nhóm OWASP) | encoding mạnh; semantic/jailbreak khó hơn — chủ đích, pipeline Tier-2 vá nốt |
| `experiments/run_ablation.py --mode af` → `statistical_tests.py` | Đóng góp thành phần + ý nghĩa thống kê | A≡F phân loại (McNemar p=1.0); F1 **0.967**; độ trễ **Mann-Whitney p<0.05** |
| `experiments/measure_latency_baseline.py` *(cần LLM)* | 2-tier giảm tải LLM | Latency **−82.97%** (26882→4577 ms mean, n=100) |
| `experiments/evaluate_reasoning.py` *(hot-swap Llama-3)* | LLM-as-Judge **chéo họ** (bỏ self-bias), n=908 escalated | **Overall 3.1/5** (Faithfulness 3.3 · Answer-Relevancy 3.56 · Context-Recall 3.27 · Context-Precision 2.25 · Audit 100%) |

**Ablation A–F & rigor bổ sung** (chống phản biện):

```bash
experiments/run_ablation.py --mode bcde        # B pure-LLM / C gate / D dense-RAG / E hybrid-RAG
experiments/run_ablation.py --mode balanced    # cân bằng 150/150 (tránh base-rate → F1 0.967 cô lập)
experiments/run_threshold_sensitivity.py       # độ nhạy ngưỡng Welford τ 2.0–5.0
experiments/run_zeroday_graded.py              # đường cong phát hiện zero-day k·σ (bão hòa ≈4σ)
experiments/run_apt_negative_control.py        # đối chứng âm APT + Wilson CI (specificity 1.0)
experiments/run_context_stress.py              # RAW tràn n_ctx tại N=100 vs Drain giữ ~80 tok
experiments/run_llm_robustness.py              # determinism (seed 42) + suy biến an toàn khi LLM chết
experiments/plot_results.py                    # vẽ biểu đồ (cần ablation chạy trước)
```

> **Diễn giải trung thực (so sánh trên dữ liệu CÂN BẰNG):** chỉ so F1 khi **cùng phân bố lớp**. Trên tập balanced 150/150 (khử base-rate): **luật thô A = 2-tầng F = 0.559** (precision cao, recall ~0.41 — luật chốt cứng ca lộ, đẩy ca tinh vi lên trên, xem `evaluate_unified_stream.py:279`); **tầng học vượt hẳn: Cổng ML 0.825** (R.755), **pure-LLM B 0.804** (R1.0/P.67). ⇒ giá trị của tầng học là **recall** mà luật thiếu. Con số **0.967** (Config A/F) là *phát hiện + HITL trên tập vận hành 94% attack* — **base-rate**, balanced phơi bày (khử còn 0.559); KHÔNG phải năng lực phân biệt. A≡F ở phát-hiện vì Rule Engine đã bắt hết ca lộ; giá trị Tier-2 nằm ở **(1)** làm giàu ngữ cảnh MITRE/NIST + reasoning kiểm toán được, **(2)** ca biên ngữ nghĩa/adversarial, **(3)** Cổng ML giảm tải LLM 83.8% + giảm 82.97% độ trễ. Nêu rõ trong Ch4.

---

## 4. Demo ONLINE — end-to-end realtime (thủ công)

Dùng khi muốn tách 3 terminal thay cho `run_demo.sh`:

```bash
# Terminal 1 — LLM server
./scripts/switch_model.sh gemma
# Terminal 2 — hệ thống thật (Tier-1 + Cổng ML + Agent)
.venv/bin/python main.py --mode server --log-level INFO
# Terminal 3 — phát luồng (chọn 1)
.venv/bin/python src/streaming/publisher.py                            # raw CSV
.venv/bin/python scripts/build_datatest.py    # dựng data/datatest.json (~3.2k sự kiện, đủ 4 nguồn)
.venv/bin/python scripts/push_datatest.py     # ✦ đẩy luồng gộp FULL 4 nguồn (APT emergent)
# Bản demo ~100k sự kiện: scripts/build_demo.py → scripts/demo.py
# Đẩy RIÊNG 1 nguồn: scripts/push_flow.py --source {cicids|dapt|zeroday|adversarial} --limit N
```

> ⚠️ **CHỈ 1 SUBSCRIBER.** Nhiều tiến trình cùng consumer group `sentinel_group` sẽ **chia** log → Dashboard thiếu. Reset sạch + bật lại đúng 1 subscriber trong 1 lệnh:
> `.venv/bin/python scripts/reset_all.py` (`--dry-run` xem trước · `--no-restart` chỉ reset).

Luồng mỗi ESCALATE: Redis → Tier-1 → **Cổng ML** → *(chỉ ca ML bỏ ngỏ)* Guardrails → RAG → LLM → **ATT&CK Mapper** → Executor → Audit HMAC → Dashboard.

---

## 5. Dashboard HITL (SOC UI) — `http://localhost:8501`

| Tài khoản | Mật khẩu | Vai trò | Quyền |
|---|---|---|---|
| `analyst` | `HanoiAnalyst2026@` | L1 | Xem cảnh báo, reasoning AI, Audit Trail |
| `manager` | `HanoiManager2026@` | L3 | + Duyệt/Bác rule chặn IP, thêm Whitelist |

**Kịch bản:** đăng nhập `analyst` → xem alert queue realtime + reasoning (Prompt/MITRE/NIST/quyết định) → đăng nhập `manager` → **Approve** 1 rule → rule thành ACTIVE, Tier-1 hot-reload (5s) enforce IP đó. *(Chạy UI ngoài Docker: `.venv/bin/streamlit run src/ui/app.py`.)*

---

## 6. Chạy riêng từng tầng (minh họa nhanh, không cần Docker)

```bash
.venv/bin/python demos/demo_tier1.py       # Rule Engine: DROP/BLOCK/ESCALATE + Welford zero-day + port scan
.venv/bin/python demos/demo_guardrails.py  # 5 lớp: injection/jailbreak/nonce/encoding/consensus
.venv/bin/python demos/demo_rag.py         # Dual-RAG hybrid: FAISS + BM25 + RRF
```

- **Tier-1 (`rule_engine`)**: 7 lớp O(1); Reputation Tầng-3.5 (IP tiền sử ≥70→BLOCK, 50–69→AWAIT_HITL, không tốn LLM).
- **Cổng ML (`ml_gateway`)**: ca ESCALATE → LightGBM `classify_ml` 4 dải (0.85/0.65/0.40) → chặn/thả 83.8% không cần LLM.
- **Guardrails**: nonce `token_hex(8)` bọc log thành DATA; `enforce_tier_consensus` (Tier-1 nói tấn công mà LLM hạ xuống → ép AWAIT_HITL).
- **RAG**: all-MiniLM-L6-v2 (FAISS cosine) + BM25 hợp nhất RRF k=60 trên MITRE + NIST 800-61r2.

---

## 2b. Golden baseline — base benign DUY NHẤT (bật mặc định)

Thay vì warmup 100 mẫu đầu ad-hoc (dễ bị đầu độc lúc khởi động), Tier-1 **seed sẵn** `(n, mean, M2)` từ **300 flow benign đã kiểm định** → Z-score chạy ngay từ **gói đầu tiên**. Sau seed vẫn cập nhật online **CÓ ĐIỀU KIỆN** (chỉ trên DROP/LOG) — chống đầu độc "ếch luộc". Luận văn §3.3 + §3.11.

```bash
# Dựng lại hồ sơ vàng (chỉ khi cần) — tự reset Welford trước → luôn n=300:
.venv/bin/python experiments/build_golden_baseline.py    # → config/golden_baseline.json
# Cờ đã bật sẵn trong config/system_settings.yaml:  tier1.golden_baseline.enabled: true
```

> Bật golden: đo dị biệt ngay gói đầu (khỏi warmup mù); APT 3/3 + zero-day 12/15 giữ nguyên; ablation cô lập khỏi golden (`_fresh_engine`) nên F1 0.967 (phát hiện nhị phân) không đổi.

---

## ⭐ Kịch bản bảo vệ tối thiểu (~12–15 phút)

15 demo là kho đầy đủ; buổi bảo vệ chỉ cần **6 demo cốt lõi**:

| # | Demo | Chứng minh | ~phút |
|---|---|---|---|
| 1 | `docker-compose ps` + `curl :5000/v1/models` | Hệ chạy thật; LLM **cục bộ / air-gapped** | 1 |
| 2 | Full pipeline online (publisher → Cổng ML/LLM ra BLOCK/ALERT) | E2E realtime + ATT&CK Mapper | 3 |
| 3 | Dashboard (`analyst`→`manager`, duyệt 1 rule) | HITL + RBAC + audit HMAC | 3 |
| 4 | `evaluate_adversarial.py --mode static/pipeline` | Defense-in-depth (guardrail tĩnh + Tier-2 100%/0% compromise) | 2 |
| 5 | `evaluate_unified_stream.py` + `evaluate_ml_gate.py` | Benchmark trung thực — F1 cân bằng luật thô **0.56** → tầng học **0.80–0.83** + APT 3/3 + zero-day 12/15 + Cổng ML offload 83.8% | 2 |
| 6 | `run_ablation.py --mode af` + `statistical_tests.py` | Đóng góp thành phần + độ trễ có ý nghĩa thống kê | 2 |

> **Mẹo:** chạy sẵn hạ tầng + bộ offline TRƯỚC buổi bảo vệ để có kết quả, lúc demo chỉ "show" lại (tránh timeout LLM).
> Câu hỏi sâu → mở đúng bằng chứng: *"Zero-day nhạy tới đâu?"* → zeroday_graded (≈4σ) · *"F1 cao có phải base-rate?"* → ablation balanced 150/150 · *"Tràn context?"* → context_stress · *"Baseline bị đầu độc?"* → §2b golden · *"Cổng ML giảm tải bao nhiêu?"* → run_ablation --mode mlgate (83.8%).

---

## 📍 Port & Endpoint (tất cả bind `127.0.0.1` — Zero-Trust)

| Dịch vụ | Endpoint | Ghi chú |
|---|---|---|
| LLM (llama.cpp) | `http://localhost:5000/v1/models` · `/v1/chat/completions` · `/health` | OpenAI-compatible |
| Dashboard HITL | `http://localhost:8501` | Streamlit + auth PBKDF2/RBAC |
| MLflow | `http://localhost:5001` | So sánh ablation |
| Redis | `localhost:6379` | Hàng đợi log |
| Neo4j Browser | `http://localhost:7474` | `neo4j` / xem `NEO4J_PASSWORD` trong `.env` |

> Muốn demo cho máy khác trong LAN: đổi mapping thành `0.0.0.0:<port>` trong `docker-compose.yml`.

---

## ⚡ Cheat Sheet

```bash
docker-compose up -d                                       # 1. hạ tầng (5 dịch vụ)
./scripts/run_demo.sh                                      # 2. FULL demo 1 lệnh
./scripts/switch_model.sh {gemma|llama}                    # 3. hot-swap LLM (Agent | Trọng tài)
.venv/bin/python scripts/reset_all.py                      # 4. reset sạch + 1 subscriber
.venv/bin/python experiments/e2e_test_runner.py --offline  # 5. E2E 22/22
.venv/bin/python experiments/evaluate_unified_stream.py    # 6. benchmark (F1/APT/zero-day)
.venv/bin/python experiments/evaluate_ml_gate.py           # 7. Cổng ML (F1/offload/né-tránh)
.venv/bin/python experiments/evaluate_adversarial.py --mode pipeline   # 8. robustness Tier-2
.venv/bin/python experiments/run_ablation.py --mode af                 # 9. ablation A/F
.venv/bin/python experiments/statistical_tests.py          # 10. McNemar + Mann-Whitney
.venv/bin/python experiments/measure_latency_baseline.py   # 11. độ trễ
.venv/bin/python experiments/plot_results.py               # 12. vẽ biểu đồ
docker-compose down                                        # 13. tắt
# Rigor: run_ablation.py --mode {mlgate,bcde,balanced} · run_threshold_sensitivity · run_zeroday_graded
#        run_apt_negative_control · run_context_stress · run_llm_robustness · evaluate_tier2_decision
```

**Demo online thủ công:** Terminal 1 `main.py --mode server` · Terminal 2 `scripts/push_datatest.py` (hoặc `scripts/demo.py` cho bản ~100k) (CHỈ 1 subscriber!).
