# 🚀 Chạy & Demo SENTINEL — Hướng dẫn nhanh

> **Luận văn Thạc sĩ · Nguyễn Đức Bình** — *Cognitive Two-Tier Architecture for Automated Threat Detection and Contextual Response using Agentic AI.*
> Báo cáo demo đầy đủ: [reports/LIVE_DEMO_REPORT.md](reports/LIVE_DEMO_REPORT.md). Bản đồ mã nguồn: [codebase_summary.md](../learning/codebase_summary.md).

**📊 Số liệu chốt (offline tất định, tái lập — 2026-07-14, GPU RTX 4060 Ti):**

| Trục | Kết quả |
|---|---|
| Phân loại (luồng gộp) | **F1 0.61** (P 0.948 / R 0.450) — golden baseline BẬT mặc định |
| Phán xử Tier-2 (651 ca escalate) | **recall 1.00** (594/594, không sót đe doạ) · acc 0.912 |
| APT (DAPT2020) | **3/3** recall · Wilson 95% [0.44, 1.00] · specificity 1.0 |
| Zero-day (signature-less) | **7/7** (Welford Z 7.5→318k; rule tĩnh sót cả 7) |
| Adversarial | tĩnh **50%** (60/120) · **Tier-2 pipeline 100%** (0% compromise) |
| Độ trễ | **−82.97%** (2-tier vs LLM-only) · Mann-Whitney p<0.05 |
| Kiểm thử | **pytest 267** · E2E 22/22 (offline 21/22, T19 latency cần LLM) |

> ⚠️ Số **benchmark** lấy từ luồng **OFFLINE tất định**; demo online chỉ để trình diễn end-to-end (phụ thuộc timing/LLM).

---

## 0. Chạy FULL demo — **1 LỆNH**

Sau khi setup (§1) 1 lần, mỗi lần demo:

```bash
./scripts/run_demo.sh              # containers → subscriber → UI → đẩy 4.796 sự kiện (4 nguồn)
./scripts/run_demo.sh --no-push    # chỉ dựng hạ tầng   |   --small: đẩy nhanh (demo ngắn)
# GPU VRAM thấp: `SENTINEL_LITE=1 ./scripts/run_demo.sh` (Llama 3 8B, ctx 8192, 1 parallel, Neo4j tắt)
```

Mở `http://localhost:8501` (đăng nhập `manager`). Tier-1 lọc ~93%; ~651 ca ESCALATE trôi qua LLM ~10–15 phút → **Dashboard điền dần** (đúng thiết kế SOC — LLM là nút cổ chai chủ đích, KHÔNG phải bug). Tắt: `pkill -f "main.py --mode server"; docker-compose stop`.

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
| `experiments/evaluate_unified_stream.py` | Phân loại + APT emergent + zero-day, 1 luồng gộp memory SẠCH (không circular) | F1 **0.61** · APT **3/3** (bản án ngày 3–4) · zero-day **7/7** |
| `experiments/evaluate_tier2_decision.py` | LLM phán quyết ĐÚNG khi escalate *(cần LLM; `--limit 12` thử nhanh)* | 651 ca → recall **1.00** · acc 0.912 · 631 HITL/20 ALERT |
| `experiments/evaluate_adversarial.py --mode static` | Guardrails tĩnh, 120 mẫu / 5 nhóm | **50%** (encoding 100%, semantic/jailbreak yếu — đúng thiết kế) |
| `experiments/evaluate_adversarial.py --mode pipeline` | Tier-2 + Consensus Guard kháng social-engineering *(cần LLM)* | **100% resisted** (0% compromise sau vá) |
| `experiments/run_ablation.py --mode af` → `statistical_tests.py` | Đóng góp thành phần + ý nghĩa thống kê | A≡F phân loại (McNemar p=1.0); độ trễ **Mann-Whitney p<0.05** |
| `experiments/measure_latency_baseline.py` *(cần LLM)* | 2-tier giảm tải LLM | Latency **−82.97%** (Tier-1 lọc ~99% log không gọi LLM) |
| `experiments/evaluate_reasoning.py` *(hot-swap Llama-3)* | LLM-as-Judge **chéo họ** (bỏ self-bias), n=188 ca escalate/300 | **Overall 3.9/5** (Faithfulness 4.0 · Answer-Relevancy 4.62 · Context-Recall 4.01 · Context-Precision 2.99 · Audit 100%) |

**Ablation A–F & rigor bổ sung** (chống phản biện):

```bash
experiments/run_ablation.py --mode bcde        # B pure-LLM / C gate / D dense-RAG / E hybrid-RAG
experiments/run_ablation.py --mode balanced    # cân bằng 150/150 (tránh base-rate 93% → F1 0.967 cô lập)
experiments/run_threshold_sensitivity.py       # độ nhạy ngưỡng Welford τ 2.0–5.0
experiments/run_zeroday_graded.py              # đường cong phát hiện zero-day k·σ (bão hòa ≈4σ)
experiments/run_apt_negative_control.py        # đối chứng âm APT + Wilson CI (specificity 1.0)
experiments/run_context_stress.py              # RAW tràn n_ctx tại N=100 vs Drain giữ ~80 tok
experiments/run_llm_robustness.py              # determinism (seed 42) + suy biến an toàn khi LLM chết
experiments/plot_results.py                    # vẽ biểu đồ (cần ablation chạy trước)
```

> **Diễn giải trung thực:** A≡F ở F1 vì Rule Engine đủ bắt tấn công lộ rõ trong tập này — giá trị Tier-2 nằm ở **(1) làm giàu ngữ cảnh MITRE/NIST + reasoning kiểm toán được**, **(2) xử lý ca biên ngữ nghĩa/adversarial rule bỏ sót**, **(3) giảm 82.97% độ trễ**. F1 0.967 (ablation) và acc 0.912 (Tier-2) ≈ base-rate của tập — không phải năng lực phân biệt (nêu rõ trong Ch4).

---

## 4. Demo ONLINE — end-to-end realtime (thủ công)

Dùng khi muốn tách 3 terminal thay cho `run_demo.sh`:

```bash
# Terminal 1 — LLM server
./scripts/switch_model.sh gemma
# Terminal 2 — hệ thống thật (Tier-1 + Agent)
.venv/bin/python main.py --mode server --log-level INFO
# Terminal 3 — phát luồng (chọn 1)
.venv/bin/python src/streaming/publisher.py                            # raw CSV
.venv/bin/python experiments/stream_unified_online.py                  # luồng gộp (APT emergent)
.venv/bin/python experiments/stream_unified_online.py --include-adversarial   # ✦ FULL 4 nguồn
```

> ⚠️ **CHỈ 1 SUBSCRIBER.** Nhiều tiến trình cùng consumer group `sentinel_group` sẽ **chia** log → Dashboard thiếu. Reset sạch + bật lại đúng 1 subscriber trong 1 lệnh:
> `.venv/bin/python scripts/reset_all.py` (`--dry-run` xem trước · `--no-restart` chỉ reset).

Luồng mỗi ESCALATE: Redis → Tier-1 → Guardrails → RAG → LLM → **ATT&CK Mapper** → Executor → Audit HMAC → Dashboard.

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

> Bật golden: F1 luồng-gộp 0.594→0.61 (FP 113→98); APT 3/3 + zero-day 7/7 giữ nguyên; ablation cô lập khỏi golden (`_fresh_engine`) nên F1 0.967 không đổi.

---

## ⭐ Kịch bản bảo vệ tối thiểu (~12–15 phút)

15 demo là kho đầy đủ; buổi bảo vệ chỉ cần **6 demo cốt lõi**:

| # | Demo | Chứng minh | ~phút |
|---|---|---|---|
| 1 | `docker-compose ps` + `curl :5000/v1/models` | Hệ chạy thật; LLM **cục bộ / air-gapped** | 1 |
| 2 | Full pipeline online (publisher → LLM ra BLOCK/ALERT) | E2E realtime + ATT&CK Mapper | 3 |
| 3 | Dashboard (`analyst`→`manager`, duyệt 1 rule) | HITL + RBAC + audit HMAC | 3 |
| 4 | `evaluate_adversarial.py --mode static/pipeline` | Defense-in-depth (tĩnh 50% + Tier-2 0% compromise) | 2 |
| 5 | `evaluate_unified_stream.py` | Benchmark trung thực (F1 0.61 + APT 3/3 + zero-day 7/7) | 2 |
| 6 | `run_ablation.py --mode af` + `statistical_tests.py` | Đóng góp thành phần + độ trễ có ý nghĩa thống kê | 2 |

> **Mẹo:** chạy sẵn hạ tầng + bộ offline TRƯỚC buổi bảo vệ để có kết quả, lúc demo chỉ "show" lại (tránh timeout LLM).
> Câu hỏi sâu → mở đúng bằng chứng: *"Zero-day nhạy tới đâu?"* → zeroday_graded (≈4σ) · *"F1 cao có phải base-rate?"* → ablation balanced 150/150 · *"Tràn context?"* → context_stress · *"Baseline bị đầu độc?"* → §2b golden.

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
.venv/bin/python experiments/evaluate_adversarial.py --mode static     # 7. robustness tĩnh
.venv/bin/python experiments/run_ablation.py --mode af                 # 8. ablation A/F
.venv/bin/python experiments/statistical_tests.py          # 9. McNemar + Mann-Whitney
.venv/bin/python experiments/measure_latency_baseline.py   # 10. độ trễ
.venv/bin/python experiments/plot_results.py               # 11. vẽ biểu đồ
.venv/bin/python scripts/build_dapt_chains.py              # 12. chuỗi APT DAPT2020
docker-compose down                                        # 13. tắt
# Rigor: run_ablation.py --mode {bcde,balanced} · run_threshold_sensitivity · run_zeroday_graded
#        run_apt_negative_control · run_context_stress · run_llm_robustness · evaluate_adversarial --mode pipeline
```

**Demo online thủ công:** Terminal 1 `main.py --mode server` · Terminal 2 `stream_unified_online.py [--include-adversarial]` (CHỈ 1 subscriber!).
