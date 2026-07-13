# SENTINEL — Tài liệu tham chiếu hàm (Function Reference) — NGÀY 5

> **Phạm vi:** Mô tả **giao diện SOC (Streamlit)** + **khung đánh giá thực nghiệm 5D** + **tích hợp gốc & kiểm thử** — 4 file UI (`src/ui/`) + ~20 script `experiments/` + `main.py` + bộ test. Đây là tầng "chứng minh & vận hành" của luận văn.
> **Cập nhật:** 2026-07-02 (đồng bộ số dòng UI theo code thực tế; script đánh giá mô tả ở mức entrypoint như DAY1).
> **Quy ước:** UI ghi *từng hàm* (có số dòng); script đánh giá ghi *Mục đích → Tác dụng → Đầu ra/Quan hệ* (mức script, vì logic nằm trong 1 hàm điều phối).
> **Trạng thái kiểm thử:** `pytest 207 passed` · `E2E 22/22 PASSED`.

---

## 💡 Sơ đồ 1 phút (đọc để hình dung nhanh)

> **UI** là cửa sổ HITL: analyst xem cảnh báo, **Duyệt/Bác luật** → persist YAML → Tier-1 hot-reload ⇒ **khép vòng phản hồi**. Mọi số KPI đọc từ **file/DB THẬT** (`pipeline_stats.json`, `audit_trail.db`, `threat_memory.db`, `llm_token_stats.json`) — không bịa.
> **Khung đánh giá** = "phòng thí nghiệm" tất định: gộp CICIDS+DAPT+zero-day thành **một luồng** rồi đo 5 trục — **Phân loại (Ablation A–F), Vận hành (Latency), Kháng cự (Adversarial), Chất lượng ngữ cảnh (LLM-Judge), Luồng gộp (APT+zero-day)** — cộng 5 script **rigor** trả lời trực diện các câu phản biện (ngưỡng, zero-day phân cấp, đối chứng âm APT, stress ngữ cảnh, độ bền LLM).

---

## Mục lục

- [0. Bản đồ kiến trúc tổng thể](#0-bản-đồ-kiến-trúc-tổng-thể)
- [NHÓM 1 — Dashboard SOC (Streamlit UI)](#nhom-1)
  - [E1. `src/ui/app.py`](#e1-apppy) · [E2. `src/ui/components.py`](#e2-componentspy) · [E3. `src/ui/auth.py`](#e3-authpy) · [E4. `src/ui/style.css`](#e4-stylecss)
- [NHÓM 2 — Ablation & Kiểm định thống kê](#nhom-2)
  - [E5–E8. `run_ablation.py` (A–F) + `statistical_tests`](#e5-e8)
- [NHÓM 3 — Kháng cự & Chất lượng suy luận](#nhom-3)
  - [E9–E11. `evaluate_adversarial.py` (static/pipeline) + `reasoning`](#e9-e11)
- [NHÓM 4 — Luồng gộp thống nhất & Rigor](#nhom-4)
  - [E12–E18. `unified_stream` + 5 script rigor](#e12-e18)
- [NHÓM 5 — Độ trễ · Vẽ · E2E · Mapper eval](#nhom-5)
  - [E19–E22. `latency / plot / e2e_runner / eval_attack_mapper`](#e19-e22)
- [NHÓM 6 — Tiện ích & Tích hợp gốc](#nhom-6)
  - [E23–E25. `seed_demo_data / tiện ích / main.py` + Tests](#e23-e25)
- [Phụ lục — Bản đồ 5D & điểm cần lưu ý](#phụ-lục)

---

<a name="0-bản-đồ-kiến-trúc-tổng-thể"></a>
## 0. Bản đồ kiến trúc tổng thể

```
A. VÒNG VẬN HÀNH (UI ↔ Pipeline):
   subscriber ghi ─► config/pipeline_stats.json (Noise Reduction THẬT)
   executor  ghi ─► config/audit_trail.db (HMAC)          ┐
   threat_memory ─► config/threat_memory.db (APT/reputation)├─► app.py đọc & render (5 tab)
   token_monitor ─► config/llm_token_stats.json (Context)  ┘
        analyst bấm "Duyệt" ─► approve_rule ─► system_settings.yaml ─► Tier-1 hot-reload (DAY1)

B. KHUNG ĐÁNH GIÁ 5D (offline, tất định — không cần Redis):
   ground_truth.json + dapt2020_chains.jsonl
        │
        ▼  build_stream()  (evaluate_unified_stream #E12 — nguồn dùng chung)
   ┌───────────────────────────────────────────────────────────────────────┐
   │ 1. Phân loại   : run_ablation.py --mode all (A–F, 3 tập)               │──► statistical_tests (McNemar, Mann-Whitney U)
   │ 2. Vận hành    : measure_latency_baseline (Two-Tier vs LLM-only)        │
   │ 3. Kháng cự    : evaluate_adversarial.py --mode all (tĩnh + LLM)        │
   │ 4. Ngữ cảnh    : evaluate_reasoning (Llama-3 chấm Gemma-2, RAGAS)       │
   │ 5. Luồng gộp   : evaluate_unified_stream (phân loại+APT+zero-day)       │
   │ + RIGOR (5)    : threshold_sensitivity · zeroday_graded · apt_negative  │
   │                  · context_stress · llm_robustness                       │
   └───────────────────────────────────────────────────────────────────────┘
        │
        ▼  results/*.json ─► plot_results ─► results/plots/*.png ─► luận văn ch4
   e2e_test_runner.py = 22 kịch bản chốt chặn toàn vẹn trước push/demo
```

**Khớp nối:** mọi script rigor **tái dùng** `build_stream / map_cicids / _is_threat` của `evaluate_unified_stream` (#E12) → đo trên **cùng dữ liệu thật**, không dựng luồng riêng lệch nhau.

---

<a name="nhom-1"></a>
# NHÓM 1 — Dashboard SOC (Streamlit UI)

<a name="e1-apppy"></a>
## E1. `src/ui/app.py`
**Vai trò:** Web Dashboard Streamlit — trung tâm **Human-in-the-Loop (HITL)** với 5 tab (Nhật ký SIEM & Audit / Phê duyệt Luật HITL / Giám sát APT / Blocklist & Whitelist / Lỗ hổng & Graph).

| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `handle_whitelist_approval(ip)` | Analyst đưa IP vào whitelist → `FeedbackListener.add_to_whitelist` (qua `FeedbackValidator`, DAY2 — G8). | [57-62](../../src/ui/app.py#L57-L62) |
| `render_demo_overview(...)` | Trang tổng quan: KPI header + phân phối action + Noise Reduction **THẬT** (đọc `pipeline_stats.json`, bỏ ước lượng ×35). | [63-188](../../src/ui/app.py#L63-L188) |
| `main_dashboard()` ⭐ | Điều phối 5 tab; nút **Duyệt/Bác** → `approve_rule`/`reject_rule` persist YAML → Tier-1 enforce; KPI "Context Budget" đọc `llm_token_stats.json`; nút Reset xóa DBs + dynamic_rules + `pipeline_stats.json`. | [189-1340](../../src/ui/app.py#L189-L1340) |

> **Số liệu THẬT (nêu khi bảo vệ):** "Logs thô"/"Noise Reduction" đọc `config/pipeline_stats.json` do **subscriber ghi**, KHÔNG phải ước lượng. Dashboard chạy qua Docker (`streamlit run src/ui/app.py`), KHÔNG do `main.py` bật.

---

<a name="e2-componentspy"></a>
## E2. `src/ui/components.py`
**Vai trò:** Component hiển thị tái dùng (thiết kế Glassmorphism SOC), tách khỏi logic.

| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `is_valid_ip(ip_str)` | Kiểm IP hợp lệ trước khi hiển thị/thao tác. | [14-24](../../src/ui/components.py#L14-L24) |
| `render_alert_card(alert, is_l3_manager, on_whitelist, card_id)` | Card cảnh báo: MITRE/confidence/reasoning + NIST playbook, **anti-XSS** (reasoning đã sanitize từ DAY2 — G5). Nhãn "Xem bản ghi Quyết định (Audit Record JSON)" làm rõ đây là ĐẦU RA, không phải input LLM. | [25-185](../../src/ui/components.py#L25-L185) |
| `render_ioc_table(iocs)` | Bảng IOC (append-only từ `SentinelState`, DAY4). | [186-195](../../src/ui/components.py#L186-L195) |
| `render_metrics_header(..., noise_reduction)` | KPI cards dùng `noise_reduction` **đo thật**. | [196-246](../../src/ui/components.py#L196-L246) |
| `render_threat_intel_tables(high_risk_ips, known_entities)` | IP nguy cơ + thực thể đã biết (từ `threat_memory.db`, DAY4). | [247-293](../../src/ui/components.py#L247-L293) |
| `render_apt_events_table(events)` | Chuỗi APT DAPT2020 đa-ngày. | [294-326](../../src/ui/components.py#L294-L326) |

---

<a name="e3-authpy"></a>
## E3. `src/ui/auth.py`
**Vai trò:** Xác thực **RBAC** 2 vai trò (L1_Analyst / L3_Manager) + chống Input Injection & brute-force.

| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `hash_password(password)` | **PBKDF2-HMAC-SHA256 (100k vòng)** — KHÔNG hardcode plaintext; cảnh báo fail-loud khi dùng HASH/SALT demo. | [40-78](../../src/ui/auth.py#L40-L78) |
| `login_screen()` | Form đăng nhập; username regex `^[a-zA-Z0-9_]{1,30}$`; lockout brute-force (5 lần, dùng `executor` DAY4). | [79-137](../../src/ui/auth.py#L79-L137) |
| `_constant_time_compare(a, b)` | `hmac.compare_digest` chống **timing attack**. | [138-145](../../src/ui/auth.py#L138-L145) |
| `require_auth()` / `logout()` | Gác trang & đăng xuất. | [146-156](../../src/ui/auth.py#L146-L156) |

---

<a name="e4-stylecss"></a>
## E4. `src/ui/style.css`
**Vai trò:** Ngôn ngữ thị giác SOC — CSS variables, Glassmorphism, Neon Glow, severity glow + pulse critical, KPI cards, tabs/sidebar/buttons, empty-state `.soc-empty` trung tính. Load trong `app.py`. *(Không có hàm — file trình bày.)*

---

<a name="nhom-2"></a>
# NHÓM 2 — Ablation & Kiểm định thống kê *(Trục 1: Phân loại)*

<a name="e5-e8"></a>
### E5. `experiments/run_ablation.py --mode af` — Ablation A & F
- **Mục đích:** So **Config A** (Tier-1 đầy đủ, KHÔNG LLM) vs **Config F** (full SENTINEL) trên `ground_truth.json`.
- **Tác dụng:** Đo Precision/Recall/F1/FPR/latency; sinh `Config_F.reasoning_outputs` (cho trọng tài #E11); đẩy MLflow.
- **Quan hệ:** Output `results/ablation_results.json` → `statistical_tests` (#E8) + `evaluate_reasoning` (#E11).

### E6. `experiments/run_ablation.py --mode bcde` — Configs B, C, D, E
- **Mục đích:** Bù 4 cấu hình giữa (A chỉ có ở #E5) — chạy THẬT, không ước tính.
- **Tác dụng:** Trên CÙNG 300 mẫu phân tầng tất định: **B** Pure-LLM (mọi mẫu→LLM, không gate/RAG/guardrails); **C** Welford-gate + LLM (không RAG); **D** gate + dense-RAG (FAISS-only); **E** gate + hybrid-RAG (FAISS+BM25+RRF). Gate Welford tính 1 lần/mẫu, dùng chung C/D/E → escalation set giống hệt nên hiệu số **D−C, E−D** cô lập đúng đóng góp từng tầng RAG. Verdict = action thô LLM (không áp consensus-guard) để đo năng lực phân loại thuần.
- **Quan hệ:** `results/ablation_bcde_results.json`; ghép với A/F của #E5.

### E7. `experiments/run_ablation.py --mode balanced` — Cân bằng 150/150 (A–F)
- **Mục đích:** Ablation **CÂN BẰNG** để phép so cấu phần CÓ ý nghĩa (tập gốc 93% tấn công khiến mọi cấu hình suy biến về dự đoán toàn-dương, F1 ≈ base rate).
- **Tác dụng:** 150 benign (expected=LOG, **warmup Welford bằng benign THẬT held-out** `benign[150:300]`) + 150 tấn công (10/lớp × 15 lớp). Có benign thật → gate có cơ hội DROP benign (true negative) nên C/D/E/F không còn buộc trùng nhau; đo P/R/F1/FPR + latency + **McNemar (B-vs-gated)**.
- **Quan hệ:** Tái dùng hàm gate/RAG/LLM từ #E6; cần LLM server; `results/ablation_balanced_results.json`.

### E8. `experiments/statistical_tests.py` *(Quan trọng)*
- **Mục đích:** Kiểm định ý nghĩa thống kê.
- **Tác dụng:** **McNemar's Test** (khác biệt phân loại A vs F) + **Mann-Whitney U** (khác biệt độ trễ), đọc `ablation_results.json`.
- **Kết quả chốt:** McNemar p=1.0 (Tầng-2 thêm giải thích, không đổi F1 cơ sở) · Mann-Whitney U=27053.5, **p=2.84×10⁻¹⁷** (speedup hai tầng có ý nghĩa).

---

<a name="nhom-3"></a>
# NHÓM 3 — Kháng cự & Chất lượng suy luận *(Trục 3 & 4)*

<a name="e9-e11"></a>
### E9. `experiments/evaluate_adversarial.py --mode static` — Kháng cự Guardrails TĨNH
- **Mục đích:** Đo kháng adversarial của lớp tĩnh (120 mẫu / 5 nhóm OWASP LLM Top-10).
- **Tác dụng:** Bơm payload qua lớp tĩnh, tính **block rate / bypass rate** (đã sửa naming khỏi "defeat_rate"). Đọc `experiments/adversarial/` (sinh bởi `build_adversarial_suite.py`, DAY2 #23).
- **Quan hệ:** `results/robustness_results.json` → `plot_results`.

### E10. `experiments/evaluate_adversarial.py --mode pipeline` — Kháng cự FULL pipeline (LLM)
- **Mục đích:** Đo kháng của **toàn pipeline Tier-2** với payload KHÓ.
- **Tác dụng:** Nhúng payload (semantic/jailbreak/rag-poison) vào flow tấn công thật → Tier-1→Guardrails→RAG→LLM; đếm **RESISTED vs COMPROMISED** (LLM bị ép ra LOG/DROP).
- **Quan hệ:** Chứng minh `enforce_tier_consensus` (DAY4) đóng lỗ hổng social-engineering (16.7%→0%).

### E11. `experiments/evaluate_reasoning.py` — LLM-as-Judge chéo họ (RAGAS)
- **Mục đích:** Chấm **chất lượng suy luận** khách quan.
- **Tác dụng:** Hot-swap sang **Llama-3 8B (Meta)** chấm reasoning của **Gemma-2 (Google)** từ `ablation_results.json` → Context Precision/Answer Relevancy/**Faithfulness**/Context Recall/Audit Completeness (chuẩn RAGAS); đẩy MLflow.
- **Quan hệ:** Cần #E5 chạy trước (sinh reasoning_outputs); dùng `switch_model.sh` (#E24). Kết quả chốt: Faithfulness **4.00**, Answer Relevancy 4.63±0.80.

---

<a name="nhom-4"></a>
# NHÓM 4 — Luồng gộp thống nhất & Rigor *(Trục 5 + phản biện)*

<a name="e12-e18"></a>
### E12. `experiments/evaluate_unified_stream.py` ⭐ *(NGUỒN DÙNG CHUNG)*
- **Mục đích:** Đánh giá luồng gộp THỐNG NHẤT (offline, tất định) — thay phương pháp 3 luồng circular cũ.
- **Tác dụng:** `build_stream()` gộp CICIDS + DAPT2020 + **zero-day REAL-DERIVED** (7 mẫu: nền flow benign thật, đẩy 1 feature cực trị, rải ngày 2–5) vào MỘT luồng sắp theo thời gian (golden-ratio interleave), stream qua Tier-1 + Welford + Threat Memory **bộ nhớ SẠCH** → đo: phân loại, **APT EMERGENT** (recall + độ trễ), zero-day (Welford bắt khi static bỏ sót).
- **Quan hệ:** Hàm `build_stream / map_cicids / _is_threat` được **tái dùng bởi #E13–E18** (không dựng luồng riêng). Output `results/unified_stream_results.json` + `reports/unified_stream_evaluation_report.md`.

### E13. `experiments/stream_unified_online.py` — Publisher ONLINE (demo end-to-end)
- **Mục đích:** Phát CÙNG luồng gộp qua TOÀN BỘ hệ thống thật (demo realtime).
- **Tác dụng:** `build_sequence()` + `enrich()` (gắn metadata DAPT/zero-day) → đẩy Redis qua pipeline (Tier-1 → APT emergent ở subscriber → LLM Agent → Dashboard); có `--dry-run`. Chỉ event ESCALATE mới gọi LLM (đúng thiết kế SOC).
- **Quan hệ:** Cần Redis + `main.py --mode server`. *(Offline #E12 = benchmark tất định; online #E13 = chứng minh end-to-end.)*

### E14. `experiments/run_threshold_sensitivity.py` *(rigor — bác "3.5σ cherry-pick")*
- **Tác dụng:** Quét τ ∈ {2.0…5.0} trên đúng luồng gộp (Tier-1, không LLM, tất định); đo trade-off: tỷ lệ escalation (tải LLM), FP-rate benign, P/R/F1 Tier-1, zero-day bắt được /7. Ghi đè `RuleEngine.z_threshold` **chỉ khi quét**; production giữ 3.5.
- **Quan hệ:** `results/threshold_sensitivity_results.json` → `plot_threshold_sensitivity()`.

### E15. `experiments/run_zeroday_graded.py` *(rigor — ranh giới phát hiện thật)*
- **Tác dụng:** Quét độ lệch k ∈ {2…100}·σ trên nhiều flow benign thật × nhiều feature; đo "noticed" (Welford gắn cờ Z>3.5σ) và "escalated" (điểm ≥ risk_threshold). Baseline Welford **đóng băng** (snapshot+restore) trước mỗi probe để z=k chính xác. Ranh giới phát hiện ≈ **4σ**.
- **Quan hệ:** `results/zeroday_graded_results.json` → `plot_zeroday_graded()`.

### E16. `experiments/run_apt_negative_control.py` *(rigor — đối chứng âm + CI)*
- **Tác dụng:** (a) **Wilson 95% CI** cho recall k/n (phù hợp n nhỏ); (b) đối chứng âm — đếm IP benign hiện diện ≥2 ngày rồi xác nhận **0 IP** kích hoạt `check_apt_chain` (**specificity=1.0**). Cơ chế phân biệt nằm ở CỔNG GHI: chỉ sự kiện gắn cờ tấn công mới ghi kho APT.
- **Quan hệ:** `results/apt_negative_control_results.json`.

### E17. `experiments/run_context_stress.py` *(rigor/observability — chống tràn ngữ cảnh)*
- **Tác dụng:** Đẩy N ∈ {1…2000} log, đo token vào LLM: **RAW** (nối thẳng → tăng TUYẾN TÍNH, vượt n_ctx nhanh) vs **COMPRESSED** (Drain template mining → **BÃO HÒA** quanh token_budget=4000/n_ctx=8192). Dùng `template_miner` (DAY2) + `token_monitor.N_CTX` (DAY4).
- **Quan hệ:** `results/context_stress_results.json` + `results/plots/context_stress.png`.

### E18. `experiments/run_llm_robustness.py` *(rigor — tất định & suy biến an toàn)*
- **Tác dụng:** (A) cùng prompt + **seed=42** gọi N lần → kiểm action GIỐNG HỆT; (B) monkeypatch `llm_client.invoke` ném ConnectionError → chạy `agent_app` đầy đủ, xác nhận hệ **KHÔNG vỡ** mà suy biến về **AWAIT_HITL** (Tier-1 vẫn bảo vệ). Kèm thống kê semantic-cache.
- **Quan hệ:** Cần LLM server cho (A); `results/llm_robustness_results.json`.

---

<a name="nhom-5"></a>
# NHÓM 5 — Độ trễ · Vẽ · E2E · Mapper eval *(Trục 2 + chốt chặn)*

<a name="e19-e22"></a>
### E19. `experiments/measure_latency_baseline.py` — Vận hành (Trục 2)
- **Tác dụng:** Chạy N log qua 2 cấu hình (Two-Tier vs LLM-only), đo Mean/Median/P95, tính **Latency Reduction** (mục tiêu ≥60%; đạt **−82.97%** vì Tier-1 lọc ~99% nên không gọi LLM cho mọi log).
- **Quan hệ:** `results/latency_benchmark.json`; bổ sung cho Mann-Whitney U (#E8).

### E20. `experiments/plot_results.py` — Trực quan hóa
- **Tác dụng:** Vẽ block-rate theo nhóm + pie accuracy (từ `robustness_results.json`); `plot_threshold_sensitivity()` + `plot_zeroday_graded()` → `results/plots/*.png` cho ch4.

### E21. `experiments/e2e_test_runner.py` *(Quan trọng kiểm thử)*
- **Tác dụng:** Chạy **22 kịch bản (T01–T22)**: RuleEngine, Guardrails, Dual-RAG, Threat Memory, Agent, Latency (T19, cần LLM), **Unified Stream (T21)** + **Online Publisher (T22)**; cờ `--offline` bỏ test cần LLM.
- **Quan hệ:** Chốt chặn toàn vẹn trước push/demo (`E2E 22/22 PASSED`).

### E22. `scripts/eval_attack_mapper.py` — Đo ATT&CK Mapper (DAY4 — D4)
- **Tác dụng:** 2 mode — **`rrf`** (offline, tất định, không LLM: dựng query flow như `node_rag_context` → top-RRF; cô lập đóng góp KB) và **`e2e`** (chạy FULL `agent_app`, cần LLM; **TỰ CÔ LẬP** threat_memory/audit/config sang DB tạm + no-op hàm ghi → KHÔNG đụng dữ liệu thật). Metrics: technique exact/parent-match, tactic-match, mapper-fired-rate, latency p50/p95, **trần KB-coverage**. Cờ `--ground-truth experiments/ground_truth_webattacks.json` (50 payload web thật) đo ở MIỀN thiết kế → **e2e 64%** (vs flow-GT 0% — flow-only ill-posed).
- **Quan hệ:** `results/attack_mapper_eval_*.json` (đã commit làm bằng chứng); tổng hợp ở `docs/METRICS_SUMMARY.md`.

---

<a name="nhom-6"></a>
# NHÓM 6 — Tiện ích & Tích hợp gốc

<a name="e23-e25"></a>
### E23. `scripts/seed_demo_data.py` — Seed từ data THẬT (không bịa)
- **Tác dụng:** Chạy pipeline thật (Tier-1 + Agent + LLM) trên mẫu CICIDS 14 lớp → quyết định thật vào audit/threat/pending-rules; `ingest_dapt_chains` 9 chuỗi APT; seed known entities. *(SEED dashboard, KHÔNG phải benchmark — benchmark ở #E12.)*

### E24. Tiện ích: `convert_report.py` · `switch_model.sh` · `cleanup.sh`
- **convert_report.py:** Markdown → DOCX (báo cáo tiến độ).
- **switch_model.sh:** Hot-swap LLM (`gemma`/`llama`), sửa `.env` + restart container `sentinel_llm`, chờ healthy — **cốt lõi cho #E11** (đổi sang Llama-3 trọng tài).
- **cleanup.sh:** Dọn artifact AN TOÀN — chỉ xóa thứ tái tạo được/gitignored (mlruns, eval DB tạm, faiss cache, logs, `__pycache__`). **KHÔNG** xóa `results/*.json` hay `plots/*.png` (dữ liệu luận văn đã commit).

### E25. `main.py` — Điểm khởi chạy tích hợp
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `setup_logger(log_level)` | Cấu hình logging. | [27-31](../../main.py#L27-L31) |
| `run_vulnerability_scan()` | Chạy Trivy SCA (DAY1 — scanner). | [32-39](../../main.py#L32-L39) |
| `build_knowledge_graph()` | Dựng Neo4j KG từ Trivy (DAY3 — graph_builder). | [40-48](../../main.py#L40-L48) |
| `handle_escalated_batch(batch)` ⭐ | **Cầu nối Tier-1 → Tier-2:** nhận batch ESCALATE từ subscriber → `agent_app.invoke(SentinelState)` (DAY4). Reset `LoopDetector` mỗi cycle. | [49-80](../../main.py#L49-L80) |
| `main()` | `argparse` mode `server`/`scan`/`full`: **server** = `subscriber.start_listening(on_batch_ready=handle_escalated_batch)`; **scan/full** = Trivy + Neo4j KG. *(KHÔNG tự chạy Streamlit.)* | [81-125](../../main.py#L81-L125) |

### Kiểm thử (Tests)
- **`tests/unit/`** — data_validator, decision_validator (+ Anti-Self-DoS + tier-consensus), feedback_validator, feedback_listener (HITL lifecycle), output_sanitizer, prompt_filter, rag_sanitizer, template_miner, entropy_scorer, threat_memory (+ APT-chain-context), subscriber (chống lộ nhãn dataset vào LLM), semantic_cache, auth (PBKDF2/RBAC), executor (HMAC chain, DB tạm), agent, rag, **attack_mapper** (35 test, không cần LLM), token_monitor.
- **`tests/integration/`** — `test_unified_stream.py` (3 nguồn trộn + APT emergent + bất biến zero-day), `test_streaming_pipeline.py`, `test_end_to_end.py`.
- **`tests/test_adversarial.py`** + **`tests/test_tier1_filter.py`** + **`tests/conftest.py`**.

---

<a name="phụ-lục"></a>
# Phụ lục — Bản đồ 5D & điểm cần lưu ý

### Ánh xạ 5 trục đánh giá ↔ script ↔ con số chốt
| Trục (5D) | Script chính | Con số chốt (nêu khi bảo vệ) |
|-----------|--------------|----------------------------|
| 1. Phân loại | E5–E7 ablation + E8 stat | F1 0.594 (P 0.939/R 1.0); McNemar p=1.0 |
| 2. Vận hành | E19 latency | Latency **−82.97%**; Mann-Whitney **p=2.8×10⁻¹⁷** |
| 3. Kháng cự | E9 tĩnh + E10 pipeline | full-pipeline adversarial **100%** RESISTED |
| 4. Ngữ cảnh | E11 LLM-Judge | Faithfulness **4.00**; reasoning 3.91/5 |
| 5. Luồng gộp | E12 unified | APT 3/3 recall 1.0 (Wilson CI [0.44,1.0]), specificity 1.0; zero-day 7/7 |
| + Mapper | E22 | web-payload e2e **64%** (miền thiết kế) |

### Điểm cần lưu ý
| # | Mức | Lưu ý | Vị trí |
|---|-----|-------|--------|
| 1 | 🟢 | UI đọc **số THẬT** (`pipeline_stats.json` do subscriber ghi) — bỏ ước lượng ×35. | [app.py:63](../../src/ui/app.py#L63) |
| 2 | 🟢 | Mọi script rigor **tái dùng** `build_stream` (#E12) → đo trên cùng dữ liệu thật, không lệch nguồn. | [evaluate_unified_stream.py](../../experiments/evaluate_unified_stream.py) |
| 3 | 🟢 | `eval_attack_mapper --mode e2e` **tự cô lập** DB/audit/config sang temp → KHÔNG đụng dữ liệu luận văn. | [eval_attack_mapper.py](../../scripts/eval_attack_mapper.py) |
| 4 | 🟢 | Trung thực: báo **cả** kết quả âm (flow-GT mapper 0% ill-posed) bên cạnh 64% miền thiết kế. | [eval_attack_mapper.py](../../scripts/eval_attack_mapper.py) |
| 5 | 🟢 | Auth **PBKDF2 100k vòng** + constant-time compare + lockout — không hardcode plaintext. | [auth.py:40](../../src/ui/auth.py#L40) |
| 6 | 🟡 | `main.py` KHÔNG bật Streamlit — Dashboard chạy riêng qua Docker (dễ nhầm khi demo). | [main.py:81](../../main.py#L81) |

### Cải tiến tích cực (nên nêu khi bảo vệ)
- ✅ **Khung 5D tất định** — mọi trục đo trên cùng luồng gộp thật, tái lập bằng seed=42.
- ✅ **Đối chứng âm + Wilson CI** cho APT — không chỉ báo recall trên n nhỏ.
- ✅ **5 script rigor** trả lời trực diện phản biện (ngưỡng cherry-pick, zero-day, specificity, tràn ngữ cảnh, độ bền LLM).
- ✅ **UI số THẬT + HITL khép vòng** — analyst duyệt luật → Tier-1 enforce ngay.
- ✅ **E2E 22/22 + 207 unit test** — chốt chặn toàn vẹn trước mỗi push.

---

*Tài liệu sinh từ phân tích mã nguồn (Ngày 5) — đối chiếu lại số dòng nếu mã thay đổi. Xem thêm: [DAY1](DAY1.md) · [DAY2](DAY2.md) · [DAY3](DAY3.md) · [DAY4](DAY4.md) · tổng quan [codebase_summary](../codebase_summary.md).*
