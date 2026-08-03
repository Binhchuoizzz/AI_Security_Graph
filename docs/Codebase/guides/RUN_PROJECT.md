# Chạy & Demo SENTINEL

> Cập nhật 31/07/2026. Chỉ số đo đạc xem [DEMO_BY_RQ.md](DEMO_BY_RQ.md); tệp này là **cách vận hành**.

---

## 0. Cài một lần

```bash
uv venv && uv pip install -r requirements.txt      # hoặc python -m venv .venv
cp .env.example .env                               # điền SENTINEL_LOG_SECRET, NEO4J_PASSWORD
```

`.env` phải có `SENTINEL_LOG_SECRET`. Thiếu nó thì chuỗi HMAC ký bằng khoá mặc định công khai
— vẫn chạy, nhưng chỉ chứng minh **tính nhất quán**, không phải chống giả mạo.

Model mặc định: **Foundation-Sec-8B-Instruct Q4_K_M**, `LLAMA_ARG_CTX_SIZE=32768` với `-np 2`
→ **16.384 token/khe**. Trùng khớp `llm.max_context_tokens` trong `config/system_settings.yaml`.

---

## 1. Demo đầy đủ — MỘT lệnh

```bash
./scripts/run_demo.sh --fresh --small     # ~5.000 sự kiện, xong Tier-1 tức thì, Tier-2 chạy dần
./scripts/run_demo.sh --fresh             # luồng đầy đủ (~100k sự kiện)
```

| cờ | tác dụng |
| :-- | :-- |
| `--fresh` | chạy `reset_all.py` — dọn uy tín IP, luật động, blacklist, stream. **Bắt buộc** khi so hai lượt |
| `--small` | đẩy `demo_small.json` thay vì luồng đầy đủ |
| `--no-push` | chỉ dựng hạ tầng + UI |
| `SENTINEL_LITE=0` | cấu hình đầy đủ: ctx 32768, 2 parallel, bật Neo4j |

Mặc định `SENTINEL_LITE=1` dùng **cùng model, cùng 16.384 token/khe** như lượt đo — chỉ khác
thông lượng (1 parallel, tắt Neo4j). Demo và số liệu luôn mô tả cùng một hệ.

Sau khi chạy: `http://localhost:8501`, đăng nhập `manager`.

---

## 2. Demo từng RQ

### RQ1 — Xả tải và độ trễ

**Xem ở đâu:** Dashboard → thẻ *Phân bổ cơ chế xả tải* (điểm tĩnh · Cổng ML · tiền sử IP ·
Z-score · chữ ký WAF · blacklist).

```bash
.venv/bin/python experiments/run_cache_efficiency.py     # bộ đệm Tầng 1.75
.venv/bin/python experiments/measure_latency_baseline.py # hai tầng vs LLM-only
```

Câu chuyện kể: đẩy luồng → phần lớn sự kiện chết ở Tier-1 với chi phí dưới mili-giây, chỉ
~10% chạm LLM. `stage_breakdown` trong `latency_benchmark.json` cho biết mỗi chặng chặn bao nhiêu.

### RQ2 — Rào chắn AI và toàn vẹn pháp y

**Xem ở đâu:** Dashboard → thẻ cảnh báo có nhãn `[NEO BẰNG CHỨNG]` và lý do `technique_not_in_rag`.

```bash
.venv/bin/python experiments/evaluate_adversarial.py --mode all   # tĩnh 120 mẫu + Tier-2 75 mẫu
.venv/bin/python experiments/run_audit_tamper.py                  # giả mạo chuỗi HMAC
.venv/bin/python -c "import sys;sys.path.insert(0,'.');from src.response.executor import verify_audit_trail_integrity as v;print(v())"
```

Câu chuyện kể: payload tiêm nhiễm bị đóng gói bằng nonce nên LLM không đọc nó như chỉ dẫn;
mọi hành động ghi vào chuỗi HMAC, sửa một dòng là phát hiện ngay.

### RQ3 — Tác tử có trạng thái và quy kết ATT&CK

**Xem ở đâu:** Dashboard → huy hiệu kỹ thuật trên thẻ cảnh báo · trang *Threat Memory (APT)*.

```bash
export SENTINEL_TRACE=1                                          # đã bật sẵn trong .env
.venv/bin/python scripts/eval_attack_mapper.py --mode rrf --evidence-layer payload
.venv/bin/python scripts/eval_attack_mapper.py --mode e2e --evidence-layer payload
```

Câu chuyện kể: RAG kép lấy tài liệu ATT&CK, RRF chọn kỹ thuật, và **mọi mã hệ công bố đều
phải có neo trong tài liệu của chính lô đó** — không có neo thì trả `N/A` + chuyển người.

Bằng chứng sống, đọc từ `logs/tier2_trace.jsonl`:

```bash
.venv/bin/python -c "
import json,re
TECH=re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
rows=[json.loads(l) for l in open('logs/tier2_trace.jsonl') if l.strip()]
bad=0
for r in rows:
    a=r.get('attack_mapper') or {}; fin=a.get('final_technique_id') or ''
    if not fin: continue
    ids=set(TECH.findall(json.dumps(r.get('rag') or {},ensure_ascii=False)))
    if ids and fin not in ids: bad+=1
print(f'{len(rows)} lô | quy kết KHÔNG neo trong RAG: {bad}')"
```

Kỳ vọng **0**. Đây là bất biến cốt lõi của hệ.

---

## 3. Chạy thủ công từng phần

```bash
docker-compose up -d redis llm mlflow agent_ui          # hạ tầng (bỏ neo4j nếu thiếu RAM)
.venv/bin/python scripts/reset_all.py                   # dọn sạch + bật đúng 1 subscriber
.venv/bin/python main.py --mode server                  # Tier-1 + Cổng ML + Agent
.venv/bin/python scripts/demo.py                        # phát luồng vào Redis
```

Đẩy riêng một nguồn: `scripts/push_flow.py --source {cicids|dapt|zeroday|adversarial} --limit N`

---

## 4. Kết quả xem ở đâu

| thứ cần xem | ở đâu |
| :-- | :-- |
| Cảnh báo, huy hiệu kỹ thuật, hàng đợi HITL | `http://localhost:8501` |
| Vết suy luận Tier-2 từng lô | `logs/tier2_trace.jsonl` |
| Vết kiểm toán có ký HMAC | `config/audit_trail.db` |
| Số liệu thô từng phép đo | `experiments/results/*.json` |
| Báo cáo gộp | `.venv/bin/python scripts/export_final_report.py` → `reports/KET_QUA_CHOT_<ngày>.md` |
| So sánh ablation | MLflow `http://localhost:5001` |
---

## 5. Kịch bản bảo vệ (~15 phút)

1. `./scripts/run_demo.sh --fresh --small` — mở Dashboard, chỉ luồng chảy vào.
2. **RQ1**: thẻ phân bổ xả tải — phần lớn sự kiện chết ở Tier-1.
3. **RQ2**: mở một thẻ có `[NEO BẰNG CHỨNG]` — hệ từ chối khẳng định kỹ thuật không có bằng chứng.
4. **RQ3**: mở một thẻ có huy hiệu kỹ thuật, đối chiếu với `logs/tier2_trace.jsonl`.
5. Chạy `run_audit_tamper.py` tại chỗ — sửa một dòng log, chuỗi HMAC báo ngay.
6. Mở `reports/KET_QUA_CHOT_<ngày>.md` cho câu hỏi về số liệu.

Câu hỏi sâu → mở đúng bằng chứng:

| hỏi | mở |
| :-- | :-- |
| "Zero-day nhạy tới đâu?" | `zeroday_graded_results.json` |
| "F1 cao có phải do base-rate?" | `ablation_balanced_results.json` |
| "Tràn ngữ cảnh thì sao?" | `context_stress_results.json` (báo **cả hai** pool) |
| "Cổng ML gỡ tải bao nhiêu?" | `ablation_mlgate_results.json` |
| "RAG kép đóng góp gì?" | `ablation_bcde_results.json` → `attribution_scores` |

---

## 6. Cổng và endpoint (đều bind `127.0.0.1`)

| dịch vụ | endpoint |
| :-- | :-- |
| LLM (llama.cpp) | `http://localhost:5000/v1/models` · `/v1/chat/completions` |
| Dashboard HITL | `http://localhost:8501` |
| MLflow | `http://localhost:5001` |
| Redis | `localhost:6379` |
| Neo4j Browser | `http://localhost:7474` |

---

## 7. Sự cố hay gặp

| triệu chứng | nguyên nhân |
| :-- | :-- |
| LLM không lên | `docker logs sentinel_llm`. Đổi model phải `--force-recreate --no-deps llm` |
| Đổi model trong `.env` không ăn | docker-compose **ưu tiên biến môi trường** hơn tệp — phải `export` |
| Dashboard trống | subscriber chưa chạy → `scripts/reset_all.py` |
| Lượt 2 khác lượt 1 | thiếu `--fresh` — Tier-1 còn nhớ IP của lượt trước |
| Số luật động phình sau khi chạy test | thiếu `SENTINEL_FREEZE_DYNAMIC_RULES=1` |
| Tier-1 loại 100% kể cả tấn công | truyền cả vỏ bọc `ev` thay vì `ev["log"]` vào `engine.evaluate()` |

---

## 8. Cheat sheet

```bash
docker-compose up -d                                    # hạ tầng
./scripts/run_demo.sh --fresh --small                   # demo 1 lệnh
.venv/bin/python scripts/reset_all.py                   # reset sạch
SENTINEL_FREEZE_DYNAMIC_RULES=1 .venv/bin/pytest tests/ -q
.venv/bin/ruff check . && uvx pyrefly check --python-interpreter-path .venv/bin/python
.venv/bin/python scripts/export_final_report.py         # gom báo cáo
docker-compose down                                     # tắt
```
