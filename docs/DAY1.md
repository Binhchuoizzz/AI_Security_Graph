# SENTINEL — Tài liệu tham chiếu hàm (Function Reference)

> **Phạm vi:** Tài liệu này mô tả **chi tiết từng hàm** của 11 file mã nguồn cốt lõi thuộc 2 pipeline dữ liệu + tầng lọc Tier-1 + tiện ích DevSecOps.
> **Cập nhật:** 2026-06-10 (sau đợt mở rộng data 14 lớp tấn công + Tầng 0.2 Injection-Signature ở Tier-1 + wiring `session_baseline` từ config).
> **Quy ước:** Mỗi hàm ghi rõ *Mục đích → Tham số → Trả về → Luồng xử lý → Tham chiếu dòng*.

---

## Mục lục

- [0. Bản đồ kiến trúc tổng thể](#0-bản-đồ-kiến-trúc-tổng-thể)
- [PIPELINE A — Streaming thời gian thực (CSE-CIC-IDS2018)](#pipeline-a)
  - [A1. `scripts/fetch_and_build_dataset.py`](#a1-fetch_and_build_datasetpy)
  - [A2. `scripts/simulate_traffic.py`](#a2-simulate_trafficpy)
  - [A3. `src/streaming/publisher.py`](#a3-publisherpy)
  - [A4. `src/streaming/subscriber.py`](#a4-subscriberpy)
- [TIER-1 — Bộ não quyết định](#tier-1)
  - [T1. `src/tier1_filter/rule_engine.py`](#t1-rule_enginepy)
  - [T2. `src/tier1_filter/feedback_listener.py`](#t2-feedback_listenerpy)
  - [T3. `src/tier1_filter/scanner.py`](#t3-scannerpy)
  - [T4. `demo_tier1.py`](#t4-demo_tier1py)
- [PIPELINE B — Bộ nhớ APT dài hạn (DAPT2020)](#pipeline-b)
  - [B1. `scripts/dapt2020_config.py`](#b1-dapt2020_configpy)
  - [B2. `scripts/fetch_dapt2020.py`](#b2-fetch_dapt2020py)
  - [B3. `scripts/build_dapt_chains.py`](#b3-build_dapt_chainspy)
- [Phụ lục — Bảng đồng bộ & điểm cần lưu ý](#phụ-lục)

---

## 0. Bản đồ kiến trúc tổng thể

```
PIPELINE A — Real-time streaming (CICIDS):
  fetch_and_build_dataset.py ─► ground_truth.json ─► simulate_traffic.py ─┐
                                                                          ├─► Redis STREAMS
  publisher.py (CSV thô) ─────────────────────────────────────────────────┘   (queue_waf / queue_firewall / queue_sysmon)
                                                                                       │ xreadgroup + xack
                                                                                       ▼
                                                       subscriber.py ─► RuleEngine.evaluate()
                                                                                       │
       ┌──────────────────────────┬──────────────────────────┬──────────────────────┼─────────────────────────┐
   BLOCK_IP → blacklist:<ip>   AWAIT_HITL → queue_hitl   ALERT/LOG → queue_decisions  ESCALATE → Tier-2 (AI)   DROP → bỏ
                                                                                                                  │
   feedback_listener.py ◄── LangGraph Agent (Tier-2) ◄─────────────────────────────────────────────────────────┘
        │ ghi dynamic_rules / whitelist  (qua FeedbackValidator — Ngày 2 G8)
        ▼
   config/system_settings.yaml ──(hot-reload mtime)──► RuleEngine

PIPELINE B — Batch / APT memory (DAPT2020):
  fetch_dapt2020.py ─► data/raw/dapt2020/dayN.csv ─► build_dapt_chains.py ─► dapt2020_chains.jsonl ─► Tier-2 Threat Memory
  dapt2020_config.py = hằng số + hàm chuẩn hóa dùng chung cho B2, B3

ĐỘC LẬP (DevSecOps):
  scanner.py ─► data/trivy-results.json ─► Neo4j Knowledge Graph  (KHÔNG nằm trong luồng traffic)
```

**Khớp nối tối quan trọng (đã xác minh đồng bộ với Ngày 2 — Guardrails):**
- `publisher`/`simulate_traffic` ghi `xadd(stream, {"log": <json>})`; `subscriber` đọc `json.loads(data["log"])` → field `"log"` đồng bộ.
- `evaluate()` gắn `tier1_score / tier1_reasons / tier1_action` vào log; batch ESCALATE → `main.py` → `node_guardrails` (`GuardrailsPipeline.process_batch`, G4) và `node_llm_triage` dùng chính các field này cho `enforce_tier_consensus` (G6).
- `map_to_cicids` xuất đủ `Source IP / Destination Port / Protocol` = `REQUIRED_FIELDS` của `DataValidator` (G3); tên chuẩn của `_KEY_ALIASES` (Tier-1) trùng với `KEY_ALIASES` (Guardrails G1) ở mọi trường chung.
- Tầng 0.2 của Tier-1 đọc `injection_patterns`/`jailbreak_patterns` **từ cùng config** mà Guardrails dùng (single source of truth).

---

<a name="pipeline-a"></a>
# PIPELINE A — Streaming thời gian thực (CSE-CIC-IDS2018)

<a name="a1-fetch_and_build_datasetpy"></a>
## A1. `scripts/fetch_and_build_dataset.py`
**Vai trò:** Tải CSE-CIC-IDS2018 từ AWS S3 → làm sạch → stratified sampling → sinh `experiments/ground_truth.json` (tập "đề thi" có gắn đáp án MITRE/action/severity) + 50 mẫu adversarial.
**Trạng thái data hiện tại:** 4267 samples / 14 lớp tấn công + 300 Benign + 50 Adversarial.

### Hằng số
| Tên | Mô tả |
|-----|-------|
| `LABEL_MAP` | Ánh xạ **15 nhãn (14 lớp tấn công + Benign)** → `{mitre, sub, action, severity}` — gồm cả `DDoS attacks-LOIC-HTTP` (T1499.001). Vừa là bộ lọc nhãn vừa là đáp án chấm điểm. |
| `FEATURE_COLS` | 15 cột đặc trưng cần trích từ CSV. |
| `S3_BUCKET`, `LOCAL_RAW_DIR` | Nguồn S3 và thư mục raw cục bộ. |
| `CSV_FILES_2018` | 9 file CSV đọc toàn phần. File `Tuesday-20-02` (3.8GB, chứa DDoS-LOIC-HTTP) **không** nằm trong list mà được đọc RIÊNG theo chunk (xem `fetch_and_build` bước 4b). |

### `_infer_service(port: int) -> str`
- **Mục đích:** Tra tên dịch vụ từ số port (22→SSH, 80→HTTP, 443→HTTPS…).
- **Trả về:** Tên dịch vụ, hoặc `PORT_<n>` nếu không có trong bảng.
- **Dòng:** [164-180](../scripts/fetch_and_build_dataset.py#L164-L180)

### `safe_int(val: Any) -> int`
- **Mục đích:** Ép kiểu int an toàn, không bao giờ ném exception.
- **Luồng:** `NaN → 0`; ép float, nếu không hữu hạn (`inf`) → `0`; bắt `ValueError/TypeError/OverflowError → 0`.
- **Dòng:** [183-190](../scripts/fetch_and_build_dataset.py#L183-L190)

### `safe_float(val: Any) -> float`
- **Mục đích:** Như `safe_int` nhưng trả `float`. Mọi lỗi/NaN/inf → `0.0`.
- **Dòng:** [193-200](../scripts/fetch_and_build_dataset.py#L193-L200)

### `download_from_aws() -> bool`
- **Mục đích:** Tải các file CSV từ S3 bucket công khai.
- **Luồng:** Tạo thư mục → kiểm tra `aws --version` (không có → in hướng dẫn, `False`) → dựng lệnh `aws s3 sync --no-sign-request` (ẩn danh) với `--exclude "*"` + `--include <file>` cho từng CSV → chạy.
- **Trả về:** `True`/`False`.
- **Dòng:** [203-234](../scripts/fetch_and_build_dataset.py#L203-L234)

### `fetch_and_build(n_per_label=50, output_path, min_per_label=20, force_regenerate=False)`
- **Mục đích:** Hàm điều phối chính — đọc CSV → tiền xử lý → sampling → ghi JSON.
- **Luồng:**
  1. Bỏ qua nếu output đã tồn tại và không `force_regenerate`.
  2. `glob` tìm CSV; trống → `download_from_aws()`.
  3. Lọc theo `CSV_FILES_2018`; đọc từng file (`on_bad_lines="skip"`), strip cột, bỏ header lạc (`Label=="Label"`), chỉ giữ nhãn trong `LABEL_MAP`.
  4. **(4b) Đọc CHUNKED file Tuesday-20-02 (3.8GB):** `pd.read_csv(chunksize=200000)`, mỗi chunk chỉ giữ dòng `Label == "DDoS attacks-LOIC-HTTP"` → trích đủ mẫu LOIC-HTTP mà KHÔNG nạp cả file vào RAM. **Dòng:** [301-327](../scripts/fetch_and_build_dataset.py#L301-L327)
  5. **Tiền xử lý** (ghi `stats` từng bước): ép numeric → thay `inf→NaN` → `drop_duplicates` → clip `Flow Duration<0` → clip `Dst Port∈[0,65535]` → window sentinel `-1→0` → `fillna(0)`.
  6. **Stratified Sampling**: mỗi nhãn lấy `min(n_per_label, n_available)` mẫu với `random_state=42`. Sinh IP có seed `sha256(label_idx)` (tách dải benign/attacker), parse timestamp, build sample `{id, logs[], expected_*, input{network_layer, application_layer, cicids_label}}`.
  7. Gọi `_generate_adversarial_samples()` thêm 50 mẫu → ghi JSON → in phân phối → kiểm ngưỡng tối thiểu → `_generate_adversarial_test_set()`.
- **Dòng:** [237-505](../scripts/fetch_and_build_dataset.py#L237-L505)

### `_generate_adversarial_samples(start_id: int) -> list`
- **Mục đích:** Sinh 50 mẫu đối kháng để test Guardrails.
- **Luồng:** 25 mẫu **structural** (Delimiter Smuggling `<<<DATA_END_<hex>>>>`, payload chứa `DROP TABLE`/`exec()`, MITRE T1190) + 25 mẫu **semantic confusion** (text vô hại + user-agent chèn zero-width joiner `‍`). Mỗi mẫu tách `network_layer` (bỏ payload) khỏi `application_layer` (chứa payload).
- **Trả về:** list 50 sample dict.
- **Dòng:** [508-636](../scripts/fetch_and_build_dataset.py#L508-L636)

### `_generate_adversarial_test_set()`
- **Mục đích:** Sinh file riêng `experiments/adversarial_samples.json` (định dạng gọn).
- **Luồng:** 25 structural (`expected_blocked: True`) + 25 semantic (`expected_blocked: False`) + metadata.
- **Dòng:** [639-675](../scripts/fetch_and_build_dataset.py#L639-L675)

### `__main__`
- Argparse `--n-per-label / --min-per-label / --regenerate-ground-truth / --output` → gọi `fetch_and_build`.
- **Dòng:** [678-695](../scripts/fetch_and_build_dataset.py#L678-L695)

---

<a name="a2-simulate_trafficpy"></a>
## A2. `scripts/simulate_traffic.py`
**Vai trò:** Phát lại (replay) `ground_truth.json` lên **Redis Streams** theo batch, phục vụ Ablation Study/demo. (Khác `publisher.py` chỗ: replay đề thi có nhãn, không phải load test CSV thô.)

### Hằng số
- `REDIS_URL` — đọc theo thứ tự **env → `redis.url` trong YAML config → default** (đã đồng bộ cách đọc với publisher/subscriber). **Dòng:** [40](../scripts/simulate_traffic.py#L40)
- `BATCH_SIZE=50`, `BATCH_DELAY_SECONDS`, `MAX_QUEUE_SIZE=10000`. **Dòng:** [40-46](../scripts/simulate_traffic.py#L40-L46)

### `determine_queue(log_entry: dict) -> str`
- **Mục đích:** Định tuyến đa nguồn (mô phỏng SIEM): WAF / Firewall-IDS / Sysmon.
- **Luồng (thứ tự ưu tiên):** port∈{21,22,23,53,139,445,3389} → `queue_firewall`; port∈{80,443,8080} → `queue_waf`; có payload/UA → `queue_waf`; mặc định → `queue_firewall`. **Không bao giờ trả `queue_sysmon`** (giữ chỗ).
- **Dòng:** [48-76](../scripts/simulate_traffic.py#L48-L76)

### `map_to_cicids(network_layer: dict, app_layer: dict) -> dict`
- **Mục đích:** Chuyển schema ground_truth (`src_ip`, `flow_duration_us`…) → schema CICIDS mà `rule_engine` mong đợi (`Source IP`, `Flow Duration`…).
- **Trả về:** dict đã map gồm core fields (`Source IP`, `Destination Port`, `Protocol` — đủ `REQUIRED_FIELDS` của Guardrails G3) + flow stats + discriminative features (Z-score) + application layer (payload/user_agent cho Guardrails).
- **Dòng:** [79-116](../scripts/simulate_traffic.py#L79-L116)

### `stream_logs_to_redis() -> None`
- **Mục đích:** Hàm chính — replay theo batch.
- **Luồng:**
  1. Kết nối Redis, load `ground_truth.json`.
  2. Chia batch (`BATCH_SIZE=50`). Backpressure: chờ nếu `xlen(queue) > MAX_QUEUE_SIZE` trên cả 3 stream.
  3. Mỗi sample: lấy từ `input{}` hoặc fallback `logs[]` → `map_to_cicids` → gắn metadata ground truth (`gt_id`, `gt_expected_action`, `gt_expected_severity`, `gt_expected_mitre`, `dataset_source`).
  4. `determine_queue` → **`xadd(stream, {"log": json}, maxlen, approximate=True)`**.
  5. Throttle theo batch (`BATCH_DELAY_SECONDS`).
- **Dòng:** [118-217](../scripts/simulate_traffic.py#L118-L217)

---

<a name="a3-publisherpy"></a>
## A3. `src/streaming/publisher.py`
**Vai trò:** Bơm log **CSV thô khối lượng lớn** → Redis Stream (load test/production). Đọc cấu hình từ `system_settings.yaml`.

### Hằng số
- `REDIS_URL`, `QUEUE_NAME` (mặc định `queue_waf`), `BATCH_DELAY_SECONDS`, `MAX_QUEUE_SIZE=10000` — đọc từ YAML config với fallback.
- `COLUMN_MAPPING` — quy đổi tên cột từ nhiều dataset (CICIDS `Src IP` / DAPT2020 `src_ip`) về schema chuẩn.
- **Dòng:** [15-60](../src/streaming/publisher.py#L15-L60)

### `_clean_val(v)`
- **Mục đích:** Làm sạch giá trị bẩn cho JSON. `NaN→0`, `Inf→0.0`, sentinel `-1→0`.
- **Dòng:** [63-71](../src/streaming/publisher.py#L63-L71)

### `_inject_ips(entry: dict, idx: int)`
- **Mục đích:** Sinh IP nguồn có seed `sha256(label_idx)` nếu log thiếu IP, chống "blacklist saturation". Attacker → `10.200.x.x`, benign → `192.168.100.x`.
- **Dòng:** [74-85](../src/streaming/publisher.py#L74-L85)

### `stream_logs_to_redis(csv_path: str)`
- **Mục đích:** Đọc CSV theo chunk 500 dòng → đẩy vào Redis Stream.
- **Luồng:**
  1. Kết nối + `ping`.
  2. Đọc `pd.read_csv(chunksize=500)`. **Backpressure thật:** chờ khi `xlen(QUEUE_NAME) > 90% MAX_QUEUE_SIZE` (ngưỡng 9000 — kích hoạt TRƯỚC khi `maxlen` tự cắt). **Dòng:** [120-122](../src/streaming/publisher.py#L120-L122)
  3. Mỗi dòng: `to_dict` → `_clean_val` → chuẩn hóa key qua `COLUMN_MAPPING` → `_inject_ips` → gắn `dataset_source` → **`xadd(maxlen=MAX_QUEUE_SIZE, approximate=True)`**.
  4. Throttle theo chunk.
- **Dòng:** [88-169](../src/streaming/publisher.py#L88-L169)

---

<a name="a4-subscriberpy"></a>
## A4. `src/streaming/subscriber.py`
**Vai trò:** Consumer + cổng gác Tier-1. Đọc Redis Streams qua **consumer group** (at-least-once), chạy `RuleEngine`, định tuyến theo action.

### Hằng số
- `REDIS_URL`, `QUEUES`, `ESCALATED_QUEUE` (=`queue_hitl`) — đọc từ YAML config.
- **Dòng:** [25-38](../src/streaming/subscriber.py#L25-L38)

### `start_listening(on_batch_ready=None, batch_size=10, timeout_sec=5)`
- **Mục đích:** Vòng lặp tiêu thụ chính.
- **Tham số:** `on_batch_ready` = callback khi đủ batch ESCALATE (nối tới Agent Workflow — `main.py` truyền `handle_escalated_batch`); `None` → chế độ standalone (in console).
- **Luồng:**
  1. Kết nối Redis → tạo consumer group `sentinel_group` cho từng stream (`xgroup_create` + `mkstream`; bỏ qua `BUSYGROUP`).
  2. Khởi tạo `RuleEngine()`.
  3. Vòng lặp: **`xreadgroup(group, consumer, streams, count=batch_size, block=1000)`**.
  4. Mỗi message: `json.loads(data["log"])` → gắn `log_source` (provenance) → **`engine.evaluate()`** → lấy `tier1_action`.
  5. **Định tuyến** ([101-127](../src/streaming/subscriber.py#L101-L127)): `ESCALATE`→`batch_buffer`; `AWAIT_HITL`→`rpush(queue_hitl)`; `BLOCK_IP`→`setex(blacklist:<ip>, 3600)` + `rpush(queue_decisions)`; `ALERT/LOG`→`rpush(queue_decisions)`; `DROP`→bỏ.
  6. **`xack(stream, group, msg_id)`** xác nhận đã xử lý.
  7. **Gom batch:** đủ `batch_size` hoặc quá `timeout_sec` → gọi `on_batch_ready`/in console.
  8. **Xử lý lỗi bền bỉ:** `ConnectionError`→retry 5s; `JSONDecodeError`→skip; lỗi khác→log & tiếp tục.
- **Lưu ý:** PEL (Pending Entries List) recovery chưa cài (ghi rõ tại [67-71](../src/streaming/subscriber.py#L67-L71)).
- **Dòng:** [41-164](../src/streaming/subscriber.py#L41-L164)

---

<a name="tier-1"></a>
# TIER-1 — Bộ não quyết định

<a name="t1-rule_enginepy"></a>
## T1. `src/tier1_filter/rule_engine.py`
**Vai trò:** Lõi chấm điểm rủi ro + phân loại 6 action (`DROP / LOG / BLOCK_IP / ALERT / AWAIT_HITL / ESCALATE`). Kết hợp rule tĩnh + WAF + **Injection-Signature (mới)** + Z-score zero-day + baseline hành vi + rule động.

### `class IPProfile(TypedDict)`
- Cấu trúc hồ sơ mỗi IP: `request_count, unique_ports, total_fwd_packets, first_seen, last_seen`.
- **Dòng:** [24-30](../src/tier1_filter/rule_engine.py#L24-L30)

### `class RunningStats` — thuật toán Welford (O(1) bộ nhớ)
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__` | Khởi tạo `n, old_m, new_m, old_s, new_s = 0`. | [37-42](../src/tier1_filter/rule_engine.py#L37-L42) |
| `push(x)` | Cập nhật trực tuyến μ và tổng bình phương lệch theo công thức Welford. | [44-53](../src/tier1_filter/rule_engine.py#L44-L53) |
| `mean()` | Trả μ (0 nếu chưa có mẫu). | [55-56](../src/tier1_filter/rule_engine.py#L55-L56) |
| `variance()` | Phương sai mẫu `new_s/(n-1)`. | [58-59](../src/tier1_filter/rule_engine.py#L58-L59) |
| `std_dev()` | Độ lệch chuẩn `sqrt(variance)`. | [61-62](../src/tier1_filter/rule_engine.py#L61-L62) |

### Hằng số module
- `CONFIG_PATH`, `_KEY_ALIASES` (JSON↔CSV key — tên chuẩn TRÙNG với `KEY_ALIASES` của Guardrails G1), `_RAW_TO_CANONICAL` (gom biến thể tên cột cho Z-score).
- **Dòng:** [65-97](../src/tier1_filter/rule_engine.py#L65-L97)

### `load_config() -> dict`
- Đọc & parse `system_settings.yaml`. **Dòng:** [100-102](../src/tier1_filter/rule_engine.py#L100-L102)

### `class SessionBaseline` — baseline hành vi theo IP
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__(deviation_threshold=2.0, window_seconds=300, ttl_seconds=600, max_profiles=10000, eviction_interval=100)` | Khởi tạo `profiles` (defaultdict), ngưỡng, **`max_profiles`** chống state exhaustion. Mọi tham số được **wire từ `tier1.session_baseline` trong config** (qua `RuleEngine.__init__`). | [115-138](../src/tier1_filter/rule_engine.py#L115-L138) |
| `_evict_stale_profiles()` | Xóa IP inactive > `ttl_seconds`, rồi recalibrate global baseline. Chống RAM OOM. | [140-156](../src/tier1_filter/rule_engine.py#L140-L156) |
| `update(source_ip, log_entry) -> dict` | **Hàm chính:** (1) nếu cache đầy → evict stale → vẫn đầy thì xóa 10% IP cũ nhất (LRU); (2) cập nhật hồ sơ; (3) chấm **3 indicator**: Port scan (>10 cổng non-HTTP → `+count×3`), tần suất cao (`>global_avg×2` → `+20`), packet TB cao (`>500` → `+15`). Trả `{deviation_score, deviation_reasons, is_anomalous, …}`. | [158-241](../src/tier1_filter/rule_engine.py#L158-L241) |
| `update_global_baseline()` | Tính lại tốc độ request trung bình toàn cục. | [243-254](../src/tier1_filter/rule_engine.py#L243-L254) |
| `reset_window()` | Xóa toàn bộ profiles (gọi sau mỗi window). | [256-259](../src/tier1_filter/rule_engine.py#L256-L259) |

### `class RuleEngine`

#### `__init__()`
- **Mục đích:** Nạp config + khởi tạo state.
- **Luồng:** Đọc `risk_threshold, sensitive_ports, max_fwd_packets, dynamic_rules` (chỉ `ACTIVE`), `whitelist_ips`; **compile `injection_patterns` + `jailbreak_patterns` từ `guardrails.*` config**; theo dõi `mtime` + `last_config_check_time`; khởi tạo `SessionBaseline` (**wire đủ `ttl_seconds`/`eviction_interval` từ `tier1.session_baseline`** — [288-297](../src/tier1_filter/rule_engine.py#L288-L297)) + 11 `RunningStats`; `warmup_count=100`.
- **Dòng:** [273-323](../src/tier1_filter/rule_engine.py#L273-L323)

#### `_check_waf_signatures(log_entry) -> Optional[str]`
- **Mục đích:** WAF regex siêu nhẹ bắt SQLi / XSS / Path Traversal / Command Injection ngay tại Tier-1 (bảo vệ Tier-2 khỏi resource starvation).
- **Luồng:** Duyệt các field `[payload, uri, user_agent, headers, message, command, process]`, match 4 nhóm regex → trả chuỗi lý do `"WAF: …"`, không match → `None`.
- **Dòng:** [325-352](../src/tier1_filter/rule_engine.py#L325-L352)

#### `_check_injection_signatures(log_entry) -> Optional[str]` 🆕
- **Mục đích:** Bắt **Prompt Injection / Jailbreak** ngay tại Tier-1 bằng `injection_patterns` + `jailbreak_patterns` đọc **từ config** — cùng nguồn pattern với Guardrails (G4), hot-reload được.
- **Luồng:** Duyệt cùng danh sách field như WAF; match injection trước, jailbreak sau → trả `"Prompt Injection Pattern: …"` / `"Jailbreak Pattern: …"`.
- **Ý nghĩa:** Đóng lỗ hổng cũ "mẫu adversarial bị DROP âm thầm" — giờ chúng được cộng điểm và **ESCALATE lên Tier-2 Guardrails** xử lý.
- **Dòng:** [353-369](../src/tier1_filter/rule_engine.py#L353-L369)

#### `evaluate(log_entry) -> dict` ⭐ Hàm trung tâm
- **Luồng nhiều tầng (cộng dồn `score`):**
  | Tầng | Việc | Điểm | Dòng |
  |------|------|------|------|
  | Hot-reload | Check mtime mỗi 5s → `reload_dynamic_rules` | — | [377-386](../src/tier1_filter/rule_engine.py#L377-L386) |
  | Chuẩn hóa key | alias → canonical | — | [393-396](../src/tier1_filter/rule_engine.py#L393-L396) |
  | Tầng 0 — Whitelist | IP∈whitelist → `DROP` ngay | — | [398-405](../src/tier1_filter/rule_engine.py#L398-L405) |
  | Tầng 0.1 — WAF | match signature | +50 | [407-411](../src/tier1_filter/rule_engine.py#L407-L411) |
  | Tầng 0.2 — Injection/Jailbreak 🆕 | match pattern từ config | +50 | [413-417](../src/tier1_filter/rule_engine.py#L413-L417) |
  | Tầng 0.5 — Z-score | per-key warmup (`stats.n≥100`); `Z>3.5` → `min(Z×5,40)` | ≤40/feature | [419-461](../src/tier1_filter/rule_engine.py#L419-L461) |
  | Tầng 1 — Static | port nhạy cảm (+40), volumetric `>max_fwd_packets` (+30) | 40/30 | [463-479](../src/tier1_filter/rule_engine.py#L463-L479) |
  | Tầng 2 — Dynamic | rule động khớp pattern | +rule_score | [481-492](../src/tier1_filter/rule_engine.py#L481-L492) |
  | Tầng 3 — Session Baseline | cộng deviation_score | biến thiên | [494-501](../src/tier1_filter/rule_engine.py#L494-L501) |
- **Phân loại action** (nếu `score ≥ risk_threshold`): `has_waf_match`→`BLOCK_IP`; **`has_injection_match`→`ESCALATE` (đẩy lên Guardrails Tier-2)**; port nhạy cảm & `fwd<200`→`BLOCK_IP`; `fwd>max`→`ALERT`; port không-nhạy & không-HTTP→`AWAIT_HITL`; còn lại→`ESCALATE`. Ngược lại → `DROP` (nếu sạch) / `LOG`. **Dòng:** [511-545](../src/tier1_filter/rule_engine.py#L511-L545)
- **🛡️ Chống Baseline Poisoning:** chỉ `push` số liệu vào `RunningStats` khi action ∈ {DROP, LOG} (traffic benign). **Dòng:** [547-552](../src/tier1_filter/rule_engine.py#L547-L552)
- **Dòng tổng:** [371-554](../src/tier1_filter/rule_engine.py#L371-L554)

#### `reload_dynamic_rules()`
- Hot-reload `risk_threshold, sensitive_ports, max_fwd_packets, whitelist_ips, dynamic_rules` (chỉ `ACTIVE`) + **`injection_patterns`/`jailbreak_patterns`** + **tham số `SessionBaseline`** (không xóa cache profiles) từ YAML.
- **Dòng:** [556-586](../src/tier1_filter/rule_engine.py#L556-L586)

---

<a name="t2-feedback_listenerpy"></a>
## T2. `src/tier1_filter/feedback_listener.py`
**Vai trò:** Vòng phản hồi tự tiến hóa — Agent Tier-2 ghi rule mới vào YAML; Tier-1 hot-reload áp dụng. Máy trạng thái 1 chiều: `PENDING_APPROVAL → ACTIVE / REJECTED`. **Mọi rule/whitelist đều qua `FeedbackValidator` (Ngày 2 — G8) trước khi persist (Zero-Trust).**

### `_save_config_atomically(config: dict)`
- **Mục đích:** Ghi YAML **nguyên tử** (tempfile + `os.replace`) chống đọc file dở; `chmod 0o644` để container đọc được (mkstemp mặc định 0600).
- **Dòng:** [41-59](../src/tier1_filter/feedback_listener.py#L41-L59)

### `class FeedbackListener`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__` | Khởi tạo `feedback_log` (audit). | [68-69](../src/tier1_filter/feedback_listener.py#L68-L69) |
| `receive_new_rule(field, pattern, score=50, source, reason)` | Nhận rule từ Agent: **validate qua `FeedbackValidator.validate_rule` (G8)** — fail → từ chối kèm errors; pass → clamp score [1,100], chống trùng `(field,pattern)`, persist `PENDING_APPROVAL`. Trả `{status, rule}`. | [71-156](../src/tier1_filter/feedback_listener.py#L71-L156) |
| `get_feedback_history()` | Lịch sử feedback trong phiên. | [158-160](../src/tier1_filter/feedback_listener.py#L158-L160) |
| `get_active_dynamic_rules()` | Đọc rule `ACTIVE` từ config. | [162-170](../src/tier1_filter/feedback_listener.py#L162-L170) |
| `get_pending_rules()` | Đọc rule `PENDING_APPROVAL` (cho dashboard L3). | [172-180](../src/tier1_filter/feedback_listener.py#L172-L180) |
| `update_rule_status(pattern, new_status, field=None)` | Đổi trạng thái rule khớp, ghi atomically. | [182-205](../src/tier1_filter/feedback_listener.py#L182-L205) |
| `approve_rule / reject_rule` | Wrapper → `ACTIVE`/`REJECTED`. | [207-211](../src/tier1_filter/feedback_listener.py#L207-L211) |
| `clear_all_dynamic_rules()` | Reset toàn bộ rule (khi chạy experiment mới). | [213-224](../src/tier1_filter/feedback_listener.py#L213-L224) |
| `add_to_whitelist / remove_from_whitelist / get_whitelisted_ips` | Quản lý whitelist IP — `add` **validate qua `FeedbackValidator.validate_whitelist_ip` (G8)**: chỉ nhận IP trong subnet tin cậy. | [226-278](../src/tier1_filter/feedback_listener.py#L226-L278) |
| `get_all_dynamic_rules()` | Đọc toàn bộ rule (mọi trạng thái). | [280-288](../src/tier1_filter/feedback_listener.py#L280-L288) |

> ⚠️ **Quyết định thiết kế:** rule `ACTIVE` hiện không có TTL (sống mãi) cho mục đích demo; production cần eviction (LRU/TTL 24h).

---

<a name="t3-scannerpy"></a>
## T3. `src/tier1_filter/scanner.py`
**Vai trò:** DevSecOps SCA — quét lỗ hổng dependencies của chính hệ thống bằng Trivy. **KHÔNG nằm trong luồng traffic**; kết quả nạp vào Neo4j KG.

### `class VulnerabilityScanner`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__(target_dir="/app", output_file="data/trivy-results.json")` | Lưu cấu hình, tạo thư mục output. | [25-28](../src/tier1_filter/scanner.py#L25-L28) |
| `run_scan()` | Kiểm tra Trivy → chạy `trivy fs --format json --scanners vuln` (skip `data/`, `knowledge_base/`). Không có Trivy hoặc lỗi → fallback mock. | [30-60](../src/tier1_filter/scanner.py#L30-L60) |
| `_generate_mock_results()` | Sinh kết quả CVE giả (`CVE-2024-XXXX`) để pipeline không gãy khi thiếu Trivy. | [62-83](../src/tier1_filter/scanner.py#L62-L83) |

---

<a name="t4-demo_tier1py"></a>
## T4. `demo_tier1.py`
**Vai trò:** Script minh họa 7 case chứng minh đủ 6 action + Z-score của `RuleEngine`. Không có hàm, chạy tuần tự.

| Case | Input | Action kỳ vọng | Cơ chế | Dòng |
|------|-------|----------------|--------|------|
| 1 | port 8080, 1 gói | `DROP` | score=0 | [9-15](../demo_tier1.py#L9-L15) |
| 2 | port 22, 5 gói | `BLOCK_IP` | port nhạy cảm + fwd<200 | [17-23](../demo_tier1.py#L17-L23) |
| 3 | port 80, 5000 gói | `ALERT` | volumetric > max | [25-31](../demo_tier1.py#L25-L31) |
| 4 | port 80, 300 gói + dynamic rule | `ESCALATE` | rule động + không brute | [33-49](../demo_tier1.py#L33-L49) |
| 5 | quét 12 port non-HTTP | `AWAIT_HITL` | session baseline port scan | [51-63](../demo_tier1.py#L51-L63) |
| 6 | IP 127.0.0.1 | `DROP` | whitelist | [65-71](../demo_tier1.py#L65-L71) |
| 7 | warmup 110 + outlier Flow Duration | Z-score path | Welford zero-day | [73-114](../demo_tier1.py#L73-L114) |

> ⚠️ Demo dùng default code (threshold 30, sensitive_ports [21,22,23,3389]); giá trị chạy thật lấy từ YAML có thể khác → cần đối chiếu config khi diễn giải kết quả.

---

<a name="pipeline-b"></a>
# PIPELINE B — Bộ nhớ APT dài hạn (DAPT2020)

<a name="b1-dapt2020_configpy"></a>
## B1. `scripts/dapt2020_config.py`
**Vai trò:** Hằng số + hàm chuẩn hóa dùng chung cho B2, B3.

### Hằng số
| Tên | Mô tả |
|-----|-------|
| `APT_PHASES` | day1→Benign, day2→Reconnaissance, day3→Establish Foothold, day4→Lateral Movement, day5→Data Exfiltration. |
| `DAPT_RAW_DIR`, `DAPT_PROCESSED_FILE` | Đường dẫn raw & output. |
| `BENIGN_LABELS` | Tập nhãn lành tính. |
| `DAPT_LABEL_TO_MITRE` | Map 12 nhãn tấn công → MITRE TTP. |
| `DAPT2020_HEADERS` | 85 cột schema raw. |

### `normalize_stage(stage_val) -> str`
- `NaN/None → "Unknown"`; `BENIGN/NORMAL → "Benign"`; còn lại giữ nguyên (strip). **Dòng:** [22-28](../scripts/dapt2020_config.py#L22-L28)

### `normalize_label(label_val) -> str`
- `NaN/None → "Unknown"`; `BENIGN/NORMAL → "Normal"`; còn lại giữ nguyên. **Dòng:** [30-36](../scripts/dapt2020_config.py#L30-L36)

---

<a name="b2-fetch_dapt2020py"></a>
## B2. `scripts/fetch_dapt2020.py`
**Vai trò:** Lấy dữ liệu raw DAPT2020 — ưu tiên Kaggle, fallback sinh synthetic.

### `download_from_kaggle() -> bool`
- **Mục đích:** Tải DAPT2020 thật từ Kaggle.
- **Luồng:** Đảm bảo `kagglehub`/`pandas` (tự pip install) → kiểm tra API key → `day_mapping` (mỗi ngày 2 file public+pvt) → tải day1-public lấy header chuẩn → mỗi file: kiểm tra header (`"Flow ID"`/`"Src IP"`), áp header nếu thiếu, đổi tên `stage→Stage`, `activity/label→label`, chuẩn hóa → gộp public+pvt → lưu `dayN.csv`.
- **Dòng:** [38-149](../scripts/fetch_dapt2020.py#L38-L149)

### `generate_synthetic_dapt2020() -> bool`
- **Mục đích:** Sinh dữ liệu giả theo schema DAPT2020 (khi không tải được).
- **Luồng:** `random.seed(42)`; 20 IP attacker `192.168.x` (lặp qua mọi ngày → persistent), 30 IP target `10.0.x`; `attack_labels_per_day` quy định nhãn theo ngày; mỗi attacker 30-100 event (`stage=Benign` nếu Normal, else phase) + 200 event benign `172.16.x`; khởi tạo `row_dict={col:0}` cho 85 cột rồi điền field chính; ép `df[DAPT2020_HEADERS]` → lưu `dayN.csv`.
- **Dòng:** [152-243](../scripts/fetch_dapt2020.py#L152-L243)

### `verify_dapt2020() -> bool`
- **Mục đích:** Kiểm tra 5 file `day1..5.csv` tồn tại, đọc được, in số dòng + 5 cột đầu.
- **Dòng:** [246-260](../scripts/fetch_dapt2020.py#L246-L260)

### `__main__`
- Nếu `day1.csv` tồn tại → verify & thoát; else thử Kaggle → fallback synthetic → verify (`exit(1)` nếu fail).
- **Dòng:** [263-285](../scripts/fetch_dapt2020.py#L263-L285)

---

<a name="b3-build_dapt_chainspy"></a>
## B3. `scripts/build_dapt_chains.py`
**Vai trò:** Từ 5 file CSV ngày → dựng "chuỗi APT" theo IP kẻ tấn công xuyên nhiều ngày → `dapt2020_chains.jsonl`.
**Trạng thái data hiện tại:** 9 chains / 402 events (324 attack events).

### `safe_int(val) -> int`
- Ép int an toàn (`NaN`/lỗi → 0). **Dòng:** [34-39](../scripts/build_dapt_chains.py#L34-L39)

### `build_chains() -> int`
- **Mục đích:** Hàm chính.
- **Luồng:**
  1. **Đọc từng ngày** (glob fallback): thêm `apt_day`, chuẩn hóa tên cột bằng so khớp mờ (`src_ip, dst_ip, label, Stage, timestamp`), normalize label & apt_phase, giữ 6 cột.
  2. `concat` tất cả; thiếu `src_ip` → sinh IP giả từ index.
  3. **Dựng chuỗi** `chains[ip]=[event…]` (mỗi event: day, phase, label, `mitre_ttp` tra map, src/dst_ip, timestamp).
  4. `parse_dapt_timestamp` (nội hàm): parse `%d/%m/%Y %I:%M:%S %p` → ISO → `datetime.min`. Sắp mỗi chuỗi theo `(day, timestamp)`.
  5. **Lọc APT thật:** ≥2 ngày khác nhau VÀ có ≥1 event tấn công. `assert len ≥ 5`.
  6. **Ghi JSONL** với cap **`MAX_ATTACK_PER_CHAIN=50` + `MAX_BENIGN_PER_CHAIN=10`** ([154-161](../scripts/build_dapt_chains.py#L154-L161)): chuỗi vượt cap → giữ 50 attack + 10 benign đầu; sắp lại theo thời gian, ghi `{attacker_ip, chain_length, days_spanned, phases, events}`.
     ⚠️ **Lưu ý schema:** `chain_length` = độ dài chuỗi **GỐC trước sampling** (có thể hàng chục nghìn); số event thực trong file = `len(events)` (≤60/chain).
  7. In thống kê min/max/avg.
- **Dòng:** [42-186](../scripts/build_dapt_chains.py#L42-L186)

### `__main__`
- Gọi `build_chains()`. **Dòng:** [188-189](../scripts/build_dapt_chains.py#L188-L189)

---

<a name="phụ-lục"></a>
# Phụ lục — Bảng đồng bộ & điểm cần lưu ý

| # | Mức độ | Vấn đề | Vị trí |
|---|--------|--------|--------|
| 1 | 🟢 Đã sửa | Mẫu adversarial từng **bị DROP âm thầm ở Tier-1** → nay **Tầng 0.2 `_check_injection_signatures`** (+50 điểm, action `ESCALATE`) bắt delimiter/injection/jailbreak bằng patterns từ config và đẩy LÊN Tier-2 Guardrails xử lý. | [rule_engine.py:353](../src/tier1_filter/rule_engine.py#L353), [rule_engine.py:528-531](../src/tier1_filter/rule_engine.py#L528-L531) |
| 2 | 🟢 Đã sửa | `session_baseline.ttl_seconds` & `eviction_interval` nay **được wire đầy đủ** vào `SessionBaseline` (cả `__init__` lẫn hot-reload, không xóa cache profiles). | [rule_engine.py:288-297](../src/tier1_filter/rule_engine.py#L288-L297), [rule_engine.py:580-586](../src/tier1_filter/rule_engine.py#L580-L586) |
| 3 | 🟢 Đã sửa | `simulate_traffic.py` nay đọc `REDIS_URL` theo thứ tự **env → YAML config → default** — đồng bộ với publisher/subscriber. | [simulate_traffic.py:40](../scripts/simulate_traffic.py#L40) |
| 4 | 🟢 Thấp | Trộn Streams (ingestion) + List (`queue_hitl`, `queue_decisions` qua `rpush`) — chủ ý, nhưng dashboard phải đọc đúng kiểu. | [subscriber.py:101-127](../src/streaming/subscriber.py#L101-L127) |
| 5 | 🟢 Đã sửa | Backpressure ở publisher nay dùng **ngưỡng 90% MAX_QUEUE_SIZE** → kích hoạt TRƯỚC khi `xadd(maxlen)` tự cắt, có tác dụng thật. | [publisher.py:120-122](../src/streaming/publisher.py#L120-L122) |
| 6 | 🟢 Đã sửa | Tier-1 nay **dùng `guardrails.injection_patterns`/`jailbreak_patterns` từ config** (cùng nguồn với Guardrails G4) + hot-reload — không còn 2 bộ pattern lệch nhau. | [rule_engine.py:572-577](../src/tier1_filter/rule_engine.py#L572-L577) |
| 7 | 🟢 Xác minh | **Liên kết Ngày 1 ↔ Ngày 2 đồng bộ:** `tier1_action/score` gắn vào log → `enforce_tier_consensus` (G6); `map_to_cicids` đủ `REQUIRED_FIELDS` (G3); tên chuẩn `_KEY_ALIASES` ≡ `KEY_ALIASES` (G1) ở 5 trường chung; `FeedbackListener` nhúng `FeedbackValidator` (G8). | nodes.py / simulate_traffic.py / feedback_listener.py |
| 8 | 🟡 Vừa | `chain_length` trong `dapt2020_chains.jsonl` là độ dài chuỗi GỐC (trước cap 50+10) — KHÁC `len(events)`. Code đọc downstream phải dùng `len(events)` khi đếm event thực. | [build_dapt_chains.py:170](../scripts/build_dapt_chains.py#L170) |

### Cải tiến tích cực (nên nêu trước hội đồng)
- ✅ **At-least-once delivery** (consumer group + `xack`) — không mất log khi crash.
- ✅ **Chống Baseline Poisoning** (chỉ học từ DROP/LOG) + **per-key warmup**.
- ✅ **State Exhaustion protection** (`max_profiles` + LRU eviction).
- ✅ **WAF early-block + Injection-Signature early-escalate** bảo vệ LLM Tier-2 khỏi resource starvation mà không nuốt mất mẫu adversarial.
- ✅ **Welford O(1)** + **TTL eviction** chống RAM OOM.
- ✅ **Hot-reload toàn diện**: rules + patterns + tham số baseline, không restart, không mất state.

---

*Tài liệu sinh tự động từ phân tích mã nguồn — đối chiếu lại số dòng nếu mã thay đổi.*
