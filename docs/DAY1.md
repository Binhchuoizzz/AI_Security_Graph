# SENTINEL — Tài liệu tham chiếu hàm (Function Reference)

> **Phạm vi:** Tài liệu này mô tả **chi tiết từng hàm** của 11 file mã nguồn cốt lõi thuộc 2 pipeline dữ liệu + tầng lọc Tier-1 + tiện ích DevSecOps.
> **Cập nhật:** 2026-06-07 (sau đợt nâng cấp Redis Streams + WAF layer + chống Baseline Poisoning).
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
        │ ghi dynamic_rules / whitelist
        ▼
   config/system_settings.yaml ──(hot-reload mtime)──► RuleEngine

PIPELINE B — Batch / APT memory (DAPT2020):
  fetch_dapt2020.py ─► data/raw/dapt2020/dayN.csv ─► build_dapt_chains.py ─► dapt2020_chains.jsonl ─► Tier-2 Threat Memory
  dapt2020_config.py = hằng số + hàm chuẩn hóa dùng chung cho B2, B3

ĐỘC LẬP (DevSecOps):
  scanner.py ─► data/trivy-results.json ─► Neo4j Knowledge Graph  (KHÔNG nằm trong luồng traffic)
```

**Khớp nối tối quan trọng:** `publisher`/`simulate_traffic` ghi `xadd(stream, {"log": <json>})`; `subscriber` đọc `json.loads(data["log"])` → field `"log"` đồng bộ.

---

<a name="pipeline-a"></a>
# PIPELINE A — Streaming thời gian thực (CSE-CIC-IDS2018)

<a name="a1-fetch_and_build_datasetpy"></a>
## A1. `scripts/fetch_and_build_dataset.py`
**Vai trò:** Tải CSE-CIC-IDS2018 từ AWS S3 → làm sạch → stratified sampling → sinh `experiments/ground_truth.json` (tập "đề thi" có gắn đáp án MITRE/action/severity) + 50 mẫu adversarial.

### Hằng số
| Tên | Mô tả |
|-----|-------|
| `LABEL_MAP` | Ánh xạ 14 nhãn tấn công → `{mitre, sub, action, severity}`. Vừa là bộ lọc nhãn vừa là đáp án chấm điểm. |
| `FEATURE_COLS` | 15 cột đặc trưng cần trích từ CSV. |
| `S3_BUCKET`, `LOCAL_RAW_DIR` | Nguồn S3 và thư mục raw cục bộ. |
| `CSV_FILES_2018` | 9 file CSV được phép xử lý (Tuesday-20-02 bị loại vì nhãn không có trong `LABEL_MAP`). |

### `_infer_service(port: int) -> str`
- **Mục đích:** Tra tên dịch vụ từ số port (22→SSH, 80→HTTP, 443→HTTPS…).
- **Trả về:** Tên dịch vụ, hoặc `PORT_<n>` nếu không có trong bảng.
- **Dòng:** [158-174](../scripts/fetch_and_build_dataset.py#L158-L174)

### `safe_int(val: Any) -> int`
- **Mục đích:** Ép kiểu int an toàn, không bao giờ ném exception.
- **Luồng:** `NaN → 0`; ép float, nếu không hữu hạn (`inf`) → `0`; bắt `ValueError/TypeError/OverflowError → 0`.
- **Dòng:** [177-184](../scripts/fetch_and_build_dataset.py#L177-L184)

### `safe_float(val: Any) -> float`
- **Mục đích:** Như `safe_int` nhưng trả `float`. Mọi lỗi/NaN/inf → `0.0`.
- **Dòng:** [187-194](../scripts/fetch_and_build_dataset.py#L187-L194)

### `download_from_aws() -> bool`
- **Mục đích:** Tải 9 file CSV từ S3 bucket công khai.
- **Luồng:** Tạo thư mục → kiểm tra `aws --version` (không có → in hướng dẫn, `False`) → dựng lệnh `aws s3 sync --no-sign-request` (ẩn danh) với `--exclude "*"` + `--include <file>` cho từng CSV → chạy.
- **Trả về:** `True`/`False`.
- **Dòng:** [197-228](../scripts/fetch_and_build_dataset.py#L197-L228)

### `fetch_and_build(n_per_label=50, output_path, min_per_label=20, force_regenerate=False)`
- **Mục đích:** Hàm điều phối chính — đọc CSV → tiền xử lý → sampling → ghi JSON.
- **Luồng:**
  1. Bỏ qua nếu output đã tồn tại và không `force_regenerate`.
  2. `glob` tìm CSV; trống → `download_from_aws()`.
  3. Lọc theo `CSV_FILES_2018`; đọc từng file (`on_bad_lines="skip"`), strip cột, bỏ header lạc (`Label=="Label"`), chỉ giữ nhãn trong `LABEL_MAP`.
  4. **Tiền xử lý** (ghi `stats` từng bước): ép numeric → thay `inf→NaN` → `drop_duplicates` → clip `Flow Duration<0` → clip `Dst Port∈[0,65535]` → window sentinel `-1→0` → `fillna(0)`.
  5. **Stratified Sampling**: mỗi nhãn lấy `min(n_per_label, n_available)` mẫu với `random_state=42`. Sinh IP có seed `sha256(label_idx)` (tách dải benign/attacker), parse timestamp, build sample `{id, logs[], expected_*, input{network_layer, application_layer, cicids_label}}`.
  6. Gọi `_generate_adversarial_samples()` thêm 50 mẫu → ghi JSON → in phân phối → kiểm ngưỡng tối thiểu → `_generate_adversarial_test_set()`.
- **Dòng:** [231-471](../scripts/fetch_and_build_dataset.py#L231-L471)

### `_generate_adversarial_samples(start_id: int) -> list`
- **Mục đích:** Sinh 50 mẫu đối kháng để test Guardrails.
- **Luồng:** 25 mẫu **structural** (Delimiter Smuggling `<<<DATA_END_<hex>>>>`, payload chứa `DROP TABLE`/`exec()`, MITRE T1190) + 25 mẫu **semantic confusion** (text vô hại + user-agent chèn zero-width joiner `‍`). Mỗi mẫu tách `network_layer` (bỏ payload) khỏi `application_layer` (chứa payload).
- **Trả về:** list 50 sample dict.
- **Dòng:** [474-602](../scripts/fetch_and_build_dataset.py#L474-L602)

### `_generate_adversarial_test_set()`
- **Mục đích:** Sinh file riêng `experiments/adversarial_samples.json` (định dạng gọn).
- **Luồng:** 25 structural (`expected_blocked: True`) + 25 semantic (`expected_blocked: False`) + metadata.
- **Dòng:** [605-641](../scripts/fetch_and_build_dataset.py#L605-L641)

### `__main__`
- Argparse `--n-per-label / --min-per-label / --regenerate-ground-truth / --output` → gọi `fetch_and_build`.
- **Dòng:** [644-661](../scripts/fetch_and_build_dataset.py#L644-L661)

---

<a name="a2-simulate_trafficpy"></a>
## A2. `scripts/simulate_traffic.py`
**Vai trò:** Phát lại (replay) `ground_truth.json` lên **Redis Streams** theo batch, phục vụ Ablation Study/demo. (Khác `publisher.py` chỗ: replay đề thi có nhãn, không phải load test CSV thô.)

### `determine_queue(log_entry: dict) -> str`
- **Mục đích:** Định tuyến đa nguồn (mô phỏng SIEM): WAF / Firewall-IDS / Sysmon.
- **Luồng (thứ tự ưu tiên):** port∈{21,22,23,53,139,445,3389} → `queue_firewall`; port∈{80,443,8080} → `queue_waf`; có payload/UA → `queue_waf`; mặc định → `queue_firewall`. **Không bao giờ trả `queue_sysmon`** (giữ chỗ).
- **Dòng:** [38-65](../scripts/simulate_traffic.py#L38-L65)

### `map_to_cicids(network_layer: dict, app_layer: dict) -> dict`
- **Mục đích:** Chuyển schema ground_truth (`src_ip`, `flow_duration_us`…) → schema CICIDS mà `rule_engine` mong đợi (`Source IP`, `Flow Duration`…).
- **Trả về:** dict đã map gồm core fields + flow stats + discriminative features (Z-score) + application layer (payload/user_agent cho Guardrails).
- **Dòng:** [69-104](../scripts/simulate_traffic.py#L69-L104)

### `stream_logs_to_redis() -> None`
- **Mục đích:** Hàm chính — replay theo batch.
- **Luồng:**
  1. Kết nối Redis, load `ground_truth.json`.
  2. Chia batch (`BATCH_SIZE=50`). Backpressure: chờ nếu `xlen(queue) > MAX_QUEUE_SIZE` trên cả 3 stream.
  3. Mỗi sample: lấy từ `input{}` hoặc fallback `logs[]` → `map_to_cicids` → gắn metadata ground truth (`gt_id`, `gt_expected_action`, `gt_expected_severity`, `gt_expected_mitre`, `dataset_source`).
  4. `determine_queue` → **`xadd(stream, {"log": json}, maxlen, approximate=True)`**.
  5. Throttle theo batch (`BATCH_DELAY_SECONDS`).
- **Dòng:** [108-203](../scripts/simulate_traffic.py#L108-L203)

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
  2. Đọc `pd.read_csv(chunksize=500)`. Backpressure: chờ nếu `xlen(QUEUE_NAME) > MAX_QUEUE_SIZE`.
  3. Mỗi dòng: `to_dict` → `_clean_val` → chuẩn hóa key qua `COLUMN_MAPPING` → `_inject_ips` → gắn `dataset_source` → **`xadd(maxlen=MAX_QUEUE_SIZE, approximate=True)`**.
  4. Throttle theo chunk.
- **Dòng:** [88-163](../src/streaming/publisher.py#L88-L163)

---

<a name="a4-subscriberpy"></a>
## A4. `src/streaming/subscriber.py`
**Vai trò:** Consumer + cổng gác Tier-1. Đọc Redis Streams qua **consumer group** (at-least-once), chạy `RuleEngine`, định tuyến theo action.

### Hằng số
- `REDIS_URL`, `QUEUES`, `ESCALATED_QUEUE` (=`queue_hitl`) — đọc từ YAML config.
- **Dòng:** [25-38](../src/streaming/subscriber.py#L25-L38)

### `start_listening(on_batch_ready=None, batch_size=10, timeout_sec=5)`
- **Mục đích:** Vòng lặp tiêu thụ chính.
- **Tham số:** `on_batch_ready` = callback khi đủ batch ESCALATE (nối tới Agent Workflow); `None` → chế độ standalone (in console).
- **Luồng:**
  1. Kết nối Redis → tạo consumer group `sentinel_group` cho từng stream (`xgroup_create` + `mkstream`; bỏ qua `BUSYGROUP`).
  2. Khởi tạo `RuleEngine()`.
  3. Vòng lặp: **`xreadgroup(group, consumer, streams, count=batch_size, block=1000)`**.
  4. Mỗi message: `json.loads(data["log"])` → gắn `log_source` (provenance) → **`engine.evaluate()`** → lấy `tier1_action`.
  5. **Định tuyến:** `ESCALATE`→`batch_buffer`; `AWAIT_HITL`→`rpush(queue_hitl)`; `BLOCK_IP`→`setex(blacklist:<ip>, 3600)` + `rpush(queue_decisions)`; `ALERT/LOG`→`rpush(queue_decisions)`; `DROP`→bỏ.
  6. **`xack(stream, group, msg_id)`** xác nhận đã xử lý.
  7. **Gom batch:** đủ `batch_size` hoặc quá `timeout_sec` → gọi `on_batch_ready`/in console.
  8. **Xử lý lỗi bền bỉ:** `ConnectionError`→retry 5s; `JSONDecodeError`→skip; lỗi khác→log & tiếp tục.
- **Lưu ý:** PEL (Pending Entries List) recovery chưa cài (ghi rõ tại [67-71](../src/streaming/subscriber.py#L67-L71)).
- **Dòng:** [41-160](../src/streaming/subscriber.py#L41-L160)

---

<a name="tier-1"></a>
# TIER-1 — Bộ não quyết định

<a name="t1-rule_enginepy"></a>
## T1. `src/tier1_filter/rule_engine.py`
**Vai trò:** Lõi chấm điểm rủi ro + phân loại 6 action (`DROP / LOG / BLOCK_IP / ALERT / AWAIT_HITL / ESCALATE`). Kết hợp rule tĩnh + WAF + Z-score zero-day + baseline hành vi + rule động.

### `class IPProfile(TypedDict)`
- Cấu trúc hồ sơ mỗi IP: `request_count, unique_ports, total_fwd_packets, first_seen, last_seen`.
- **Dòng:** [25-30](../src/tier1_filter/rule_engine.py#L25-L30)

### `class RunningStats` — thuật toán Welford (O(1) bộ nhớ)
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__` | Khởi tạo `n, old_m, new_m, old_s, new_s = 0`. | [38-43](../src/tier1_filter/rule_engine.py#L38-L43) |
| `push(x)` | Cập nhật trực tuyến μ và tổng bình phương lệch theo công thức Welford. | [45-54](../src/tier1_filter/rule_engine.py#L45-L54) |
| `mean()` | Trả μ (0 nếu chưa có mẫu). | [56-57](../src/tier1_filter/rule_engine.py#L56-L57) |
| `variance()` | Phương sai mẫu `new_s/(n-1)`. | [59-60](../src/tier1_filter/rule_engine.py#L59-L60) |
| `std_dev()` | Độ lệch chuẩn `sqrt(variance)`. | [62-63](../src/tier1_filter/rule_engine.py#L62-L63) |

### Hằng số module
- `CONFIG_PATH`, `_KEY_ALIASES` (JSON↔CSV key), `_RAW_TO_CANONICAL` (gom biến thể tên cột cho Z-score).
- **Dòng:** [66-98](../src/tier1_filter/rule_engine.py#L66-L98)

### `load_config() -> dict`
- Đọc & parse `system_settings.yaml`. **Dòng:** [101-103](../src/tier1_filter/rule_engine.py#L101-L103)

### `class SessionBaseline` — baseline hành vi theo IP
| Hàm | Mục đích & Luồng | Dòng |
|-----|------------------|------|
| `__init__(deviation_threshold=2.0, window_seconds=300, ttl_seconds=600, max_profiles=10000)` | Khởi tạo `profiles` (defaultdict), ngưỡng, **`max_profiles`** chống state exhaustion. | [116-137](../src/tier1_filter/rule_engine.py#L116-L137) |
| `_evict_stale_profiles()` | Xóa IP inactive > `ttl_seconds`, rồi recalibrate global baseline. Chống RAM OOM. | [139-155](../src/tier1_filter/rule_engine.py#L139-L155) |
| `update(source_ip, log_entry) -> dict` | **Hàm chính:** (1) nếu cache đầy → evict stale → vẫn đầy thì xóa 10% IP cũ nhất (LRU); (2) cập nhật hồ sơ; (3) chấm **3 indicator**: Port scan (>10 cổng non-HTTP → `+count×3`), tần suất cao (`>global_avg×2` → `+20`), packet TB cao (`>500` → `+15`). Trả `{deviation_score, deviation_reasons, is_anomalous, …}`. | [157-240](../src/tier1_filter/rule_engine.py#L157-L240) |
| `update_global_baseline()` | Tính lại tốc độ request trung bình toàn cục. | [242-253](../src/tier1_filter/rule_engine.py#L242-L253) |
| `reset_window()` | Xóa toàn bộ profiles (gọi sau mỗi window). | [255-258](../src/tier1_filter/rule_engine.py#L255-L258) |

### `class RuleEngine`

#### `__init__()`
- **Mục đích:** Nạp config + khởi tạo state.
- **Luồng:** Đọc `risk_threshold, sensitive_ports, max_fwd_packets, dynamic_rules` (chỉ `ACTIVE`), `whitelist_ips`; theo dõi `mtime` + `last_config_check_time`; khởi tạo `SessionBaseline` + 11 `RunningStats`; `warmup_count=100`.
- **Dòng:** [272-312](../src/tier1_filter/rule_engine.py#L272-L312)

#### `_check_waf_signatures(log_entry) -> Optional[str]`
- **Mục đích:** WAF regex siêu nhẹ bắt SQLi / XSS / Path Traversal / Command Injection ngay tại Tier-1 (bảo vệ Tier-2 khỏi resource starvation).
- **Luồng:** Duyệt các field `[payload, uri, user_agent, headers, message, command, process]`, match 4 nhóm regex → trả chuỗi lý do `"WAF: …"`, không match → `None`.
- **Dòng:** [314-340](../src/tier1_filter/rule_engine.py#L314-L340)

#### `evaluate(log_entry) -> dict` ⭐ Hàm trung tâm
- **Luồng nhiều tầng (cộng dồn `score`):**
  | Tầng | Việc | Điểm | Dòng |
  |------|------|------|------|
  | Hot-reload | Check mtime mỗi 5s → `reload_dynamic_rules` | — | [347-359](../src/tier1_filter/rule_engine.py#L347-L359) |
  | Chuẩn hóa key | alias → canonical | — | [365-367](../src/tier1_filter/rule_engine.py#L365-L367) |
  | Tầng 0 — Whitelist | IP∈whitelist → `DROP` ngay | — | [369-376](../src/tier1_filter/rule_engine.py#L369-L376) |
  | Tầng 0.1 — WAF | match signature | +50 | [378-382](../src/tier1_filter/rule_engine.py#L378-L382) |
  | Tầng 0.5 — Z-score | per-key warmup (`stats.n≥100`); `Z>3.5` → `min(Z×5,40)` | ≤40/feature | [384-426](../src/tier1_filter/rule_engine.py#L384-L426) |
  | Tầng 1 — Static | port nhạy cảm (+40), volumetric `>max_fwd_packets` (+30) | 40/30 | [428-444](../src/tier1_filter/rule_engine.py#L428-L444) |
  | Tầng 2 — Dynamic | rule động khớp pattern | +rule_score | [446-457](../src/tier1_filter/rule_engine.py#L446-L457) |
  | Tầng 3 — Session Baseline | cộng deviation_score | biến thiên | [459-465](../src/tier1_filter/rule_engine.py#L459-L465) |
- **Phân loại action** (nếu `score ≥ risk_threshold`): `has_waf_match`→`BLOCK_IP`; port nhạy cảm & `fwd<200`→`BLOCK_IP`; `fwd>max`→`ALERT`; port không-nhạy & không-HTTP→`AWAIT_HITL`; còn lại→`ESCALATE`. Ngược lại → `DROP` (nếu sạch) / `LOG`. **Dòng:** [476-506](../src/tier1_filter/rule_engine.py#L476-L506)
- **🛡️ Chống Baseline Poisoning:** chỉ `push` số liệu vào `RunningStats` khi action ∈ {DROP, LOG} (traffic benign). **Dòng:** [508-513](../src/tier1_filter/rule_engine.py#L508-L513)
- **Dòng tổng:** [342-515](../src/tier1_filter/rule_engine.py#L342-L515)

#### `reload_dynamic_rules()`
- Hot-reload `risk_threshold, sensitive_ports, max_fwd_packets, whitelist_ips, dynamic_rules` (chỉ `ACTIVE`) từ YAML.
- **Dòng:** [517-531](../src/tier1_filter/rule_engine.py#L517-L531)

---

<a name="t2-feedback_listenerpy"></a>
## T2. `src/tier1_filter/feedback_listener.py`
**Vai trò:** Vòng phản hồi tự tiến hóa — Agent Tier-2 ghi rule mới vào YAML; Tier-1 hot-reload áp dụng. Máy trạng thái 1 chiều: `PENDING_APPROVAL → ACTIVE / REJECTED`.

### `_save_config_atomically(config: dict)`
- **Mục đích:** Ghi YAML **nguyên tử** (tempfile + `os.replace`) chống đọc file dở.
- **Dòng:** [41-55](../src/tier1_filter/feedback_listener.py#L41-L55)

### `class FeedbackListener`
| Hàm | Mục đích | Dòng |
|-----|----------|------|
| `__init__` | Khởi tạo `feedback_log` (audit). | [64-65](../src/tier1_filter/feedback_listener.py#L64-L65) |
| `receive_new_rule(field, pattern, score=50, source, reason)` | Nhận rule từ Agent: clamp score [1,100], chống trùng `(field,pattern)`, persist `PENDING_APPROVAL`. Trả `{status, rule}`. | [67-138](../src/tier1_filter/feedback_listener.py#L67-L138) |
| `get_feedback_history()` | Lịch sử feedback trong phiên. | [140-142](../src/tier1_filter/feedback_listener.py#L140-L142) |
| `get_active_dynamic_rules()` | Đọc rule `ACTIVE` từ config. | [144-152](../src/tier1_filter/feedback_listener.py#L144-L152) |
| `get_pending_rules()` | Đọc rule `PENDING_APPROVAL` (cho dashboard L3). | [154-162](../src/tier1_filter/feedback_listener.py#L154-L162) |
| `update_rule_status(pattern, new_status, field=None)` | Đổi trạng thái rule khớp, ghi atomically. | [164-187](../src/tier1_filter/feedback_listener.py#L164-L187) |
| `approve_rule / reject_rule` | Wrapper → `ACTIVE`/`REJECTED`. | [189-193](../src/tier1_filter/feedback_listener.py#L189-L193) |
| `clear_all_dynamic_rules()` | Reset toàn bộ rule (khi chạy experiment mới). | [195-206](../src/tier1_filter/feedback_listener.py#L195-L206) |
| `add_to_whitelist / remove_from_whitelist / get_whitelisted_ips` | Quản lý whitelist IP. | [208-254](../src/tier1_filter/feedback_listener.py#L208-L254) |
| `get_all_dynamic_rules()` | Đọc toàn bộ rule (mọi trạng thái). | [256-263](../src/tier1_filter/feedback_listener.py#L256-L263) |

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
| 4 | port 80, 300 gói + dynamic rule | `ESCALATE` | rule động + không brute | [33-50](../demo_tier1.py#L33-L50) |
| 5 | quét 12 port non-HTTP | `AWAIT_HITL` | session baseline port scan | [52-64](../demo_tier1.py#L52-L64) |
| 6 | IP 127.0.0.1 | `DROP` | whitelist | [66-72](../demo_tier1.py#L66-L72) |
| 7 | warmup 110 + outlier Flow Duration | Z-score path | Welford zero-day | [74-105](../demo_tier1.py#L74-L105) |

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
  6. **Ghi JSONL:** với chuỗi >20 event → sample 10 attack + 10 benign; ≤20 → giữ nguyên. Sắp lại theo thời gian, ghi `{attacker_ip, chain_length, days_spanned, phases, events}`.
  7. In thống kê min/max/avg.
- **Dòng:** [42-182](../scripts/build_dapt_chains.py#L42-L182)

### `__main__`
- Gọi `build_chains()`. **Dòng:** [185-186](../scripts/build_dapt_chains.py#L185-L186)

---

<a name="phụ-lục"></a>
# Phụ lục — Bảng đồng bộ & điểm cần lưu ý

| # | Mức độ | Vấn đề | Vị trí |
|---|--------|--------|--------|
| 1 | 🔴 Cao | Mẫu adversarial prompt-injection (port 80, payload `<<<DATA_END_>>>`) **bị DROP ở Tier-1**, không tới Tier-2 Guardrails (do bỏ 80/443 khỏi `sensitive_ports` + WAF regex không bắt delimiter). `expected_action=ALERT` ≠ DROP → sai lệch ablation. | rule_engine `evaluate`, config `sensitive_ports`, `guardrails.injection_patterns` |
| 2 | 🟡 Vừa | `session_baseline.ttl_seconds` & `eviction_interval` trong config **không được wire** vào `SessionBaseline` (dùng default). | [rule_engine.py:290-294](../src/tier1_filter/rule_engine.py#L290-L294) |
| 3 | 🟡 Vừa | `simulate_traffic.py` **không đọc `REDIS_URL` từ config** (chỉ env/default), khác publisher/subscriber. | [simulate_traffic.py:30](../scripts/simulate_traffic.py#L30) |
| 4 | 🟢 Thấp | Trộn Streams (ingestion) + List (`queue_hitl`, `queue_decisions` qua `rpush`) — chủ ý, nhưng dashboard phải đọc đúng kiểu. | [subscriber.py:112-125](../src/streaming/subscriber.py#L112-L125) |
| 5 | 🟢 Thấp | Backpressure ở publisher gần như dead-code vì `xadd(maxlen)` đã tự cắt. | [publisher.py:120](../src/streaming/publisher.py#L120) |
| 6 | 🟢 Thấp | `guardrails.injection_patterns` trong config không được Tier-1 WAF dùng (regex hardcode riêng). | [rule_engine.py:314-340](../src/tier1_filter/rule_engine.py#L314-L340) |

### Cải tiến tích cực (nên nêu trước hội đồng)
- ✅ **At-least-once delivery** (consumer group + `xack`) — không mất log khi crash.
- ✅ **Chống Baseline Poisoning** (chỉ học từ DROP/LOG) + **per-key warmup**.
- ✅ **State Exhaustion protection** (`max_profiles` + LRU eviction).
- ✅ **WAF early-block** bảo vệ LLM Tier-2 khỏi resource starvation.
- ✅ **Welford O(1)** + **TTL eviction** chống RAM OOM.

---

*Tài liệu sinh tự động từ phân tích mã nguồn — đối chiếu lại số dòng nếu mã thay đổi.*
