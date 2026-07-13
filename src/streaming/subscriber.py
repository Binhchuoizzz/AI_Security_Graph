"""
Log Subscriber & Kích hoạt Tier 1 (+ APT emergent)

Kết nối vào Redis Streams qua consumer group 'sentinel_group', dùng `xreadgroup`
để đảm bảo at-least-once delivery. Sau khi xử lý, `xack` xác nhận tin nhắn đã hoàn tất.

Mỗi log đi qua Tier-1 (RuleEngine + Welford) rồi ĐỊNH TUYẾN theo mức độ:
  DROP/LOG (lành tính) · BLOCK_IP (chặn ngay) · AWAIT_HITL (đẩy người) ·
  ESCALATE (đáng ngờ -> Agent/LLM). Đa số log dừng ở Tier-1; chỉ ESCALATE mới gọi Tier-2.

APT EMERGENT (kích hoạt khi message mang metadata DAPT — vd luồng gộp online
`experiments/stream_unified_online.py`): mỗi sự kiện APT lẻ tín hiệu thấp được GHI
dần vào Threat Memory; khi tích lũy đủ đa-ngày, `check_apt_chain` BẬT -> escalate
chuỗi APT lên Agent. Traffic thường không có metadata APT nên đường production không đổi.
"""

import json
import os
import sys
import time
from typing import Any, cast

import redis  # type: ignore
import yaml  # type: ignore
from dotenv import load_dotenv  # type: ignore

load_dotenv()

# Khắc phục lỗi ModuleNotFound khi chạy trực tiếp file trong python
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.agent.threat_memory import ThreatMemoryStore
from src.tier1_filter.rule_engine import RuleEngine

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")
try:
    with open(CONFIG_PATH) as f:
        _config = yaml.safe_load(f)
except Exception:
    _config = {}

# Nhận config theo chuẩn OS Env hoặc YAML fallback
REDIS_URL = os.getenv("REDIS_URL", _config.get("redis", {}).get("url", "redis://localhost:6379/0"))
# Hỗ trợ cấu trúc Multi-source cho Log Correlation (CICIDS2018 + DAPT2020)
QUEUES = _config.get("redis", {}).get("queues", ["queue_firewall", "queue_waf", "queue_sysmon"])
ESCALATED_QUEUE = _config.get("redis", {}).get("escalated_queue", "queue_hitl")

# Các khóa NHÃN DATASET (mang "đáp án" ground-truth / DAPT / zero-day) — phải LOẠI
# khỏi log TRƯỚC khi đưa lên Agent/LLM, nếu không prompt sẽ bị lộ đáp án (label
# leakage) làm mất giá trị demo online. GIỮ `gt_id` (định danh mờ, phục vụ đối
# chiếu hậu kiểm) và các trường tier1_*/apt_emergent/apt_phases (enrichment do
# HỆ THỐNG tự suy ra — tương đương SIEM context thật, không phải đáp án).
_DATASET_LABEL_KEYS = frozenset(
    {
        "gt_cicids_label",
        "gt_expected_action",
        "gt_expected_severity",
        "gt_expected_mitre",
        "gt_label",
        "expected_threat",
        "apt_phase",
        "apt_day",
        "apt_label",
        "apt_timestamp",
        "apt_is_attack",
        "zd_id",
        "zd_name",
        "zd_mitre",
    }
)


def _strip_dataset_labels(log: dict) -> dict:
    """Bản sao log KHÔNG còn nhãn dataset — an toàn để đưa vào prompt LLM."""
    return {k: v for k, v in log.items() if k not in _DATASET_LABEL_KEYS}


def _apply_blacklist_memory(action: str, evaluated_log: dict, is_blacklisted: bool) -> str:
    """TRÍ NHỚ Tier-1 (Redis blacklist, TTL 1h): IP đã bị chặn gần đây (bởi Tier-1 HOẶC
    Tier-2) -> Tier-1 CHẶN NGAY lần tái phạm, KHÔNG leo thang Tier-2 lại. Đây là cơ chế
    "nhớ mặt" trả lời cho 'chạy lần 2 sao Tier-2 lại block tiếp'.

    Whitelist (đã cho qua) và log đang BLOCK_IP được GIỮ NGUYÊN — không đè. Trả về action
    (có thể đã bị ép BLOCK_IP) và ghi lý do vào evaluated_log để hiển thị/đối chiếu.
    """
    if (
        is_blacklisted
        and not evaluated_log.get("is_whitelisted")
        and action not in ("BLOCK_IP", "WHITELIST_DROP")
    ):
        evaluated_log["tier1_action"] = "BLOCK_IP"
        evaluated_log["tier1_reasons"] = (evaluated_log.get("tier1_reasons") or []) + [
            "TRÍ NHỚ Tier-1: IP đã bị chặn gần đây (blacklist TTL 1h) — chặn ngay, "
            "KHÔNG leo thang Tier-2 lại"
        ]
        return "BLOCK_IP"
    return action


def start_listening(on_batch_ready=None, batch_size=10, timeout_sec=5):
    """
    on_batch_ready: Hàm callback được gọi khi đủ batch size hoặc hết timeout.
    """
    print(f"[*] Connecting Subscriber to Redis: {REDIS_URL}")
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        print("[+] Redis connection successful. Waiting for live stream...")
    except Exception as e:
        print(f"[!] Subscriber failed to connect to Redis: {e}")
        return

    # Khởi tạo Consumer Group cho từng Stream
    GROUP_NAME = "sentinel_group"
    CONSUMER_NAME = "sentinel_consumer_1"
    for q in QUEUES:
        try:
            r.xgroup_create(q, GROUP_NAME, id="0", mkstream=True)
            print(f"[+] Consumer group '{GROUP_NAME}' created/verified for stream '{q}'")
        except redis.exceptions.ResponseError as e:  # type: ignore[attr-defined]
            if "BUSYGROUP" in str(e):
                pass
            else:
                print(f"[!] Warning: failed to create consumer group for {q}: {e}")

    # Ghi nhận limitation phục vụ thesis defense
    print(
        "[*] Note: PEL (Pending Entries List) recovery not implemented. "
        "Pending messages from previous crash will be reprocessed manually if needed."
    )

    # Ngưỡng (Threshold) được load từ system_settings.yaml (hiện tại: 15)
    engine = RuleEngine()
    print(f"[*] Tier 1 Firewall Armed (Threshold={engine.risk_threshold}).")
    print(f"[*] Subscribed and listening on multiple streams via group '{GROUP_NAME}': {QUEUES}...")

    # Threat Memory để ghi chuỗi APT EMERGENT từ luồng (chỉ kích hoạt khi message
    # mang metadata DAPT, ví dụ stream_unified_online.py). Traffic thường không có
    # apt_phase nên đường production không bị ảnh hưởng.
    memory = ThreatMemoryStore()
    apt_fired: set[str] = set()  # IP đã bật cảnh báo APT (tránh leo thang lặp)

    # Bộ đệm gom sự cố (Incident-Level Aggregation Buffers)
    batch_buffer = []
    last_batch_time = time.time()

    # Chuẩn bị luồng đọc (dùng dict[Any, Any] để tránh lỗi ép kiểu static analysis của redis-py)
    streams_dict: dict[Any, Any] = {str(q): ">" for q in QUEUES}

    # Counter THẬT cho Dashboard (chống "ước lượng ×35"): ghi ra file chia sẻ qua volume
    # config/ — container Dashboard đọc TIN CẬY (Redis chỉ reach được từ host). Tích lũy
    # qua nhiều lần chạy: nạp lại file cũ khi khởi động.
    _stats_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "pipeline_stats.json"
    )
    try:
        with open(_stats_path) as _sf:
            _s = json.load(_sf)
        raw_logs_total = int(_s.get("raw_logs_total", 0))
        tier1_dropped_total = int(_s.get("tier1_dropped_total", 0))
    except Exception:
        raw_logs_total = tier1_dropped_total = 0

    def _flush_stats():
        try:
            _tmp = _stats_path + ".tmp"
            with open(_tmp, "w") as _f:
                json.dump(
                    {"raw_logs_total": raw_logs_total, "tier1_dropped_total": tier1_dropped_total},
                    _f,
                )
            os.replace(_tmp, _stats_path)
        except Exception:
            pass

    # Ring buffer các block Tier-1 gần nhất (kèm LÝ DO) -> config/tier1_blocks.json.
    # Dashboard container đọc qua volume config/ (KHÔNG reach được Redis — xem chú thích trên),
    # để hiển thị "Tier-1 đã chặn gì" mà không tốn LLM.
    _t1blocks_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "tier1_blocks.json"
    )
    tier1_recent_blocks: list[dict] = []

    def _flush_tier1_blocks():
        try:
            _tmp = _t1blocks_path + ".tmp"
            with open(_tmp, "w") as _f:
                json.dump(tier1_recent_blocks[-50:], _f, ensure_ascii=False)
            os.replace(_tmp, _t1blocks_path)
        except Exception:
            pass

    while True:
        try:
            # XREADGROUP lắng nghe trên nhiều stream cùng lúc.
            # Trả về: [[stream_name, [(msg_id, {field: value}), ...]], ...]
            # Tối ưu hóa throughput bằng cách lấy `count=batch_size` thay vì 1
            response = cast(
                Any,
                r.xreadgroup(GROUP_NAME, CONSUMER_NAME, streams_dict, count=batch_size, block=1000),
            )
            if response:
                for stream_name, messages in response:
                    for msg_id, data in messages:
                        # Cô lập per-message: 1 log hỏng KHÔNG phá cả batch.
                        try:
                            raw_log = json.loads(data["log"])

                            # Gắn nhãn Provenance (Nguồn gốc) để phục vụ SIEM Correlation
                            raw_log["log_source"] = stream_name

                            # Gọi ngay Tier 1 Rule Engine để cân nhắc
                            evaluated_log = engine.evaluate(raw_log)
                            action = evaluated_log.get("tier1_action", "DROP")

                            # ── Số liệu THẬT cho Dashboard: đếm log thô qua Tier-1 + số bị
                            # lọc (DROP) -> Noise Reduction THẬT (ghi ra file cuối mỗi batch).
                            raw_logs_total += 1
                            if action in ("DROP", "WHITELIST_DROP"):
                                tier1_dropped_total += 1

                            # ── APT EMERGENT: ghi chuỗi từ luồng + leo thang khi bản án bật ──
                            # Chỉ chạy với event mang metadata DAPT (apt_phase + apt_is_attack).
                            # Mỗi sự kiện APT lẻ tín hiệu THẤP (thường DROP/LOG ở Tier-1) nên
                            # bản án "is_apt" phải NỔI LÊN DẦN từ Threat Memory đa-ngày, không
                            # phải từ một flow đơn — đúng với cơ chế offline.
                            if raw_log.get("apt_phase") and raw_log.get("apt_is_attack"):
                                apt_ip = raw_log.get("Source IP") or raw_log.get("src_ip", "")
                                if apt_ip:
                                    before = memory.check_apt_chain(apt_ip)
                                    memory.record_apt_event(
                                        src_ip=apt_ip,
                                        dst_ip=raw_log.get("Destination IP", ""),
                                        apt_phase=raw_log.get("apt_phase"),
                                        apt_day=raw_log.get("apt_day"),
                                        label=raw_log.get("apt_label", ""),
                                        timestamp=raw_log.get("apt_timestamp", ""),
                                    )
                                    after = memory.check_apt_chain(apt_ip)
                                    if (
                                        (not before["is_apt"])
                                        and after["is_apt"]
                                        and apt_ip not in apt_fired
                                        # IP whitelist: KHÔNG escalate lên LLM (giữ đặc cách
                                        # cho qua) — vẫn ghi chuỗi APT ở trên để quan sát.
                                        and not evaluated_log.get("is_whitelisted")
                                    ):
                                        apt_fired.add(apt_ip)
                                        evaluated_log["apt_emergent"] = True
                                        evaluated_log["apt_phases"] = after.get("phases_seen", "")
                                        evaluated_log["tier1_reasons"] = (
                                            evaluated_log.get("tier1_reasons") or []
                                        ) + [
                                            f"APT chain emergent: {after.get('chain_length')} ngày "
                                            f"(phases={after.get('phases_seen')})"
                                        ]
                                        print(
                                            f"[APT] EMERGENT chain {apt_ip} @ ngày "
                                            f"{after.get('max_day_seen')} -> ESCALATE lên Agent"
                                        )
                                        action = "ESCALATE"  # đẩy APT qua full pipeline (LLM)

                            # ── TRÍ NHỚ Tier-1 (Redis blacklist, TTL 1h) ────────────────────
                            # Kẻ ĐÃ bị chặn gần đây (Tier-1 HOẶC Tier-2) -> chặn thẳng lần tái
                            # phạm, không leo thang Tier-2 lại. (logic tách ra _apply_blacklist_memory)
                            _mem_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                "src_ip", ""
                            )
                            if _mem_ip and action not in ("BLOCK_IP", "WHITELIST_DROP"):
                                try:
                                    _is_bl = bool(r.exists(f"blacklist:{_mem_ip}"))
                                except Exception:
                                    _is_bl = False
                                action = _apply_blacklist_memory(action, evaluated_log, _is_bl)

                            # ── Phân luồng định tuyến thông minh (Tier 1 Routing) ─────────
                            if action == "ESCALATE":
                                alert_msg = f"[!] ESCALATE TO AI | Source: {stream_name} | Risk: {evaluated_log.get('tier1_score')} | Vi phạm: {evaluated_log.get('tier1_reasons')}"
                                print(alert_msg)
                                # Loại nhãn dataset trước khi lên LLM (chống label leakage);
                                # bản FULL (kèm nhãn) vẫn nằm ở queue_decisions/queue_hitl
                                # để đối chiếu hậu kiểm.
                                batch_buffer.append(_strip_dataset_labels(evaluated_log))

                            elif action == "AWAIT_HITL":
                                # Đẩy sang hàng đợi HITL để Streamlit dashboard hiển thị
                                print(f"[*] routing AWAIT_HITL (Infiltration) -> {ESCALATED_QUEUE}")
                                r.rpush(ESCALATED_QUEUE, json.dumps(evaluated_log))

                            elif action == "BLOCK_IP":
                                # Đẩy IP vào blacklist của Redis với TTL 1 giờ
                                src_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                    "src_ip", ""
                                )
                                if src_ip:
                                    print(f"[*] routing BLOCK_IP -> Blacklist: {src_ip}")
                                    r.setex(f"blacklist:{src_ip}", 3600, "1")
                                    # Lưu block Tier-1 (kèm lý do) cho Dashboard đọc qua file
                                    tier1_recent_blocks.append(
                                        {
                                            "ip": src_ip,
                                            "score": evaluated_log.get("tier1_score", 0),
                                            "reasons": [
                                                str(x)
                                                for x in (evaluated_log.get("tier1_reasons") or [])
                                            ],
                                            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        }
                                    )
                                    if len(tier1_recent_blocks) > 200:
                                        del tier1_recent_blocks[:-100]
                                # Ghi nhận vào log quyết định để phục vụ ablation study
                                r.rpush("queue_decisions", json.dumps(evaluated_log))

                            elif action in ("ALERT", "LOG"):
                                # Chỉ ghi nhận vào ablation log phục vụ thống kê nghiên cứu
                                r.rpush("queue_decisions", json.dumps(evaluated_log))

                            elif action == "WHITELIST_DROP":
                                # IP whitelist: CHO QUA (không chặn) nhưng VẪN được Tier-1 phân
                                # tích đầy đủ — ghi 1 bản audit RIÊNG (action=WHITELIST) mang theo
                                # "kiểu tấn công + suy luận" (tier1_reasons) để analyst QUAN SÁT
                                # bằng thẻ Whitelist. Khác log tấn công ở chỗ: KHÔNG bị chặn/HITL.
                                src_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                    "src_ip", ""
                                )
                                if src_ip:
                                    from src.response.executor import _log_to_db

                                    _wl_reasons = [
                                        str(x) for x in (evaluated_log.get("tier1_reasons") or [])
                                    ]
                                    _wl_summary = (
                                        " · ".join(_wl_reasons[:2])
                                        if _wl_reasons
                                        else "không có dấu hiệu tấn công"
                                    )
                                    _wl_score = evaluated_log.get("tier1_score", 0)
                                    _log_to_db(
                                        "WHITELIST",
                                        src_ip,
                                        f"IP whitelist — CHO QUA, KHÔNG chặn (điểm Tier-1 "
                                        f"{_wl_score}). Phân tích để giám sát: {_wl_summary}",
                                        raw_log=json.dumps(_strip_dataset_labels(evaluated_log)),
                                    )

                        except json.JSONDecodeError:
                            print(f"[!] Malformed JSON in message {msg_id}. Bỏ qua (đã xack).")
                        except Exception as e:
                            print(f"[!] Lỗi xử lý message {msg_id}: {e}. Bỏ qua (đã xack).")
                        finally:
                            # LUÔN xack (kể cả message lỗi) -> poison message không kẹt
                            # vĩnh viễn trong Pending Entries List của consumer group.
                            try:
                                r.xack(stream_name, GROUP_NAME, msg_id)
                            except Exception:
                                pass

                # Ghi counter THẬT ra file (Dashboard container đọc qua volume config/)
                _flush_stats()
                _flush_tier1_blocks()

            # Kiểm tra xem có cần trigger batch không
            current_time = time.time()
            if batch_buffer and (
                len(batch_buffer) >= batch_size or (current_time - last_batch_time) > timeout_sec
            ):
                if on_batch_ready:
                    print(f"[*] Triggering Agent Workflow for batch of {len(batch_buffer)} logs...")
                    on_batch_ready(batch_buffer)
                else:
                    # Chế độ độc lập (standalone mode) — ghi log ra màn hình (console)
                    for log in batch_buffer:
                        print(
                            f"[ESCALATE] gt_id={log.get('gt_id')} "
                            f"ip={log.get('Source IP')} score={log.get('tier1_score')}"
                        )
                batch_buffer = []
                last_batch_time = current_time
            elif not batch_buffer:
                last_batch_time = current_time  # Đặt lại timer khi nhàn rỗi (tránh timing bug)

        except KeyboardInterrupt:
            print("\n[*] Subscriber offline (Shutdown).")
            break
        except redis.ConnectionError as e:
            print(f"[!] Redis connection lost: {e}. Retrying in 5s...")
            time.sleep(5)
        except json.JSONDecodeError:
            print("[!] Malformed JSON Log received via Redis. Skipping.")
        except Exception as e:
            print(f"[!] Unexpected error in stream processing: {e}")


if __name__ == "__main__":
    start_listening()
