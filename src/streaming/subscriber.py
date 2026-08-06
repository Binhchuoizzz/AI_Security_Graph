"""
Log Subscriber & Kích hoạt Tier 1 (+ APT emergent)

Kết nối vào Redis Streams qua consumer group 'sentinel_group', dùng `xreadgroup`
để đảm bảo at-least-once delivery. Sau khi xử lý, `xack` xác nhận tin nhắn đã hoàn tất.

Mỗi log đi qua Tier-1 (RuleEngine + Welford) rồi ĐỊNH TUYẾN theo mức độ:
  DROP/LOG (lành tính) · BLOCK_IP (chặn ngay) · AWAIT_HITL (đẩy người) ·
  ESCALATE (đáng ngờ -> Agent/LLM). Đa số log dừng ở Tier-1; chỉ ESCALATE mới gọi Tier-2.

APT EMERGENT (kích hoạt khi message mang metadata DAPT — vd luồng gộp online
`experiments/unified_dataset.py` → scripts/demo.py): mỗi sự kiện APT lẻ tín hiệu thấp được GHI
dần vào Threat Memory; khi tích lũy đủ đa-ngày, `check_apt_chain` BẬT -> escalate
chuỗi APT lên Agent. Traffic thường không có metadata APT nên đường production không đổi.
"""

import json
import os
import queue
import re
import sys
import threading
import time
from typing import Any, cast

import redis  # type: ignore
import yaml  # type: ignore
from dotenv import load_dotenv  # type: ignore

load_dotenv()

# Khắc phục lỗi ModuleNotFound khi chạy trực tiếp file trong python
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.agent.threat_memory import ThreatMemoryStore
from src.guardrails.constants import TIER_ML, TIER_RULE
from src.guardrails.state_monitor import audit_logger
from src.response.executor import block_ip, raise_alert
from src.tier1_filter.feedback_listener import FeedbackListener
from src.tier1_filter.ml_gateway import MLGateway
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

# Các khóa NHÃN DATASET (mang "đáp án" ground-truth / DAPT / zero-day / gray-zone /
# adversarial) — phải LOẠI khỏi log TRƯỚC khi đưa lên Agent/LLM, nếu không prompt sẽ bị
# lộ đáp án (label leakage) làm mất giá trị demo online.
#
# LỌC THEO TIỀN TỐ, KHÔNG theo danh sách đen thủ công. Bản trước liệt kê tay từng khoá và
# đã sót đúng những nguồn thêm sau: `gz_mitre` (đáp án MITRE nguyên văn), `adv_id`/
# `adv_source`, và `unified_source` (tự khai 'zeroday'/'adversarial'/'grayzone'). Mỗi lần
# thêm một nguồn dữ liệu là một lần danh sách đen lặng lẽ hở. Quy tắc tiền tố đóng lỗ đó:
# mọi khoá do BỘ DỰNG DỮ LIỆU gắn đều mang tiền tố nguồn, nên mặc định bị loại; thứ nào
# cần giữ phải được ghi TƯỜNG MINH vào _LABEL_KEY_ALLOW.
_LABEL_KEY_PREFIXES = ("gt_", "zd_", "adv_", "gz_", "apt_", "wa_")

# Ngoại lệ CÓ CHỦ ĐÍCH — không phải đáp án:
#   gt_id            : định danh mờ (GT-001), phục vụ đối chiếu hậu kiểm, không nói nhãn.
#   apt_emergent /   : do HỆ THỐNG tự suy ra từ Threat Memory (tương đương SIEM context
#   apt_phases         thật), KHÔNG đọc từ dataset -> giữ lại mới đúng ngữ nghĩa vận hành.
_LABEL_KEY_ALLOW = frozenset({"gt_id", "apt_emergent", "apt_phases"})

# Khoá nhãn KHÔNG mang tiền tố nguồn -> phải liệt kê tay.
_DATASET_LABEL_KEYS = frozenset(
    {
        "expected_threat",
        "unified_source",  # tự khai nguồn ('zeroday'/'adversarial'/'grayzone') = lộ đáp án
        "dataset_source",
        "label",
        "Label",
        # Cờ lát DÀN DỰNG của luồng demo. Nó KHÔNG nói kỹ thuật nào, nhưng lát dàn dựng
        # được chọn ĐÚNG bằng tiêu chí "có mã kỹ thuật", nên cờ này tương quan HOÀN HẢO với
        # việc mẫu đó có đáp án hay không — thừa sức làm mồi cho LLM. Tước như mọi nhãn khác.
        "demo_staged",
    }
)


def _is_dataset_label_key(key: str) -> bool:
    if key in _LABEL_KEY_ALLOW:
        return False
    return key in _DATASET_LABEL_KEYS or key.startswith(_LABEL_KEY_PREFIXES)


def _strip_dataset_labels(log: dict) -> dict:
    """Bản sao log KHÔNG còn nhãn dataset — an toàn để đưa vào prompt LLM."""
    return {k: v for k, v in log.items() if not _is_dataset_label_key(k)}


def _redact_redis_url(url: str) -> str:
    """Ẩn mật khẩu trong REDIS_URL trước khi in/log (redis://:pass@host -> redis://:***@host).

    Mật khẩu Redis CHỈ được sống trong .env — không bao giờ để rò ra stdout/journald.
    """
    return re.sub(r"(://[^:/@]*:)[^@/]*@", r"\1***@", url)


# ── PHÂN BỔ GIẢM TẢI: cơ chế NÀO đã chặn sự kiện này? ────────────────────────
# VÌ SAO CẦN. Trước đây chỉ có `tier1_dropped_total` — biết "bao nhiêu bị chặn" nhưng KHÔNG
# biết "chặn bởi cái gì". Sự kiện dừng ở Tier-1 không sinh dòng `tier2_trace.jsonl` nào, nên
# hậu kiểm mù hoàn toàn. Hệ quả thực tế: không trả lời được câu "đẩy lần 2 có nhẹ hơn lần 1
# không, nhờ cơ chế nào" — đúng câu hỏi mà cả kiến trúc 'nhớ mặt' sinh ra để trả lời.
#
# Gom về MỘT bảng dấu hiệu duy nhất thay vì rải chuỗi khắp nơi (bài học ML_GATE_MARKERS:
# chuỗi trùng lặp ở nhiều tệp thì sửa một chỗ là lệch chỗ còn lại).
#
# THỨ TỰ CÓ Ý NGHĨA: một sự kiện thường mang NHIỀU lý do; ta quy cho cơ chế đã THỰC SỰ quyết
# định. Hai cơ chế TRÍ NHỚ đứng đầu vì chúng ghi đè action và chính là thứ chỉ xuất hiện từ
# lần đẩy thứ hai trở đi — tức phần giảm tải cần đo.
OFFLOAD_MARKERS: tuple[tuple[str, str], ...] = (
    ("t1_blacklist_memory", "TRÍ NHỚ Tier-1: IP đã bị chặn gần đây"),
    ("t1_reputation_block", "IP có tiền sử NGUY HIỂM (điểm danh tiếng"),
    ("t1_reputation_escalate", "IP có tiền sử đáng ngờ (điểm danh tiếng"),
    ("t1_waf_signature", "WAF: Phát hiện "),
    ("t1_injection_signature", "Prompt Injection Pattern: "),
    ("t1_injection_signature", "Jailbreak Pattern: "),
    ("t1_dynamic_rule", "Luật động [từ Tác tử]: "),
    ("t1_apt_chain", "APT chain emergent: "),
    ("t1_zscore", "Phát hiện dị biệt thống kê Zero-day ["),
)


def classify_offload_mechanisms(evaluated_log: dict) -> list[str]:
    """TẤT CẢ cơ chế Tier-1 đã khai hoả trên sự kiện này (`['t1_other']` nếu không cơ chế nào).

    LỖI ĐO LƯỜNG ĐÃ VÁ. Bản trước trả về DUY NHẤT khớp đầu tiên theo thứ tự khai báo. Một sự
    kiện thường khớp nhiều cơ chế cùng lúc, và `t1_reputation_block` đứng gần đầu bảng — nên
    ở lượt chạy WARM, khi hầu hết IP đã có tiền sử, nhãn "danh tiếng" CHE hết nhãn cụ thể.
    Đo được giữa hai lượt đẩy cùng một tệp 5.000 sự kiện: chữ ký WAF báo 337 -> 0 và trí nhớ
    blacklist 106 -> 0, trông như hai cơ chế đó ngừng hoạt động. Thực tế chúng vẫn chạy; chỉ
    là mất nhãn. Bảng "cơ chế chặn" vì thế KHÔNG so được giữa lượt nguội và lượt warm — đúng
    cái bảng dùng để trả lời câu hỏi trung tâm của RQ1.

    Đa nhãn thì tổng các cơ chế LỚN HƠN số sự kiện; đó là đúng và phải đọc như vậy. Muốn quy
    về một nhãn duy nhất cho mỗi sự kiện thì dùng `primary_offload_mechanism`.
    """
    reasons = evaluated_log.get("tier1_reasons") or []
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    blob = " ǁ ".join(str(r) for r in reasons)
    hits: list[str] = []
    for key, marker in OFFLOAD_MARKERS:
        if marker in blob and key not in hits:
            hits.append(key)
    return hits or ["t1_other"]


def primary_offload_mechanism(evaluated_log: dict) -> str:
    """Một nhãn duy nhất cho mỗi sự kiện — giữ tương thích với chỗ cần tổng = số sự kiện."""
    return classify_offload_mechanisms(evaluated_log)[0]


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


def start_listening(on_batch_ready=None, batch_size=10, timeout_sec=5, agent_workers=1):
    """
    on_batch_ready: Hàm callback được gọi khi đủ batch size hoặc hết timeout.
    agent_workers: số worker nền xử lý Tier-2 (LLM). >=1 => DECOUPLE khỏi vòng đọc Redis
        (vòng đọc + Tier-1 + thống kê KHÔNG bị chặn bởi LLM chậm -> Dashboard cập nhật tức
        thì). >=2 => chạy nhiều lô SONG SONG, tận dụng các slot llama.cpp (-np). =0 => gọi
        đồng bộ trong vòng đọc (hành vi CŨ, giữ để tương thích/kiểm thử).
    """
    print(f"[*] Connecting Subscriber to Redis: {_redact_redis_url(REDIS_URL)}")
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
    ml_gateway = MLGateway()
    print(f"[*] Tier 1 Firewall Armed (Threshold={engine.risk_threshold}).")
    print(f"[*] Subscribed and listening on multiple streams via group '{GROUP_NAME}': {QUEUES}...")

    # Threat Memory để ghi chuỗi APT EMERGENT từ luồng (chỉ kích hoạt khi message
    # mang metadata DAPT, ví dụ luồng gộp từ scripts/demo.py). Traffic thường không có
    # apt_phase nên đường production không bị ảnh hưởng.
    memory = ThreatMemoryStore()
    apt_fired: set[str] = set()  # IP đã bật cảnh báo APT (tránh leo thang lặp)

    # Bộ đệm gom sự cố (Incident-Level Aggregation Buffers - Entity-based)
    import collections

    ip_buffers = collections.defaultdict(list)
    ip_last_updated = {}

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
        offload_counts = dict(_s.get("offload_counts") or {})
    except Exception:
        raw_logs_total = tier1_dropped_total = 0
        offload_counts = {}
    # LUỸ KẾ, cùng giao ước với raw_logs_total. Số của TỪNG lần đẩy lấy bằng cách chụp
    # pipeline_stats.json trước/sau rồi trừ — không cần cơ chế reset riêng, và không mất
    # dữ liệu nếu subscriber khởi động lại giữa chừng. Dùng dict (không rebind) để closure
    # _flush_stats thấy được cập nhật mà không cần `nonlocal`.

    def _flush_stats():
        try:
            _tmp = _stats_path + ".tmp"
            with open(_tmp, "w") as _f:
                json.dump(
                    {
                        "raw_logs_total": raw_logs_total,
                        "tier1_dropped_total": tier1_dropped_total,
                        "offload_counts": offload_counts,
                        "pending_llm_queue": agent_q.qsize() if agent_q is not None else 0,
                    },
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

    def _tier1_block_record(ip: str, log: dict) -> dict:
        """Hình dạng DUY NHẤT của một bản ghi trong `tier1_blocks.json`.

        BẮT BUỘC đi qua hàm này ở MỌI chỗ append. Trước đây nhánh Cổng ML append thẳng
        `evaluated_log` (khoá `"Source IP"`, `"tier1_score"`…) còn nhánh rule engine append
        dict `{ip, score, reasons, ts}`. Bên đọc `_get_tier1_blocks()` lọc bằng `b.get("ip")`
        ở CẢ HAI vòng (đếm và khử trùng) rồi `continue` khi thiếu — nên **mọi IP do Cổng ML
        chặn đều bị bỏ lặng lẽ, không bao giờ hiện trên Dashboard**. Một tầng phòng thủ vô
        hình, đúng tầng mà RQ1 cần trưng ra.
        """
        return {
            "ip": ip,
            "score": log.get("tier1_score", 0),
            "reasons": [str(x) for x in (log.get("tier1_reasons") or [])],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            # LOG THÔ ĐẦY ĐỦ để analyst audit tận gốc "cái gì đã bị chặn". Sidecar chỉ có
            # ip/score/reasons thì nhìn bảng Tier-1 KHÔNG thể truy ra bản ghi nào gây ra
            # lệnh chặn. Vẫn _strip_dataset_labels để không lộ nhãn đáp án của bộ dữ liệu.
            "raw_log": _strip_dataset_labels(log),
        }

    # ── SUY HAO DANH TIẾNG (decay) ─────────────────────────────────────────────────
    # threat_memory.decay_reputation() ĐÃ tồn tại và có unit test, nhưng TRƯỚC ĐÂY KHÔNG
    # NƠI NÀO trong code sản phẩm gọi nó — nên điểm xấu của một IP là VĨNH VIỄN trên thực
    # tế, trái với tài liệu ("decay S·(1−λ)ᵗ → không chặn vĩnh viễn") và trái với câu trả
    # lời Q12 đã soạn cho buổi bảo vệ. Nối vào đây để lời tuyên bố thành SỰ THẬT.
    # Chỉ chạm IP im lặng >= 7 ngày nên KHÔNG ảnh hưởng số liệu của một lượt demo/benchmark.
    # NHỊP THEO NGÀY, không theo giờ: điều kiện lọc là "im lặng >= 7 NGÀY" và hệ số 0.95
    # rõ ràng được thiết kế cho nhịp ngày. Gọi mỗi giờ thì điểm phai NHANH GẤP 24 LẦN ý đồ
    # (100 -> dưới ngưỡng chặn 70 chỉ sau ~7 giờ thay vì ~7 ngày) — tức tự nới lỏng phòng thủ.
    _decay_interval_s = 86_400.0
    _last_decay_at = [time.time()]

    def _maybe_decay_reputation():
        if time.time() - _last_decay_at[0] < _decay_interval_s:
            return
        _last_decay_at[0] = time.time()
        try:
            from src.agent.threat_memory import threat_memory

            threat_memory.decay_reputation()
        except Exception as _e:
            print(f"[!] decay_reputation lỗi: {_e}")

    # ── Bộ worker Tier-2 (DECOUPLE LLM khỏi vòng đọc Redis) ─────────────────────────
    # on_batch_ready (agent) là phần CHẬM. Gọi ĐỒNG BỘ trong vòng đọc sẽ chặn việc nạp
    # Redis + cập nhật thống kê -> Dashboard "đơ". Thay vào đó đẩy lô escalate vào hàng
    # đợi cho N worker nền xử lý song song (tận dụng slot llama.cpp -np; các khóa ở
    # audit/reputation/cache + loop_detector thread-local bảo đảm an toàn đa luồng).
    #
    # HÀNG ĐỢI KHÔNG GIỚI HẠN (maxsize=0) — quyết định CÓ CHỦ ĐÍCH (2026-07-16):
    # bản bounded(64) cũ khiến put() CHẶN vòng đọc khi Tier-2 tụt hậu (đo thật: qsize
    # kẹt 64/64 suốt lượt chạy 4.796 sự kiện). Đổi sang không giới hạn vì:
    #   1) Vòng đọc Tier-1 không bao giờ được phép đứng (Dashboard/stats phải sống);
    #   2) Redis stream (maxlen 10k/queue) mới là buffer bền thật sự phía trước;
    #   3) Cổng ML của Tier-1 hấp thụ phần lớn lô nên backlog thực tế nhỏ.
    # RỦI RO CHẤP NHẬN: backlog nằm trong RAM tiến trình — quy mô demo (nghìn lô nhỏ)
    # là an toàn; hướng sản xuất (Kafka persistent) đã ghi ở thesis ch5. Có cảnh báo
    # HIGH-WATER bên dưới để backlog phình là thấy ngay trong log.
    agent_q: queue.Queue | None = None
    agent_pool: list[threading.Thread] = []
    agent_stop = threading.Event()
    # Ngưỡng cảnh báo backlog kế tiếp (512 rồi gấp đôi dần: 1024, 2048, ...)
    agent_q_highwater = 512
    if on_batch_ready and agent_workers >= 1:
        agent_q = queue.Queue(maxsize=0)

        def _agent_worker(q: queue.Queue):
            while not agent_stop.is_set():
                try:
                    batch = q.get(timeout=1.0)
                except queue.Empty:
                    continue
                if batch is None:  # sentinel dừng sạch
                    q.task_done()
                    break
                try:
                    on_batch_ready(batch)
                    # Đếm TẠI CHỖ số sự kiện THỰC SỰ được Tier-2 phân tích xong. Trước đây
                    # Dashboard suy con số này bằng `escalated_to_llm − pending_llm_queue`,
                    # mà hai vế KHÁC ĐƠN VỊ: vế trái đếm SỰ KIỆN, vế phải đếm LÔ trong hàng
                    # đợi. Phép trừ ấy cho 841 trong khi Tier-2 mới xong 89 — sai 9 lần.
                    offload_counts["tier2_analysed"] = offload_counts.get(
                        "tier2_analysed", 0
                    ) + len(batch)
                    offload_counts["tier2_batches"] = offload_counts.get("tier2_batches", 0) + 1
                except Exception as e:  # 1 lô lỗi KHÔNG được giết worker
                    print(f"[!] Agent worker lỗi xử lý lô: {e}")
                    offload_counts["tier2_failed"] = offload_counts.get("tier2_failed", 0) + len(
                        batch
                    )
                finally:
                    q.task_done()

        for _i in range(agent_workers):
            _t = threading.Thread(
                target=_agent_worker, args=(agent_q,), name=f"agent-worker-{_i}", daemon=True
            )
            _t.start()
            agent_pool.append(_t)
        print(f"[*] Tier-2 agent pool: {agent_workers} worker song song (decoupled khỏi vòng đọc).")

    def _warn_backlog():
        """High-water cho hàng đợi KHÔNG giới hạn: backlog vượt ngưỡng (512, 1024, ...)
        thì la to trong log — phình RAM phải THẤY được, không được phình im lặng."""
        nonlocal agent_q_highwater
        if agent_q is not None and agent_q.qsize() >= agent_q_highwater:
            print(
                f"[!] HIGH-WATER: hàng đợi Tier-2 đang gánh {agent_q.qsize()} lô trong RAM "
                f"(vượt ngưỡng {agent_q_highwater}). Tier-2 tụt hậu xa — cân nhắc tăng "
                f"agent_workers / slot llama.cpp (-np), hoặc hạ tốc độ đẩy luồng."
            )
            agent_q_highwater *= 2

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

                            # ── PHÂN BỔ GIẢM TẢI ────────────────────────────────────────
                            # Đếm ở ĐÂY vì đây là điểm `action` của Tier-1 đã CHỐT (sau cả
                            # APT lẫn trí nhớ blacklist) nhưng CHƯA rẽ sang Cổng ML/LLM —
                            # tức đúng ranh giới "Tier-1 tự xử" và "phải nhờ tầng trên".
                            offload_counts[f"action:{action}"] = (
                                offload_counts.get(f"action:{action}", 0) + 1
                            )
                            if action != "ESCALATE":
                                # ĐA NHÃN: đếm MỌI cơ chế đã khai hoả, không chỉ cơ chế đầu
                                # bảng — nếu không, ở lượt warm nhãn "danh tiếng" che sạch
                                # nhãn chữ ký/blacklist và bảng cơ chế mất khả năng so sánh
                                # giữa các lượt (xem `classify_offload_mechanisms`).
                                for _mech in classify_offload_mechanisms(evaluated_log):
                                    offload_counts[_mech] = offload_counts.get(_mech, 0) + 1
                                # Nhãn CHÍNH (tổng = số sự kiện) để đọc phân bổ theo tỉ lệ.
                                _pri = f"primary:{primary_offload_mechanism(evaluated_log)}"
                                offload_counts[_pri] = offload_counts.get(_pri, 0) + 1

                            # ── Phân luồng định tuyến thông minh (Tier 1 Routing) ─────────
                            if action == "ESCALATE":
                                _src_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                    "src_ip", "UNKNOWN"
                                )

                                # ── TIER-1 ML GATEWAY (CỔNG ML) ──
                                ml_action, ml_reasoning, ml_conf = ml_gateway.evaluate(raw_log)
                                # Ranh giới cuối trước LLM: Cổng ML tự quyết (ml_action có
                                # giá trị) hay phải nhờ Tier-2. Đây là mẫu số của "tỉ lệ gỡ
                                # tải khỏi LLM" nên phải đếm tại chỗ, không suy ngược từ log.
                                _mlk = "ml_gate_resolved" if ml_action else "escalated_to_llm"
                                offload_counts[_mlk] = offload_counts.get(_mlk, 0) + 1
                                if ml_action:
                                    # ML tự tin ra quyết định -> Chặn/Báo ngay mà KHÔNG cần LLM
                                    if ml_action == "BLOCK_IP":
                                        block_ip(
                                            _src_ip,
                                            ml_reasoning or "",
                                            raw_log=json.dumps(evaluated_log),
                                            tier=TIER_ML,
                                        )
                                        tier1_dropped_total += 1
                                        FeedbackListener().receive_new_rule(
                                            "Source IP",
                                            _src_ip,
                                            score=100,
                                            reason=ml_reasoning or "",
                                            source="ml_triage",
                                            status="ACTIVE",
                                        )
                                    elif ml_action == "ALERT":
                                        # raise_alert tự leo thang -> BLOCK nếu IP đã ALERT trước
                                        # đó (repeat-offender). Lấy action THẬT để hiển thị/đếm.
                                        ml_action = (
                                            raise_alert(
                                                _src_ip,
                                                ml_reasoning or "",
                                                raw_log=json.dumps(evaluated_log),
                                                # ALERT của Cổng ML nằm dải YẾU (0.40–0.65):
                                                # truyền độ tin cậy để KHÔNG bị tính vào bộ
                                                # đếm tái phạm rồi tự leo thang thành chặn.
                                                confidence=ml_conf,
                                                tier=TIER_ML,
                                            )
                                            or "ALERT"
                                        )
                                        if ml_action == "BLOCK_IP":
                                            tier1_dropped_total += 1
                                    elif ml_action == "DROP":
                                        # Log sạch do Cổng ML xác nhận -> noise reduction THẬT.
                                        tier1_dropped_total += 1

                                    # Cổng ML "giải quyết" theo BA cách, chỉ HAI trong đó ghi ra
                                    # sổ kiểm toán: BLOCK_IP và ALERT. Nhánh DROP (log sạch) im
                                    # lặng hoàn toàn — đó là lý do `ml_gate_resolved` = 1.881 mà
                                    # nhật ký chỉ có 210 dòng. Tách bộ đếm theo hành động để
                                    # Dashboard nói được "1.671 ca cho qua" thay vì để hụt.
                                    offload_counts[f"ml_gate:{ml_action}"] = (
                                        offload_counts.get(f"ml_gate:{ml_action}", 0) + 1
                                    )

                                    audit_event = {
                                        "event_type": "ML_TRIAGE_DECISION",
                                        "source_ip": _src_ip,
                                        "tier1_score": evaluated_log.get("tier1_score", 0.0),
                                        "tier1_action": "ESCALATE",
                                        "agent_decision": ml_action,
                                        "agent_reasoning": ml_reasoning,
                                        "mitre_technique": "UNKNOWN",
                                        "latency_ms": 1,
                                    }
                                    audit_logger.log_event(audit_event)

                                    evaluated_log["tier1_action"] = ml_action
                                    evaluated_log["tier1_reasons"] = (
                                        evaluated_log.get("tier1_reasons") or []
                                    ) + [ml_reasoning]
                                    # CHỈ BLOCK_IP. Bản cũ nhận cả `WHITELIST_DROP` — mà
                                    # whitelist drop là CHO QUA, không phải lệnh chặn; để lẫn
                                    # thì bảng "đã chặn" đếm luôn cả lưu lượng được đặc cách.
                                    if ml_action == "BLOCK_IP" and _src_ip:
                                        tier1_recent_blocks.append(
                                            _tier1_block_record(_src_ip, evaluated_log)
                                        )
                                        if len(tier1_recent_blocks) > 200:
                                            del tier1_recent_blocks[:-100]

                                    try:
                                        import mlflow

                                        if mlflow.active_run():
                                            mlflow.log_metric("ML_Triage_Bypass", 1)
                                            mlflow.log_metric("ML_Triage_Confidence", ml_conf)
                                    except Exception:
                                        pass

                                    r.rpush("queue_decisions", json.dumps(evaluated_log))
                                    continue  # Bỏ qua vòng đẩy lên queue LLM

                                # CƠ CHẾ SUPPRESSION (ỨC CHẾ SPAM LLM)
                                _suppressed = False
                                if _src_ip != "UNKNOWN":
                                    try:
                                        _is_pending = bool(r.exists(f"pending_ai:{_src_ip}"))
                                    except Exception:
                                        _is_pending = False
                                    if _is_pending:
                                        _suppressed = True
                                        # Sự kiện ĐÃ được tính vào `escalated_to_llm` nhưng sẽ
                                        # KHÔNG bao giờ tới Tier-2 (IP này đang có lô chạy dở,
                                        # TTL 60s). Không đếm riêng thì phễu không khép được và
                                        # người đọc thấy "tới LLM" lớn hơn hẳn nhật ký Tier-2.
                                        offload_counts["tier2_suppressed"] = (
                                            offload_counts.get("tier2_suppressed", 0) + 1
                                        )

                                if _suppressed:
                                    # Ghi nhận thầm lặng, không đẩy lên queue LLM để tránh spam
                                    r.rpush("queue_decisions", json.dumps(evaluated_log))
                                else:
                                    alert_msg = f"[!] ESCALATE TO AI | Source: {stream_name} | Risk: {evaluated_log.get('tier1_score')} | Vi phạm: {evaluated_log.get('tier1_reasons')}"
                                    print(alert_msg)
                                    # Loại nhãn dataset trước khi lên LLM (chống label leakage);
                                    # bản FULL (kèm nhãn) vẫn nằm ở queue_decisions/queue_hitl
                                    # để đối chiếu hậu kiểm.
                                    ip_buffers[_src_ip].append(_strip_dataset_labels(evaluated_log))
                                    ip_last_updated[_src_ip] = time.time()

                                    # ── Kiểm tra cục bộ cho riêng IP này ──
                                    if len(ip_buffers[_src_ip]) >= batch_size:
                                        if agent_q is not None:
                                            print(
                                                f"[*] Enqueue lô {len(ip_buffers[_src_ip])} logs (IP: {_src_ip}) -> Tier-2 pool "
                                                f"(qsize~{agent_q.qsize()})"
                                            )
                                            agent_q.put(list(ip_buffers[_src_ip]))
                                            _warn_backlog()
                                            # CẮM CỜ PENDING_AI KHI BẮT ĐẦU ĐẨY LÊN LLM
                                            try:
                                                r.setex(f"pending_ai:{_src_ip}", 60, "1")
                                            except Exception:
                                                pass
                                        elif on_batch_ready:
                                            print(
                                                f"[*] Triggering Agent Workflow for batch of {len(ip_buffers[_src_ip])} logs (IP: {_src_ip})..."
                                            )
                                            on_batch_ready(ip_buffers[_src_ip])
                                        else:
                                            for log in ip_buffers[_src_ip]:
                                                print(
                                                    f"[ESCALATE] gt_id={log.get('gt_id')} "
                                                    f"ip={log.get('Source IP')} score={log.get('tier1_score')}"
                                                )
                                        del ip_buffers[_src_ip]
                                        del ip_last_updated[_src_ip]

                            elif action == "BLOCK_IP":
                                # Đẩy IP vào blacklist của Redis với TTL 1 giờ
                                src_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                    "src_ip", ""
                                )
                                if src_ip:
                                    print(f"[*] routing BLOCK_IP -> Blacklist: {src_ip}")
                                    r.setex(f"blacklist:{src_ip}", 3600, "1")
                                    # KHO KNOWN-BAD BỀN: Tier-1 signature-block cũng nhớ VĨNH VIỄN
                                    # (reputation=100) -> lần sau chặn on-sight, không chỉ 1h TTL.
                                    try:
                                        memory.mark_ip_blocked(src_ip)
                                    except Exception as _e:
                                        print(f"[!] mark_ip_blocked lỗi {src_ip}: {_e}")
                                    # Lưu block Tier-1 (kèm lý do) cho Dashboard đọc qua file
                                    tier1_recent_blocks.append(
                                        _tier1_block_record(src_ip, evaluated_log)
                                    )
                                    if len(tier1_recent_blocks) > 200:
                                        del tier1_recent_blocks[:-100]
                                # Ghi nhận vào log quyết định để phục vụ ablation study
                                r.rpush("queue_decisions", json.dumps(evaluated_log))

                            elif action in ("ALERT", "LOG"):
                                # Chỉ ghi nhận vào ablation log phục vụ thống kê nghiên cứu
                                r.rpush("queue_decisions", json.dumps(evaluated_log))
                                if action == "ALERT":
                                    src_ip = evaluated_log.get("Source IP") or evaluated_log.get(
                                        "src_ip", ""
                                    )
                                    if src_ip:
                                        from src.response.executor import _log_to_db

                                        _wl_reasons = [
                                            str(x)
                                            for x in (evaluated_log.get("tier1_reasons") or [])
                                        ]
                                        _wl_summary = (
                                            " · ".join(_wl_reasons[:2])
                                            if _wl_reasons
                                            else "Cảnh báo"
                                        )
                                        _log_to_db(
                                            "ALERT",
                                            src_ip,
                                            f"Tier-1 Cảnh báo (ALERT): {_wl_summary}",
                                            raw_log=json.dumps(
                                                _strip_dataset_labels(evaluated_log)
                                            ),
                                            tier=TIER_RULE,
                                        )

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
                                        tier=TIER_RULE,
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

            # Kiem tra xem co can trigger batch do timeout khong
            current_time = time.time()
            stale_ips = []
            for ip, last_time in ip_last_updated.items():
                if (current_time - last_time) > timeout_sec and len(ip_buffers[ip]) > 0:
                    stale_ips.append(ip)

            for ip in stale_ips:
                if agent_q is not None:
                    print(
                        f"[*] Enqueue lô {len(ip_buffers[ip])} logs (IP: {ip}, Timeout) -> Tier-2 pool "
                        f"(qsize~{agent_q.qsize()})"
                    )
                    agent_q.put(list(ip_buffers[ip]))
                    _warn_backlog()
                    try:
                        r.setex(f"pending_ai:{ip}", 60, "1")
                    except Exception:
                        pass
                elif on_batch_ready:
                    print(
                        f"[*] Triggering Agent Workflow for batch of {len(ip_buffers[ip])} logs (IP: {ip}, Timeout)..."
                    )
                    on_batch_ready(ip_buffers[ip])
                else:
                    for log in ip_buffers[ip]:
                        print(
                            f"[ESCALATE] gt_id={log.get('gt_id')} "
                            f"ip={log.get('Source IP')} score={log.get('tier1_score')}"
                        )
                del ip_buffers[ip]
                del ip_last_updated[ip]

            # Ghi counter THẬT ra file (Dashboard container đọc qua volume config/)
            # Được gọi ở ĐÂY để dù không có log mới (idle), Dashboard vẫn thấy Queue giảm dần
            _flush_stats()
            _flush_tier1_blocks()
            _maybe_decay_reputation()

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

    # ── Dừng SẠCH worker pool khi thoát vòng lặp (KeyboardInterrupt) ──
    if agent_q is not None:
        print(f"[*] Dừng {len(agent_pool)} worker Tier-2 (drain lô đang chờ, tối đa 3s/worker)...")
        agent_stop.set()
        for _ in agent_pool:
            try:
                agent_q.put_nowait(None)  # sentinel đánh thức worker idle để thoát
            except queue.Full:
                pass
        for _t in agent_pool:
            _t.join(timeout=3.0)


if __name__ == "__main__":
    # Số worker Tier-2 phải KHỚP số slot llama.cpp (`-np`), nếu không thì slot thừa nằm
    # không: KV cache của nó vẫn chiếm VRAM mà chẳng phục vụ request nào. Đo được: server
    # chạy `-np 2` trong khi mã luôn gọi `start_listening()` với mặc định 1 worker.
    start_listening(agent_workers=int(os.getenv("SENTINEL_AGENT_WORKERS", "2")))
