"""
Đánh giá Hiệu năng Độ trễ: Hệ thống 2 Lớp (Two-Tier) so với LLM-only
[Luận văn Ch.4 §Two-Tier Latency Trade-off — claim độ trễ chủ đạo ~0.6ms / −99% vs LLM]

CHỨC NĂNG:
  Đo độ trễ của 2 chế độ:
    - Two-Tier:  Tier1 → Guardrail → RAG → LLM
    - Baseline:  Mỗi sự kiện → LLM trực tiếp (không lọc, không RAG)

  Mẫu lấy THEO BƯỚC NHẢY trên `build_stream()` để giữ nguyên tỉ lệ lành/độc của luồng thật.
  Bản cũ ép 50 benign + 50 tấn công — xoá đúng điều kiện làm nên lợi thế của kiến trúc hai
  tầng, nên đo ra SENTINEL chậm hơn LLM-only 7,8% (p = 1,000).
  Mục tiêu: Giảm thiểu độ trễ ≥ 60% so với baseline chỉ dùng LLM.

  LƯU Ý: Yêu cầu llama.cpp server chạy tại port 5000.
  Nếu server không hoạt động, kiểm thử sẽ được bỏ qua (SKIP) an toàn.

KẾT QUẢ ĐẦU RA:
  experiments/results/latency_benchmark.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def check_llm_server():
    """Kiểm tra máy chủ llama.cpp có đang chạy hay không. Thử kết nối với các port 5000 và 8080."""
    import urllib.request

    for port in [5000, 8080]:
        try:
            req = urllib.request.Request(f"http://localhost:{port}/v1/models")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    # Thiết lập biến môi trường để LLMClient sử dụng port chính xác
                    os.environ["LLM_API_BASE"] = f"http://127.0.0.1:{port}/v1"
                    print(f"  LLM server detected on port {port}")
                    return True
        except Exception:
            continue
    return False


def load_test_events(n=100):
    """Lấy mẫu từ LUỒNG THẬT, giữ nguyên tỉ lệ lành/độc.

    BẢN CŨ ÉP 50 benign + 50 tấn công. Đó là chỗ chết của phép đo: lợi thế của kiến trúc hai
    tầng ĐẾN TỪ việc đại đa số lưu lượng SOC là vô hại và bị loại rẻ tiền ở Tier-1. Ép về
    50/50 là xoá đúng cái điều kiện làm nên lợi thế — Tier-1 chỉ loại được 11/100, 89 ca vẫn
    gọi LLM và phải trả thêm chi phí đi qua tầng lọc, nên hệ "hai tầng" đo ra CHẬM HƠN
    LLM-only 7,8% (p = 1,000). Con số đó tả một kịch bản không tồn tại trong vận hành.

    Lấy mẫu THEO BƯỚC NHẢY trên `build_stream()` để tỉ lệ lớp đúng như luồng thật, và để mẫu
    trải đều toàn bộ dòng thời gian thay vì dồn vào một đoạn.
    """
    from experiments.unified_dataset import build_stream

    warmup, main, _apt_truth, _n_chains = build_stream()
    if not main:
        return [], []
    stride = max(1, len(main) // n)
    events = main[::stride][:n]
    n_attack = sum(1 for e in events if e.get("expected_threat"))
    print(
        f"  Lấy {len(events)}/{len(main)} sự kiện (bước nhảy {stride}) — "
        f"tấn công {n_attack} ({100 * n_attack / max(len(events), 1):.1f}%), giữ nguyên tỉ lệ luồng thật"
    )
    # `warmup` phải chạy qua Tier-1 TRƯỚC để Welford có nền thống kê. Không mồi thì Z-score
    # tính trên n nhỏ và Tier-1 hành xử khác hẳn lúc vận hành — sai luôn đại lượng đang đo.
    return events, warmup


def measure_two_tier(events: list, warmup: list | None = None) -> tuple[list, dict]:
    """Chạy ĐÚNG đường nóng đang triển khai; trả (độ trễ mỗi sự kiện ms, phân rã theo chặng).

    BẢN CŨ THIẾU HAI TẦNG LỌC RẺ NHẤT. Nó chỉ có `RuleEngine -> guardrails -> RAG -> LLM`:
    không Cổng ML LightGBM, và `DualRetriever(use_cache=False)` tức TẮT luôn Semantic Cache.
    Mà RQ1 hỏi đích danh cả ba — "Welford O(1), Cổng Học máy LightGBM và Bộ đệm Semantic
    Cache Tầng 1.75". Nói cách khác, phép đo cũ không đo kiến trúc mà luận văn đang tuyên bố:
    nó đo một hệ đã bị gỡ mất hai chặng loại rẻ, nên mọi ca ESCALATE đều rơi thẳng xuống LLM.

    Đường nóng thật, theo `src/streaming/subscriber.py`:
        RuleEngine.evaluate  -> DROP/WHITELIST_DROP thì dừng
        ESCALATE             -> MLGateway.evaluate -> tự quyết được thì dừng
        còn lại              -> guardrails -> RAG (CÓ cache) -> LLM
    """
    from src.agent.llm_client import LLMClient
    from src.guardrails.prompt_filter import GuardrailsPipeline
    from src.rag.retriever import DualRetriever
    from src.tier1_filter.ml_gateway import MLGateway
    from src.tier1_filter.rule_engine import RuleEngine

    engine = RuleEngine()
    ml_gateway = MLGateway()
    guardrails = GuardrailsPipeline()
    retriever = DualRetriever(use_cache=True)  # Tier-1.75: cache BẬT, đúng như vận hành
    llm = LLMClient()

    # Mồi Welford bằng lưu lượng lành tính, KHÔNG tính vào độ trễ.
    # `ev["log"]` chứ không phải `ev`: phần tử của `build_stream()` là VỎ BỌC
    # {source, log, expected_threat, label, t}. Truyền cả vỏ thì Tier-1 không thấy trường nào
    # nó biết -> score 0 -> DROP sạch, kể cả tấn công, mà không ném lỗi nào. Nguồn sự thật:
    # `unified_dataset.score_stream()`.
    for w in warmup or []:
        try:
            engine.evaluate(w["log"])
        except Exception:
            pass

    latencies: list[float] = []
    # Đếm ca THOÁT ở từng chặng + tổng thời gian chặng đó, để biết lợi thế đến từ đâu chứ
    # không chỉ biết tổng nhanh/chậm.
    stage_n = {"tier1_drop": 0, "ml_gate": 0, "llm": 0}
    stage_ms: dict[str, list[float]] = {"tier1_drop": [], "ml_gate": [], "llm": []}

    for wrapper in events:
        log = wrapper["log"]
        t_start = time.perf_counter()

        result = engine.evaluate(log)
        # Tier-1 XONG VIỆC với mọi hành động TRỪ `ESCALATE`. Nguồn sự thật là `subscriber.py`:
        # toàn bộ nhánh Cổng ML/LLM nằm trong `if action == "ESCALATE"`, và chính nó đếm mọi
        # hành động khác là "đã gỡ tải".
        #
        # LỖI ĐÃ VÁ (04/08/2026): điều kiện cũ là `in ("DROP", "WHITELIST_DROP")`, tức coi
        # `BLOCK_IP` · `ALERT` · `AWAIT_HITL` là CHƯA xử lý xong. Hậu quả kép: (1) tỉ lệ xả tải
        # bị hạ thấp — đo 74,0% trong khi cùng luồng, cùng engine, đếm đúng thì là 90,6%;
        # (2) những ca Tier-1 ĐÃ CHẶN vẫn bị gửi lên LLM trong phép đo, nên độ trễ hai tầng
        # cộng thêm hàng chục giây không có thật. Cùng họ với lỗi ở `evaluate_feedback_loop`.
        if result.get("tier1_action") != "ESCALATE":
            dt = (time.perf_counter() - t_start) * 1000
            stage_n["tier1_drop"] += 1
            stage_ms["tier1_drop"].append(dt)
            latencies.append(dt)
            continue

        # ── TIER-1 CỔNG ML (LightGBM) ──
        ml_action, _ml_reason, _ml_conf = ml_gateway.evaluate(log)
        if ml_action:
            dt = (time.perf_counter() - t_start) * 1000
            stage_n["ml_gate"] += 1
            stage_ms["ml_gate"].append(dt)
            latencies.append(dt)
            continue

        # ── TIER-2 ──
        guard_result = guardrails.process_batch([log])
        safe_log = guard_result.get("batch_encapsulated", str(log))
        context = retriever.retrieve(safe_log[:500])
        try:
            llm.invoke(
                [
                    {
                        "role": "user",
                        "content": str(context.get("combined_prompt", "")) + "\n" + safe_log[:1000],
                    }
                ]
            )
        except Exception:
            pass  # gọi LLM hỏng vẫn tính thời gian đã tiêu

        dt = (time.perf_counter() - t_start) * 1000
        stage_n["llm"] += 1
        stage_ms["llm"].append(dt)
        latencies.append(dt)

    total = max(len(events), 1)
    breakdown = {
        "n_events": len(events),
        "escaped_at": stage_n,
        "escaped_pct": {k: round(100 * v / total, 2) for k, v in stage_n.items()},
        "offload_pct": round(100 * (stage_n["tier1_drop"] + stage_n["ml_gate"]) / total, 2),
        "mean_ms_by_stage": {
            k: round(float(np.mean(v)), 3) if v else None for k, v in stage_ms.items()
        },
        "rag_cache": retriever.cache.get_stats() if getattr(retriever, "cache", None) else None,
    }
    print(
        f"  Thoát ở Tier-1: {stage_n['tier1_drop']} · Cổng ML: {stage_n['ml_gate']} · "
        f"tới LLM: {stage_n['llm']}  (xả tải {breakdown['offload_pct']}%)"
    )
    return latencies, breakdown


def measure_llm_only_baseline(events: list) -> list:
    """Chạy chế độ chỉ dùng LLM (không có Tier 1, không có RAG) và trả về độ trễ (ms)."""
    from src.agent.llm_client import LLMClient

    llm = LLMClient()
    latencies = []

    for event in events:
        t_start = time.perf_counter()

        # Suy luận trực tiếp bằng LLM — không lọc, không RAG.
        # Cùng nội dung log như nhánh hai tầng (`ev["log"]`), nếu không thì hai nhánh nhận
        # prompt dài ngắn khác nhau và phép so độ trễ mất tính công bằng.
        raw_log = json.dumps(event["log"], default=str)[:1500]
        try:
            _ = llm.invoke([{"role": "user", "content": raw_log}])
        except Exception:
            pass

        latencies.append((time.perf_counter() - t_start) * 1000)

    return latencies


def derive_stats(two_tier: list, baseline: list) -> dict:
    """Thống kê phái sinh từ độ trễ thô — MỘT chỗ tính duy nhất.

    Tách khỏi `run()` để lượt đo cũ (JSON đã lưu `per_event_*_ms`) tính bù được bằng ĐÚNG
    công thức này thay vì chép số từ log — chép tay là đúng chỗ số liệu bị sai lệch.

    Mann-Whitney U một phía (`alternative="less"`): giả thuyết đối là hai tầng NHANH HƠN.
    Dùng phi tham số vì độ trễ ở đây hai đỉnh và lệch nặng, t-test giả định sai phân bố.
    """
    out: dict[str, float | bool | None] = {
        "two_tier_median_ms": round(float(np.median(two_tier)), 2),
        "two_tier_p95_ms": round(float(np.percentile(two_tier, 95)), 2),
        "baseline_median_ms": round(float(np.median(baseline)), 2),
        "baseline_p95_ms": round(float(np.percentile(baseline, 95)), 2),
    }
    try:
        from scipy.stats import mannwhitneyu

        stat, p = mannwhitneyu(two_tier, baseline, alternative="less")
        out["mannwhitney_u"] = round(float(stat), 2)
        out["mannwhitney_p"] = float(p)
        out["significant_p05"] = bool(p < 0.05)
    except ImportError:
        out["mannwhitney_p"] = None
        out["significant_p05"] = None
    return out


def run(n_events: int = 100):
    # Kiểm tra máy chủ LLM
    if not check_llm_server():
        print("[SKIP] llama.cpp server not running on port 5000 or 8080.")
        print("       Start with one of:")
        print("         docker-compose up -d --force-recreate --no-deps llm")
        print("         (model + ctx lấy từ LLM_MODEL_FILE / LLAMA_ARG_CTX_SIZE trong .env)")
        print("         hoặc đặt LLM_API_BASE=http://127.0.0.1:8080/v1")
        print("       Then re-run this script.")

        # Lưu kết quả bỏ qua (skip) — KHÔNG được xoá mất số đo THẬT đã có.
        # BUG CŨ: ghi đè thẳng latency_benchmark.json bằng {"status": "SKIPPED"} nên chỉ
        # cần lỡ chạy script lúc LLM chưa bật là MẤT TRẮNG kết quả đã đo (số này đang được
        # UI và luận văn trích dẫn). Nay giữ kết quả cũ dưới `previous_result`, và dùng
        # context manager để file luôn được đóng/flush.
        Path("experiments/results").mkdir(parents=True, exist_ok=True)
        out_path = Path("experiments/results/latency_benchmark.json")
        payload: dict = {"status": "SKIPPED", "reason": "LLM server not available"}
        if out_path.exists():
            try:
                prev = json.loads(out_path.read_text())
                if prev.get("status") != "SKIPPED":
                    payload["previous_result"] = prev
            except (OSError, json.JSONDecodeError):
                pass  # file hỏng/không đọc được -> cứ ghi marker skip
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2)
        return False

    print(f"Loading {n_events} test events...")
    events, warmup = load_test_events(n_events)
    actual_n = len(events)
    print(f"  Loaded {actual_n} events (+ {len(warmup)} mồi Welford, không tính giờ)")

    print(f"\n[1/2] Measuring Two-Tier latency ({actual_n} events)...")
    two_tier_latencies, stage_breakdown = measure_two_tier(events, warmup)

    print(f"\n[2/2] Measuring LLM-only baseline ({actual_n} events)...")
    baseline_latencies = measure_llm_only_baseline(events)

    # Thống kê
    two_tier_mean = np.mean(two_tier_latencies)
    baseline_mean = np.mean(baseline_latencies)
    reduction_pct = (baseline_mean - two_tier_mean) / baseline_mean * 100

    print(f"""
═══════════════════════════════════════
LATENCY BENCHMARK RESULTS ({actual_n} events)
═══════════════════════════════════════
Baseline (LLM-only):
  Mean:   {baseline_mean:.1f} ms
  Median: {np.median(baseline_latencies):.1f} ms
  P95:    {np.percentile(baseline_latencies, 95):.1f} ms

Two-Tier (SENTINEL):
  Mean:   {two_tier_mean:.1f} ms
  Median: {np.median(two_tier_latencies):.1f} ms
  P95:    {np.percentile(two_tier_latencies, 95):.1f} ms

Latency Reduction: {reduction_pct:.1f}%
Target:            ≥ 60%
Status:            {"✅ PASS" if reduction_pct >= 60 else "❌ FAIL"}
═══════════════════════════════════════
    """)

    # Lưu kết quả chi tiết
    results = {
        "hardware": "i7-14700KF / RTX 4060 Ti 16GB / 32GB DDR5",
        "n_events": actual_n,
        "sampling": "strided trên build_stream() — GIỮ tỉ lệ lành/độc thật, KHÔNG ép 50/50",
        "pipeline": "RuleEngine -> MLGateway -> guardrails -> DualRetriever(cache ON) -> LLM",
        "baseline_mean_ms": round(baseline_mean, 2),
        "two_tier_mean_ms": round(two_tier_mean, 2),
        "latency_reduction_pct": round(reduction_pct, 2),
        "target_pct": 60,
        "pass": bool(reduction_pct >= 60),
        # Median/P95/Mann-Whitney từng CHỈ được in ra màn hình rồi mất theo phiên terminal.
        # Với phân bố hai đỉnh như ở đây (đa số ca xong trong ~1 ms, số ít phải chờ LLM ~23 s)
        # thì mean một mình mô tả sai; median và P95 mới nói được đuôi. Ghi vào JSON để báo cáo
        # đọc thẳng, không ai phải chép tay từ log.
        **derive_stats(two_tier_latencies, baseline_latencies),
        # Phân rã theo chặng: tổng nhanh/chậm KHÔNG cho biết lợi thế đến từ đâu. Nếu số ca
        # thoát ở Tier-1 + Cổng ML thấp thì con số tổng chỉ đang tả tập mẫu, không tả kiến trúc.
        "stage_breakdown": stage_breakdown,
        # CỜ TỰ KIỂM. Lợi thế của kiến trúc hai tầng ĐẾN TỪ việc phần lớn lưu lượng bị loại
        # rẻ tiền trước LLM. Nếu tỉ lệ xả tải trong chính lượt đo này thấp bất thường thì
        # con số độ trễ đang tả một kịch bản không tồn tại trong vận hành — đúng chỗ bản đo
        # cũ sập (ép 50/50 -> xả tải 11% -> kết luận "chậm hơn 7,8%").
        "metric_valid": bool(stage_breakdown["offload_pct"] >= 50.0),
        "metric_valid_reason": (
            f"xả tải đo được {stage_breakdown['offload_pct']}% "
            f"({'đại diện luồng thật' if stage_breakdown['offload_pct'] >= 50 else 'THẤP BẤT THƯỜNG — kiểm lại cách lấy mẫu trước khi trích'})"
        ),
        "per_event_two_tier_ms": [round(x, 2) for x in two_tier_latencies],
        "per_event_baseline_ms": [round(x, 2) for x in baseline_latencies],
    }

    Path("experiments/results").mkdir(exist_ok=True)
    with open("experiments/results/latency_benchmark.json", "w") as fh:
        json.dump(results, fh, indent=2)
    print("Saved: experiments/results/latency_benchmark.json")

    # Kiểm định thống kê Mann-Whitney U
    try:
        from scipy.stats import mannwhitneyu

        stat, p_value = mannwhitneyu(two_tier_latencies, baseline_latencies, alternative="less")
        print(f"Mann-Whitney U Test: stat={stat:.2f}, p={p_value:.6f}")
        print(f"Statistical significance: {'✅ p < 0.05' if p_value < 0.05 else '❌ p >= 0.05'}")
    except ImportError:
        print("[WARN] scipy not installed, skipping Mann-Whitney U test")
        print("       Install with: pip install scipy")

    return reduction_pct >= 60


if __name__ == "__main__":
    # LỖI ĐÃ SỬA: script KHÔNG có argparse, nên `--n 1000` mà tài liệu hướng dẫn bị nuốt IM
    # LẶNG qua sys.argv và mọi lượt đo vẫn chạy n=100. Tức con số độ trễ đang trích trong luận
    # văn là mẫu 100 — dưới ngưỡng mà chính tài liệu đặt ra (cần ~1000 để đủ ca chạm LLM), và
    # cái cờ lẽ ra để sửa điều đó thì chưa bao giờ có tác dụng.
    #
    # CHI PHÍ: nhánh baseline gửi MỌI sự kiện thẳng lên LLM (~18,9 s/lần đo được ở lượt gần
    # nhất). n=100 mất ~30 phút; n=1000 mất ~5 giờ. Giữ mặc định 100 để không ai vô tình khởi
    # động một lượt 5 giờ, nhưng cờ nay CÓ THẬT.
    _ap = argparse.ArgumentParser(description="Độ trễ hai tầng vs LLM-only")
    _ap.add_argument(
        "--n",
        type=int,
        default=100,
        help="số sự kiện lấy mẫu (strided trên build_stream). Tài liệu khuyến nghị 1000 để có "
        "đủ ca chạm LLM; đổi lại lượt đo kéo dài ~5 giờ vì nhánh baseline gọi LLM cho mọi ca.",
    )
    _args = _ap.parse_args()
    success = run(_args.n)
    sys.exit(0 if success else 1)
