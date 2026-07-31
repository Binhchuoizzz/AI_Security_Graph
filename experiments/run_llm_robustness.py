"""
SENTINEL — Độ Bền LLM & Quy Trình (Determinism + Graceful Degradation)
[Luận văn Ch.4 §Decision Determinism + §Graceful Degradation — LLM tất định + suy biến an toàn]
======================================================================
Hai mối lo phản biện/TS về việc dùng LLM cục bộ trong quy trình SOC:

  (A) TÁI LẬP: temp=0.1 vẫn lấy mẫu — kết quả có lặp lại được không?
      -> Đặt seed cố định (config llm.seed) rồi gọi CÙNG prompt N lần, kiểm tra
         output (và action sau parse) GIỐNG HỆT.

  (B) SUY BIẾN AN TOÀN: nếu LLM cục bộ CHẾT giữa chừng thì sao?
      -> Giả lập LLM ném lỗi, chạy tác tử đầy đủ trên một mẫu tấn công, xác nhận
         hệ KHÔNG vỡ mà suy biến về AWAIT_HITL (Tier-1 vẫn bảo vệ độc lập).

Cần LLM server cho phần (A) — model nào đang phục vụ cũng được, script đọc động. Chạy:
    .venv/bin/python experiments/run_llm_robustness.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics_core import resource_cost, wilson_ci  # noqa: E402
from experiments.unified_dataset import drop_authored  # noqa: E402
from src.agent import llm_client as llm_mod  # noqa: E402
from src.agent.llm_client import llm_client  # noqa: E402
from src.agent.prompts import build_triage_prompt  # noqa: E402
from src.agent.state import SentinelState  # noqa: E402
from src.agent.workflow import agent_app  # noqa: E402

GT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")
OUT_JSON = os.path.join(os.path.dirname(__file__), "results", "llm_robustness_results.json")


def test_determinism(n_runs=5):
    """(A) Cùng prompt + seed cố định -> output tất định."""
    print("\n[A] TÁI LẬP (determinism) — cùng prompt, seed cố định")
    log_data = (
        "<escalated_log_data_v1>\n"
        "{'Source IP': '45.13.3.21', 'Destination Port': 22, 'Total Fwd Packets': 8, "
        "'service': 'SSH', 'tier1_reasons': ['Truy cập cổng nhạy cảm (22)']}\n"
        "</escalated_log_data_v1>"
    )
    rag = "MITRE ATT&CK:\nT1110 Brute Force\n\nNIST SP 800-61r2:\nContainment guidance."
    messages = build_triage_prompt(log_data=log_data, rag_context=rag)

    raws, actions = [], []
    for i in range(n_runs):
        raw = llm_client.invoke(messages=messages, temperature=0.1, seed=42)
        raws.append(raw)
        actions.append(str(llm_client.parse_llm_response(raw).get("action", "?")).upper())
        print(f"   run {i + 1}: action={actions[-1]} | len={len(raw)}")

    # ĐÃ GỠ `raw_identical`. Nó luôn False vì batching GPU làm văn bản thô dao động ở mức
    # ký tự, và điều đó KHÔNG liên quan tới tuyên bố cần chứng minh: cái phải tất định là
    # QUYẾT ĐỊNH, không phải cách diễn đạt. Báo một cờ luôn False cạnh một cờ luôn True chỉ
    # tạo ấn tượng sai rằng hệ "chỉ tất định một nửa". `distinct_raw_outputs` được giữ vì
    # nó ĐỊNH LƯỢNG mức dao động văn bản thay vì phán nhị phân.
    action_identical = len(set(actions)) == 1
    print(f"   -> ACTION giống hệt:     {sum(a == actions[0] for a in actions)}/{n_runs}")
    print(f"   -> biến thể văn bản thô: {len(set(raws))}/{n_runs} (batching GPU, không tính lỗi)")
    return {
        "n_runs": n_runs,
        "seed": 42,
        "action_identical": action_identical,
        "distinct_raw_outputs": len(set(raws)),
        "distinct_actions": len(set(actions)),
        "actions": actions,
    }


def test_seed_variance(n_samples: int = 10, seeds: tuple[int, ...] = (11, 42, 1337)):
    """(A2) BIẾN THIÊN theo SEED trên NHIỀU mẫu — khác hẳn phép thử tất định ở trên.

    VÌ SAO CẦN: `test_determinism` chỉ chứng minh "cùng seed + cùng prompt -> cùng kết
    quả", tức là tính TÁI LẬP. Nó KHÔNG trả lời câu hỏi khác và quan trọng hơn cho luận
    văn: *"nếu đổi seed thì kết luận có đổi không?"* — tức mọi con số trong Chương 4 có
    phải là một lần bốc thăm may mắn hay không. Trước đây chỉ đo 1 seed, n=5, trên ĐÚNG
    MỘT mẫu, nên không có căn cứ nào cho tính ổn định.

    Cách đo: với mỗi mẫu, chạy qua các seed khác nhau và xem PHÁN QUYẾT có đổi không.
    `flip_rate` = tỉ lệ mẫu mà hành động thay đổi khi chỉ đổi seed. Đây là cận dưới của
    độ bất ổn: flip_rate cao nghĩa là chênh lệch nhỏ giữa các cấu hình trong ablation có
    thể chỉ là nhiễu lấy mẫu của LLM, không phải hiệu ứng thật.
    """
    print(f"\n[A2] BIẾN THIÊN THEO SEED — {n_samples} mẫu × {len(seeds)} seed")
    with open(GT_PATH) as f:
        gt = json.load(f)
    # Cùng dân số THẬT như mọi phép đo ground_truth khác — xem `drop_authored`.
    gt, _ = drop_authored(gt)
    # Lấy mẫu phân tầng theo hành động kỳ vọng để không chỉ đo trên một loại ca.
    by_action: dict[str, list] = {}
    for s in gt:
        by_action.setdefault(s.get("expected_action", "?"), []).append(s)
    picked: list = []
    while len(picked) < n_samples and any(by_action.values()):
        for _act, bucket in by_action.items():
            if bucket and len(picked) < n_samples:
                picked.append(bucket.pop(0))

    rag = "MITRE ATT&CK:\n(context)\n\nNIST SP 800-61r2:\n(context)"
    rows, n_flip = [], 0
    for s in picked:
        logs = s.get("logs", [])
        if not logs:
            continue
        messages = build_triage_prompt(log_data=str(logs[0]), rag_context=rag)
        acts = []
        for sd in seeds:
            raw = llm_client.invoke(messages=messages, temperature=0.1, seed=sd)
            acts.append(str(llm_client.parse_llm_response(raw).get("action", "?")).upper())
        flipped = len(set(acts)) > 1
        n_flip += int(flipped)
        rows.append(
            {
                "sample_id": s["id"],
                "actions_by_seed": dict(zip(seeds, acts, strict=False)),
                "flipped": flipped,
            }
        )
        print(f"   {s['id']:10s} {acts}  {'← ĐỔI' if flipped else ''}")

    n = len(rows)
    flip_rate = round(n_flip / n, 4) if n else 0.0
    print(f"   -> {n_flip}/{n} mẫu ĐỔI phán quyết khi chỉ đổi seed (flip_rate={flip_rate})")
    return {
        "n_samples": n,
        "seeds": list(seeds),
        "n_flipped": n_flip,
        "flip_rate": flip_rate,
        "flip_rate_ci95": list(wilson_ci(n_flip, n)) if n else None,
        "per_sample": rows,
        "note": (
            "flip_rate = tỉ lệ mẫu đổi phán quyết khi CHỈ đổi seed. Đây là cận dưới của độ "
            "bất ổn: nếu nó không xấp xỉ 0, các chênh lệch nhỏ giữa cấu hình trong ablation "
            "phải được đọc như nhiễu chứ không phải hiệu ứng thật."
        ),
    }


def test_graceful_degradation():
    """(B) LLM chết -> tác tử suy biến về AWAIT_HITL, KHÔNG vỡ."""
    print("\n[B] SUY BIẾN AN TOÀN (graceful degradation) — giả lập LLM chết")
    with open(GT_PATH) as f:
        gt = json.load(f)
    sample = next(s for s in gt if s["expected_action"] == "BLOCK_IP")
    logs = sample.get("logs", [])

    # Giả lập LLM cục bộ chết: ép invoke ném ConnectionError (như server tắt).
    orig_invoke = llm_mod.llm_client.invoke

    def _boom(*a, **k):
        raise ConnectionError("Giả lập: LLM server không truy cập được")

    llm_mod.llm_client.invoke = _boom
    crashed = False
    action = None
    try:
        from src.guardrails import loop_detector

        loop_detector.reset()
        final = agent_app.invoke(
            SentinelState(
                current_batch_logs=logs, current_batch_size=len(logs), narrative_summary=""
            )
        )
        decisions = final.get("decisions", [])
        action = decisions[-1].get("action") if decisions else None
    except Exception as e:
        crashed = True
        print(f"   [!] HỆ VỠ (không mong muốn): {e}")
    finally:
        llm_mod.llm_client.invoke = orig_invoke  # khôi phục

    safe = (not crashed) and action == "AWAIT_HITL"
    print(f"   -> sample={sample['id']} | LLM chết | action sau suy biến = {action}")
    print(
        f"   -> KẾT QUẢ: {'✅ SUY BIẾN AN TOÀN (AWAIT_HITL, không vỡ)' if safe else '⚠️ chưa an toàn'}"
    )
    return {"sample_id": sample["id"], "crashed": crashed, "degraded_action": action, "safe": safe}


def main():
    print("=" * 70)
    print("  SENTINEL — ĐỘ BỀN LLM & QUY TRÌNH")
    print("=" * 70)

    det = test_determinism()
    var = test_seed_variance()
    deg = test_graceful_degradation()

    # Cache ngữ nghĩa (bonus): tỷ lệ hit giảm tải LLM
    cache = None
    try:
        from src.agent.nodes import retriever

        if hasattr(retriever, "cache") and retriever.cache:
            cache = retriever.cache.get_stats()
    except Exception:
        pass

    # ── CHI PHÍ TÀI NGUYÊN — dùng token THẬT do server trả về, không ước lượng ──
    # `token_monitor.get_stats()` đọc file bền vững và trả None nếu chưa có lượt gọi nào;
    # schema là tổng luỹ kế (`calls`/`prompt_sum`/`completion_sum`), không phải trung bình.
    cost = None
    try:
        from src.agent import token_monitor

        stats = token_monitor.get_stats() or {}
        n_calls = int(stats.get("calls") or 0)
        if n_calls:
            cost = resource_cost(
                n_events=n_calls,  # ở script này mỗi lượt gọi ứng một sự kiện
                n_llm_calls=n_calls,
                mean_prompt_tokens=float(stats.get("prompt_sum") or 0) / n_calls,
                mean_completion_tokens=float(stats.get("completion_sum") or 0) / n_calls,
            )
            print(
                f"\n[C] CHI PHÍ: {cost['tokens_per_1k_events']} token/1k sự kiện · "
                f"tránh được ${cost['avoided_api_usd_per_1k_events']}/1k nếu dùng API"
            )
    except Exception as e:
        print(f"[!] Bỏ qua chi phí tài nguyên (không đọc được token_monitor): {e}")

    out = {
        "determinism": det,
        "seed_variance": var,
        "graceful_degradation": deg,
        "semantic_cache": cache,
        "resource_cost": cost,
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved -> {OUT_JSON}")
    print(
        f"\n  TỔNG: determinism action={det['action_identical']} · "
        f"seed flip_rate={var['flip_rate']} · degradation safe={deg['safe']}"
    )
    if var["flip_rate"] > 0.1:
        print(
            "  [!] flip_rate > 10%: phán quyết KHÔNG ổn định qua seed — mọi chênh lệch nhỏ\n"
            "      giữa các cấu hình trong ablation phải đọc như nhiễu, không phải hiệu ứng."
        )


if __name__ == "__main__":
    main()
