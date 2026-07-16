"""Chống hồi quy cho sự cố đo Tier-2 (phát hiện 2026-07-15).

Sự cố: `evaluate_tier2_decision.py` gọi `agent_app.invoke()` liên tiếp mà QUÊN
`loop_detector.reset()`. Bộ đếm loop-guard cộng dồn qua các invoke, nên sau
`max_iterations`(=10) invoke/luồng, MỌI invoke sau đều FORCE_STOP -> RuntimeError.
Nhánh `except` hạ về AWAIT_HITL, và AWAIT_HITL lại nằm trong FLAG_ACTIONS -> một cú
CRASH bị tính là "bắt đúng đe doạ" (TP). Kết quả: 631/651 ca crash, recall giả 1.00,
accuracy 0.9124 = đúng base rate. Số hỏng này đã lọt vào luận văn Ch4.

Hai test dưới khoá lại hai lớp phòng thủ:
  1. `_tier2_decide` phải reset loop-guard -> >10 invoke liên tiếp KHÔNG sinh lỗi.
  2. Ca agent không cho ra phán quyết KHÔNG được tính là TP; phải bị loại khỏi mẫu số
     và làm `metric_valid=false`.

Không cần LLM/GPU: stub `agent_app.invoke` mô phỏng đúng hành vi thăm node của đồ thị.
"""

from experiments import evaluate_tier2_decision as ev

# Ngưỡng loop-guard là 10 -> 15 invoke đủ để bẫy lỗi cộng dồn.
N_INVOKES = 15


def _item(is_threat=True):
    return {"log": {"source_ip": "10.0.0.9"}, "source": "cicids", "is_threat": is_threat}


def test_tier2_decide_resets_loop_guard_across_invokes(monkeypatch):
    """>10 lần _tier2_decide liên tiếp -> 0 invoke_error (thiếu reset() sẽ FAIL từ ca thứ 11)."""
    from src.guardrails import loop_detector

    def fake_invoke(_state):
        # Mô phỏng đồ thị thật: mỗi lần chạy đều ghi nhận thăm node qua loop-guard.
        res = loop_detector.record_visit("node_guardrails")
        if res["action"] == "FORCE_STOP":
            raise RuntimeError(res["reason"])
        return {"decisions": [{"action": "ALERT", "confidence": 0.8}]}

    monkeypatch.setattr(ev.agent_app, "invoke", fake_invoke)
    loop_detector.reset()

    results = [ev._tier2_decide(_item()) for _ in range(N_INVOKES)]

    errored = [r["invoke_error"] for r in results if r["invoke_error"]]
    assert not errored, (
        f"{len(errored)}/{N_INVOKES} invoke lỗi vì loop-guard cộng dồn — "
        f"_tier2_decide phải gọi loop_detector.reset() trước mỗi invoke. Lỗi: {errored[:3]}"
    )
    assert all(r["llm_action"] == "ALERT" for r in results)


def test_crash_is_not_counted_as_a_correct_detection(monkeypatch):
    """Agent crash -> KHÔNG được thành TP; phải bị loại khỏi mẫu số và cờ metric_valid=false."""

    def always_crash(_state):
        raise RuntimeError("Infinite loop detected: Node 'node_guardrails' visited 11 times")

    monkeypatch.setattr(ev.agent_app, "invoke", always_crash)

    r = ev._tier2_decide(_item(is_threat=True))
    assert r["invoke_error"], "ca crash phải được đánh dấu invoke_error"

    # Chính xác cái bẫy cũ: mặc định AWAIT_HITL vẫn 'flagged', nên nếu bộ tính điểm
    # không loại ca lỗi ra thì crash sẽ hoá thành TP.
    assert ev._is_flagged(r["llm_action"]), "giữ nguyên hành vi cũ: AWAIT_HITL vẫn là flagged"

    scored = [x for x in [r] if not x["invoke_error"]]
    assert scored == [], "ca lỗi phải bị LOẠI khỏi tập chấm điểm (nếu không -> recall giả 1.00)"


def test_summary_flags_invalid_metric_when_agent_mostly_crashes(monkeypatch, tmp_path):
    """Tái hiện đúng sự cố cũ ở mức summary: đa số ca crash -> metric_valid=false."""

    def always_crash(_state):
        raise RuntimeError("boom")

    monkeypatch.setattr(ev.agent_app, "invoke", always_crash)
    monkeypatch.setattr(
        ev, "collect_escalated", lambda: [_item(is_threat=(i % 10) != 0) for i in range(20)]
    )
    monkeypatch.setattr(ev, "_write_report", lambda _s: None)

    summary = ev.run(workers=2, out=str(tmp_path / "out.json"))

    assert summary is not None
    assert summary["metric_valid"] is False, "run toàn crash PHẢI bị đánh dấu không hợp lệ"
    assert summary["n_invoke_errors"] == 20
    assert summary["agent_reliability"] == 0.0
    assert summary["confusion"]["tp"] == 0, "crash KHÔNG được đóng góp TP"
    assert summary["threat_recall"] == 0.0, "recall không được bị bơm bởi ca crash"
