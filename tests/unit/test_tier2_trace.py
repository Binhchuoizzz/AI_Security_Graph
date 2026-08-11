"""Unit tests cho Tier-2 execution tracer (`src/agent/trace.py`).

Tracer là công cụ ĐO, nên bản thân nó phải đáng tin hơn thứ nó đo. Ba nhóm bất biến:

  1. TẮT nghĩa là TẮT — không tạo file, không dựng bản ghi, và mọi điểm cắm phải nằm sau
     một cổng `if trace.enabled():` (khoá bằng phép quét AST, không bằng niềm tin).
  2. Đúng MỘT dòng JSON cho MỖI invoke, kể cả khi đồ thị ném lỗi, và không bao giờ trộn
     trường giữa các luồng — vì Tier-2 chạy nhiều worker song song.
  3. Hỏng thì im lặng tự tắt, TUYỆT ĐỐI không ném lỗi ra pipeline. Một cái đĩa đầy không
     được phép làm sập cả SOC.
"""

import ast
import json
import pathlib
import threading

import pytest

from src.agent import trace

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture
def sink(tmp_path, monkeypatch):
    """Bật tracer vào một file tạm; luôn trả module về TẮT + đóng fd sau mỗi test."""
    path = tmp_path / "t.jsonl"
    monkeypatch.setenv("SENTINEL_TRACE", "1")
    monkeypatch.setenv("SENTINEL_TRACE_FILE", str(path))
    monkeypatch.setenv("SENTINEL_TRACE_MAX_CHARS", "0")  # 0 = không cắt
    trace.configure()
    yield path
    monkeypatch.delenv("SENTINEL_TRACE", raising=False)
    trace.configure()


def _lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ==============================================================================
# 1. TẮT nghĩa là TẮT
# ==============================================================================


def test_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_TRACE", raising=False)
    monkeypatch.setenv("SENTINEL_TRACE_FILE", str(tmp_path / "x.jsonl"))
    trace.configure()
    try:
        assert trace.enabled() is False
        trace.begin({"current_batch_logs": [{"Source IP": "1.1.1.1"}]})
        trace.add("llm", prompt="x")
        trace.flush()
        assert not (tmp_path / "x.jsonl").exists(), "TẮT mà vẫn tạo file"
        assert trace._record.get() is None, "TẮT mà vẫn dựng bản ghi -> có chi phí thừa"
    finally:
        trace.configure()


def test_all_trace_add_calls_are_guarded():
    """Mọi `trace.add(...)` trong mã nguồn phải nằm trong `if trace.enabled():`.

    Đây là bất biến giữ cho tracer thật sự ZERO-COST khi tắt. Quét bằng AST trên VĂN BẢN
    nguồn (không import) nên test chạy nhanh và không kéo theo FAISS/LLM. Thêm một
    `trace.add` không có cổng ở bất kỳ đâu -> test này đỏ ngay.
    """
    targets = [
        ROOT / "src" / "agent" / "nodes.py",
        ROOT / "src" / "agent" / "workflow.py",
        ROOT / "src" / "guardrails" / "decision_validator.py",
    ]
    problems = []
    for f in targets:
        tree = ast.parse(f.read_text(encoding="utf-8"))

        def _is_gate(node):
            t = getattr(node, "test", None)
            return (
                isinstance(t, ast.Call)
                and isinstance(t.func, ast.Attribute)
                and t.func.attr == "enabled"
                and isinstance(t.func.value, ast.Name)
                and t.func.value.id == "trace"
            )

        guarded = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _is_gate(node):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        guarded.add(id(sub))

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("add", "begin", "flush")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "trace"
                and id(node) not in guarded
            ):
                problems.append(f"{f.relative_to(ROOT)}:{node.lineno} trace.{node.func.attr}")

    # `begin`/`flush` trong _TracedGraph.invoke nằm sau một `if not trace.enabled(): return`
    # (cổng đảo) nên KHÔNG bị bọc trong `if trace.enabled():` — chấp nhận đúng các dòng đó.
    problems = [p for p in problems if "workflow.py" not in p]
    assert not problems, "trace.add KHÔNG có cổng enabled(): " + ", ".join(problems)


# ==============================================================================
# 2. Bật: một dòng mỗi invoke, khoá nối đầy đủ
# ==============================================================================


def test_one_line_per_begin_flush(sink):
    for i in range(3):
        trace.begin({"current_batch_logs": [{"Source IP": f"10.0.0.{i}"}]})
        trace.add("llm", cache_hit=False)
        trace.flush()
    recs = _lines(sink)
    assert len(recs) == 3
    assert len({r["trace_id"] for r in recs}) == 3
    for r in recs:
        assert r["status"] == "ok" and r["schema"] == 1 and r["duration_ms"] >= 0
        assert r["llm"]["cache_hit"] is False


def test_add_without_begin_is_noop(sink):
    """Gọi node trực tiếp (test/eval) mà không begin() -> im lặng, không tạo file."""
    trace.add("llm", prompt="x")
    trace.flush()
    assert not sink.exists()


def test_begin_flushes_stale_record(sink):
    """begin() hai lần liên tiếp: bản ghi cũ phải được GHI RA với status 'abandoned',
    không được nuốt mất — mất bản ghi là mất đúng lô bất thường."""
    trace.begin({"current_batch_logs": []})
    trace.add("llm", a=1)
    trace.begin({"current_batch_logs": []})
    trace.flush()
    recs = _lines(sink)
    assert len(recs) == 2
    assert recs[0]["status"] == "abandoned" and recs[0]["llm"]["a"] == 1
    assert recs[1]["status"] == "ok"


def test_batch_meta_captures_join_keys(sink):
    """`gt_id` là khoá nối MẠNH NHẤT về Tier-1 (nó sống sót _strip_dataset_labels)."""
    trace.begin(
        {
            "current_batch_logs": [
                {
                    "Source IP": "1.2.3.4",
                    "gt_id": "GT-1",
                    "tier1_action": "ESCALATE",
                    "tier1_score": 55,
                },
                {"src_ip": "1.2.3.4", "gt_id": "GT-2", "tier1_score": 30},
            ]
        }
    )
    trace.flush()
    b = _lines(sink)[0]["batch"]
    assert b["size"] == 2
    assert b["source_ips"] == ["1.2.3.4"], "IP trùng phải được khử"
    assert b["gt_ids"] == ["GT-1", "GT-2"]
    assert b["tier1_score_max"] == 55.0


def test_truncation_cap_and_uncapped(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_TRACE", "1")
    monkeypatch.setenv("SENTINEL_TRACE_FILE", str(tmp_path / "c.jsonl"))
    monkeypatch.setenv("SENTINEL_TRACE_MAX_CHARS", "100")
    trace.configure()
    try:
        trace.begin({"current_batch_logs": []})
        trace.add("llm", prompt=[{"role": "user", "content": "X" * 5000}])
        trace.flush()
        v = _lines(tmp_path / "c.jsonl")[0]["llm"]["prompt"][0]["content"]
        assert v.startswith("X" * 100)
        assert "TRUNCATED 4900 of 5000 chars" in v, "phải cắt LỒNG NHAU, không chỉ mức trên"
    finally:
        monkeypatch.delenv("SENTINEL_TRACE", raising=False)
        trace.configure()


# ==============================================================================
# 3. An toàn đa luồng — Tier-2 chạy nhiều worker
# ==============================================================================


def test_concurrent_flush_never_interleaves(sink):
    """8 luồng × 20 bản ghi, mỗi bản ghi mang một blob 200 KB.

    Nếu thiếu khoá ghi, các dòng sẽ xen vào nhau và `json.loads` gãy. Nếu bản ghi dùng
    biến chung thay vì ContextVar, `tid` và `tid2` của cùng một bản ghi sẽ lệch nhau.
    """
    n_threads, per_thread = 8, 20

    def worker(tid):
        for _ in range(per_thread):
            trace.begin({"current_batch_logs": []})
            trace.add("m", tid=tid, blob="X" * 200_000)
            trace.add("m", tid2=tid)
            trace.flush()

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    recs = _lines(sink)
    assert len(recs) == n_threads * per_thread
    assert len({r["trace_id"] for r in recs}) == len(recs)
    for r in recs:
        assert r["m"]["tid"] == r["m"]["tid2"], "trường của hai luồng bị trộn vào một bản ghi"
        assert len(r["m"]["blob"]) == 200_000


def test_record_survives_copied_context(sink):
    """Bản ghi phải sống qua `copy_context().run(...)`.

    LangGraph đẩy task sang executor thread bằng `copy_context()`. Với `threading.local`
    thì section thêm trong thread đó sẽ MẤT LẶNG LẼ; với ContextVar + sửa-tại-chỗ thì còn.
    Đây là chốt hồi quy cho chính lựa chọn thiết kế đó.
    """
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    trace.begin({"current_batch_logs": []})
    ctx = contextvars.copy_context()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(ctx.run, trace.add, "rag", technique_query="q").result()
    trace.flush()
    assert _lines(sink)[0]["rag"]["technique_query"] == "q"


# ==============================================================================
# 4. Không bao giờ ném lỗi
# ==============================================================================


def test_unwritable_sink_never_raises_and_self_disables(tmp_path, monkeypatch):
    """Trỏ sink vào một THƯ MỤC -> open() luôn hỏng kể cả khi chạy bằng root.

    (Dùng chmod 0o500 sẽ pass giả khi test chạy dưới root trong Docker.)
    """
    monkeypatch.setenv("SENTINEL_TRACE", "1")
    monkeypatch.setenv("SENTINEL_TRACE_FILE", str(tmp_path))  # là thư mục
    trace.configure()
    try:
        assert trace.enabled() is True
        trace.begin({"current_batch_logs": []})
        trace.add("llm", a=1)
        trace.flush()  # không được ném
        assert trace.enabled() is False, "sink hỏng phải TỰ TẮT tracer"
        trace.begin({"current_batch_logs": []})
        trace.flush()
    finally:
        monkeypatch.delenv("SENTINEL_TRACE", raising=False)
        trace.configure()


def test_unserializable_payload_never_raises(sink):
    trace.begin({"current_batch_logs": []})
    trace.add("x", obj=object(), s={1, 2, 3})
    trace.flush()
    assert len(_lines(sink)) == 1


def test_add_replaces_non_dict_section(sink):
    trace.begin({"current_batch_logs": []})
    rec = trace._record.get()
    rec["llm"] = "không phải dict"
    trace.add("llm", a=1)
    trace.flush()
    assert _lines(sink)[0]["llm"] == {"a": 1}


# ==============================================================================
# 5. Proxy _TracedGraph — một invoke = một bản ghi, kể cả khi ném lỗi
# ==============================================================================


class _Boom:
    def invoke(self, state, *a, **k):
        raise RuntimeError("nổ")


class _Fake:
    def invoke(self, state, *a, **k):
        return {"decisions": [{"action": "BLOCK_IP", "target": "1.2.3.4", "confidence": 0.9}]}

    def get_graph(self):
        return "graph-obj"


def _traced(app):
    from src.agent.workflow import _TracedGraph

    return _TracedGraph(app)


def test_traced_graph_emits_record_on_raise(sink):
    """Lô ném lỗi VẪN phải có bản ghi — đó chính là lô cần audit nhất."""
    with pytest.raises(RuntimeError):
        _traced(_Boom()).invoke({"current_batch_logs": []})
    r = _lines(sink)[0]
    assert r["status"] == "error" and r["error"]["type"] == "RuntimeError"


def test_traced_graph_records_final_state(sink):
    _traced(_Fake()).invoke({"current_batch_logs": [{"Source IP": "1.2.3.4"}]})
    r = _lines(sink)[0]
    assert r["status"] == "ok"
    assert r["final"]["action"] == "BLOCK_IP" and r["final"]["target"] == "1.2.3.4"


def test_traced_graph_transparent_when_disabled(tmp_path, monkeypatch):
    """Khi tắt, proxy KHÔNG được chạm vào begin/flush."""
    monkeypatch.delenv("SENTINEL_TRACE", raising=False)
    trace.configure()

    def boom(*a, **k):
        raise AssertionError("đường TẮT vẫn gọi tracer")

    monkeypatch.setattr(trace, "begin", boom)
    monkeypatch.setattr(trace, "flush", boom)
    out = _traced(_Fake()).invoke({"current_batch_logs": []})
    assert out["decisions"][0]["action"] == "BLOCK_IP"


def test_traced_graph_delegates_other_attributes():
    app = _traced(_Fake())
    assert app.get_graph() == "graph-obj"
    assert hasattr(app, "invoke")


# ==============================================================================
# 6. Vòng lặp HITL — hai bản vá cắt "phiếu trùng" (hồi quy đo được trên luồng thật)
# ==============================================================================


def test_await_hitl_verdict_is_cached():
    """`AWAIT_HITL` PHẢI được ghi vào response cache.

    HỒI QUY THẬT (ba lượt chạy luồng demo, 2026-07-28): ở lượt KHÔNG reset, 163/338 lô
    Tier-2 (48%) là IP ĐÃ phán quyết ở lượt trước, và 151/163 (93%) trong số đó đã nhận
    AWAIT_HITL. Bản cũ cố ý bỏ qua cache cho AWAIT_HITL với lý do "cần dữ liệu tươi", nhưng
    phiếu HITL đã được tạo rồi — gọi lại LLM chỉ đẻ thêm PHIẾU TRÙNG, tốn ~22 s mỗi lô để
    ra đúng kết luận cũ.
    """
    import ast
    import pathlib as _pl

    src = (_pl.Path(__file__).resolve().parents[2] / "src" / "agent" / "nodes.py").read_text()
    tree = ast.parse(src)
    # Không được tồn tại `if ... != "AWAIT_HITL"` bao quanh lời gọi response_cache.set
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        body = ast.dump(node)
        if "response_cache" in body and "AWAIT_HITL" in ast.dump(node.test):
            raise AssertionError(
                "response_cache.set vẫn bị chặn bởi điều kiện AWAIT_HITL -> vòng lặp phiếu "
                "trùng sẽ tái phát"
            )
    assert "response_cache.set(raw_logs_str" in src


def _run_hitl_node(monkeypatch, *, total_incidents: int):
    """Chạy `node_human_in_the_loop` với mọi tác dụng phụ bị bắt lại, trả về nhật ký gọi."""
    import src.agent.nodes as N
    import src.response.executor as EX
    import src.tier1_filter.feedback_listener as FL

    calls: dict = {"db": [], "alert": [], "ticket": [], "incident": []}

    monkeypatch.setattr(
        N.threat_memory, "get_ip_reputation", lambda ip: {"total_incidents": total_incidents}
    )
    monkeypatch.setattr(
        N, "_handle_threat_memory_incident", lambda t, a, m, c: calls["incident"].append(a)
    )
    monkeypatch.setattr(
        EX, "_log_to_db", lambda a, t, r, raw_log="", *_a, **_k: calls["db"].append(a)
    )
    monkeypatch.setattr(
        EX,
        "raise_alert",
        lambda t, r, raw_log="", confidence=None, tier="": calls["alert"].append(t) or "BLOCK_IP",
    )
    monkeypatch.setattr(
        FL.FeedbackListener,
        "receive_new_rule",
        lambda self, *a, **k: calls["ticket"].append(a[:2]),
    )

    decision = {
        "action": "AWAIT_HITL",
        "target": "203.0.113.9",
        "confidence": 0.42,
        "mitre_technique": "N/A",
        "reasoning": "không đủ căn cứ",
        "hitl_reason": "llm_abstained",
    }
    state = N.SentinelState(
        current_batch_logs=[{"Source IP": "203.0.113.9", "payload": "idA=2"}],
        decisions=[decision],
    )
    N.node_human_in_the_loop(state)
    return calls, decision


def test_first_time_hitl_creates_ticket_and_logs_await_hitl(monkeypatch):
    """Lần ĐẦU: ghi AWAIT_HITL, đẻ đúng một phiếu, KHÔNG gọi choke-point cảnh báo."""
    calls, decision = _run_hitl_node(monkeypatch, total_incidents=0)
    assert calls["db"] == ["AWAIT_HITL"]
    assert len(calls["ticket"]) == 1
    assert calls["alert"] == []
    assert calls["incident"] == ["AWAIT_HITL"]
    assert decision["action"] == "AWAIT_HITL"


def test_repeat_hitl_escalates_and_does_not_duplicate_ticket(monkeypatch):
    """TÁI PHẠM: đi vào `raise_alert`, KHÔNG đẻ phiếu trùng, và ghi ĐÚNG hành động đã làm.

    LỖI ĐÃ SỬA 11/08/2026 — bản trước chỉ gán `latest_decision["action"] = "ALERT"` rồi rơi
    thẳng xuống `_log_to_db("AWAIT_HITL", ...)` ghi cứng và vẫn đẻ phiếu. Ba hệ quả đo được:
    20/336 lô trong `tier2_trace.jsonl` ghi ALERT trong khi hệ thống làm AWAIT_HITL; phiếu
    HITL trùng vẫn sinh ra; và `raise_alert` không bao giờ được gọi nên đường "ALERT lần 2
    -> tự BLOCK" không tồn tại.

    Test cũ chỉ kiểm `'latest_decision["action"] = "ALERT"' in source` nên vẫn xanh suốt —
    lý do nó phải được thay bằng test hành vi.
    """
    calls, decision = _run_hitl_node(monkeypatch, total_incidents=3)
    assert calls["alert"] == ["203.0.113.9"], "tái phạm phải đi qua choke-point cảnh báo"
    assert calls["ticket"] == [], "KHÔNG được đẻ phiếu HITL trùng khi đã leo thang"
    assert calls["db"] == [], "raise_alert tự ghi audit — không ghi thêm dòng AWAIT_HITL"
    assert decision["action"] == "BLOCK_IP", (
        "phải ghi SỰ THẬT raise_alert đã thực thi, không ghi ý định"
    )
    assert calls["incident"] == ["BLOCK_IP"]
