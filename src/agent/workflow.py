"""
Dựng và biên dịch đồ thị trạng thái LangGraph của Tier-2.

Lắp ráp các Node thành một quy trình (Workflow) khép kín.
"""

try:
    from langgraph.graph import END, StateGraph  # type: ignore
    from langgraph.graph.state import CompiledStateGraph  # type: ignore
except ImportError:
    raise ImportError("Missing dependency: pip install langgraph")

from typing import cast

from src.agent import trace
from src.agent.nodes import (
    node_action_executor,
    node_attack_mapper,
    node_guardrails,
    node_human_in_the_loop,
    node_llm_triage,
    node_rag_context,
    route_after_triage,
    route_triage_decision,
)
from src.agent.state import SentinelState


def create_agent_workflow() -> CompiledStateGraph:
    """Khởi tạo và biên dịch LangGraph cho quá trình phân tích bảo mật."""
    workflow = StateGraph(SentinelState)

    workflow.add_node("guardrails", node_guardrails)
    workflow.add_node("rag_context", node_rag_context)
    workflow.add_node("llm_triage", node_llm_triage)
    workflow.add_node("attack_mapper", node_attack_mapper)
    workflow.add_node("action_executor", node_action_executor)
    workflow.add_node("human_in_the_loop", node_human_in_the_loop)

    workflow.set_entry_point("guardrails")
    workflow.add_edge("guardrails", "rag_context")
    workflow.add_edge("rag_context", "llm_triage")

    # Sau triage: nếu confidence > 0.7 và là mối-đe-doạ -> attack_mapper (làm giàu
    # MITRE có cấu trúc); ngược lại định tuyến thẳng theo action như cũ.
    workflow.add_conditional_edges(
        "llm_triage",
        route_after_triage,
        {
            "map": "attack_mapper",
            "execute_action": "action_executor",
            "await_hitl": "human_in_the_loop",
            "end_cycle": END,  # Hành động LOG/benign thì kết thúc luôn
        },
    )

    # Sau attack_mapper -> định tuyến theo action (HITL / Action Executor / END),
    # mang theo quyết định đã được làm giàu MITRE.
    workflow.add_conditional_edges(
        "attack_mapper",
        route_triage_decision,
        {
            "execute_action": "action_executor",
            "await_hitl": "human_in_the_loop",
            "end_cycle": END,
        },
    )

    workflow.add_edge("action_executor", END)
    workflow.add_edge("human_in_the_loop", END)

    app = workflow.compile()

    return app


class _TracedGraph:
    """Proxy mỏng quanh CompiledStateGraph: mở/đóng đúng một bản ghi trace mỗi invoke.

    Vì sao bọc Ở SINGLETON chứ không ở `main.py`: có tám nơi gọi `agent_app.invoke(...)`
    (main.py + 7 script trong `experiments/`/`scripts/`). Bọc ở đây phủ hết bằng một chỗ
    sửa, và đảm bảo bất biến "một invoke = một bản ghi" không phụ thuộc người gọi nhớ hay
    quên.

    `flush()` nằm trong `except BaseException` rồi `raise` tiếp - lô ném lỗi vẫn có bản ghi,
    vì đó chính là lô cần audit nhất. Khi `SENTINEL_TRACE` tắt, invoke đi thẳng xuống graph:
    chi phí đúng một phép đọc bool.
    """

    # Cố Ý không dùng `__slots__`. Nó chặn `setattr` trên instance, mà đó chính là cách
    # `tests/unit/test_tier2_eval_loop_guard.py` (và khuôn mẫu tương tự trong experiments)
    # stub `agent_app.invoke` để chạy không cần LLM/GPU:
    #     monkeypatch.setattr(ev.agent_app, "invoke", fake_invoke)
    # Thêm `__slots__` làm ba test đó gãy cả ở thân test lẫn lúc teardown. Proxy phải thay
    # Thế được hoàn toàn cho CompiledStateGraph trần trước đây - kể cả ở khả năng vá.
    def __init__(self, app: CompiledStateGraph):
        self._app = app

    def __getattr__(self, name: str):
        # Mọi API khác (stream/get_graph/...) uỷ quyền thẳng xuống graph đã biên dịch.
        return getattr(self._app, name)

    def invoke(self, state, *args, **kwargs) -> dict:
        # LangGraph khai `invoke` trả `GraphOutput`, nhưng lúc chạy nó trả về chính
        # cuốn trạng thái dạng dict. Khai đúng ở đây thì bảy chỗ gọi bên ngoài `src/`
        # (main.py và các script đo) không phải rải chú thích bỏ qua kiểu nữa.
        if not trace.enabled():
            return cast(dict, self._app.invoke(state, *args, **kwargs))
        trace.begin(state)
        try:
            out = self._app.invoke(state, *args, **kwargs)
        except BaseException as e:
            trace.flush(status="error", error=e)
            raise
        trace.flush(status="ok", final_state=out)
        return cast(dict, out)


# Thực thể duy nhất agent_app để xuất ra ngoài (Singleton)
agent_app = _TracedGraph(create_agent_workflow())
