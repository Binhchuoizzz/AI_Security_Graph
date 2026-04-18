"""
LangGraph StateGraph Workflow cho SENTINEL Agent

Lắp ráp các Node thành một quy trình (Workflow) khép kín.
"""
import sys
import os

try:
    from langgraph.graph import StateGraph, END
except ImportError:
    raise ImportError("Missing dependency: pip install langgraph")

from src.agent.state import SentinelState
from src.agent.nodes import (
    node_guardrails,
    node_rag_context,
    node_llm_triage,
    node_action_executor,
    node_human_in_the_loop,
    route_triage_decision
)

def create_agent_workflow() -> StateGraph:
    """
    Khởi tạo và biên dịch LangGraph cho quá trình phân tích bảo mật.
    """
    # 1. Khởi tạo Graph với State Schema
    workflow = StateGraph(SentinelState)

    # 2. Thêm các Trạm xử lý (Nodes)
    workflow.add_node("guardrails", node_guardrails)
    workflow.add_node("rag_context", node_rag_context)
    workflow.add_node("llm_triage", node_llm_triage)
    workflow.add_node("action_executor", node_action_executor)
    workflow.add_node("human_in_the_loop", node_human_in_the_loop)

    # 3. Nối các Cạnh (Edges) - Luồng chính
    # Bắt đầu luồng bằng việc lọc qua Guardrails
    workflow.set_entry_point("guardrails")
    
    # Guardrails xong -> RAG Context
    workflow.add_edge("guardrails", "rag_context")
    
    # RAG lấy xong -> Gửi cho LLM Triage
    workflow.add_edge("rag_context", "llm_triage")

    # 4. Nối các Cạnh Điều kiện (Conditional Edges)
    # Dựa vào quyết định của LLM để rẽ nhánh
    workflow.add_conditional_edges(
        "llm_triage",
        route_triage_decision,
        {
            "execute_action": "action_executor",
            "await_hitl": "human_in_the_loop",
            "end_cycle": END  # Hành động LOG/benign thì kết thúc luôn
        }
    )

    # 5. Kết thúc các luồng hành động
    workflow.add_edge("action_executor", END)
    workflow.add_edge("human_in_the_loop", END)

    # Biên dịch (Compile) Graph
    app = workflow.compile()
    
    return app

# Singleton App để export
agent_app = create_agent_workflow()
