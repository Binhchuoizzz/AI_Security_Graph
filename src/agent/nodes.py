"""
LangGraph Nodes for SENTINEL Agent

Chứa logic của từng trạm xử lý trong StateGraph.
Tuân thủ Batching Strategy: Incident-Level Aggregation (1 Batch = 1 Quyết định).
"""
import json
import logging
from typing import Dict, Any

from src.agent.state import SentinelState
from src.agent.llm_client import llm_client
from src.agent.prompts import build_triage_prompt
from src.rag.retriever import DualRetriever

logger = logging.getLogger(__name__)

# Khởi tạo Retriever (Singleton)
retriever = DualRetriever(use_cache=True)


def node_rag_context(state: SentinelState) -> Dict[str, Any]:
    """
    RAG Context Node: Trích xuất thông tin từ batch log để query RAG.
    Do áp dụng Incident-Level Aggregation, ta có thể dùng narrative_summary
    cũ, hoặc trích xuất vài keyword từ log đầu tiên trong batch.
    """
    logger.info("--- NODE: RAG CONTEXT ---")
    
    # Heuristic đơn giản: lấy log đầu tiên làm query, hoặc dùng narrative_summary nếu batch trống
    # (Trong thực tế Tier 1 sẽ gom cụm các log giống nhau, nên log đầu tiên đủ đại diện)
    query_text = ""
    if state.current_batch_logs:
        first_log = state.current_batch_logs[0]
        # Gom các trường quan trọng (vd: message, payload)
        query_text = str(first_log.get('message', '')) + " " + str(first_log.get('payload', ''))
    elif state.narrative_summary:
        query_text = state.narrative_summary
    else:
        query_text = "suspicious network activity"

    # Chỉ lấy 50 ký tự đầu tiên để search, tránh query RAG quá dài làm nhiễu FAISS
    query_text = query_text[:50]
    
    # Truy xuất RAG
    results = retriever.retrieve(query_text)
    
    # Trả về các trường cần update vào State
    return {
        "rag_mitre_context": results.get("mitre_context", ""),
        "rag_iso_context": results.get("iso_context", "")
    }


def node_llm_triage(state: SentinelState) -> Dict[str, Any]:
    """
    LLM Triage Node: Phân tích toàn bộ cụm log (Incident-Level) và đưa ra 1 quyết định duy nhất.
    """
    logger.info("--- NODE: LLM TRIAGE ---")
    
    # 1. Đóng gói Raw Logs (kết hợp với Guardrails Encapsulation)
    # Vì State có lưu `current_batch_encapsulated` từ trước (nếu đi qua guardrails node),
    # nhưng ở đây ta cứ lấy thô rồi tự format lại cho chắc.
    raw_logs_str = "\n".join([str(log) for log in state.current_batch_logs])
    
    # 2. Xây dựng Prompt
    rag_combined = f"MITRE ATT&CK:\n{state.rag_mitre_context}\n\nISO 27001:\n{state.rag_iso_context}"
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_combined)
    
    # Nếu có narrative_summary (bối cảnh cũ), nhét thêm vào System Prompt để giữ context
    if state.narrative_summary:
        messages[0]["content"] += f"\n\n=== PREVIOUS CONTEXT ===\n{state.narrative_summary}"

    # 3. Gọi LLM qua Oobabooga API
    raw_response = llm_client.invoke(messages=messages, temperature=0.1)
    
    # 4. Parse JSON an toàn (3-Layer Fallback)
    decision_json = llm_client.parse_llm_response(raw_response)
    
    # 5. Cập nhật State
    action = decision_json.get("action", "AWAIT_HITL")
    reasoning = decision_json.get("reasoning", "No reasoning provided.")
    new_iocs = decision_json.get("extracted_iocs", [])
    
    decision_entry = {
        "action": action,
        "confidence": decision_json.get("confidence", 0.0),
        "reasoning": reasoning,
        "mitre_technique": decision_json.get("mitre_technique", ""),
        "iso_control": decision_json.get("iso_control", ""),
        "cycle_count": state.cycle_count + 1
    }

    # Cập nhật narrative_summary để giữ bối cảnh cho batch tiếp theo
    new_narrative = f"Last Incident: {action} based on RAG - {decision_json.get('mitre_technique', 'None')}. Reasoning: {reasoning}"

    return {
        "decisions": [decision_entry],  # Sẽ được reducer append
        "extracted_iocs": new_iocs,     # Sẽ được reducer append
        "narrative_summary": new_narrative,
        "cycle_count": state.cycle_count + 1
    }


def node_action_executor(state: SentinelState) -> Dict[str, Any]:
    """
    Action Executor Node: Xử lý các action BLOCK_IP hoặc ALERT.
    Trong framework luận văn, node này sẽ in log giả lập hoặc đẩy API về tường lửa.
    """
    logger.info("--- NODE: ACTION EXECUTOR ---")
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "UNKNOWN")
    
    if action == "BLOCK_IP":
        logger.warning(f"🚨 [MOCK API TƯỜNG LỬA] ĐANG CHẶN IP dựa trên quyết định: {latest_decision.get('reasoning')}")
    elif action == "ALERT":
        logger.info(f"⚠️ [MOCK SIEM] Đẩy CẢNH BÁO lên dashboard: {latest_decision.get('reasoning')}")
        
    return {}


def node_human_in_the_loop(state: SentinelState) -> Dict[str, Any]:
    """
    HITL Node: Treo lại các cảnh báo phức tạp hoặc Parse Failures.
    """
    logger.info("--- NODE: HUMAN IN THE LOOP (AWAIT_HITL) ---")
    latest_decision = state.decisions[-1] if state.decisions else {}
    logger.warning(f"⏸️ [HÀNG ĐỢI SOC ANALYST] Cần con người kiểm duyệt: {latest_decision.get('reasoning')}")
    return {}


# ==============================================================================
# CONDITIONAL EDGES (ROUTING)
# ==============================================================================

def route_triage_decision(state: SentinelState) -> str:
    """
    Quyết định nhánh đi tiếp theo dựa trên Action từ LLM.
    """
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "LOG")
    
    if action in ["BLOCK_IP", "ALERT"]:
        return "execute_action"
    elif action == "AWAIT_HITL":
        return "await_hitl"
    else:
        return "end_cycle"
