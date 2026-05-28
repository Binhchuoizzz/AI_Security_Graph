"""
LangGraph Nodes for SENTINEL Agent

Chứa logic của từng trạm xử lý trong StateGraph.
Tuân thủ Batching Strategy: Incident-Level Aggregation (1 Batch = 1 Quyết định).
"""

import os
import json
import logging
from typing import Dict, Any

from src.agent.state import SentinelState
from src.agent.llm_client import llm_client
from src.agent.prompts import build_triage_prompt
from src.agent.threat_memory import threat_memory
from src.rag.retriever import DualRetriever
from src.guardrails.prompt_filter import GuardrailsPipeline, DelimitedDataEncapsulator
from src.guardrails.output_sanitizer import output_sanitizer
from src.response.executor import block_ip, raise_alert
from src.tier1_filter.feedback_listener import FeedbackListener

logger = logging.getLogger(__name__)

# Khởi tạo Retriever (Singleton)
retriever = DualRetriever(use_cache=True)

# Khởi tạo Guardrails (Singleton)
guardrails_pipeline = GuardrailsPipeline()


def node_guardrails(state: SentinelState) -> Dict[str, Any]:
    """
    Guardrails Node: Nén log và làm sạch trước khi đưa vào RAG/LLM.
    """
    logger.info("--- NODE: GUARDRAILS (MINING & FILTERING) ---")

    if not state.current_batch_logs:
        return {"current_batch_encapsulated": ""}

    # Đối với batch hiện tại, ta dùng GuardrailsPipeline để xử lý và đóng gói
    # GuardrailsPipeline.process_batch trả về một dictionary chứa kết quả
    processed_data = guardrails_pipeline.process_batch(state.current_batch_logs)

    return {
        "current_batch_encapsulated": processed_data["batch_encapsulated"],
        "_guardrails_system_instruction": processed_data["system_instruction"],
    }


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
        query_text = (
            str(first_log.get("message", "")) + " " + str(first_log.get("payload", ""))
        )
    elif state.narrative_summary:
        query_text = state.narrative_summary
    else:
        query_text = "suspicious network activity"

    # Lấy đủ context (200 chars) để query RAG chính xác cho multi-source correlation
    query_text = query_text.strip()[:200]

    # Truy xuất RAG
    results = retriever.retrieve(query_text)

    # Trả về các trường cần update vào State
    return {
        "rag_mitre_context": results.get("mitre_context", ""),
        "rag_nist_context": results.get("nist_context", ""),
    }


import mlflow
import time


def node_llm_triage(state: SentinelState) -> Dict[str, Any]:
    """
    LLM Triage Node: Phân tích toàn bộ cụm log (Incident-Level) và đưa ra 1 quyết định duy nhất.
    Tích hợp MLflow để theo dõi Reasoning Latency và Performance Metrics (RQ1, RQ4).
    Tích hợp Long-Term Threat Memory để inject IP reputation context.
    """
    logger.info("--- NODE: LLM TRIAGE ---")

    # 0. Query Long-Term Threat Memory cho source IPs trong batch
    threat_context_parts = []
    seen_ips = set()
    for log in state.current_batch_logs:
        src_ip = log.get("Source IP") or log.get("src_ip", "")
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            # Check if this IP is a known internal entity (legitimate traffic)
            entity = threat_memory.is_known_entity(src_ip)
            if entity:
                threat_context_parts.append(
                    f"⚠️ IP {src_ip} is a KNOWN INTERNAL ENTITY "
                    f"({entity['entity_type']}: {entity['description']}). "
                    f"Consider as LEGITIMATE traffic unless proven otherwise."
                )
            # Get IP reputation from long-term memory
            ip_context = threat_memory.get_context_for_prompt(src_ip)
            if ip_context:
                threat_context_parts.append(ip_context)
    
    threat_memory_context = "\n".join(threat_context_parts)

    # 1. Đóng gói Raw Logs (kết hợp với Guardrails Encapsulation)
    raw_logs_str = state.current_batch_encapsulated
    if not raw_logs_str:
        # SAFETY: Nếu encapsulated rỗng, wrap thủ công thay vì bypass guardrails
        from src.guardrails.prompt_filter import DelimitedDataEncapsulator

        emergency_enc = DelimitedDataEncapsulator()
        raw_content = "\n".join([str(log) for log in state.current_batch_logs])
        raw_logs_str = emergency_enc.encapsulate(raw_content)

    # 2. Xây dựng Prompt (inject Guardrails system_instruction vào LLM)
    rag_combined = f"MITRE ATT&CK:\n{state.rag_mitre_context}\n\nNIST SP 800-61r2:\n{state.rag_nist_context}"
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_combined)

    # CRITICAL: Inject Guardrails system instruction vào system prompt
    guardrails_instruction = getattr(state, "_guardrails_system_instruction", "")
    logger.info(f"Guardrails instruction length: {len(guardrails_instruction)}")
    if guardrails_instruction:
        messages[0]["content"] = (
            guardrails_instruction + "\n\n" + messages[0]["content"]
        )

    if state.narrative_summary:
        messages[0][
            "content"
        ] += f"\n\n=== PREVIOUS CONTEXT ===\n{state.narrative_summary}"

    # 3. Gọi LLM và Đo lường Latency với MLflow
    start_time = time.time()

    raw_response = llm_client.invoke(messages=messages, temperature=0.1)

    end_time = time.time()
    latency_sec = end_time - start_time

    # 4. Parse JSON an toàn (3-Layer Fallback)
    decision_json = llm_client.parse_llm_response(raw_response)

    # 5. Cập nhật State
    action = decision_json.get("action", "AWAIT_HITL")
    confidence = 0.0
    try:
        confidence = float(decision_json.get("confidence", 0.0))
    except (ValueError, TypeError):
        pass
    reasoning = decision_json.get("reasoning", "No reasoning provided.")
    new_iocs = decision_json.get("extracted_iocs", [])

    # Ghi nhận vào MLflow (Tracking)
    try:
        # Tự động set URI nếu chạy trong Docker, nếu chạy ngoài thì localhost
        mlflow.set_tracking_uri(
            os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001")
        )
        mlflow.set_experiment("Sentinel_Reasoning_Latency")
        with mlflow.start_run(run_name=f"Triage_Cycle_{state.cycle_count}", nested=True):
            mlflow.log_metric("reasoning_latency_sec", latency_sec)
            mlflow.log_metric("confidence_score", confidence)
            mlflow.log_param("action_taken", action)
            mlflow.log_param("batch_size", len(state.current_batch_logs))
    except Exception as e:
        logger.warning(f"MLflow tracking failed (Ignored in dev mode): {e}")

    target = "UNKNOWN_TARGET"
    if new_iocs and isinstance(new_iocs, list) and len(new_iocs) > 0:
        target = new_iocs[0].get("value", "UNKNOWN_TARGET")

    if target == "UNKNOWN_TARGET" and state.current_batch_logs:
        # Fallback to Source IP or src_ip if no IOC was explicitly extracted
        log_entry = state.current_batch_logs[0]
        target = log_entry.get("Source IP") or log_entry.get("src_ip", "UNKNOWN_TARGET")

    decision_entry = {
        "action": action,
        "confidence": confidence,
        "reasoning": reasoning,
        "target": target,
        "mitre_technique": decision_json.get("mitre_technique", ""),
        "nist_control": decision_json.get("nist_control", ""),
        "cycle_count": state.cycle_count + 1,
    }

    new_narrative = f"Last Incident: {action} based on RAG - {decision_json.get('mitre_technique', 'None')}. Reasoning: {reasoning}"

    # 6. Sanitize LLM output trước khi lưu (chống Data Exfil via Markdown)
    new_narrative = output_sanitizer.sanitize(new_narrative)
    reasoning = output_sanitizer.sanitize(reasoning)

    # 7. Record incident vào Long-Term Threat Memory
    if target != "UNKNOWN_TARGET" and action in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
        threat_memory.record_incident(
            ip=target,
            action=action,
            mitre_technique=decision_json.get("mitre_technique", "")
        )
        # Check APT pattern
        apt_check = threat_memory.check_apt_pattern(target)
        if apt_check and apt_check["is_apt_candidate"]:
            logger.warning(
                f"[APT DETECTION] IP {target} flagged as APT candidate: "
                f"{apt_check['total_incidents']} incidents over {apt_check['days_active']} days"
            )
            threat_memory.record_apt_indicator(
                indicator_type="persistent_ip",
                indicator_value=target,
                confidence=confidence,
                related_ips=target,
                mitre_chain=decision_json.get("mitre_technique", "")
            )

    return {
        "decisions": [decision_entry],
        "extracted_iocs": new_iocs,
        "narrative_summary": new_narrative,
        "threat_memory_context": threat_memory_context,
        "cycle_count": state.cycle_count + 1,
    }


def node_action_executor(state: SentinelState) -> Dict[str, Any]:
    """
    Action Executor Node: Xử lý các action BLOCK_IP hoặc ALERT.
    Trong framework luận văn, node này sẽ in log giả lập hoặc đẩy API về tường lửa.
    """
    logger.info("--- NODE: ACTION EXECUTOR ---")
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "UNKNOWN")
    
    # Format reasoning — sanitize output trước khi ghi DB (Data Exfil defense)
    mitre = latest_decision.get("mitre_technique", "N/A")
    conf = latest_decision.get("confidence", 0.0)
    raw_reasoning = latest_decision.get("reasoning", "No reasoning provided.")
    safe_reasoning = output_sanitizer.sanitize(raw_reasoning)
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2f}] {safe_reasoning}"

    if action == "BLOCK_IP":
        block_ip(
            latest_decision.get("target", "UNKNOWN_IP"),
            formatted_reasoning,
        )

        # Nếu LLM phân tích ra rule chặn động, đẩy về Tier 1
        rule_pattern = latest_decision.get("target", "UNKNOWN_IP")
        # Gọi feedback listener
        FeedbackListener().receive_new_rule(
            "Source IP",
            rule_pattern,
            score=100,
            reason=raw_reasoning,
        )

    elif action == "ALERT":
        raise_alert(
            latest_decision.get("target", "UNKNOWN_TARGET"),
            formatted_reasoning,
        )

    return {}


def node_human_in_the_loop(state: SentinelState) -> Dict[str, Any]:
    """
    HITL Node: Treo lại các cảnh báo phức tạp hoặc Parse Failures.
    """
    logger.info("--- NODE: HUMAN IN THE LOOP (AWAIT_HITL) ---")
    latest_decision = state.decisions[-1] if state.decisions else {}
    
    mitre = latest_decision.get("mitre_technique", "N/A")
    conf = latest_decision.get("confidence", 0.0)
    raw_reasoning = latest_decision.get("reasoning", "No reasoning provided.")
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2f}] {raw_reasoning}"
    
    logger.warning(
        f" [HÀNG ĐỢI SOC ANALYST] Cần con người kiểm duyệt: {formatted_reasoning}"
    )
    
    # Mặc dù AWAIT_HITL không block, nhưng vẫn cần ghi log vào DB để UI hiển thị
    from src.response.executor import _log_to_db
    _log_to_db("AWAIT_HITL", latest_decision.get("target", "UNKNOWN_TARGET"), formatted_reasoning)
    
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
