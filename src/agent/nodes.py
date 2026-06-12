"""
LangGraph Nodes for SENTINEL Agent
"""

import os
import logging
import time
import mlflow  # type: ignore
from typing import Dict, Any

from src.agent.state import SentinelState
from src.agent.llm_client import llm_client
from src.agent.prompts import build_triage_prompt
from src.agent.threat_memory import threat_memory
from src.rag.retriever import DualRetriever
from src.guardrails import (
    GuardrailsPipeline,
    DelimitedDataEncapsulator,
    output_sanitizer,
    loop_detector,
    context_overflow_guard,
    audit_logger,
    DecisionValidator,
)
from src.response.executor import block_ip, raise_alert
from src.tier1_filter.feedback_listener import FeedbackListener

logger = logging.getLogger(__name__)

# Khởi tạo Retriever (Singleton)
retriever = DualRetriever(use_cache=True)

# Khởi tạo Guardrails / DecisionValidator (Singleton)
guardrails_pipeline = GuardrailsPipeline()
decision_validator = DecisionValidator()


def node_guardrails(state: SentinelState) -> Dict[str, Any]:
    """
    Guardrails Node: Nén log và làm sạch trước khi đưa vào RAG/LLM.
    """
    logger.info("--- NODE: GUARDRAILS (MINING & FILTERING) ---")
    
    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_guardrails")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if not state.current_batch_logs:
        return {"current_batch_encapsulated": ""}

    # 2. Xử lý và nén log qua pipeline
    processed_data = guardrails_pipeline.process_batch(state.current_batch_logs)
    batch_enc = processed_data["batch_encapsulated"]

    # 3. Giám sát tràn Context Window (Context Overflow Guard)
    # Ước lượng token: 2000 tokens cơ bản của prompt + kích thước của log đóng gói
    prompt_tokens_est = 2000
    log_tokens_est = len(batch_enc) // 4
    overflow_res = context_overflow_guard.check(prompt_tokens_est, log_tokens_est)

    if overflow_res["is_overflow"]:
        logger.warning(
            f"[GUARDRAILS] Log volume overflow detected by ContextOverflowGuard! "
            f"Est tokens: {overflow_res['total_tokens']}/{overflow_res['max_allowed']}. Truncating logs..."
        )
        # Giới hạn cứng logs đóng gói ở mức an toàn
        batch_enc = batch_enc[:4000] + "\n... [TRUNCATED DUE TO CONTEXT OVERFLOW]"

    return {
        "current_batch_encapsulated": batch_enc,
        "_guardrails_system_instruction": processed_data["system_instruction"],
    }


def node_rag_context(state: SentinelState) -> Dict[str, Any]:
    """
    RAG Context Node: Trích xuất thông tin từ batch log để query RAG.
    """
    logger.info("--- NODE: RAG CONTEXT ---")
    
    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_rag_context")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    query_text = ""
    if state.current_batch_logs:
        first_log = state.current_batch_logs[0]
        parts = []
        # 1. Web/app attacks: nội dung payload/message (nếu có)
        msg = (str(first_log.get("message", "")) + " " + str(first_log.get("payload", ""))).strip()
        if msg:
            parts.append(msg)
        # 2. Flow-based attacks (CICIDS): không có payload -> dựng query từ
        #    metadata flow THẬT (service/port/protocol) để RAG map đúng MITRE.
        svc = first_log.get("service") or first_log.get("Service")
        if svc:
            parts.append(f"service {svc}")
        port = first_log.get("Destination Port") or first_log.get("dst_port")
        if port not in (None, "", 0):
            parts.append(f"destination port {port}")
        uri = first_log.get("uri") or first_log.get("URI")
        if uri:
            parts.append(f"uri {uri}")
        # 3. Bối cảnh phát hiện của Tier-1 (lý do escalate: brute force, port scan,
        #    volumetric, WAF/injection...) — tín hiệu mạnh để truy xuất kỹ thuật phù hợp.
        for reason in (first_log.get("tier1_reasons") or [])[:3]:
            parts.append(str(reason))
        query_text = " ".join(parts).strip()

    if not query_text:
        query_text = state.narrative_summary or "suspicious network activity"

    query_text = query_text.strip()[:300]

    # 2. Truy xuất RAG (đã được RAGSanitizer xử lý ngầm định trong retriever)
    results = retriever.retrieve(query_text)

    return {
        "rag_mitre_context": results.get("mitre_context", ""),
        "rag_nist_context": results.get("nist_context", ""),
    }


def node_llm_triage(state: SentinelState) -> Dict[str, Any]:
    """
    LLM Triage Node: Phân tích toàn bộ cụm log (Incident-Level) và đưa ra 1 quyết định duy nhất.
    """
    logger.info("--- NODE: LLM TRIAGE ---")
    
    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_llm_triage")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    # Query Long-Term Threat Memory cho source IPs trong batch
    threat_context_parts = []
    seen_ips = set()
    for log in state.current_batch_logs:
        src_ip = log.get("Source IP") or log.get("src_ip", "")
        if src_ip and src_ip not in seen_ips:
            seen_ips.add(src_ip)
            entity = threat_memory.is_known_entity(src_ip)
            if entity:
                threat_context_parts.append(
                    f"⚠️ IP {src_ip} is a KNOWN INTERNAL ENTITY "
                    f"({entity['entity_type']}: {entity['description']}). "
                    f"Consider as LEGITIMATE traffic unless proven otherwise."
                )
            ip_context = threat_memory.get_context_for_prompt(src_ip)
            if ip_context:
                threat_context_parts.append(ip_context)
    
    threat_memory_context = "\n".join(threat_context_parts)

    # Đóng gói Raw Logs (kết hợp với Guardrails Encapsulation)
    raw_logs_str = state.current_batch_encapsulated
    if not raw_logs_str:
        emergency_enc = DelimitedDataEncapsulator()
        raw_content = "\n".join([str(log) for log in state.current_batch_logs])
        raw_logs_str = emergency_enc.encapsulate(raw_content)

    # Xây dựng Prompt (inject Guardrails system_instruction vào LLM)
    rag_combined = f"MITRE ATT&CK:\n{state.rag_mitre_context}\n\nNIST SP 800-61r2:\n{state.rag_nist_context}"
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_combined)

    guardrails_instruction = getattr(state, "_guardrails_system_instruction", "")
    logger.info(f"Guardrails instruction length: {len(guardrails_instruction)}")
    if guardrails_instruction:
        messages[0]["content"] = (
            guardrails_instruction + "\n\n" + messages[0]["content"]
        )

    if state.narrative_summary:
        messages[0]["content"] += f"\n\n=== PREVIOUS CONTEXT ===\n{state.narrative_summary}"

    start_time = time.time()
    raw_response = llm_client.invoke(messages=messages, temperature=0.1)
    end_time = time.time()
    latency_sec = end_time - start_time

    # Parse JSON an toàn
    decision_json = llm_client.parse_llm_response(raw_response)

    # 2. CHẠY QUYẾT ĐỊNH QUA LLM DECISION VALIDATOR (Enforce Enum, Shield critical, Sanitize reasoning)
    validated_decision = decision_validator.validate_decision(decision_json)

    # 2b. LÁ CHẮN BẤT ĐỒNG TIER-1/TIER-2 (chống social-engineering ngữ nghĩa):
    # Nếu Tier-1 (xác định) coi luồng là tấn công nhưng LLM hạ cấp xuống bỏ qua,
    # buộc AWAIT_HITL — Tier-1 không thể bị "nói chuyện" hạ cấp như LLM.
    tier1_flagged_attack = any(
        log.get("tier1_action") in ("BLOCK_IP", "ESCALATE", "AWAIT_HITL", "ALERT")
        or float(log.get("tier1_score", 0) or 0) >= 30
        for log in state.current_batch_logs
    )
    validated_decision = decision_validator.enforce_tier_consensus(
        validated_decision, tier1_flagged_attack
    )

    action = validated_decision.get("action", "AWAIT_HITL")
    confidence = validated_decision.get("confidence", 0.0)
    reasoning = validated_decision.get("reasoning", "No reasoning provided.")
    new_iocs = validated_decision.get("extracted_iocs", [])

    # Ghi nhận vào MLflow (Tracking)
    try:
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
        logger.warning(f"MLflow tracking failed: {e}")

    target = "UNKNOWN_TARGET"
    if new_iocs and isinstance(new_iocs, list) and len(new_iocs) > 0:
        target = new_iocs[0].get("value", "UNKNOWN_TARGET")

    if target == "UNKNOWN_TARGET" and state.current_batch_logs:
        log_entry = state.current_batch_logs[0]
        target = log_entry.get("Source IP") or log_entry.get("src_ip", "UNKNOWN_TARGET")

    decision_entry = {
        "action": action,
        "confidence": confidence,
        "reasoning": reasoning,
        "target": target,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "cycle_count": state.cycle_count + 1,
    }

    new_narrative = f"Last Incident: {action} based on RAG - {validated_decision.get('mitre_technique', 'None')}. Reasoning: {reasoning}"
    # Đã sanitize trong decision_validator, nhưng vẫn bảo vệ kép cho narrative summary
    new_narrative = output_sanitizer.sanitize(new_narrative)

    # 3. GHI LOG KIỂM TOÁN (Audit Trail)
    # Lấy thông số từ Tier-1 log để đối chiếu trong ablation study
    t1_score = 0
    t1_action = "LOG"
    if state.current_batch_logs:
        first_log = state.current_batch_logs[0]
        t1_score = first_log.get("tier1_score", 0)
        t1_action = first_log.get("tier1_action", "LOG")

    audit_event = {
        "event_type": "LLM_TRIAGE_DECISION",
        "source_ip": target,
        "tier1_score": t1_score,
        "tier1_action": t1_action,
        "guardrail_injected": validated_decision.get("_injection_detected", False) or decision_json.get("_injection_detected", False),
        "agent_decision": action,
        "agent_reasoning": reasoning,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "hitl_approved": False if action == "AWAIT_HITL" else None,
        "latency_ms": latency_sec * 1000,
        "metadata": {
            "total_logs_in_batch": len(state.current_batch_logs),
            "cycle_count": state.cycle_count,
            "raw_decision": decision_json
        }
    }
    audit_logger.log_event(audit_event)

    # Record incident vào Long-Term Threat Memory
    if target != "UNKNOWN_TARGET" and action in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
        threat_memory.record_incident(
            ip=target,
            action=action,
            mitre_technique=validated_decision.get("mitre_technique", "")
        )
        apt_check = threat_memory.check_apt_pattern(target)
        # Chuỗi APT đa-ngày EMERGENT (threat_events — tích lũy từ luồng gộp online)
        apt_chain = threat_memory.check_apt_chain(target)
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
                mitre_chain=validated_decision.get("mitre_technique", "")
            )
        elif apt_chain.get("is_apt"):
            logger.warning(
                f"[APT DETECTION] IP {target} part of multi-day APT chain: "
                f"{apt_chain['chain_length']} days, phases={apt_chain.get('phases_seen', '')}"
            )
            threat_memory.record_apt_indicator(
                indicator_type="multi_day_chain",
                indicator_value=target,
                confidence=confidence,
                related_ips=target,
                mitre_chain=str(apt_chain.get("phases_seen", ""))[:120],
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
    """
    logger.info("--- NODE: ACTION EXECUTOR ---")
    
    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_action_executor")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "UNKNOWN")
    
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

        rule_pattern = latest_decision.get("target", "UNKNOWN_IP")
        
        # Gọi feedback listener (chạy qua FeedbackValidator ngầm định)
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
    
    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_human_in_the_loop")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    latest_decision = state.decisions[-1] if state.decisions else {}
    
    mitre = latest_decision.get("mitre_technique", "N/A")
    conf = latest_decision.get("confidence", 0.0)
    raw_reasoning = latest_decision.get("reasoning", "No reasoning provided.")
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2f}] {raw_reasoning}"
    
    logger.warning(
        f" [HÀNG ĐỢI SOC ANALYST] Cần con người kiểm duyệt: {formatted_reasoning}"
    )
    
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
