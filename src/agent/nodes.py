"""
LangGraph Nodes for SENTINEL Agent
"""

import logging
import os
import time
from typing import Any

import mlflow  # type: ignore

from src.agent.attack_mapper import (
    AttackMapperInput,
    map_attack,
)
from src.agent.llm_client import DECISION_JSON_SCHEMA, llm_client
from src.agent.prompts import build_triage_prompt
from src.agent.response_cache import response_cache
from src.agent.state import SentinelState
from src.agent.threat_memory import threat_memory
from src.guardrails import (
    DecisionValidator,
    DelimitedDataEncapsulator,
    GuardrailsPipeline,
    audit_logger,
    context_overflow_guard,
    decision_policy,
    loop_detector,
    output_sanitizer,
)
from src.guardrails.constants import normalize_log_keys
from src.rag.retriever import DualRetriever
from src.response.executor import block_ip, raise_alert
from src.tier1_filter.feedback_listener import FeedbackListener

logger = logging.getLogger(__name__)

# Khởi tạo Retriever (Singleton)
retriever = DualRetriever(use_cache=True)

# Số ký tự payload thô tối đa đưa vào TRUY VẤN RAG (không ảnh hưởng prompt gửi LLM — LLM
# vẫn nhận log đầy đủ). Giữ nhỏ để từ vựng payload không lấn át nhãn phát hiện của Tier-1
# khi truy xuất MITRE (xem chú thích chi tiết ở node_rag_context).
PAYLOAD_QUERY_CHARS = 120

# Nhãn phát hiện của Tier-1 là TIẾNG VIỆT ("WAF: Phát hiện SQL Injection (SQLi) trong
# 'message'"), còn kho MITRE/NIST là TIẾNG ANH và embedder all-MiniLM-L6-v2 thiên tiếng
# Anh -> nhãn gần như KHÔNG đóng góp tín hiệu truy xuất, để payload lấn át (đo thật: SQLi
# ra T1110.x/T1555 thay vì T1190). Ánh xạ sang cụm từ CHUẨN tiếng Anh đúng từ vựng MITRE
# để truy vấn neo vào kỹ thuật, không neo vào từ ngữ trong payload.
_ATTACK_TERMS: tuple[tuple[str, str], ...] = (
    ("sql injection", "SQL injection exploit public-facing application web vulnerability"),
    ("sqli", "SQL injection exploit public-facing application web vulnerability"),
    ("cross-site scripting", "cross-site scripting XSS drive-by compromise web client exploit"),
    ("xss", "cross-site scripting XSS drive-by compromise web client exploit"),
    ("path traversal", "path traversal local file inclusion exploit public-facing application"),
    ("lfi", "path traversal local file inclusion exploit public-facing application"),
    ("command injection", "command and scripting interpreter command injection exploit"),
    ("brute", "brute force password guessing valid accounts remote services"),
    ("quét cổng", "network service discovery port scanning reconnaissance"),
    ("port scan", "network service discovery port scanning reconnaissance"),
    ("cổng nhạy cảm", "remote services SSH RDP SMB valid accounts lateral movement"),
)


def _canonical_attack_terms(reasons: list) -> list[str]:
    """Suy cụm từ MITRE tiếng Anh từ các lý do phát hiện (tiếng Việt) của Tier-1."""
    joined = " ".join(str(r) for r in reasons).lower()
    out: list[str] = []
    for needle, terms in _ATTACK_TERMS:
        if needle in joined and terms not in out:
            out.append(terms)
    return out


# Khởi tạo Guardrails / DecisionValidator (Singleton)
guardrails_pipeline = GuardrailsPipeline()
decision_validator = DecisionValidator()


def node_guardrails(state: SentinelState) -> dict[str, Any]:
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


def node_rag_context(state: SentinelState) -> dict[str, Any]:
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
        # 1. TÍN HIỆU PHÂN LOẠI của Tier-1 đứng ĐẦU (vd "WAF: Phát hiện SQL Injection").
        #    BUG ĐÃ SỬA: trước đây payload THÔ đứng đầu và chiếm hết ngân sách 300 ký tự.
        #    Payload tấn công chứa những từ như 'password'/'cookie'/'admin' kéo truy xuất
        #    ngữ nghĩa sang nhóm ĐÁNH CẮP THÔNG TIN ĐĂNG NHẬP: đo thật với một payload SQLi
        #    (`SELECT password FROM users`) RAG trả về T1539/T1110.004/T1555 và KHÔNG hề có
        #    T1190 — bỏ chữ 'password' ra thì T1190 lên hạng 1. RAG sai ngữ cảnh -> LLM
        #    (đúng như prompt dặn) từ chối map kỹ thuật -> AWAIT_HITL -> LLM KHÔNG BAO GIỜ
        #    chặn được. Đặt nhãn phát hiện lên trước để truy vấn neo vào NGỮ NGHĨA tấn công.
        _reasons = (first_log.get("tier1_reasons") or [])[:3]
        parts.extend(_canonical_attack_terms(_reasons))  # cụm chuẩn tiếng Anh TRƯỚC
        for reason in _reasons:
            parts.append(str(reason))
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
        # 3. Payload/message THÔ đứng CUỐI và bị CẮT NGẮN: vẫn giữ tín hiệu từ vựng của
        #    cuộc tấn công (UNION SELECT, <script>…) nhưng KHÔNG cho nó lấn át truy vấn.
        msg = (str(first_log.get("message", "")) + " " + str(first_log.get("payload", ""))).strip()
        if msg:
            parts.append(msg[:PAYLOAD_QUERY_CHARS])
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


def _degraded_reason(decision: dict) -> str:
    """Câu giải thích cho analyst khi quyết định KHÔNG có phần lập luận của LLM.

    Chỉ xảy ra ở đường suy biến an toàn (LLM trả JSON hỏng / rỗng). Nói rõ nguyên nhân
    thay vì "No reasoning provided." — analyst cần biết đây là LỖI ĐỊNH DẠNG của model,
    không phải hệ thống đánh giá sự cố là vô hại, và vì sao độ tin cậy = 0.
    """
    err = str(decision.get("error", "") or "")
    if err == "parse_failed":
        return (
            "Tác tử AI đã phân tích nhưng model trả về JSON KHÔNG hợp lệ — không trích được "
            "phần lập luận. Hệ thống suy biến an toàn: chuyển sự cố cho người xử lý thay vì "
            "tự quyết. Độ tin cậy 0 phản ánh việc KHÔNG có phán quyết hợp lệ, KHÔNG có nghĩa "
            "là sự cố vô hại. Xem LOG THÔ bên dưới để phân tích thủ công."
        )
    if err:
        return (
            f"Không có lập luận của tác tử AI (lỗi: {err}). Hệ thống suy biến an toàn: chuyển "
            f"người xử lý. Xem LOG THÔ bên dưới."
        )
    return (
        "Model không trả về phần lập luận cho quyết định này. Chuyển người xử lý để đảm bảo "
        "an toàn. Xem LOG THÔ bên dưới."
    )


def node_llm_triage(state: SentinelState) -> dict[str, Any]:
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
    rag_combined = (
        f"MITRE ATT&CK:\n{state.rag_mitre_context}\n\nNIST SP 800-61r2:\n{state.rag_nist_context}"
    )
    messages = build_triage_prompt(log_data=raw_logs_str, rag_context=rag_combined)

    guardrails_instruction = getattr(state, "_guardrails_system_instruction", "")
    logger.info(f"Guardrails instruction length: {len(guardrails_instruction)}")
    if guardrails_instruction:
        messages[0]["content"] = guardrails_instruction + "\n\n" + messages[0]["content"]

    if state.narrative_summary:
        messages[0]["content"] += f"\n\n=== PREVIOUS CONTEXT ===\n{state.narrative_summary}"

    decision_json = {}
    _feature_log = state.current_batch_logs[0] if state.current_batch_logs else {}
    cached_decision = response_cache.get(raw_logs_str)
    if not cached_decision:
        # Lớp 2 — gộp theo ĐẶC TRƯNG: các flow cùng bản chất (khác mỗi IP/timestamp, vd
        # hàng trăm DAPT nền benign) dùng chung 1 verdict -> KHÔNG tốn 1 call LLM mỗi cái.
        cached_decision = response_cache.get_by_features(_feature_log)
    if cached_decision:
        validated_decision = cached_decision
        decision_json = cached_decision
        raw_response = '{"status": "from_cache"}'
        latency_sec = 0.001
        logger.info("[NODE LLM] Trả về quyết định từ Response Cache (Bypass LLM)")
    else:
        start_time = time.time()
        # Suy biến có kiểm soát (graceful degradation): nếu LLM cục bộ chết/không kết nối
        # được (connection refused, timeout sau retry), KHÔNG để vỡ đồ thị — trả chuỗi rỗng
        # để parse_llm_response cho AWAIT_HITL an toàn. Tier-1 (xác định) vẫn bảo vệ độc lập.
        try:
            # response_format=json_schema -> server ép JSON hợp lệ (hết "parse lỗi"/prose) và
            # reasoning bám tiếng Việt; max_tokens rộng để JSON reasoning dài KHÔNG bị cắt cụt.
            raw_response = llm_client.invoke(
                messages=messages,
                temperature=0.1,
                response_format=DECISION_JSON_SCHEMA,
                max_tokens=1536,
            )
        except Exception as e:
            logger.error(
                f"[LLM UNAVAILABLE] Tier-2 (LLM) call thất bại ({e}). Suy biến an toàn -> AWAIT_HITL; "
                f"Tier-1 vẫn bảo vệ độc lập."
            )
            raw_response = ""
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

        # Ghi vào Cache nếu hợp lệ (KHÔNG cache AWAIT_HITL: mỗi ca cần người xem luôn tươi
        # -> giữ đủ HITL hiển thị). Ghi cả exact-match lẫn feature-cache (gộp flow tương lai).
        if validated_decision.get("action") != "AWAIT_HITL":
            response_cache.set(raw_logs_str, validated_decision)
            response_cache.set_by_features(_feature_log, validated_decision)

    action = validated_decision.get("action", "AWAIT_HITL")
    confidence = validated_decision.get("confidence", 0.0)

    # ── CHÍNH SÁCH ĐỘ-TIN-CẬY THỐNG NHẤT (chung Cổng ML + LLM) ────────────────────
    # Confidence LÁI action thay vì để LLM tự chọn (sửa lỗi "0.75 + T1571 chung chung -> BLOCK").
    #   LLM cho là ĐE DOẠ (BLOCK_IP/ALERT) -> map theo ngưỡng: >=0.85 BLOCK · 0.65–0.85 ALERT ·
    #     <0.65 AWAIT_HITL (không chắc -> người).  DROP/LOG (sạch) và AWAIT_HITL (LLM tự thấy
    #   không chắc) GIỮ NGUYÊN. Chạy SAU validate + enforce_tier_consensus + shield (vẫn ưu tiên).
    # QUAN TRỌNG: nếu shield critical-asset đã hạ BLOCK->ALERT thì KHÔNG remap (tránh đẩy ngược
    # ALERT->BLOCK, phá bảo vệ hạ tầng).
    if action in ("BLOCK_IP", "ALERT") and not validated_decision.get("_critical_shield"):
        action = decision_policy.classify_llm(is_threat=True, confidence=float(confidence or 0.0))
        validated_decision["action"] = action

    # Khi LLM trả JSON hỏng, parse_llm_response suy biến an toàn về AWAIT_HITL và KHÔNG có
    # khoá 'reasoning'. Mặc định cũ ("No reasoning provided.") khiến Dashboard trông như
    # agent im lặng/hỏng, trong khi thực tế là: agent ĐÃ chạy, LLM ĐÃ trả lời, nhưng câu
    # trả lời sai định dạng -> chuyển người xử lý. Nói thẳng điều đó cho analyst.
    reasoning = validated_decision.get("reasoning") or _degraded_reason(validated_decision)
    new_iocs = validated_decision.get("extracted_iocs", [])

    # Ghi nhận vào MLflow (Tracking)
    try:
        mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5001"))
        mlflow.set_experiment("Sentinel_Reasoning_Latency")
        with mlflow.start_run(run_name=f"Triage_Cycle_{state.cycle_count}", nested=True):
            mlflow.log_metric("reasoning_latency_sec", latency_sec)
            mlflow.log_metric("confidence_score", confidence)
            mlflow.log_param("action_taken", action)
            mlflow.log_param("batch_size", len(state.current_batch_logs))
    except Exception as e:
        logger.warning(f"MLflow tracking failed: {e}")

    # Target để THỰC THI (block/alert) LUÔN lấy từ Source IP của batch HIỆN TẠI, KHÔNG
    # lấy từ extracted_iocs của quyết định: khi Response Cache HIT trên một IP KHÁC có
    # cùng vân log (cùng payload/flow), IOC trong cache là IP CŨ -> nếu dùng làm target
    # sẽ CHẶN NHẦM IP cũ. IOC chỉ là metadata làm giàu, không phải mục tiêu thực thi.
    target = "UNKNOWN_TARGET"
    if state.current_batch_logs:
        log_entry = state.current_batch_logs[0]
        target = log_entry.get("Source IP") or log_entry.get("src_ip") or "UNKNOWN_TARGET"

    # Chỉ log lớp-ứng-dụng THUẦN payload (không có Source IP flow) mới rơi về IOC trích xuất.
    if target == "UNKNOWN_TARGET" and new_iocs and isinstance(new_iocs, list) and len(new_iocs) > 0:
        target = new_iocs[0].get("value", "UNKNOWN_TARGET")

    decision_entry = {
        "action": action,
        "confidence": confidence,
        "reasoning": reasoning,
        "target": target,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "cycle_count": state.cycle_count + 1,
        # Cờ tình trạng parse LLM (parse_failed/parse_salvaged) — để attack_mapper KHÔNG
        # dập một technique "tự tin" lên một triage rỗng/hỏng (tránh MITRE gây hiểu lầm).
        "error": validated_decision.get("error", ""),
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
        "guardrail_injected": validated_decision.get("_injection_detected", False)
        or decision_json.get("_injection_detected", False),
        "agent_decision": action,
        "agent_reasoning": reasoning,
        "mitre_technique": validated_decision.get("mitre_technique", ""),
        "nist_control": validated_decision.get("nist_control", ""),
        "hitl_approved": False if action == "AWAIT_HITL" else None,
        "latency_ms": latency_sec * 1000,
        "metadata": {
            "total_logs_in_batch": len(state.current_batch_logs),
            "cycle_count": state.cycle_count,
            "raw_decision": decision_json,
        },
    }
    audit_logger.log_event(audit_event)

    # Record incident logic moved to node_action_executor & node_human_in_the_loop

    return {
        "decisions": [decision_entry],
        "extracted_iocs": new_iocs,
        "narrative_summary": new_narrative,
        "threat_memory_context": threat_memory_context,
        "cycle_count": state.cycle_count + 1,
    }


def node_attack_mapper(state: SentinelState) -> dict[str, Any]:
    """
    ATT&CK Mapper Node: chạy SAU node_llm_triage cho các quyết định tin cậy cao.

    Biến `mitre_technique` free-text của triage thành bản đồ MITRE ATT&CK CÓ CẤU
    TRÚC (tactic/technique/sub-technique/URL/mapping_confidence/recommended_response),
    bồi đắp vào quyết định mới nhất để node HITL / Action Executor dùng được.

    TÁI DÙNG hạ tầng sẵn có: `retriever` (DualRetriever) + `llm_client`. KHÔNG gọi
    LLM thêm trong đường XÁC ĐỊNH (web attack phổ biến) -> giữ độ trễ thấp.
    """
    logger.info("--- NODE: ATT&CK MAPPER ---")

    # 1. Phát hiện vòng lặp vô hạn (Loop Detection)
    visit_res = loop_detector.record_visit("node_attack_mapper")
    if visit_res["action"] == "FORCE_STOP":
        raise RuntimeError(visit_res["reason"])

    if not state.decisions:
        return {}

    decision = dict(state.decisions[-1])  # copy để bồi đắp, giữ action/target/confidence

    # GATE: nếu triage KHÔNG đọc được (parse_failed) thì KHÔNG dập một MITRE "tự tin" lên một
    # triage rỗng — sẽ gây hiểu lầm (vd T1548.003 "Sudo Caching" trên một flow mạng). Để
    # technique NEUTRAL, giữ reasoning trung thực; con người xác minh (đã AWAIT_HITL).
    if decision.get("error") == "parse_failed":
        logger.warning(
            "[ATT&CK MAPPER] Bỏ qua ánh xạ vì triage parse_failed — tránh MITRE gây hiểu lầm."
        )
        decision.update(
            {
                "mitre_technique": "N/A — chưa phân loại (LLM parse lỗi)",
                "mitre_technique_id": "",
                "mitre_tactic": "",
                "mitre_tactic_id": "",
                "mitre_subtechnique": "",
                "mitre_subtechnique_id": "",
                "mitre_url": "",
                "mapping_confidence": 0.0,
                "mapping_status": "unmapped_parse_failed",
                "recommended_response": "Chờ người xác minh (AWAIT_HITL).",
            }
        )
        return {"decisions": [decision]}

    # Kỹ thuật LLM tự suy (GIỮ LẠI trước khi mapper chuẩn hoá). Nếu triage đã nêu 1
    # technique CỤ THỂ (Txxxx / AML.Txxxx) thì ƯU TIÊN giữ nó cho badge — để badge KHỚP
    # với phần reasoning người xem đọc, và tránh mọi alert bị gom hết về AML.T0051 chỉ vì
    # tín hiệu injection lọt trong tier1_reasons. Chỉ dùng kết quả mapper khi LLM để N/A.
    import re as _re

    _llm_tech_raw = str(decision.get("mitre_technique", "")).strip()
    _llm_tech_m = _re.search(r"\b(AML\.T\d{4}|T\d{4}(?:\.\d{3})?)\b", _llm_tech_raw, _re.IGNORECASE)

    # Dựng đầu vào mapper từ triage + batch log thật.
    first_log = state.current_batch_logs[0] if state.current_batch_logs else {}
    payload = (str(first_log.get("message", "")) + " " + str(first_log.get("payload", ""))).strip()
    # Tín hiệu loại tấn công: free-text mitre_technique + reasoning + tier1_reasons.
    type_hint = " ".join(
        [
            str(decision.get("mitre_technique", "")),
            str(decision.get("reasoning", "")),
            " ".join(str(r) for r in (first_log.get("tier1_reasons") or [])[:3]),
        ]
    ).strip()

    mapper_input = AttackMapperInput(
        attack_type=type_hint,
        confidence=float(decision.get("confidence", 0.0) or 0.0),
        payload=payload,
        features=first_log if isinstance(first_log, dict) else {},
    )

    try:
        mapping = map_attack(mapper_input, retriever=retriever, llm=llm_client)
    except Exception as e:
        # Suy biến an toàn: mapping hỏng KHÔNG được phá đồ thị — giữ quyết định gốc.
        logger.error(f"[ATT&CK MAPPER] Lỗi ánh xạ ({e}). Giữ nguyên quyết định triage.")
        return {}

    # Ưu tiên technique CỤ THỂ của LLM cho hiển thị (badge == reasoning); fallback mapper
    # khi LLM để N/A / không nêu technique-id hợp lệ. Enrichment tactic/url/response vẫn
    # luôn lấy từ mapper (có cấu trúc, verify được).
    if _llm_tech_m and _llm_tech_raw.upper() != "N/A":
        _final_tech = _llm_tech_raw
        _final_tech_id = _llm_tech_m.group(1).upper()
    else:
        _final_tech = f"{mapping.mitre_technique_id} - {mapping.mitre_technique}".strip(" -")
        _final_tech_id = mapping.mitre_technique_id

    # Bồi đắp các trường có cấu trúc vào quyết định (free-text được thay bằng chuẩn hoá).
    decision.update(
        {
            "mitre_technique": _final_tech,
            "mitre_tactic": mapping.mitre_tactic,
            "mitre_tactic_id": mapping.mitre_tactic_id,
            "mitre_technique_id": _final_tech_id,
            "mitre_subtechnique": mapping.mitre_subtechnique or "",
            "mitre_subtechnique_id": mapping.mitre_subtechnique_id or "",
            "mitre_url": mapping.mitre_url,
            "mapping_confidence": mapping.mapping_confidence,
            "mapping_status": mapping.mapping_status,
            "recommended_response": mapping.recommended_response,
        }
    )

    logger.info(
        f"[ATT&CK MAPPER] {mapping.mitre_technique_id} ({mapping.mitre_tactic}) "
        f"status={mapping.mapping_status} conf={mapping.mapping_confidence:.2f}"
    )

    # LÁ CHẮN BẢO VỆ CHỐNG HALLUCINATION (TỰ CHÉM):
    # Nếu LLM phân tích nhưng mapper không thể khớp với bất kỳ kỹ thuật MITRE nào,
    # hoặc độ tin cậy của việc khớp rất thấp, ép hành động về AWAIT_HITL để con người duyệt.
    if (
        mapping.mapping_status in ("unresolved", "low_confidence", "unmapped_parse_failed")
        or not _final_tech_id
    ):
        logger.warning(
            f"[ATT&CK MAPPER] Dấu hiệu tự chém/không match kỹ thuật rõ ràng "
            f"(status={mapping.mapping_status}). Ép action về AWAIT_HITL."
        )
        decision["action"] = "AWAIT_HITL"
        if "[CẢNH BÁO]" not in str(decision.get("reasoning", "")):
            decision["reasoning"] = (
                f"[CẢNH BÁO: Không thể ánh xạ kỹ thuật, nghi ngờ tự chém] {decision.get('reasoning', '')}"
            )

    return {"decisions": [decision]}


# ── Học "kỹ thuật" (behavioral signature) — không chỉ nhớ IP ─────────────────
# Điểm cho luật hành vi: đủ vượt risk_threshold để Tier-1 CỜ (flag/ESCALATE) IP
# mới cùng ngón đòn, nhưng KHÔNG cao như luật IP (100) để tránh hard-block mù trên
# một heuristic hành vi (an toàn: vẫn PENDING + HITL duyệt trước khi ACTIVE).
BEHAVIORAL_RULE_SCORE = 50

# Chữ ký công cụ tấn công RÕ RÀNG trên User-Agent (an toàn, khái quát hoá tốt —
# bất kỳ IP nào dùng công cụ này đều đáng ngờ). CỐ Ý loại "curl"/"python-requests"
# vì quá phổ biến trong automation hợp lệ → tránh dương-tính-giả.
_TOOL_SIGNATURES = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "hydra",
    "gobuster",
    "dirbuster",
    "dirb",
    "wpscan",
    "nuclei",
    "zgrab",
    "acunetix",
    "havij",
    "metasploit",
    "fuzz",
)

# Token tấn công đặc trưng trên URI (đủ hẹp để không FP diện rộng ở score 50).
_URI_ATTACK_TOKENS = (
    "union select",
    "../../",
    "..\\..\\",
    "/etc/passwd",
    "<script",
    "cmd.exe",
    "/bin/bash",
    "%00",
    "' or '1'='1",
    "exec(",
    "; ls",
    "wget http",
)


def _check_apt_signal(target: str, mitre_technique: str, confidence: float):
    """Kiểm tra tín hiệu APT (persistent-IP / multi-day chain) và ghi indicator.
    KHÔNG record_incident ở đây — nơi gọi đã ghi (raise_alert / _handle_threat_memory_incident)
    nên tránh đếm TRÙNG total_alerts (điều kiện repeat-offender phụ thuộc số này)."""
    if target == "UNKNOWN_TARGET":
        return
    apt_check = threat_memory.check_apt_pattern(target)
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
            mitre_chain=mitre_technique,
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


def _handle_threat_memory_incident(
    target: str, action: str, mitre_technique: str, confidence: float
):
    """Ghi incident (tăng reputation/total_*) rồi kiểm tra APT. Dùng cho BLOCK_IP/AWAIT_HITL.
    Lưu ý: nhánh ALERT KHÔNG dùng hàm này nữa — raise_alert là choke-point ghi ALERT +
    tự leo thang repeat-offender (tránh đếm trùng total_alerts)."""
    if target == "UNKNOWN_TARGET" or action not in ["BLOCK_IP", "ALERT", "AWAIT_HITL"]:
        return
    threat_memory.record_incident(ip=target, action=action, mitre_technique=mitre_technique)
    _check_apt_signal(target, mitre_technique, confidence)


def _derive_behavioral_rule(log_entry: dict) -> tuple[str, str, int] | None:
    """
    Trích một CHỮ KÝ HÀNH VI an toàn từ log gây ra BLOCK để Tier-1 có thể bắt
    nhanh một IP KHÁC dùng CÙNG kỹ thuật (không chỉ nhớ đúng IP cũ).

    Ưu tiên chữ ký công cụ trên User-Agent (khái quát nhất); fallback token tấn
    công trên URI. Trả `None` nếu không có chữ ký an toàn → chỉ ghi luật IP
    (suy biến nhẹ nhàng). Field trả về LUÔN là nơi token thực sự nằm, để luật
    khớp đúng field của log tương lai. Mọi field/score đều qua FeedbackValidator.
    """
    norm = normalize_log_keys(log_entry)
    ua = str(norm.get("User-Agent", "")).strip()
    uri = str(norm.get("URI", "")).strip()
    ua_l, uri_l = ua.lower(), uri.lower()

    for tool in _TOOL_SIGNATURES:
        if tool in ua_l:
            return ("User-Agent", tool, BEHAVIORAL_RULE_SCORE)
    for tok in _URI_ATTACK_TOKENS:
        if tok in uri_l:
            return ("URI", tok, BEHAVIORAL_RULE_SCORE)
    return None


def _serialize_repr_log(batch_logs: list, target_ip: str) -> str:
    """Chọn LOG THÔ đại diện cho một quyết định (khớp Source IP == target, fallback log
    đầu batch) và tuần tự hoá JSON để đính kèm audit -> Dashboard hiển thị đầu vào thô.
    Suy biến an toàn: batch rỗng / lỗi serialize -> '{}'."""
    import json as _json

    repr_log = next(
        (
            lg
            for lg in (batch_logs or [])
            if str(normalize_log_keys(lg).get("Source IP", "")) == target_ip
        ),
        ((batch_logs or [{}])[0] if batch_logs else {}),
    )
    try:
        return _json.dumps(repr_log, ensure_ascii=False, default=str)
    except Exception:
        return "{}"


def node_action_executor(state: SentinelState) -> dict[str, Any]:
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
    raw_reasoning = latest_decision.get("reasoning") or _degraded_reason(latest_decision)
    safe_reasoning = output_sanitizer.sanitize(raw_reasoning)
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2%}] {safe_reasoning}"

    # LOG THÔ đại diện (khớp target, fallback log đầu batch) -> đính kèm audit để Dashboard
    # hiển thị "cái gì đã vào Tier-1/LLM". Đây là đặc trưng luồng ĐÃ LOẠI nhãn (label leak).
    raw_log_json = _serialize_repr_log(
        state.current_batch_logs, str(latest_decision.get("target", ""))
    )

    target = latest_decision.get("target", "UNKNOWN_TARGET")
    mitre_tech = latest_decision.get("mitre_technique", "")
    confidence = latest_decision.get("confidence", 0.0)

    # Cờ: block ĐÃ thực thi bên trong raise_alert (repeat-offender) -> KHÔNG chặn lại ở dưới.
    _alert_escalated_block = False

    # ALERT: raise_alert là CHOKE-POINT THỐNG NHẤT (chung với Cổng ML) — ghi ALERT, và nếu IP
    # TÁI PHẠM (đã cảnh báo trước) / known-bad thì TỰ leo thang -> BLOCK ngay bên trong.
    if action == "ALERT":
        result_action = raise_alert(target, formatted_reasoning, raw_log=raw_log_json)
        # Tín hiệu APT (persistent-IP / multi-day) — đọc incident vừa ghi, KHÔNG record trùng.
        _check_apt_signal(target, mitre_tech, confidence)
        if result_action == "BLOCK_IP":
            logger.warning(f"[*] Escalate ALERT -> BLOCK_IP for {target} (tái phạm cảnh báo)")
            action = "BLOCK_IP"
            latest_decision["action"] = "BLOCK_IP"
            formatted_reasoning += " [HỆ THỐNG LEO THANG: IP tái phạm cảnh báo -> tự động CHẶN]"
            _alert_escalated_block = True

    if action == "BLOCK_IP":
        # Ghi incident cho BLOCK_IP TRỰC TIẾP từ LLM. Nếu do leo thang ALERT thì raise_alert đã
        # xử lý reputation/incident -> KHÔNG ghi lại (tránh đếm trùng).
        if not _alert_escalated_block:
            _handle_threat_memory_incident(target, action, mitre_tech, confidence)
            block_ip(
                target,
                formatted_reasoning,
                raw_log=raw_log_json,
            )

        rule_pattern = target
        rule_source = "ml_triage" if getattr(state, "_ml_bypass", False) else "langgraph_agent"

        # (1) Luật theo IP — "nhớ mặt" kẻ tấn công (chạy qua FeedbackValidator ngầm định)
        FeedbackListener().receive_new_rule(
            "Source IP",
            rule_pattern,
            score=100,
            reason=raw_reasoning,
            source=rule_source,
            status="ACTIVE",
        )

        # (2) Luật theo CHỮ KÝ HÀNH VI — "nhớ ngón đòn": trích chữ ký công cụ/URI từ
        # log gây ra block để Tier-1 CỜ nhanh một IP KHÁC dùng CÙNG kỹ thuật. Suy biến
        # nhẹ nhàng: không có log hoặc không có chữ ký an toàn → bỏ qua, chỉ giữ luật IP.
        offending = next(
            (
                lg
                for lg in state.current_batch_logs
                if str(normalize_log_keys(lg).get("Source IP", "")) == str(rule_pattern)
            ),
            None,
        )
        if offending:
            beh = _derive_behavioral_rule(offending)
            if beh:
                b_field, b_pattern, b_score = beh
                FeedbackListener().receive_new_rule(
                    b_field,
                    b_pattern,
                    score=b_score,
                    source=f"{rule_source}_behavioral",
                    reason=f"Behavioral signature learned from {rule_pattern}: {raw_reasoning}",
                    status="ACTIVE",
                )
                logger.info(
                    f"--- LEARNED TECHNIQUE: {b_field}~'{b_pattern}' (score {b_score}) "
                    f"from {rule_pattern} ---"
                )

    return {}


def node_human_in_the_loop(state: SentinelState) -> dict[str, Any]:
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
    raw_reasoning = latest_decision.get("reasoning") or _degraded_reason(latest_decision)
    formatted_reasoning = f"[MITRE: {mitre}] [Độ tin cậy: {conf:.2%}] {raw_reasoning}"

    logger.warning(f" [HÀNG ĐỢI SOC ANALYST] Cần con người kiểm duyệt: {formatted_reasoning}")

    target = latest_decision.get("target", "UNKNOWN_TARGET")
    _handle_threat_memory_incident(target, "AWAIT_HITL", mitre, conf)

    from src.response.executor import _log_to_db

    raw_log_json = _serialize_repr_log(
        state.current_batch_logs, str(latest_decision.get("target", ""))
    )
    _log_to_db(
        "AWAIT_HITL",
        latest_decision.get("target", "UNKNOWN_TARGET"),
        formatted_reasoning,
        raw_log=raw_log_json,
    )

    # Đưa vào hàng đợi duyệt luật (Tab Phê duyệt Luật HITL) để human có thể xem xét
    target_ip = latest_decision.get("target", "UNKNOWN_TARGET")
    if target_ip != "UNKNOWN_TARGET":
        from src.tier1_filter.feedback_listener import FeedbackListener

        FeedbackListener().receive_new_rule(
            "Source IP",
            target_ip,
            score=50,  # 50 cho AWAIT_HITL vì chưa chắc chắn
            source="langgraph_agent_hitl",
            reason=formatted_reasoning,
        )

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


# Action cần làm giàu MITRE (bỏ qua LOG/benign — ánh xạ ATT&CK cho benign vô nghĩa).
_MAPPABLE_ACTIONS = {"BLOCK_IP", "ALERT", "AWAIT_HITL"}


def route_after_triage(state: SentinelState) -> str:
    """
    Cổng điều kiện SAU triage — gate theo ACTION:
      - Nếu là verdict đáng-hành-động (BLOCK_IP/ALERT/AWAIT_HITL) -> attack_mapper ("map").
      - Ngược lại (LOG/benign) -> giữ nguyên định tuyến theo action.

    GHI CHÚ THIẾT KẾ: trước đây cổng còn đòi confidence > 0.7, nhưng đo thực tế
    cho thấy triage gán ALERT với confidence ~0.6-0.7 cho bất thường flow, nên
    ngưỡng strict đó lọc mất gần như mọi verdict thật. ALERT vẫn là threat verdict
    đáng làm giàu ATT&CK cho analyst -> gate theo ACTION (không theo confidence).
    Sau attack_mapper, route_triage_decision định tuyến tiếp theo action.
    """
    latest_decision = state.decisions[-1] if state.decisions else {}
    action = latest_decision.get("action", "LOG")

    if action in _MAPPABLE_ACTIONS:
        return "map"
    return route_triage_decision(state)
