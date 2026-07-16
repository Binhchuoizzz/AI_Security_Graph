"""
LangGraph Agent: Lược đồ trạng thái State Schema (Đối tượng bộ nhớ cấu trúc)

CHỐNG SEMANTIC DRIFT:
  Summary Memory thuần túy (tóm tắt → tóm tắt → tóm tắt) sẽ dẫn đến
  hiện tượng Semantic Drift: các IOCs chi tiết (IP, Hash, Port) dần bị
  rơi rụng hoặc làm mờ qua mỗi vòng tóm tắt.

  GIẢI PHÁP: Structured MemoryObject chia thành 2 phần tách biệt:
  1. narrative_summary: Bối cảnh chung dạng text (LLM được phép tóm tắt)
  2. extracted_iocs: Mảng JSON cứng lưu IOCs (LLM chỉ được APPEND, KHÔNG
     được tóm tắt đè lên hoặc xóa bỏ)

  Điều này đảm bảo:
  - Bối cảnh phiên phân tích trước được giữ lại (narrative)
  - IP, Port, Hash nghi ngờ KHÔNG BAO GIỜ bị làm mờ qua tóm tắt (iocs)
  - Metrics token luôn nằm trong tầm kiểm soát
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class IOCEntry:
    """
    Indicator of Compromise — lưu cứng, không bao giờ bị tóm tắt.
    Agent chỉ được APPEND vào list, không được sửa/xóa entries cũ.
    """

    ioc_type: str  # "ip", "port", "hash", "domain", "user_agent", "uri"
    value: str  # Giá trị cụ thể: "192.168.1.100", "445", "abc123..."
    severity: str  # "low", "medium", "high", "critical"
    source_template: str = ""  # Template ID nơi phát hiện IOC này
    first_seen: str = ""  # Định dạng thời gian ISO
    context: str = ""  # Ghi chú ngắn: "Port scanning 12 ports"

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "severity": self.severity,
            "source_template": self.source_template,
            "first_seen": self.first_seen,
            "context": self.context,
        }


@dataclass
class AgentDecision:
    """Lịch sử quyết định của Agent — phục vụ audit trail."""

    timestamp: str
    action: str  # "ESCALATE", "BLOCK_IP", "ALERT", "LOG", "AWAIT_HITL"
    target: str  # IP, Host, User bị tác động
    confidence: float  # 0.0 - 1.0
    reasoning: str  # Giải thích ngắn gọn
    mitre_technique: str = ""  # VD: "T1110.003 - Brute Force: Password Spraying"
    nist_control: str = ""  # Ví dụ: "Containment - Network isolation"
    hitl_status: str = "N/A"  # Các trạng thái: "PENDING", "APPROVED", "REJECTED", "N/A"

    # === MITRE ATT&CK MAPPING (có cấu trúc) — do node_attack_mapper bồi đắp ===
    # Free-text mitre_technique ở trên được tách thành các trường kiểm chứng được.
    # Mặc định rỗng để các luồng cũ (chưa qua mapper) vẫn hợp lệ.
    mitre_tactic: str = ""  # VD: "Initial Access"
    mitre_tactic_id: str = ""  # VD: "TA0001"
    mitre_technique_id: str = ""  # VD: "T1190"
    mitre_subtechnique: str = ""  # VD: "JavaScript" (rỗng nếu không có)
    mitre_subtechnique_id: str = ""  # VD: "T1059.007"
    mitre_url: str = ""  # Link technique chính thức
    mapping_confidence: float = 0.0  # Độ tin cậy của riêng phép ánh xạ [0,1]
    mapping_status: str = ""  # "resolved" | "low_confidence" | "" (chưa map)
    recommended_response: str = ""  # Phản hồi đề xuất (rule-based theo tactic)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "target": self.target,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "mitre_technique": self.mitre_technique,
            "nist_control": self.nist_control,
            "hitl_status": self.hitl_status,
            "mitre_tactic": self.mitre_tactic,
            "mitre_tactic_id": self.mitre_tactic_id,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_subtechnique": self.mitre_subtechnique,
            "mitre_subtechnique_id": self.mitre_subtechnique_id,
            "mitre_url": self.mitre_url,
            "mapping_confidence": self.mapping_confidence,
            "mapping_status": self.mapping_status,
            "recommended_response": self.recommended_response,
        }


@dataclass
class SentinelState:
    """
    LangGraph State Schema — Structured MemoryObject.
    Đây là state object duy nhất được truyền qua các node trong LangGraph.

    NGUYÊN TẮC SỬ DỤNG:
    - narrative_summary: LLM được phép tóm tắt lại, CÓ THỂ ghi đè
    - extracted_iocs: LLM CHỈ ĐƯỢC APPEND. KHÔNG BAO GIỜ xóa hoặc tóm tắt đè.
    - decisions: Chỉ append thêm. Lịch sử audit trail bất khả xâm phạm.
    - current_batch: Dữ liệu batch hiện tại (reset mỗi cycle)
    """

    # === NARRATIVE MEMORY (có thể tóm tắt) ===
    narrative_summary: str = ""
    """
    Bối cảnh chung dạng text tự do.
    LLM tóm tắt lại sau mỗi batch: "Trong 30 phút qua, hệ thống phát hiện
    một chuỗi tấn công Brute Force từ vùng IP 192.168.1.0/24 nhắm vào
    SSH port 22..." → Giữ ngữ cảnh nhưng tiết kiệm token.
    """

    # === IOC REGISTRY (KHÔNG được tóm tắt — chỉ append) ===
    extracted_iocs: list[dict[str, Any]] = field(default_factory=list)
    """
    Mảng JSON cứng lưu tất cả IOCs đã phát hiện.
    Mỗi phần tử là dict từ IOCEntry.to_dict().
    Agent TUYỆT ĐỐI KHÔNG tóm tắt đè lên list này.
    Chỉ được dùng 2 operations: APPEND (thêm IOC mới) hoặc READ (đọc).
    """

    # === DECISION HISTORY (audit trail) ===
    decisions: list[dict[str, Any]] = field(default_factory=list)
    """
    Lịch sử quyết định. Mỗi phần tử là dict từ AgentDecision.to_dict().
    Không xóa, không sửa, chỉ append.
    """

    # === CURRENT BATCH DATA (reset mỗi cycle) ===
    current_batch_logs: list[dict[str, Any]] = field(default_factory=list)
    """Log entries của batch hiện tại (đã qua Guardrails)."""

    current_batch_encapsulated: str = ""
    """Text đã đóng gói bởi DelimitedDataEncapsulator — sẵn sàng cho LLM."""

    _guardrails_system_instruction: str = ""
    """System prompt sinh động từ Guardrails (chứa dynamic delimiters)."""

    current_batch_size: int = 0
    """Số log trong batch hiện tại."""

    # === RAG CONTEXT (refresh mỗi cycle) ===
    rag_mitre_context: str = ""
    """Context từ MITRE ATT&CK FAISS search."""

    rag_nist_context: str = ""
    """Context từ NIST SP 800-61r2 FAISS search."""

    # === METADATA ===
    cycle_count: int = 0
    """Số batch đã xử lý (tăng dần)."""

    _ml_bypass: bool = False
    """Cờ hiệu cho biết ML Triage đã bypass RAG/LLM."""

    _ml_bypass_action: str = ""
    """Action được gán bởi ML Triage khi bypass."""

    last_updated: str = ""
    """Timestamp ISO format của lần cập nhật state gần nhất."""

    # === FEEDBACK LOOP ===
    pending_rules: list[dict[str, Any]] = field(default_factory=list)
    """
    Rules mới sinh bởi Agent chờ đẩy về Tier 1.
    Sau khi feedback_listener xử lý, list này được clear.
    """

    # === LONG-TERM THREAT MEMORY (persistent context) ===
    threat_memory_context: str = ""
    """
    Context từ Long-Term Memory Store (SQLite persistent).
    Chứa IP reputation, organizational context, APT indicators.
    Inject vào prompt để Agent biết lịch sử IP trước khi phân tích.
    """

    # === HELPER METHODS ===

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        severity: str = "medium",
        source_template: str = "",
        context: str = "",
    ):
        """
        Thêm IOC mới vào registry. Kiểm tra trùng lặp trước khi append.
        """
        # Kiểm tra trùng lặp: không thêm IOC đã tồn tại (cùng type + value)
        for existing in self.extracted_iocs:
            if existing.get("ioc_type") == ioc_type and existing.get("value") == value:
                return  # Bỏ qua nếu đã tồn tại

        ioc = IOCEntry(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            source_template=source_template,
            first_seen=datetime.now(timezone.utc).isoformat(),
            context=context,
        )
        self.extracted_iocs.append(ioc.to_dict())

    def add_decision(
        self,
        action: str,
        target: str,
        confidence: float,
        reasoning: str,
        mitre_technique: str = "",
        nist_control: str = "",
        hitl_status: str = "N/A",
        **mitre_mapping: Any,
    ):
        """
        Ghi nhận quyết định mới vào audit trail.

        mitre_mapping (tùy chọn): các trường có cấu trúc do node_attack_mapper
        bồi đắp (mitre_tactic, mitre_tactic_id, mitre_technique_id,
        mitre_subtechnique, mitre_subtechnique_id, mitre_url, mapping_confidence,
        mapping_status, recommended_response). Khoá lạ bị bỏ qua an toàn.
        """
        allowed = {
            "mitre_tactic",
            "mitre_tactic_id",
            "mitre_technique_id",
            "mitre_subtechnique",
            "mitre_subtechnique_id",
            "mitre_url",
            "mapping_confidence",
            "mapping_status",
            "recommended_response",
        }
        extra = {k: v for k, v in mitre_mapping.items() if k in allowed}
        decision = AgentDecision(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            target=target,
            confidence=confidence,
            reasoning=reasoning,
            mitre_technique=mitre_technique,
            nist_control=nist_control,
            hitl_status=hitl_status,
            **extra,
        )
        self.decisions.append(decision.to_dict())

    def get_iocs_by_severity(self, severity: str) -> list:
        """Lọc IOCs theo mức severity."""
        return [ioc for ioc in self.extracted_iocs if ioc.get("severity") == severity]

    def get_iocs_summary_for_prompt(self, max_iocs: int = 20) -> str:
        """
        Format IOC list cho LLM prompt.
        Giới hạn max_iocs để tiết kiệm token.
        """
        if not self.extracted_iocs:
            return "No IOCs extracted yet."

        lines = [f"Known IOCs ({len(self.extracted_iocs)} total):"]
        for ioc in self.extracted_iocs[-max_iocs:]:  # Lấy N gần nhất
            lines.append(
                f"  [{ioc['severity'].upper()}] {ioc['ioc_type']}: "
                f"{ioc['value']} — {ioc.get('context', '')}"
            )
        if len(self.extracted_iocs) > max_iocs:
            lines.append(f"  ... and {len(self.extracted_iocs) - max_iocs} older IOCs")
        return "\n".join(lines)

    def get_memory_for_prompt(self) -> str:
        """
        Tổng hợp memory cho LLM prompt.
        Kết hợp narrative (tóm tắt) + IOCs (cứng) + recent decisions + threat memory.
        """
        parts = []

        # Phần 1: Tóm tắt Bối cảnh (có thể bị LLM tóm tắt lại)
        if self.narrative_summary:
            parts.append(f"=== Session Context ===\n{self.narrative_summary}")

        # Phần 2: Danh sách IOC (KHÔNG BAO GIỜ bị tóm tắt)
        iocs_text = self.get_iocs_summary_for_prompt()
        parts.append(f"=== Extracted IOCs (IMMUTABLE) ===\n{iocs_text}")

        # Phần 3: Quyết định gần đây (Lấy 3 cái gần nhất)
        if self.decisions:
            recent = self.decisions[-3:]
            decision_lines = ["=== Recent Decisions ==="]
            for d in recent:
                decision_lines.append(
                    f"  [{d['timestamp']}] {d['action']} → {d['target']} "
                    f"(confidence: {d['confidence']:.1%})"
                )
            parts.append("\n".join(decision_lines))

        # Phần 4: Long-Term Threat Memory (persistent context)
        if self.threat_memory_context:
            parts.append(f"=== Long-Term Threat Intelligence ===\n{self.threat_memory_context}")

        return "\n\n".join(parts)

    def reset_current_batch(self):
        """Reset batch data cho cycle mới. KHÔNG reset IOCs, narrative, hay threat memory."""
        self.current_batch_logs = []
        self.current_batch_encapsulated = ""
        self.current_batch_size = 0
        self.rag_mitre_context = ""
        self.rag_nist_context = ""
        self.pending_rules = []
        self.threat_memory_context = ""
        self.cycle_count += 1
        self.last_updated = datetime.now(timezone.utc).isoformat()
