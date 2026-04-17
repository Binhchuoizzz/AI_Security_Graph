"""
LangGraph Agent: State Schema (Structured MemoryObject)

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
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class IOCEntry:
    """
    Indicator of Compromise — lưu cứng, không bao giờ bị tóm tắt.
    Agent chỉ được APPEND vào list, không được sửa/xóa entries cũ.
    """
    ioc_type: str       # "ip", "port", "hash", "domain", "user_agent", "uri"
    value: str          # Giá trị cụ thể: "192.168.1.100", "445", "abc123..."
    severity: str       # "low", "medium", "high", "critical"
    source_template: str = ""   # Template ID nơi phát hiện IOC này
    first_seen: str = ""        # Timestamp ISO format
    context: str = ""           # Ghi chú ngắn: "Port scanning 12 ports"

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "severity": self.severity,
            "source_template": self.source_template,
            "first_seen": self.first_seen,
            "context": self.context
        }


@dataclass
class AgentDecision:
    """Lịch sử quyết định của Agent — phục vụ audit trail."""
    timestamp: str
    action: str         # "ESCALATE", "BLOCK_IP", "ALERT", "LOG", "AWAIT_HITL"
    target: str         # IP, Host, User bị tác động
    confidence: float   # 0.0 - 1.0
    reasoning: str      # Giải thích ngắn gọn
    mitre_technique: str = ""  # VD: "T1110.003 - Brute Force: Password Spraying"
    iso_control: str = ""      # Ví dụ: "A.9.4.2 - Secure log-on procedures"
    hitl_status: str = "N/A"   # Các trạng thái: "PENDING", "APPROVED", "REJECTED", "N/A"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "target": self.target,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "mitre_technique": self.mitre_technique,
            "iso_control": self.iso_control,
            "hitl_status": self.hitl_status
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
    extracted_iocs: List[Dict[str, Any]] = field(default_factory=list)
    """
    Mảng JSON cứng lưu tất cả IOCs đã phát hiện.
    Mỗi phần tử là dict từ IOCEntry.to_dict().
    Agent TUYỆT ĐỐI KHÔNG tóm tắt đè lên list này.
    Chỉ được dùng 2 operations: APPEND (thêm IOC mới) hoặc READ (đọc).
    """

    # === DECISION HISTORY (audit trail) ===
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    """
    Lịch sử quyết định. Mỗi phần tử là dict từ AgentDecision.to_dict().
    Không xóa, không sửa, chỉ append.
    """

    # === CURRENT BATCH DATA (reset mỗi cycle) ===
    current_batch_logs: List[Dict[str, Any]] = field(default_factory=list)
    """Log entries của batch hiện tại (đã qua Guardrails)."""

    current_batch_encapsulated: str = ""
    """Text đã đóng gói bởi DelimitedDataEncapsulator — sẵn sàng cho LLM."""

    current_batch_size: int = 0
    """Số log trong batch hiện tại."""

    # === RAG CONTEXT (refresh mỗi cycle) ===
    rag_mitre_context: str = ""
    """Context từ MITRE ATT&CK FAISS search."""

    rag_iso_context: str = ""
    """Context từ ISO 27001 FAISS search."""

    # === METADATA ===
    cycle_count: int = 0
    """Số batch đã xử lý (tăng dần)."""

    last_updated: str = ""
    """Timestamp ISO format của lần cập nhật state gần nhất."""

    # === FEEDBACK LOOP ===
    pending_rules: List[Dict[str, Any]] = field(default_factory=list)
    """
    Rules mới sinh bởi Agent chờ đẩy về Tier 1.
    Sau khi feedback_listener xử lý, list này được clear.
    """

    # === HELPER METHODS ===

    def add_ioc(self, ioc_type: str, value: str, severity: str = "medium",
                source_template: str = "", context: str = ""):
        """
        Thêm IOC mới vào registry. Kiểm tra trùng lặp trước khi append.
        """
        # Kiểm tra trùng lặp: không thêm IOC đã tồn tại (cùng type + value)
        for existing in self.extracted_iocs:
            if existing.get('ioc_type') == ioc_type and existing.get('value') == value:
                return  # Bỏ qua nếu đã tồn tại

        ioc = IOCEntry(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            source_template=source_template,
            first_seen=datetime.utcnow().isoformat(),
            context=context
        )
        self.extracted_iocs.append(ioc.to_dict())

    def add_decision(self, action: str, target: str, confidence: float,
                      reasoning: str, mitre_technique: str = "",
                      iso_control: str = "", hitl_status: str = "N/A"):
        """Ghi nhận quyết định mới vào audit trail."""
        decision = AgentDecision(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            target=target,
            confidence=confidence,
            reasoning=reasoning,
            mitre_technique=mitre_technique,
            iso_control=iso_control,
            hitl_status=hitl_status
        )
        self.decisions.append(decision.to_dict())

    def get_iocs_by_severity(self, severity: str) -> list:
        """Lọc IOCs theo mức severity."""
        return [ioc for ioc in self.extracted_iocs if ioc.get('severity') == severity]

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
        Kết hợp narrative (tóm tắt) + IOCs (cứng) + recent decisions.
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

        return "\n\n".join(parts)

    def reset_current_batch(self):
        """Reset batch data cho cycle mới. KHÔNG reset IOCs hay narrative."""
        self.current_batch_logs = []
        self.current_batch_encapsulated = ""
        self.current_batch_size = 0
        self.rag_mitre_context = ""
        self.rag_iso_context = ""
        self.pending_rules = []
        self.cycle_count += 1
        self.last_updated = datetime.utcnow().isoformat()
