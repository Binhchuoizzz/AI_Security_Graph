"""
Tier 1 Filter: Rule-based Engine

Hoạt động như một Firewall cực nhẹ, chấm điểm sơ bộ (Risk Score) các gói tin
từ luồng phân tích. Dựa trên heuristic, các gói tin "sạch" sẽ bị gạt bỏ mà
không cần tiêu tốn tài nguyên của LangGraph AI, giảm thiểu rủi ro nghẽn cổ chai (Bottleneck).
"""
import json

class RuleEngine:
    def __init__(self, risk_threshold: int = 50):
        # Điểm số để quyết định có đánh bẫy và ESCALATE lên LLM không
        self.risk_threshold = risk_threshold

    def evaluate(self, log_entry: dict) -> dict:
        """
        Phân tách JSON log và trả về bản thân log đính kèm theo điểm dị thường (anomaly score).
        Tối ưu tốc độ cao nhất có thể. (O(1) dictionary lookups)
        """
        score = 0
        reasons = []

        # Các feature phổ biến của bộ CICIDS2017
        dest_port = log_entry.get('Destination Port', -1)
        fwd_packets = log_entry.get('Total Fwd Packets', 0)
        
        # Rule 1 cơ bản: Quét truy cập trái phép vào các Port nhạy cảm
        # (21:FTP, 22:SSH, 23:Telnet, 3389:RDP)
        if dest_port in [21, 22, 23, 3389]:
            score += 40
            reasons.append(f"Truy cập cổng quản trị rủi ro cao (Port {dest_port})")

        # Rule 2: Thể tích packet bất thường (Dấu hiệu Volumetric Attack / DDoS)
        # Ép kiểu an toàn đề phòng log string
        try:
            if float(fwd_packets) > 1000:
                score += 30
                reasons.append(f"Mật độ gói tin FWD tăng đột biến ({fwd_packets} pkts)")
        except (ValueError, TypeError):
            pass

        # Cập nhật kết quả vào JSON gốc
        log_entry['tier1_score'] = score
        log_entry['tier1_reasons'] = reasons
        
        # Action Handler: Nếu vượt ngưỡng thì PASS cho LLM (ESCALATE)
        log_entry['tier1_action'] = "ESCALATE" if score >= self.risk_threshold else "DROP"

        return log_entry
