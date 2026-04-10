"""
Guardrails: Log Template Miner (Semantic Pruning Engine)

Module chống tràn Context Window khi bị Application Layer DDoS.
Sử dụng thuật toán Drain-like để nén hàng nghìn dòng log trùng lặp
thành các Template đại diện + frequency.

Chiến lược 3 lớp:
  1. Template Mining:  10,000 dòng log → N Templates (~10-50 Templates)
  2. Entropy Scoring:  Ưu tiên giữ nguyên log chứa payload lạ (SQLi/XSS)
  3. Token Budgeting:  Cắt tỉa cho vừa ngân sách 4,000 tokens

Tách riêng module này từ prompt_filter.py để dễ kiểm thử
và viết Ablation Study (có/không Template Mining).
"""
import re
import math
from collections import Counter


class LogTemplateMiner:
    """
    Thuật toán nén log theo kiểu Drain3 (simplified).
    Gom các dòng log có cùng cấu trúc thành 1 Template duy nhất + frequency.

    Ví dụ:
      Input:  5,000 dòng "GET /login.php?user=admin", "GET /login.php?user=root", ...
      Output: 1 Template "GET /login.php?user=<VAR>" (Count: 5000, Time_Range: 0.1s-299s)
    """
    def __init__(self):
        self.templates = {}  # {template_key: {"template": str, "count": int, "samples": [], "time_range": [min, max]}}

    def _tokenize(self, log_str: str) -> list:
        """Tách log thành các token."""
        return log_str.split()

    def _generalize(self, tokens: list) -> str:
        """
        Thay thế các token có vẻ là biến (IP, số, hash, timestamp) bằng <VAR>.
        Giữ lại cấu trúc gốc (verb, path, keyword).
        """
        generalized = []
        for token in tokens:
            # IP address pattern
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', token):
                generalized.append("<IP>")
            # Hex hash (session ID, cookie, etc.)
            elif re.match(r'^[a-f0-9]{8,}$', token, re.IGNORECASE):
                generalized.append("<HASH>")
            # Numeric value
            elif re.match(r'^\d+(\.\d+)?$', token):
                generalized.append("<NUM>")
            # Token chứa số xen lẫn chữ (ví dụ: user123, id=456)
            elif re.search(r'\d', token):
                generalized.append("<VAR>")
            else:
                generalized.append(token)
        return " ".join(generalized)

    def add_log(self, log_str: str, timestamp: float = None):
        """Thêm một dòng log vào bộ template."""
        tokens = self._tokenize(log_str)
        template_key = self._generalize(tokens)

        if template_key not in self.templates:
            self.templates[template_key] = {
                "template": template_key,
                "count": 0,
                "samples": [],
                "time_range": [float('inf'), float('-inf')]
            }

        entry = self.templates[template_key]
        entry["count"] += 1

        # Giữ lại tối đa 3 sample gốc để LLM vẫn thấy được chi tiết
        if len(entry["samples"]) < 3:
            entry["samples"].append(log_str)

        # Cập nhật time range
        if timestamp is not None:
            entry["time_range"][0] = min(entry["time_range"][0], timestamp)
            entry["time_range"][1] = max(entry["time_range"][1], timestamp)

    def add_log_dict(self, log_entry: dict):
        """
        Thêm log dạng dict (từ Redis stream).
        Tự động ghép các field thành chuỗi để mining.
        """
        # Ghép các field quan trọng thành chuỗi log
        key_fields = ['Source IP', 'Destination Port', 'Protocol', 'URI', 'Path',
                       'Flow Duration', 'Total Fwd Packets']
        parts = []
        for field in key_fields:
            val = log_entry.get(field)
            if val is not None:
                parts.append(f"{field}={val}")
        log_str = " ".join(parts) if parts else str(log_entry)

        timestamp = log_entry.get('Timestamp', log_entry.get('Flow Duration'))
        try:
            timestamp = float(timestamp) if timestamp else None
        except (ValueError, TypeError):
            timestamp = None

        self.add_log(log_str, timestamp)

    def get_summary(self) -> list:
        """Trả về danh sách các template đã nén, sắp xếp theo frequency giảm dần."""
        return sorted(self.templates.values(), key=lambda x: x["count"], reverse=True)

    def get_compression_ratio(self, total_logs: int) -> float:
        """Tính tỷ lệ nén: bao nhiêu dòng log gốc → bao nhiêu template."""
        if total_logs == 0:
            return 0.0
        return total_logs / max(len(self.templates), 1)

    def format_for_llm(self) -> str:
        """
        Xuất summary dạng text để đưa thẳng vào prompt LLM.
        Ví dụ output:
          [Template_ID: 1] GET /login.php?user=<VAR> (Count: 5000, Time_Range: 0.1s - 299s)
            Sample: GET /login.php?user=admin
            Sample: GET /login.php?user=root
        """
        lines = []
        for i, tmpl in enumerate(self.get_summary(), 1):
            time_str = ""
            if tmpl["time_range"][0] != float('inf'):
                time_str = f", Time_Range: {tmpl['time_range'][0]:.1f}s - {tmpl['time_range'][1]:.1f}s"
            lines.append(f"[Template_ID: {i}] {tmpl['template']} (Count: {tmpl['count']}{time_str})")
            for sample in tmpl["samples"]:
                lines.append(f"  Sample: {sample}")
        return "\n".join(lines)

    def reset(self):
        """Reset toàn bộ templates. Gọi sau mỗi batch 5 phút."""
        self.templates = {}


class EntropyScorer:
    """
    Tính Shannon Entropy cho một chuỗi ký tự.
    Log chứa payload SQLi/XSS thường có entropy cao hơn traffic bình thường.
    Những log có entropy > threshold sẽ được giữ nguyên (không bị nén thành Template).
    """
    def __init__(self, threshold: float = 4.5):
        self.threshold = threshold

    @staticmethod
    def calculate(text: str) -> float:
        """Tính Shannon Entropy."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def is_suspicious(self, log_str: str) -> bool:
        """Log có entropy cao = khả năng chứa payload tấn công."""
        return self.calculate(log_str) > self.threshold

    def score_and_classify(self, log_str: str) -> dict:
        """Trả về entropy score + classification."""
        entropy = self.calculate(log_str)
        return {
            "entropy": round(entropy, 3),
            "is_suspicious": entropy > self.threshold,
            "action": "KEEP_RAW" if entropy > self.threshold else "COMPRESS_TO_TEMPLATE"
        }


class TokenBudgetManager:
    """
    Quản lý ngân sách token cho phần dữ liệu log trong prompt.
    Nếu vượt budget, tự động chuyển sang chế độ Top-K Sampling.

    Chiến lược ưu tiên khi vượt ngân sách:
      1. Giữ nguyên log đầu + cuối khung 5 phút (ngữ cảnh bắt đầu/kết thúc)
      2. Giữ log có entropy cao (khả năng chứa payload)
      3. Top-K Templates theo frequency (cao nhất = nguy hiểm nhất)
    """
    def __init__(self, budget: int = 4000, top_k: int = 5):
        self.budget = budget
        self.top_k = top_k

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Ước lượng token (xấp xỉ: 1 token ~ 4 ký tự cho tiếng Anh)."""
        return len(text) // 4

    def fit_to_budget(self, template_summaries: list, raw_priority_logs: list = None) -> str:
        """
        Cắt tỉa dữ liệu cho vừa ngân sách token.
        Args:
            template_summaries: List template từ LogTemplateMiner.get_summary()
            raw_priority_logs: List các dòng log entropy cao (giữ nguyên)
        """
        output_lines = []
        current_tokens = 0

        # Bước 1: Ưu tiên đưa log entropy cao vào trước (giữ nguyên bản raw)
        if raw_priority_logs:
            output_lines.append("=== HIGH-ENTROPY LOGS (Possible Attack Payloads) ===")
            for log in raw_priority_logs:
                log_line = f"  [RAW] {log}"
                line_tokens = self.estimate_tokens(log_line)
                if current_tokens + line_tokens > self.budget * 0.4:  # Dành 40% budget cho raw
                    break
                output_lines.append(log_line)
                current_tokens += line_tokens

        # Bước 2: Đổ template summaries theo frequency giảm dần
        output_lines.append("=== COMPRESSED LOG TEMPLATES ===")
        for tmpl in template_summaries:
            time_str = ""
            if tmpl.get("time_range") and tmpl["time_range"][0] != float('inf'):
                time_str = f", Time: {tmpl['time_range'][0]:.1f}s-{tmpl['time_range'][1]:.1f}s"
            line = f"  [Pattern x{tmpl['count']}] {tmpl['template']}{time_str}"

            # Đính kèm 1 sample nếu còn chỗ
            for sample in tmpl['samples'][:1]:
                line += f"\n    Example: {sample}"

            line_tokens = self.estimate_tokens(line)

            if current_tokens + line_tokens > self.budget:
                remaining = len(template_summaries) - len([l for l in output_lines if l.startswith("  [Pattern")])
                output_lines.append(f"  [TRUNCATED: {remaining} more patterns omitted due to token budget]")
                break

            output_lines.append(line)
            current_tokens += line_tokens

        return "\n".join(output_lines)
