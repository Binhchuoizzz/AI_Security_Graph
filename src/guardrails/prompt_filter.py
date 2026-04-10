"""
Guardrails: Prompt Filter & Semantic Pruning Engine

Module này đóng vai trò lá chắn cuối cùng trước khi dữ liệu log chạm vào LLM.
Gồm 3 tầng bảo vệ:
  1. Prompt Injection Detection: Phát hiện và vô hiệu hóa mã độc ẩn trong log.
  2. Log Template Mining (Drain3): Nén hàng nghìn dòng log trùng lặp thành Template.
  3. Token Budgeting & Top-K Sampling: Đảm bảo prompt không bao giờ vượt VRAM budget.
"""
import re
import math
import yaml
import os
from collections import Counter

# =========================================================================
# Load cấu hình trung tâm
# =========================================================================
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'system_settings.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

# =========================================================================
# 1. PROMPT INJECTION DETECTOR
# =========================================================================
class PromptInjectionDetector:
    """
    Quét toàn bộ value trong log JSON để tìm dấu hiệu Prompt Injection.
    Nếu phát hiện, log đó sẽ bị sanitize (xóa nội dung độc) trước khi đưa vào LLM.
    """
    def __init__(self, patterns: list = None):
        config = load_config()
        self.patterns = patterns or config['guardrails']['injection_patterns']
        # Compile regex một lần duy nhất để tối ưu tốc độ
        self.compiled = [re.compile(re.escape(p), re.IGNORECASE) for p in self.patterns]

    def scan(self, log_entry: dict) -> dict:
        """Quét và sanitize log. Trả về log đã sạch + flag cảnh báo."""
        is_injected = False
        sanitized = {}
        detected_patterns = []

        for key, value in log_entry.items():
            str_value = str(value)
            for i, pattern in enumerate(self.compiled):
                if pattern.search(str_value):
                    is_injected = True
                    detected_patterns.append(self.patterns[i])
                    # Thay thế nội dung độc bằng placeholder an toàn
                    str_value = pattern.sub("[REDACTED_INJECTION]", str_value)
            sanitized[key] = str_value

        sanitized['_guardrail_injected'] = is_injected
        sanitized['_guardrail_detected_patterns'] = detected_patterns
        return sanitized

# =========================================================================
# 2. ENTROPY SCORER (Importance Scoring)
# =========================================================================
class EntropyScorer:
    """
    Tính Shannon Entropy cho một chuỗi ký tự.
    Log chứa payload SQLi/XSS thường có entropy cao hơn traffic bình thường.
    """
    def __init__(self, threshold: float = None):
        config = load_config()
        self.threshold = threshold or config['guardrails']['entropy_threshold']

    @staticmethod
    def calculate(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def score_log(self, log_entry: dict) -> float:
        """Tính entropy trung bình của tất cả các value trong log."""
        values = [str(v) for v in log_entry.values() if v]
        if not values:
            return 0.0
        combined = " ".join(values)
        return self.calculate(combined)

    def is_high_entropy(self, log_entry: dict) -> bool:
        return self.score_log(log_entry) > self.threshold

# =========================================================================
# 3. LOG TEMPLATE MINER (Simplified Drain-like Algorithm)
# =========================================================================
class LogTemplateMiner:
    """
    Thuật toán nén log theo kiểu Drain3 (simplified).
    Gom các dòng log có cùng cấu trúc thành 1 Template duy nhất + frequency.
    
    Ví dụ:
      Input:  10,000 dòng "GET /login?user=admin", "GET /login?user=root", ...
      Output: 1 Template "GET /login?user=<VAR>" với frequency=10,000
    """
    def __init__(self):
        self.templates = {}  # {template_key: {"template": str, "count": int, "samples": []}}

    def _tokenize(self, log_str: str) -> list:
        """Tách log thành các token."""
        return log_str.split()

    def _generalize(self, tokens: list) -> str:
        """
        Thay thế các token có vẻ là biến (IP, số, hash) bằng <VAR>.
        Giữ lại cấu trúc gốc (verb, path, keyword).
        """
        generalized = []
        for token in tokens:
            # Nếu token chứa số hoặc IP-like pattern -> coi là biến
            if re.search(r'\d', token) or re.search(r'[a-f0-9]{8,}', token, re.IGNORECASE):
                generalized.append("<VAR>")
            else:
                generalized.append(token)
        return " ".join(generalized)

    def add_log(self, log_str: str):
        """Thêm một dòng log vào bộ template."""
        tokens = self._tokenize(log_str)
        template_key = self._generalize(tokens)

        if template_key not in self.templates:
            self.templates[template_key] = {
                "template": template_key,
                "count": 0,
                "samples": []
            }
        self.templates[template_key]["count"] += 1
        # Giữ lại tối đa 3 sample gốc để LLM vẫn thấy được chi tiết
        if len(self.templates[template_key]["samples"]) < 3:
            self.templates[template_key]["samples"].append(log_str)

    def get_summary(self) -> list:
        """Trả về danh sách các template đã nén, sắp xếp theo frequency giảm dần."""
        return sorted(self.templates.values(), key=lambda x: x["count"], reverse=True)

    def get_compression_ratio(self, total_logs: int) -> float:
        """Tính tỷ lệ nén: bao nhiêu dòng log gốc -> bao nhiêu template."""
        if total_logs == 0:
            return 0.0
        return total_logs / max(len(self.templates), 1)

# =========================================================================
# 4. TOKEN BUDGET MANAGER
# =========================================================================
class TokenBudgetManager:
    """
    Quản lý ngân sách token cho phần dữ liệu log trong prompt.
    Nếu vượt budget, tự động chuyển sang chế độ Top-K Sampling.
    """
    def __init__(self, budget: int = None, top_k: int = None):
        config = load_config()
        self.budget = budget or config['guardrails']['token_budget']
        self.top_k = top_k or config['guardrails']['top_k_samples']

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Ước lượng token (xấp xỉ: 1 token ~ 4 ký tự cho tiếng Anh)."""
        return len(text) // 4

    def fit_to_budget(self, template_summaries: list) -> str:
        """
        Nhận danh sách template từ LogTemplateMiner, rồi cắt tỉa cho vừa budget.
        Chiến lược: Ưu tiên các template có frequency cao nhất (nguy hiểm nhất).
        """
        output_lines = []
        current_tokens = 0

        for tmpl in template_summaries:
            # Tạo bản tóm tắt cho template
            line = f"[Pattern x{tmpl['count']}] {tmpl['template']}"
            # Đính kèm sample nếu còn chỗ
            for sample in tmpl['samples'][:self.top_k]:
                line += f"\n  Sample: {sample}"

            line_tokens = self.estimate_tokens(line)

            if current_tokens + line_tokens > self.budget:
                output_lines.append(f"[TRUNCATED: {len(template_summaries) - len(output_lines)} more patterns omitted due to token budget]")
                break

            output_lines.append(line)
            current_tokens += line_tokens

        return "\n".join(output_lines)

# =========================================================================
# 5. FEATURE EXTRACTOR (DDoS Behavioral Summary)
# =========================================================================
class FeatureExtractor:
    """
    Thay vì đưa 10,000 dòng log DDoS cho LLM, module này tóm tắt thành
    một vector hành vi ngắn gọn (~50 tokens).
    """
    @staticmethod
    def summarize_behavior(logs: list) -> str:
        if not logs:
            return "No logs to summarize."

        total = len(logs)
        unique_ips = len(set(log.get('Source IP', 'unknown') for log in logs))
        unique_ports = len(set(log.get('Destination Port', 0) for log in logs))

        # Tính request rate trung bình (giả lập)
        paths = [str(log.get('URI', log.get('Path', 'N/A'))) for log in logs]
        top_path = Counter(paths).most_common(1)
        top_path_str = top_path[0][0] if top_path else "N/A"

        summary = (
            f"Behavior Summary:\n"
            f"  Total Events: {total}\n"
            f"  Unique Source IPs: {unique_ips}\n"
            f"  Unique Dest Ports: {unique_ports}\n"
            f"  Most Targeted Path: {top_path_str}\n"
            f"  Pattern: {'Distributed' if unique_ips > 10 else 'Concentrated'} attack"
        )
        return summary
