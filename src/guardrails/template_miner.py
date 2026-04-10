"""
Guardrails: Log Template Miner (Volume Compression Engine)

QUAN TRỌNG - RANH GIỚI TRÁCH NHIỆM:
  Module này CHỈ phục vụ MỘT mục đích duy nhất: NÉN VOLUME.
  Giảm 10,000 dòng log trùng lặp → N Templates (~10-50) để vừa Context Window.

  Module này KHÔNG phòng thủ Prompt Injection.
  Module này KHÔNG lọc nội dung độc hại.
  Prompt Injection defense được xử lý hoàn toàn bởi prompt_filter.py
  (Delimited Data Encapsulation).

  Luồng xử lý đúng:
    Raw Logs → [Template Miner: NÉN VOLUME] → [Prompt Filter: PHÒNG THỦ INJECTION]
             → [Token Budget: CẮT TỈA] → LLM

  Drain3 tách log thành:
    - Template (static structure): "GET /login.php?user=<VAR>"
    - Variables (dynamic params): ["admin", "root", "' OR 1=1--"]

  Variables ĐƯỢC GIỮ LẠI dưới dạng Samples (3 samples/template).
  Chúng sẽ được đóng gói bởi DelimitedDataEncapsulator trước khi vào LLM.
"""
import re
import math
from collections import Counter


class LogTemplateMiner:
    """
    Thuật toán nén log theo kiểu Drain3 (simplified).
    GOM NHÓM các dòng log có cùng cấu trúc → 1 Template + frequency + samples.

    Ví dụ:
      Input:  5,000 dòng "GET /login.php?user=admin", "GET /login.php?user=root"
      Output: Template "GET /login.php?user=<VAR>" (Count: 5000)
              Samples: ["GET /login.php?user=admin",
                        "GET /login.php?user=root",
                        "GET /login.php?user=' OR 1=1--"]  ← GIỮ NGUYÊN variables

    SAMPLES CHỨA NỘI DUNG GỐC (bao gồm cả payload tấn công).
    Đây là BY DESIGN — LLM cần thấy payload để phân tích.
    Prompt Injection defense xảy ra ở tầng SAU (Encapsulation).
    """
    def __init__(self, max_samples: int = 3):
        self.templates = {}
        self.max_samples = max_samples
        self.total_logs_processed = 0

    def _tokenize(self, log_str: str) -> list:
        return log_str.split()

    def _generalize(self, tokens: list) -> str:
        """
        Thay thế variables bằng typed placeholders.
        Giữ lại structure gốc để gom nhóm.
        """
        generalized = []
        for token in tokens:
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', token):
                generalized.append("<IP>")
            elif re.match(r'^[a-f0-9]{8,}$', token, re.IGNORECASE):
                generalized.append("<HASH>")
            elif re.match(r'^\d+(\.\d+)?$', token):
                generalized.append("<NUM>")
            elif re.search(r'\d', token):
                generalized.append("<VAR>")
            else:
                generalized.append(token)
        return " ".join(generalized)

    def add_log(self, log_str: str, timestamp: float = None):
        """Thêm log vào bộ template. GIỮ NGUYÊN nội dung gốc trong samples."""
        self.total_logs_processed += 1
        tokens = self._tokenize(log_str)
        template_key = self._generalize(tokens)

        if template_key not in self.templates:
            self.templates[template_key] = {
                "template": template_key,
                "count": 0,
                "samples": [],  # Giữ log GỐC (bao gồm cả injection payload)
                "time_range": [float('inf'), float('-inf')]
            }

        entry = self.templates[template_key]
        entry["count"] += 1

        # Giữ max_samples log gốc — KHÔNG lọc nội dung
        if len(entry["samples"]) < self.max_samples:
            entry["samples"].append(log_str)

        if timestamp is not None:
            entry["time_range"][0] = min(entry["time_range"][0], timestamp)
            entry["time_range"][1] = max(entry["time_range"][1], timestamp)

    def add_log_dict(self, log_entry: dict):
        """Thêm log dạng dict từ Redis stream."""
        key_fields = ['Source IP', 'Destination Port', 'Protocol',
                       'Total Fwd Packets', 'Flow Duration']
        parts = [f"{f}={log_entry.get(f)}" for f in key_fields if log_entry.get(f) is not None]
        log_str = " ".join(parts) if parts else str(log_entry)

        timestamp = log_entry.get('Timestamp', log_entry.get('Flow Duration'))
        try:
            timestamp = float(timestamp) if timestamp else None
        except (ValueError, TypeError):
            timestamp = None
        self.add_log(log_str, timestamp)

    def get_summary(self) -> list:
        """Trả về templates sắp xếp theo frequency giảm dần."""
        return sorted(self.templates.values(), key=lambda x: x["count"], reverse=True)

    def get_compression_ratio(self) -> float:
        """Compression Ratio = total logs / template count."""
        if self.total_logs_processed == 0:
            return 0.0
        return self.total_logs_processed / max(len(self.templates), 1)

    def format_for_llm(self) -> str:
        """
        Format output cho LLM. Samples GỐC được giữ nguyên.
        Output này sẽ được chuyển qua DelimitedDataEncapsulator
        trước khi đưa vào prompt.
        """
        lines = []
        for i, tmpl in enumerate(self.get_summary(), 1):
            time_str = ""
            if tmpl["time_range"][0] != float('inf'):
                time_str = (f", Time: {tmpl['time_range'][0]:.1f}s"
                            f"-{tmpl['time_range'][1]:.1f}s")
            lines.append(
                f"[Template {i}] {tmpl['template']} "
                f"(Count: {tmpl['count']}{time_str})"
            )
            for sample in tmpl["samples"]:
                lines.append(f"  Sample: {sample}")
        lines.append(f"\n[Stats] Total: {self.total_logs_processed} logs → "
                      f"{len(self.templates)} templates "
                      f"(Compression: {self.get_compression_ratio():.0f}x)")
        return "\n".join(lines)

    def reset(self):
        """Reset sau mỗi time window."""
        self.templates.clear()
        self.total_logs_processed = 0


class EntropyScorer:
    """
    Shannon Entropy scorer cho log strings.
    Log chứa SQLi/XSS payload thường có entropy cao hơn traffic bình thường.

    Dùng để UU TIÊN (prioritize) log nào cần giữ nguyên trong Token Budget,
    KHÔNG dùng để "lọc" hay "bảo vệ" chống injection.
    """
    def __init__(self, threshold: float = 4.5):
        self.threshold = threshold

    @staticmethod
    def calculate(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def is_high_entropy(self, log_str: str) -> bool:
        return self.calculate(log_str) > self.threshold

    def score(self, log_str: str) -> dict:
        entropy = self.calculate(log_str)
        return {
            "entropy": round(entropy, 3),
            "is_high_entropy": entropy > self.threshold,
            "priority": "HIGH" if entropy > self.threshold else "NORMAL"
        }


class TokenBudgetManager:
    """
    Quản lý ngân sách token. Cắt tỉa cho vừa Context Window.

    Chiến lược ưu tiên khi vượt ngân sách:
      1. HIGH-ENTROPY logs (giữ nguyên raw — khả năng chứa payload)
      2. Top-K Templates theo frequency (cao = nguy hiểm/phổ biến nhất)
      3. Truncate phần còn lại + ghi chú số patterns bị cắt
    """
    def __init__(self, budget: int = 4000):
        self.budget = budget

    @staticmethod
    def estimate_tokens(text: str) -> int:
        return len(text) // 4

    def fit_to_budget(self, template_text: str,
                       high_entropy_logs: list = None) -> str:
        """
        Cắt tỉa cho vừa ngân sách.
        Output sẽ được chuyển tiếp qua DelimitedDataEncapsulator.
        """
        output_lines = []
        current_tokens = 0

        # Priority 1: High-entropy logs (40% budget)
        if high_entropy_logs:
            output_lines.append("--- HIGH-PRIORITY LOGS (anomalous entropy) ---")
            for log in high_entropy_logs:
                line = f"  {log}"
                t = self.estimate_tokens(line)
                if current_tokens + t > self.budget * 0.4:
                    break
                output_lines.append(line)
                current_tokens += t

        # Priority 2: Template summaries (remaining 60%)
        output_lines.append("--- COMPRESSED TEMPLATES ---")
        for line in template_text.split('\n'):
            t = self.estimate_tokens(line)
            if current_tokens + t > self.budget:
                output_lines.append("[TRUNCATED due to token budget]")
                break
            output_lines.append(line)
            current_tokens += t

        output_lines.append(f"--- Token usage: ~{current_tokens}/{self.budget} ---")
        return "\n".join(output_lines)
