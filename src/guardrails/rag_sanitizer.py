"""
Guardrails: RAG Poisoning Sanitizer (Structural Sanitization & Instruction Neutralization)
"""

import logging
import re
import unicodedata

from src.guardrails.prompt_filter import (
    HTMLTagStripper,
    load_config,
    strip_dangerous_tags_recursive,
    strip_html_tags_fallback,
)

logger = logging.getLogger(__name__)


class RAGSanitizer:
    """
    Phòng thủ chống RAG Poisoning (Indirect Prompt Injection) ở 2 thời điểm:
      1. Ingest (Nạp tài liệu): Làm sạch Unicode, ký tự ẩn, HTML/JS tags,
         Markdown images/links.
      2. Retrieve (Truy xuất): Xóa delimiter markers, vô hiệu hóa
         các chỉ thị lệnh độc hại.
    """

    def __init__(self):
        config = load_config()
        self.injection_patterns = config.get("guardrails", {}).get("injection_patterns", [])
        self.jailbreak_patterns = config.get("guardrails", {}).get("jailbreak_patterns", [])

        # Tạo regex để bắt các pattern không phân biệt hoa thường
        self.injection_res = [
            re.compile(re.escape(p), re.IGNORECASE) for p in self.injection_patterns
        ]
        self.jailbreak_res = [
            re.compile(re.escape(p), re.IGNORECASE) for p in self.jailbreak_patterns
        ]

    @staticmethod
    def sanitize_ingest(text: str, max_length: int = 1500) -> str:
        """
        Nạp tài liệu: Làm sạch cấu trúc và giới hạn dung lượng
        để ngăn chặn payload ẩn.
        """
        if not text:
            return ""

        # 1. Normalize Unicode (chống Unicode homoglyph attacks)
        clean = unicodedata.normalize("NFKC", text)

        # 2. Xóa các ký tự điều khiển (control characters) và zero-width
        # characters
        control_chars = (
            r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
            r"\u200b-\u200f\u2028-\u202f\u2060-\u206f]"
        )
        clean = re.sub(control_chars, "", clean)

        # 3. Làm sạch HTML/JS tags
        clean = strip_dangerous_tags_recursive(clean)
        try:
            stripper = HTMLTagStripper()
            stripper.feed(clean)
            clean = stripper.get_data()
        except Exception:
            clean = strip_html_tags_fallback(clean)

        # 4. Làm sạch Markdown images và links
        clean = re.sub(r"!\[[^\]]*\]\s*\([^\)]+\)", "[IMG_STRIPPED]", clean, flags=re.IGNORECASE)
        clean = re.sub(
            r"\[[^\]]*\]\s*\(https?://[^\)]+\)", "[LINK_STRIPPED]", clean, flags=re.IGNORECASE
        )

        # 5. Truncate (chặn buffer overflow / context window exhaustion)
        if len(clean) > max_length:
            clean = clean[:max_length] + "... [TRUNCATED FOR SECURITY]"

        return clean

    def sanitize_retrieve(self, text: str) -> str:
        """
        Truy xuất: Neutralize prompt injection và jailbreak patterns để tránh
        kích hoạt khi LLM đọc context.
        Đồng thời strip hoàn toàn delimiter dynamic markers để chống
        Delimiter Smuggling.
        """
        if not text:
            return ""

        # 1. Loại bỏ mọi dấu hiệu của dynamic delimiters (<<<...>>>)
        clean = re.sub(r"<<<[^>]*>>>", "[DELIMITER_STRIPPED]", text)

        # 2. Phát hiện và trung hòa Prompt Injection patterns
        for pattern_re in self.injection_res:
            new_clean = pattern_re.sub("[POISONOUS_INSTRUCTION_NEUTRALIZED]", clean)
            if new_clean != clean:
                logger.warning(
                    f"[RAG SANITIZER] Injection pattern neutralized: {pattern_re.pattern}"
                )
            clean = new_clean

        # 3. Phát hiện và trung hòa Jailbreak patterns
        for pattern_re in self.jailbreak_res:
            new_clean = pattern_re.sub("[POISONOUS_JAILBREAK_NEUTRALIZED]", clean)
            if new_clean != clean:
                logger.warning(
                    f"[RAG SANITIZER] Jailbreak pattern neutralized: {pattern_re.pattern}"
                )
            clean = new_clean

        return clean

    def sanitize_cache_entry(self, entry: dict) -> dict:
        """
        Làm sạch một cache entry được lấy ra từ Semantic Cache.
        Ngăn chặn Cache Poisoning bypass lớp bảo vệ RAG.
        """
        if not entry:
            return {}

        sanitized = dict(entry)

        # 1. Làm sạch các kết quả thô trong lists
        if "mitre_results" in sanitized and isinstance(sanitized["mitre_results"], list):
            sanitized["mitre_results"] = [
                {**r, "text": self.sanitize_retrieve(r.get("text", ""))}
                if isinstance(r, dict)
                else r
                for r in sanitized["mitre_results"]
            ]
        if "nist_results" in sanitized and isinstance(sanitized["nist_results"], list):
            sanitized["nist_results"] = [
                {**r, "text": self.sanitize_retrieve(r.get("text", ""))}
                if isinstance(r, dict)
                else r
                for r in sanitized["nist_results"]
            ]

        # 2. Làm sạch context văn bản
        if "mitre_context" in sanitized and isinstance(sanitized["mitre_context"], str):
            sanitized["mitre_context"] = self.sanitize_retrieve(sanitized["mitre_context"])
        if "nist_context" in sanitized and isinstance(sanitized["nist_context"], str):
            sanitized["nist_context"] = self.sanitize_retrieve(sanitized["nist_context"])

        return sanitized
