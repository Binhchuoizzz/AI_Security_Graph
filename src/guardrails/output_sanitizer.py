"""
Bộ làm sạch đầu ra (Output Sanitizer): Phòng thủ rò rỉ dữ liệu (Vector tấn công #04)
"""

import re
import logging
import base64

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Sanitize LLM output TRƯỚC khi render trên UI hoặc ghi DB.
    Chống Data Exfiltration và bypass bằng Obfuscation/Invisible Characters.
    """

    # Patterns nguy hiểm trong output
    DANGEROUS_PATTERNS = [
        # Markdown image (exfil vector chính - hỗ trợ khoảng trắng tùy chọn)
        (r'!\[[^\]]*\]\s*\([^\)]+\)', '[IMG_STRIPPED]'),
        # Markdown links to external domains (hỗ trợ khoảng trắng tùy chọn)
        (r'\[[^\]]*\]\s*\(https?://[^\)]+\)', '[LINK_STRIPPED]'),
        # HTML img tags
        (r'<img[^>]*>', '[IMG_STRIPPED]'),
        # Thẻ HTML anchor
        (r'<a\s[^>]*>.*?</a>', '[LINK_STRIPPED]'),
        # Thẻ HTML iframe (nội dung nhúng)
        (r'<iframe[^>]*>.*?</iframe>', '[IFRAME_STRIPPED]'),
        # Thẻ HTML script
        (r'<script[^>]*>.*?</script>', '[SCRIPT_STRIPPED]'),
        # Thẻ HTML object/embed (rò rỉ dựa trên plugin)
        (r'<object[^>]*>.*?</object>', '[OBJECT_STRIPPED]'),
        (r'<embed[^>]*/?>', '[EMBED_STRIPPED]'),
        # Định dạng Data URI (có thể mã hóa mã HTML/JS tùy ý)
        (
            r'data:[a-zA-Z]+/[a-zA-Z+]+;base64,[A-Za-z0-9+/=]+',
            '[DATA_URI_STRIPPED]'
        ),
        # Định dạng SVG có khả năng thực thi JavaScript
        (r'<svg[^>]*>.*?</svg>', '[SVG_STRIPPED]'),
        # Thẻ style (rò rỉ dựa trên CSS qua url())
        (r'<style[^>]*>.*?</style>', '[STYLE_STRIPPED]'),
    ]

    def __init__(self):
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), replacement)
            for pattern, replacement in self.DANGEROUS_PATTERNS
        ]
        self._strip_count = 0

    def _sanitize_base64(self, text: str) -> str:
        # Tìm kiếm khối Base64 hợp lệ, độ dài tối thiểu 8
        # để giảm chi phí false positive
        pattern = re.compile(r'\b[A-Za-z0-9+/]{8,}={0,2}\b')
        clean = text

        def repl(match):
            val = match.group(0)
            try:
                pad = len(val) % 4
                if pad:
                    val += '=' * (4 - pad)
                decoded = base64.b64decode(
                    val.encode(), validate=True
                ).decode('utf-8', errors='ignore')
                triggers = [
                    "<script", "<img", "javascript:",
                    "onload=", "onerror=", "iframe"
                ]
                if len(decoded) > 3 and any(
                    char in decoded.lower() for char in triggers
                ):
                    self._strip_count += 1
                    return "[BASE64_OBFUSCATED_STRIPPED]"
            except Exception:
                pass
            return match.group(0)

        return pattern.sub(repl, clean)

    def _sanitize_hex(self, text: str) -> str:
        pattern = re.compile(r'\b(0x)?([a-fA-F0-9]{8,})\b')
        clean = text

        def repl(match):
            hex_digits = match.group(2)
            try:
                decoded = bytes.fromhex(hex_digits).decode(
                    'utf-8', errors='ignore'
                )
                triggers = [
                    "<script", "<img", "javascript:",
                    "onload=", "onerror=", "iframe"
                ]
                if len(decoded) > 3 and any(
                    char in decoded.lower() for char in triggers
                ):
                    self._strip_count += 1
                    return "[HEX_OBFUSCATED_STRIPPED]"
            except Exception:
                pass
            return match.group(0)

        return pattern.sub(repl, clean)

    def sanitize(self, text: str) -> str:
        """
        Làm sạch văn bản đầu ra. Loại bỏ các cấu trúc Markdown/HTML
        nguy hiểm, ANSI escapes, ký tự ẩn (zero-width) và kiểm tra
        obfuscation (Base64/Hex).
        """
        if not text:
            return text

        self._strip_count = 0
        clean = text

        # 1. Loại bỏ các ký tự ẩn tàng hình (Zero-width characters)
        clean = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad]", "", clean)

        # 2. Loại bỏ các mã escape định dạng thiết bị cuối (ANSI escape codes)
        clean = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", clean)

        # 3. Quét các cấu trúc Markdown/HTML nguy hiểm tĩnh TRƯỚC
        # (để bắt được Data URIs)
        for compiled_re, replacement in self.compiled_patterns:
            matches = compiled_re.findall(clean)
            if matches:
                self._strip_count += len(matches)
                clean = compiled_re.sub(replacement, clean)

        # 4. Quét giải mã Base64/Hex SÂU để phát hiện payload ẩn
        clean = self._sanitize_base64(clean)
        clean = self._sanitize_hex(clean)

        if self._strip_count > 0:
            logger.warning(
                f"[OUTPUT SANITIZER] Stripped {self._strip_count} dangerous "
                f"patterns/obfuscated vectors from LLM output"
            )

        return clean

    def sanitize_for_db(self, text: str) -> str:
        """
        Sanitize text trước khi ghi vào SQLite.
        Bổ sung manual escaping để tương thích với các test suites hiện tại.
        """
        if not text:
            return text
        clean = self.sanitize(text)
        # Bổ sung escaping để đảm bảo backward compatibility với bộ test suite
        clean = clean.replace("'", "''")
        return clean

    @property
    def last_strip_count(self) -> int:
        """Số patterns đã bị strip trong lần sanitize gần nhất."""
        return self._strip_count


# Thực thể duy nhất (Singleton)
output_sanitizer = OutputSanitizer()
