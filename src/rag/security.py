"""
RAG Security Layer: Structural Sanitization & Defense

Threat Model: 
Indirect Prompt Injection via RAG (RAG Poisoning).
Attacker nhúng payload thao túng (ví dụ: IGNORE INSTRUCTIONS) vào log (User-Agent, URI).
Khi RAG retrieve các chunk này và đưa vào LLM prompt, LLM sẽ bị thao túng.

Giải pháp:
- Không dùng keyword blacklist (gây false positive với log hợp lệ).
- Dùng Structural Sanitization: Xóa ký tự điều khiển tàng hình (null bytes, zero-width spaces),
  chuẩn hóa unicode, giới hạn độ dài.
- Tương lai có thể mở rộng thêm Document Provenance Tracking.
"""
import re
import unicodedata

def structural_sanitize(text: str, max_length: int = 1500) -> str:
    """
    Sanitize text chunks trước khi đưa vào LLM Context.
    """
    if not text:
        return ""

    # 1. Normalize Unicode (chống Unicode homoglyph attacks)
    text = unicodedata.normalize('NFKC', text)

    # 2. Xóa các ký tự điều khiển (control characters) và tàng hình
    # Giữ lại \n, \t, \r
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202f\u2060-\u206f]', '', text)

    # 3. Truncate (chặn buffer overflow / context window exhaustion)
    if len(text) > max_length:
        text = text[:max_length] + "... [TRUNCATED FOR SECURITY]"

    return text

def log_tokenizer(text: str) -> list[str]:
    """
    Custom tokenizer cho BM25 tối ưu cho Security Logs.
    Giữ nguyên các token mang tính định danh cao như:
    - CVE IDs (CVE-2014-0160)
    - IP addresses (192.168.1.1)
    - Port/Protocol/Hash/Words thông thường
    """
    # Regex bắt CVE, IPv4, và các từ thông thường
    tokens = re.findall(r'CVE-\d{4}-\d+|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9_.-]+', text)
    return [t.lower() for t in tokens if t.strip()]
