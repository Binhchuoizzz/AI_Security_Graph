"""
Tầng bảo mật RAG: Làm sạch cấu trúc & Phòng thủ

Mô hình đe dọa (Threat Model):
Prompt Injection gián tiếp qua RAG (RAG Poisoning).
Kẻ tấn công nhúng payload thao túng (ví dụ: IGNORE INSTRUCTIONS) vào log (User-Agent, URI).
Khi RAG truy xuất các chunk này và đưa vào LLM prompt, LLM sẽ bị thao túng.

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
    Ủy quyền cho RAGSanitizer.sanitize_ingest để đảm bảo tính đồng nhất
    và độ phủ bảo mật cao nhất (loại bỏ HTML/JS tags, Markdown images/links).
    """
    from src.guardrails.rag_sanitizer import RAGSanitizer
    return RAGSanitizer.sanitize_ingest(text, max_length)



def log_tokenizer(text: str) -> list[str]:
    """
    Custom tokenizer cho BM25 tối ưu cho Security Logs.
    Giữ nguyên các token mang tính định danh cao như:
    - CVE IDs (CVE-2014-0160)
    - IP addresses (192.168.1.1)
    - Port/Protocol/Hash/Words thông thường
    """
    # Regex bắt CVE, IPv4, và các từ thông thường
    tokens = re.findall(r"CVE-\d{4}-\d+|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9_.-]+", text)
    return [t.lower() for t in tokens if t.strip()]


# =========================================================================
# PHÒNG THỦ RAG POISONING — Tính toàn vẹn của tài liệu (Attack Vector #06)
# =========================================================================

import hashlib
import os
import logging

logger = logging.getLogger(__name__)

CHECKSUM_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_base", "checksums.sha256"
)
KB_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "knowledge_base"
)


def verify_document_integrity(exclude_generated: bool = False) -> dict:
    """
    Kiểm tra SHA-256 hash của Knowledge Base files trước khi load.
    So sánh với checksums.sha256 đã được pre-computed.
    
    Trả về:
      {"verified": True/False, "details": [...]}
    
    Nếu hash không khớp → KB có thể đã bị tamper (RAG Poisoning).
    """
    results = {"verified": True, "details": []}

    if not os.path.exists(CHECKSUM_PATH):
        logger.warning("[RAG SECURITY] checksums.sha256 not found — integrity check skipped")
        results["verified"] = False
        results["details"].append("Checksum file missing")
        return results

    # Phân tích tệp checksum
    expected_hashes = {}
    with open(CHECKSUM_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line and "  " in line:
                hash_val, filename = line.split("  ", 1)
                expected_hashes[filename.strip()] = hash_val.strip()

    # Xác minh từng tệp
    for filename, expected_hash in expected_hashes.items():
        if exclude_generated and "faiss_index/" in filename:
            continue
        filepath = os.path.join(KB_DIR, filename)
        if not os.path.exists(filepath):
            results["verified"] = False
            results["details"].append(f"MISSING: {filename}")
            continue

        # Tính toán hash thực tế
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()

        if actual_hash == expected_hash:
            results["details"].append(f"OK: {filename}")
        else:
            results["verified"] = False
            results["details"].append(
                f"TAMPERED: {filename} — expected {expected_hash[:12]}..., "
                f"got {actual_hash[:12]}..."
            )
            logger.critical(
                f"[RAG SECURITY] Knowledge Base INTEGRITY VIOLATION: {filename}. "
                f"Possible RAG Poisoning attack!"
            )

    return results


def add_provenance(chunk: str, source_file: str, chunk_index: int) -> str:
    """
    Gắn provenance tag vào mỗi RAG chunk.
    Giúp LLM phân biệt nguồn gốc context và phát hiện nội dung lạ.
    """
    provenance = f"[SOURCE: {source_file} | CHUNK: {chunk_index} | VERIFIED: SENTINEL_KB]"
    return f"{provenance}\n{chunk}"

