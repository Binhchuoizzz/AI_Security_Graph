"""
RAG: Knowledge Base Embedder (FAISS Index Builder)

CHỨC NĂNG:
  Đọc knowledge base JSON (MITRE ATT&CK + NIST SP 800-61r2) → tạo text chunks
  → embed bằng Sentence-Transformers → build FAISS index riêng cho mỗi nguồn.

  Tạo ra 2 FAISS index:
    knowledge_base/faiss_index/mitre_attack.index
    knowledge_base/faiss_index/nist_800_61r2.index
  + 2 metadata files:
    knowledge_base/faiss_index/mitre_attack_metadata.json
    knowledge_base/faiss_index/nist_800_61r2_metadata.json

  Metadata map: vector index position → original chunk text + source ID

CHỈ CHẠY 1 LẦN (hoặc khi update knowledge base):
  python -m src.rag.embedder

MÔ HÌNH EMBEDDING:
  all-MiniLM-L6-v2 (~90MB, chạy CPU, 384 dimensions)
  Lý do chọn: nhẹ, nhanh, chất lượng đủ cho semantic search trong domain security.
"""

import json
import logging
import os
import pickle
import sys

import numpy as np  # type: ignore

# Đảm bảo import được src.rag.security
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)
from src.guardrails import RAGSanitizer
from src.rag.security import log_tokenizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Khai báo đường dẫn
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KB_DIR = os.path.join(BASE_DIR, "knowledge_base")
INDEX_DIR = os.path.join(KB_DIR, "faiss_index")
MITRE_JSON = os.path.join(KB_DIR, "mitre_attack.json")
NIST_JSON = os.path.join(KB_DIR, "nist_800_61r2.json")

# Khởi tạo mô hình
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384


def load_mitre_chunks() -> list[dict]:
    """
    Chuyển mỗi MITRE technique thành 1 text chunk để embed.
    Format chunk: "T1110 - Brute Force (Credential Access): ..."
    Giữ detection_indicators và response_actions để Agent có context hành động.
    """
    with open(MITRE_JSON, encoding="utf-8") as f:
        data = json.load(f)

    chunks = []
    techniques = data if isinstance(data, list) else data.get("techniques", [])
    for tech in techniques:
        # Xây dựng đoạn văn bản (chunk) giàu ngữ nghĩa để nhúng (embedding)
        text_parts = [
            f"{tech['id']} - {tech['name']} ({tech.get('tactic', 'Unknown')})",
            f"Description: {tech.get('description', '')}",
        ]
        if tech.get("detection_indicators"):
            text_parts.append(f"Detection Indicators: {', '.join(tech['detection_indicators'])}")
        if tech.get("log_patterns"):
            text_parts.append(f"Log Patterns: {', '.join(tech['log_patterns'])}")
        if tech.get("response_actions"):
            text_parts.append(f"Response Actions: {', '.join(tech['response_actions'])}")

        chunk_text = "\n".join(text_parts)
        sanitized_text = RAGSanitizer.sanitize_ingest(chunk_text)

        chunks.append(
            {
                "text": sanitized_text,
                "metadata": {
                    "source": "mitre_attack",
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech.get("tactic", "Unknown"),
                },
            }
        )

    logger.info(f"Loaded {len(chunks)} MITRE ATT&CK technique chunks")
    return chunks


def load_nist_chunks_json() -> list[dict]:
    """
    [LEGACY] Chuyển mỗi NIST SP 800-61r2 phase/control thành 1 text chunk để embed.
    Chỉ tạo ra 6 chunks từ curated JSON — không đủ granularity cho RAG.
    Giữ lại cho backward compatibility.
    """
    with open(NIST_JSON, encoding="utf-8") as f:
        data = json.load(f)

    chunks = []
    for ctrl in data.get("controls", []):
        text_parts = [
            f"{ctrl['control']} - {ctrl['name']} ({ctrl.get('domain', 'Unknown')})",
            f"Description: {ctrl.get('description', '')}",
        ]
        if ctrl.get("applicability"):
            text_parts.append(f"Applicability: {ctrl['applicability']}")
        if ctrl.get("response_guidance"):
            text_parts.append(f"Response Guidance: {ctrl['response_guidance']}")

        chunk_text = "\n".join(text_parts)
        sanitized_text = RAGSanitizer.sanitize_ingest(chunk_text)

        chunks.append(
            {
                "text": sanitized_text,
                "metadata": {
                    "source": "nist_800_61r2",
                    "id": ctrl["control"],
                    "name": ctrl["name"],
                    "domain": ctrl.get("domain", "Unknown"),
                },
            }
        )

    logger.info(f"[LEGACY] Loaded {len(chunks)} NIST SP 800-61r2 control chunks")
    return chunks


# Đường dẫn tới tệp văn bản trích xuất từ PDF NIST
NIST_TXT_PATH = os.path.join(BASE_DIR, "data", "knowledge", "nist_800_61r2.txt")


def load_nist_chunks() -> list[dict]:
    """
    Phân tách toàn bộ tài liệu NIST SP 800-61r2 (79 trang) thành các đoạn văn bản
    nhỏ (paragraph-level chunks) để tối ưu cho việc truy xuất ngữ nghĩa (semantic RAG).
    Mục tiêu: 80-120 đoạn.

    Chiến lược:
      - Nguồn: Văn bản trích xuất từ PDF (data/knowledge/nist_800_61r2.txt)
      - Phân tách: Sử dụng cửa sổ trượt dựa trên câu qua RecursiveCharacterTextSplitter
      - chunk_size: 1500 ký tự (~256 tokens)
      - overlap: 190 ký tự (~32 tokens)
      - Giữ các tiêu đề phần dưới dạng siêu dữ liệu (gắn nhãn giai đoạn Incident Response)

    Tự động chuyển về phân tách JSON cũ nếu không tìm thấy tệp văn bản.
    """
    if not os.path.exists(NIST_TXT_PATH):
        logger.warning(
            f"NIST text file not found at {NIST_TXT_PATH}. "
            f"Falling back to legacy JSON chunking (6 controls only)."
        )
        return load_nist_chunks_json()

    import re

    from langchain_text_splitters import RecursiveCharacterTextSplitter  # type: ignore

    with open(NIST_TXT_PATH, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    original_len = len(text)

    # Làm sạch các ký tự rác từ PDF
    text = re.sub(r"\n{3,}", "\n\n", text)  # Thu gọn các dòng trống thừa
    text = re.sub(r"NIST SP 800-61.*?\n", "", text)  # Loại bỏ các tiêu đề lặp lại
    text = re.sub(r"Page \d+\n", "", text)  # Loại bỏ số trang
    text = re.sub(r"\f", "", text)  # Loại bỏ ký tự phân trang (form feed)
    text = re.sub(r"^\d+\s*\n", "", text, flags=re.MULTILINE)  # Loại bỏ số trang độc lập

    logger.info(f"NIST text loaded: {original_len} chars → {len(text)} chars after cleanup")

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,  # ~256 tokens for all-MiniLM-L6-v2
        chunk_overlap=190,  # ~32 tokens overlap
        separators=[
            "\n\n",  # paragraph break (highest priority)
            "\n",  # line break
            ". ",  # sentence break
            " ",  # word break (fallback)
        ],
        length_function=len,
    )

    raw_chunks = splitter.split_text(text)

    # Gắn nhãn giai đoạn ứng phó sự cố (IR phase) cho mỗi đoạn bằng từ khóa khớp
    # Mỗi giai đoạn có các từ đồng nghĩa/liên quan từ tài liệu NIST
    ir_phase_keywords = {
        "Preparation": [
            "preparation",
            "preparing",
            "prepared",
            "readiness",
            "incident response plan",
            "irp",
            "policy",
            "training",
            "exercise",
            "toolkit",
            "jump bag",
            "contact list",
            "war room",
            "communication plan",
            "resource",
        ],
        "Detection": [
            "detection",
            "detect",
            "detecting",
            "identified",
            "indicator",
            "precursor",
            "sign",
            "symptom",
            "monitoring",
            "alerting",
            "ids",
            "intrusion detection",
            "anomaly",
            "signature",
            "log analysis",
            "correlation",
            "siem",
            "sensor",
            "network monitoring",
        ],
        "Analysis": [
            "analysis",
            "analyze",
            "analyzing",
            "triage",
            "investigate",
            "investigation",
            "priorit",
            "severity",
            "categoriz",
            "classify",
            "validation",
            "verify",
            "false positive",
            "incident category",
            "functional impact",
            "information impact",
            "recoverability",
        ],
        "Containment": [
            "containment",
            "contain",
            "containing",
            "isolat",
            "quarantin",
            "sandbox",
            "segmentation",
            "block",
            "disconnect",
            "short-term containment",
            "long-term containment",
            "network isolation",
            "disable account",
        ],
        "Eradication": [
            "eradication",
            "eradicat",
            "eliminat",
            "remov",
            "clean",
            "disinfect",
            "patch",
            "remediat",
            "vulnerability",
            "root cause",
            "malware removal",
            "reimag",
            "rebuild",
        ],
        "Recovery": [
            "recovery",
            "recover",
            "restoring",
            "restored",
            "rebuild",
            "reconstitut",
            "backup",
            "business continuity",
            "return to normal",
            "service restoration",
            "validation testing",
            "monitoring after",
        ],
        "Post-Incident": [
            "post-incident",
            "lessons learned",
            "after action",
            "retrospective",
            "improvement",
            "metrics",
            "incident cost",
            "follow-up",
            "report",
            "what happened",
            "what could be improved",
            "retention",
            "evidence retention",
        ],
    }

    chunks = []
    for i, chunk_text in enumerate(raw_chunks):
        # Tính điểm mỗi giai đoạn dựa trên số lượng từ khóa khớp
        text_lower = chunk_text.lower()
        phase_scores = {}
        for phase, keywords in ir_phase_keywords.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > 0:
                phase_scores[phase] = score

        if phase_scores:
            phase = max(phase_scores, key=lambda k: phase_scores[k])
        else:
            phase = "General"

        sanitized_text = RAGSanitizer.sanitize_ingest(chunk_text)

        chunks.append(
            {
                "text": sanitized_text,
                "metadata": {
                    "source": "nist_800_61r2",
                    "id": f"nist_{i:03d}",
                    "name": f"NIST SP 800-61r2 Chunk {i}",
                    "domain": "Incident Response",
                    "ir_phase": phase,
                },
            }
        )

    logger.info(
        f"Generated {len(chunks)} NIST paragraph-level chunks "
        f"(target: 80-120, from {original_len} chars)"
    )

    if len(chunks) < 30:
        logger.warning(
            f"Only {len(chunks)} chunks generated — source file may be truncated. "
            f"Supplementing with legacy JSON controls."
        )
        chunks.extend(load_nist_chunks_json())

    return chunks


def build_indexes(chunks: list[dict], index_name: str, model=None):
    """
    Xây dựng 2 loại Index phục vụ Hybrid Search:
    1. FAISS IndexFlatIP (Truy xuất ngữ nghĩa - Dense)
    2. BM25Okapi (Truy xuất từ khóa - Sparse)

    Tham số:
        chunks: Danh sách các đoạn văn bản kèm siêu dữ liệu.
        index_name: Tiền tố tên của các tệp lưu trữ.
        model: Thực thể SentenceTransformer đã được nạp sẵn.

    Lưu trữ:
      - Tệp FAISS index: {index_name}.index
      - Tệp BM25 corpus: {index_name}_bm25.pkl
      - Tệp siêu dữ liệu JSON: {index_name}_metadata.json
    """
    try:
        import faiss  # type: ignore
        from rank_bm25 import BM25Okapi  # type: ignore
        from sentence_transformers import SentenceTransformer  # type: ignore
    except ImportError as e:
        logger.error(
            f"Missing dependency: {e}. Run: pip install sentence-transformers faiss-cpu rank_bm25"
        )
        raise

    # Sử dụng lại model nếu đã load, tránh load lại lần thứ 2
    if model is None:
        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        model = SentenceTransformer(EMBEDDING_MODEL)

    # 1. Build Dense Index (FAISS - Tìm kiếm vector ngữ nghĩa)
    texts = [chunk["text"] for chunk in chunks]
    logger.info(f"Building Dense Embeddings ({len(texts)} chunks) for [{index_name}]...")

    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    embeddings = np.array(embeddings, dtype="float32")

    logger.info(f"Embeddings shape: {embeddings.shape}")

    # Xây dựng FAISS index (Inner Product = cosine similarity khi được chuẩn hóa)
    index = faiss.IndexFlatIP(EMBEDDING_DIM)
    index.add(embeddings)  # type: ignore

    os.makedirs(INDEX_DIR, exist_ok=True)
    index_path = os.path.join(INDEX_DIR, f"{index_name}.index")
    faiss.write_index(index, index_path)
    logger.info(f"Saved FAISS index: {index_path} ({index.ntotal} vectors)")

    # 2. Build Sparse Index (BM25 - Tìm kiếm từ khóa chính xác)
    logger.info(f"Building Sparse Index (BM25) for [{index_name}]...")
    tokenized_corpus = [log_tokenizer(text) for text in texts]
    bm25 = BM25Okapi(tokenized_corpus)

    bm25_path = os.path.join(INDEX_DIR, f"{index_name}_bm25.pkl")
    with open(bm25_path, "wb") as f:
        pickle.dump(bm25, f)
    logger.info(f"Saved BM25 corpus: {bm25_path}")

    # Lưu siêu dữ liệu metadata (ánh xạ vị trí → thông tin chunk)
    metadata = []
    for i, chunk in enumerate(chunks):
        metadata.append({"index_position": i, "text": chunk["text"], **chunk["metadata"]})

    metadata_path = os.path.join(INDEX_DIR, f"{index_name}_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved metadata: {metadata_path} ({len(metadata)} entries)")

    return index


def update_checksums_file():
    """Tự động tính toán lại SHA-256 cho toàn bộ tệp KB và index, ghi đè checksums.sha256."""
    import hashlib

    files_to_hash = [
        ("mitre_attack.json", MITRE_JSON),
        ("nist_800_61r2.json", NIST_JSON),
        ("faiss_index/mitre_attack.index", os.path.join(INDEX_DIR, "mitre_attack.index")),
        ("faiss_index/mitre_attack_bm25.pkl", os.path.join(INDEX_DIR, "mitre_attack_bm25.pkl")),
        (
            "faiss_index/mitre_attack_metadata.json",
            os.path.join(INDEX_DIR, "mitre_attack_metadata.json"),
        ),
        ("faiss_index/nist_800_61r2.index", os.path.join(INDEX_DIR, "nist_800_61r2.index")),
        ("faiss_index/nist_800_61r2_bm25.pkl", os.path.join(INDEX_DIR, "nist_800_61r2_bm25.pkl")),
        (
            "faiss_index/nist_800_61r2_metadata.json",
            os.path.join(INDEX_DIR, "nist_800_61r2_metadata.json"),
        ),
    ]

    checksum_lines = []
    for rel_name, abs_path in files_to_hash:
        if os.path.exists(abs_path):
            sha256 = hashlib.sha256()
            with open(abs_path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            checksum_lines.append(f"{sha256.hexdigest()}  {rel_name}")

    checksums_path = os.path.join(KB_DIR, "checksums.sha256")
    with open(checksums_path, "w", encoding="utf-8") as f:
        f.write("\n".join(checksum_lines) + "\n")
    logger.info(f"Updated {checksums_path} with {len(checksum_lines)} file hashes.")


def build_all_indexes():
    """Build cả 2 FAISS indexes: MITRE ATT&CK + NIST SP 800-61r2."""
    from src.rag.security import verify_document_integrity

    integrity_result = verify_document_integrity(exclude_generated=True)
    if not integrity_result["verified"]:
        logger.critical(f"KB integrity check FAILED: {integrity_result['details']}")
        raise RuntimeError("Knowledge Base integrity violation detected")

    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        raise

    logger.info("=" * 60)
    logger.info("SENTINEL Knowledge Base Indexer")
    logger.info("=" * 60)

    # Load model MỘT LẦN DUY NHẤT, dùng chung cho cả 2 indexes
    logger.info(f"Loading embedding model: {EMBEDDING_MODEL} (shared instance)")
    shared_model = SentenceTransformer(EMBEDDING_MODEL)

    # MITRE ATT&CK (Khung tham chiếu kỹ thuật tấn công)
    mitre_chunks = load_mitre_chunks()
    build_indexes(mitre_chunks, "mitre_attack", model=shared_model)

    # NIST SP 800-61r2 (Khung ứng phó sự cố bảo mật)
    nist_chunks = load_nist_chunks()
    build_indexes(nist_chunks, "nist_800_61r2", model=shared_model)

    # Cập nhật mã checksum cho các index và pickle file mới tạo
    update_checksums_file()

    logger.info("=" * 60)
    logger.info(f"All indexes built successfully in: {INDEX_DIR}")
    logger.info(f"Total vectors: {len(mitre_chunks) + len(nist_chunks)}")
    logger.info("=" * 60)


if __name__ == "__main__":
    build_all_indexes()
