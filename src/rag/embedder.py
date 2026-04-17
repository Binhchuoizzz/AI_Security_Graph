"""
RAG: Knowledge Base Embedder (FAISS Index Builder)

CHỨC NĂNG:
  Đọc knowledge base JSON (MITRE ATT&CK + ISO 27001) → tạo text chunks
  → embed bằng Sentence-Transformers → build FAISS index riêng cho mỗi nguồn.

  Tạo ra 2 FAISS index:
    knowledge_base/faiss_index/mitre_attack.index
    knowledge_base/faiss_index/iso_27001.index
  + 2 metadata files:
    knowledge_base/faiss_index/mitre_attack_metadata.json
    knowledge_base/faiss_index/iso_27001_metadata.json

  Metadata map: vector index position → original chunk text + source ID

CHỈ CHẠY 1 LẦN (hoặc khi update knowledge base):
  python -m src.rag.embedder

MÔ HÌNH EMBEDDING:
  all-MiniLM-L6-v2 (~90MB, chạy CPU, 384 dimensions)
  Lý do chọn: nhẹ, nhanh, chất lượng đủ cho semantic search trong domain security.
"""
import json
import os
import logging
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KB_DIR = os.path.join(BASE_DIR, 'knowledge_base')
INDEX_DIR = os.path.join(KB_DIR, 'faiss_index')
MITRE_JSON = os.path.join(KB_DIR, 'mitre_attack.json')
ISO_JSON = os.path.join(KB_DIR, 'iso_27001_controls.json')

# Model
EMBEDDING_MODEL = 'all-MiniLM-L6-v2'
EMBEDDING_DIM = 384


def load_mitre_chunks() -> list[dict]:
    """
    Chuyển mỗi MITRE technique thành 1 text chunk để embed.
    Format chunk: "T1110 - Brute Force (Credential Access): ..."
    Giữ detection_indicators và response_actions để Agent có context hành động.
    """
    with open(MITRE_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    chunks = []
    for tech in data.get('techniques', []):
        # Build rich text chunk cho embedding
        text_parts = [
            f"{tech['id']} - {tech['name']} ({tech.get('tactic', 'Unknown')})",
            f"Description: {tech.get('description', '')}",
        ]
        if tech.get('detection_indicators'):
            text_parts.append(f"Detection Indicators: {', '.join(tech['detection_indicators'])}")
        if tech.get('log_patterns'):
            text_parts.append(f"Log Patterns: {', '.join(tech['log_patterns'])}")
        if tech.get('response_actions'):
            text_parts.append(f"Response Actions: {', '.join(tech['response_actions'])}")

        chunk_text = "\n".join(text_parts)

        chunks.append({
            'text': chunk_text,
            'metadata': {
                'source': 'mitre_attack',
                'id': tech['id'],
                'name': tech['name'],
                'tactic': tech.get('tactic', 'Unknown'),
            }
        })

    logger.info(f"Loaded {len(chunks)} MITRE ATT&CK technique chunks")
    return chunks


def load_iso_chunks() -> list[dict]:
    """
    Chuyển mỗi ISO 27001 control thành 1 text chunk để embed.
    Format chunk: "A.8.20 - Networks security (Technological Controls): ..."
    """
    with open(ISO_JSON, 'r', encoding='utf-8') as f:
        data = json.load(f)

    chunks = []
    for ctrl in data.get('controls', []):
        text_parts = [
            f"{ctrl['control']} - {ctrl['name']} ({ctrl.get('domain', 'Unknown')})",
            f"Description: {ctrl.get('description', '')}",
        ]
        if ctrl.get('applicability'):
            text_parts.append(f"Applicability: {ctrl['applicability']}")
        if ctrl.get('response_guidance'):
            text_parts.append(f"Response Guidance: {ctrl['response_guidance']}")

        chunk_text = "\n".join(text_parts)

        chunks.append({
            'text': chunk_text,
            'metadata': {
                'source': 'iso_27001',
                'id': ctrl['control'],
                'name': ctrl['name'],
                'domain': ctrl.get('domain', 'Unknown'),
            }
        })

    logger.info(f"Loaded {len(chunks)} ISO 27001 control chunks")
    return chunks


def build_faiss_index(chunks: list[dict], index_name: str):
    """
    Embed text chunks → build FAISS IndexFlatIP (Inner Product = cosine similarity
    khi vectors đã normalized).

    Lưu:
      - FAISS index file: {index_name}.index
      - Metadata JSON: {index_name}_metadata.json (map index position → chunk info)
    """
    try:
        from sentence_transformers import SentenceTransformer
        import faiss
    except ImportError as e:
        logger.error(f"Missing dependency: {e}. Run: pip install sentence-transformers faiss-cpu")
        raise

    # Load embedding model
    logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Extract text for embedding
    texts = [chunk['text'] for chunk in chunks]
    logger.info(f"Embedding {len(texts)} chunks...")

    # Embed
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True)
    embeddings = np.array(embeddings, dtype='float32')

    logger.info(f"Embeddings shape: {embeddings.shape}")

    # Build FAISS index (Inner Product = cosine similarity khi normalized)
    index = faiss.IndexFlatIP(EMBEDDING_DIM)
    index.add(embeddings)

    # Save index
    os.makedirs(INDEX_DIR, exist_ok=True)
    index_path = os.path.join(INDEX_DIR, f'{index_name}.index')
    faiss.write_index(index, index_path)
    logger.info(f"Saved FAISS index: {index_path} ({index.ntotal} vectors)")

    # Save metadata (map position → chunk info)
    metadata = []
    for i, chunk in enumerate(chunks):
        metadata.append({
            'index_position': i,
            'text': chunk['text'],
            **chunk['metadata']
        })

    metadata_path = os.path.join(INDEX_DIR, f'{index_name}_metadata.json')
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved metadata: {metadata_path} ({len(metadata)} entries)")

    return index


def build_all_indexes():
    """Build cả 2 FAISS indexes: MITRE ATT&CK + ISO 27001."""
    logger.info("=" * 60)
    logger.info("SENTINEL Knowledge Base Indexer")
    logger.info("=" * 60)

    # MITRE ATT&CK
    mitre_chunks = load_mitre_chunks()
    build_faiss_index(mitre_chunks, 'mitre_attack')

    # ISO 27001
    iso_chunks = load_iso_chunks()
    build_faiss_index(iso_chunks, 'iso_27001')

    logger.info("=" * 60)
    logger.info(f"All indexes built successfully in: {INDEX_DIR}")
    logger.info(f"Total vectors: {len(mitre_chunks) + len(iso_chunks)}")
    logger.info("=" * 60)


if __name__ == '__main__':
    build_all_indexes()
