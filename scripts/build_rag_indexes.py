#!/usr/bin/env python3
"""
SENTINEL RAG Index Builder

Script wrapper gọi vào src.rag.embedder.build_all_indexes()
để build FAISS + BM25 indexes cho cả MITRE ATT&CK và NIST SP 800-61r2.

USAGE:
  python scripts/build_rag_indexes.py

OUTPUT:
  knowledge_base/faiss_index/
    ├── mitre_attack.index          (FAISS dense vectors)
    ├── mitre_attack_bm25.pkl       (BM25Okapi sparse index)
    ├── mitre_attack_metadata.json  (Chunk text + IDs)
    ├── nist_800_61r2.index
    ├── nist_800_61r2_bm25.pkl
    └── nist_800_61r2_metadata.json
"""

import os
import sys

# Đảm bảo thư mục gốc dự án nằm trong PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.rag.embedder import build_all_indexes

if __name__ == "__main__":
    print("=" * 60)
    print("SENTINEL RAG Index Builder")
    print("Building FAISS + BM25 indexes for Hybrid Search (RRF k=60)")
    print("=" * 60)
    build_all_indexes()
    print("\n✅ All indexes built successfully.")
