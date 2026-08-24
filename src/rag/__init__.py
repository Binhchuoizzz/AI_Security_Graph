"""
Truy xuất lai Dual-RAG trên kho MITRE ATT&CK và NIST SP 800-61r2.

Bao gom cac thanh phan:
- Embedder: Tao FAISS index tu knowledge base.
- Retriever: Hybrid Search (FAISS + BM25) voi RRF Fusion.
- SemanticCache: Cache ket qua embedding de giam latency.
- Security: Structural Sanitization chong RAG Poisoning.
"""
