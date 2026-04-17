"""
RAG: Dual-RAG Retriever (MITRE ATT&CK + ISO 27001)

CHỨC NĂNG:
  Nhận query text (từ escalated log) → embed → search FAISS
  → trả context từ CẢ HAI knowledge bases (MITRE + ISO).

  Tích hợp SemanticCache: nếu query đã từng search, trả kết quả từ cache
  thay vì embed + FAISS search lại.

  Pipeline:
    query_text → SemanticCache.get()
                   ├── HIT  → return cached result
                   └── MISS → embed(query) → FAISS search (MITRE) → FAISS search (ISO)
                              → merge results → SemanticCache.put() → return

CÁCH DÙNG:
  from src.rag.retriever import DualRetriever
  retriever = DualRetriever()
  context = retriever.retrieve("brute force SSH port 22 multiple failed logins")
  print(context['mitre_context'])   # MITRE techniques found
  print(context['iso_context'])     # ISO controls recommended
  print(context['combined_prompt']) # Ready-to-use RAG prompt section
"""
import json
import os
import logging
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INDEX_DIR = os.path.join(BASE_DIR, 'knowledge_base', 'faiss_index')

# Defaults
DEFAULT_TOP_K = 3
EMBEDDING_MODEL = 'all-MiniLM-L6-v2'


class DualRetriever:
    """
    Dual-RAG Retriever: search MITRE ATT&CK + ISO 27001 song song.

    Supports ablation:
      - enabled_sources=["mitre", "iso"]  → Config F (Full)
      - enabled_sources=["mitre"]         → Config D (MITRE-only)
      - enabled_sources=["iso"]           → Config E (ISO-only)
      - enabled_sources=[]                → Config A (No RAG)
    """

    def __init__(self, enabled_sources: list[str] = None, top_k: int = DEFAULT_TOP_K,
                 use_cache: bool = True):
        """
        Args:
            enabled_sources: List of RAG sources to enable. Default: ["mitre", "iso"]
            top_k: Number of top results per source.
            use_cache: Whether to use SemanticCache.
        """
        try:
            from sentence_transformers import SentenceTransformer
            import faiss
        except ImportError as e:
            logger.error(f"Missing dependency: {e}. Run: pip install sentence-transformers faiss-cpu")
            raise

        self.enabled_sources = enabled_sources or ["mitre", "iso"]
        self.top_k = top_k
        self.faiss = faiss

        # Load embedding model (same as used for indexing)
        logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
        self.model = SentenceTransformer(EMBEDDING_MODEL)

        # Load FAISS indexes + metadata
        self.indexes = {}
        self.metadata = {}

        if "mitre" in self.enabled_sources:
            self._load_index("mitre", "mitre_attack")

        if "iso" in self.enabled_sources:
            self._load_index("iso", "iso_27001")

        # Semantic Cache
        self.cache = None
        if use_cache:
            from src.rag.semantic_cache import SemanticCache
            self.cache = SemanticCache(max_size=500, ttl_seconds=1800)
            logger.info("SemanticCache enabled (max_size=500, TTL=1800s)")

        logger.info(f"DualRetriever initialized: sources={self.enabled_sources}, top_k={top_k}")

    def _load_index(self, source_key: str, index_name: str):
        """Load FAISS index + metadata từ disk."""
        index_path = os.path.join(INDEX_DIR, f'{index_name}.index')
        metadata_path = os.path.join(INDEX_DIR, f'{index_name}_metadata.json')

        if not os.path.exists(index_path):
            logger.warning(f"FAISS index not found: {index_path}. Run: python -m src.rag.embedder")
            return

        self.indexes[source_key] = self.faiss.read_index(index_path)
        with open(metadata_path, 'r', encoding='utf-8') as f:
            self.metadata[source_key] = json.load(f)

        logger.info(f"Loaded {source_key} index: {self.indexes[source_key].ntotal} vectors")

    def _search_single(self, query_embedding: np.ndarray, source_key: str) -> list[dict]:
        """
        Search một FAISS index, trả top_k results.
        Returns list of {text, score, metadata}.
        """
        if source_key not in self.indexes:
            return []

        index = self.indexes[source_key]
        meta = self.metadata[source_key]

        # Search
        scores, indices = index.search(query_embedding, min(self.top_k, index.ntotal))

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx == -1:  # FAISS returns -1 for empty slots
                continue
            entry = meta[idx]
            results.append({
                'text': entry['text'],
                'score': float(score),
                'source': source_key,
                'id': entry.get('id', ''),
                'name': entry.get('name', ''),
            })

        return results

    def retrieve(self, query_text: str) -> dict:
        """
        Main retrieval function.

        Args:
            query_text: Text to search for (e.g., escalated log summary).

        Returns:
            dict with keys:
              - mitre_results: list of MITRE matches
              - iso_results: list of ISO matches
              - mitre_context: formatted string of MITRE context
              - iso_context: formatted string of ISO context
              - combined_prompt: ready-to-inject RAG context for LLM prompt
              - cache_hit: whether result came from cache
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get(query_text)
            if cached['hit']:
                logger.debug("SemanticCache HIT")
                result = cached['result']
                result['cache_hit'] = True
                return result

        # Embed query
        query_embedding = self.model.encode(
            [query_text], normalize_embeddings=True
        ).astype('float32')

        # Search both indexes
        mitre_results = self._search_single(query_embedding, "mitre")
        iso_results = self._search_single(query_embedding, "iso")

        # Format context strings
        mitre_context = self._format_context(mitre_results, "MITRE ATT&CK")
        iso_context = self._format_context(iso_results, "ISO 27001")

        # Build combined prompt section
        combined_prompt = self._build_combined_prompt(mitre_context, iso_context)

        result = {
            'mitre_results': mitre_results,
            'iso_results': iso_results,
            'mitre_context': mitre_context,
            'iso_context': iso_context,
            'combined_prompt': combined_prompt,
            'cache_hit': False,
        }

        # Cache result
        if self.cache:
            self.cache.put(query_text, result)

        return result

    def _format_context(self, results: list[dict], source_name: str) -> str:
        """Format search results into readable context string."""
        if not results:
            return f"[{source_name}] No relevant matches found."

        lines = [f"[{source_name} Context — Top {len(results)} matches]"]
        for i, r in enumerate(results, 1):
            lines.append(f"\n--- Match {i} (Score: {r['score']:.3f}) ---")
            lines.append(r['text'])

        return "\n".join(lines)

    def _build_combined_prompt(self, mitre_context: str, iso_context: str) -> str:
        """
        Build RAG context section ready to inject into LLM prompt.
        Cấu trúc này sẽ nằm giữa System Prompt và Log Data trong Agent prompt.
        """
        parts = ["=== KNOWLEDGE BASE CONTEXT (RAG) ==="]

        if mitre_context:
            parts.append("")
            parts.append(mitre_context)

        if iso_context:
            parts.append("")
            parts.append(iso_context)

        parts.append("")
        parts.append("=== END KNOWLEDGE BASE CONTEXT ===")

        return "\n".join(parts)

    def get_cache_stats(self) -> dict:
        """Trả về cache statistics cho MLflow logging."""
        if self.cache:
            return self.cache.get_stats()
        return {'cache_enabled': False}


# Quick test
if __name__ == '__main__':
    retriever = DualRetriever()

    test_queries = [
        "brute force SSH port 22 multiple failed login attempts",
        "SYN flood high packet count DDoS attack",
        "SQL injection in web application URI parameter",
        "lateral movement RDP internal network",
        "data exfiltration DNS tunneling unusual outbound traffic",
    ]

    for query in test_queries:
        print(f"\n{'='*70}")
        print(f"QUERY: {query}")
        print(f"{'='*70}")
        result = retriever.retrieve(query)

        print(f"\n--- MITRE Results ({len(result['mitre_results'])}) ---")
        for r in result['mitre_results']:
            print(f"  [{r['score']:.3f}] {r['id']} - {r['name']}")

        print(f"\n--- ISO Results ({len(result['iso_results'])}) ---")
        for r in result['iso_results']:
            print(f"  [{r['score']:.3f}] {r['id']} - {r['name']}")

        print(f"\nCache hit: {result['cache_hit']}")

    # Print cache stats
    print(f"\n{'='*70}")
    print(f"Cache Stats: {retriever.get_cache_stats()}")
