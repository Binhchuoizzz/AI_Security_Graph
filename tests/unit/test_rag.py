import pytest  # type: ignore

from src.rag.graph_builder import KnowledgeGraphBuilder


def test_knowledge_graph_builder_initializes_without_crashing():
    # Khởi tạo được và chịu được khi thiếu Neo4j
    builder = KnowledgeGraphBuilder()
    assert builder is not None
    builder.close()


def test_embedder_class_exists():
    try:
        from src.rag.embedder import build_indexes  # noqa: F401

        assert True
    except ImportError:
        pytest.fail("build_indexes not found in src.rag.embedder")
