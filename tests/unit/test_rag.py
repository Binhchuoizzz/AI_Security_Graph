import pytest  # type: ignore

from src.rag.graph_builder import KnowledgeGraphBuilder


def test_knowledge_graph_builder_initializes_without_crashing():
    # It should initialize and handle missing Neo4j gracefully
    builder = KnowledgeGraphBuilder()
    assert builder is not None
    builder.close()


def test_embedder_class_exists():
    try:
        from src.rag.embedder import build_indexes  # noqa: F401

        assert True
    except ImportError:
        pytest.fail("build_indexes not found in src.rag.embedder")
