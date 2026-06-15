import json
import logging
import os

from neo4j import GraphDatabase  # type: ignore
from neo4j.exceptions import ServiceUnavailable  # type: ignore

logger = logging.getLogger(__name__)


class KnowledgeGraphBuilder:
    """Xây dựng đồ thị tri thức (Knowledge Graph) trong Neo4j từ dữ liệu lỗ hổng bảo mật."""

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "SentinelGraphPass2026!")
        self.driver = None

        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            logger.info("Connected to Neo4j successfully.")
        except ServiceUnavailable as e:
            logger.warning(f"Could not connect to Neo4j: {e}")
            logger.warning("Graph building will be skipped or mocked.")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def build_from_trivy(self, trivy_json_path="data/trivy-results.json"):
        """Đọc kết quả từ Trivy và xây dựng các nút/cạnh trong đồ thị."""
        if not self.driver:
            logger.warning("No Neo4j connection. Running mock graph build.")
            self._mock_build()
            return

        try:
            with open(trivy_json_path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.error(f"Failed to read Trivy results from {trivy_json_path}")
            return

        logger.info("Building Knowledge Graph from Trivy results...")
        with self.driver.session() as session:
            # 1. Xóa các nút lỗ hổng cũ để tránh trùng lặp khi quét lại
            session.run("MATCH (v:Vulnerability) DETACH DELETE v")

            # 2. Thêm nút Thành phần Hệ thống (System Component Node)
            session.run(
                "MERGE (c:Component {name: $name}) SET c.type = 'Application'", name="SENTINEL_SOC"
            )

            results = data.get("Results", [])
            for result in results:
                target = result.get("Target", "Unknown")
                vulnerabilities = result.get("Vulnerabilities", [])

                # Tạo thành phần con (sub-component) cho target (ví dụ: requirements.txt, Dockerfile)
                session.run(
                    "MERGE (t:SubComponent {name: $name}) "
                    "MERGE (c:Component {name: 'SENTINEL_SOC'}) "
                    "MERGE (c)-[:CONTAINS]->(t)",
                    name=target,
                )

                for vuln in vulnerabilities:
                    vuln_id = vuln.get("VulnerabilityID")
                    severity = vuln.get("Severity")
                    pkg_name = vuln.get("PkgName")
                    description = vuln.get("Description", "")[:200]  # Cắt ngắn bớt

                    session.run(
                        "MERGE (v:Vulnerability {id: $vuln_id}) "
                        "SET v.severity = $severity, v.package = $pkg_name, v.description = $description "
                        "MERGE (t:SubComponent {name: $target}) "
                        "MERGE (t)-[:HAS_VULNERABILITY]->(v)",
                        vuln_id=vuln_id,
                        severity=severity,
                        pkg_name=pkg_name,
                        description=description,
                        target=target,
                    )

            # Đếm số lượng nút
            result = session.run("MATCH (n) RETURN count(n) as count")
            single_result = result.single()
            count = single_result["count"] if single_result else 0
            logger.info(f"Knowledge Graph updated. Total nodes: {count}")

    def _mock_build(self):
        """Cơ chế giả lập (mock) khi Neo4j ngoại tuyến hoặc thiếu demo."""
        logger.info("Generating mock Knowledge Graph output (Neo4j unreachable)")
        os.makedirs("demo_outputs", exist_ok=True)
        with open("demo_outputs/knowledge_graph.json", "w") as f:
            f.write('{"nodes": 450, "edges": 1200, "status": "Mocked Successfully"}')
