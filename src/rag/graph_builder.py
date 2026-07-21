import json
import logging
import os
from datetime import datetime, timezone

from neo4j import GraphDatabase  # type: ignore
from neo4j.exceptions import ServiceUnavailable  # type: ignore

logger = logging.getLogger(__name__)


class KnowledgeGraphBuilder:
    """Xây dựng đồ thị tri thức (Knowledge Graph) trong Neo4j từ dữ liệu lỗ hổng bảo mật."""

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        # KHÔNG hardcode mật khẩu thật trong code (git track). Thiếu env -> giá trị
        # placeholder chắc chắn SAI để kết nối fail-loud thay vì lộ secret.
        self.password = os.getenv("NEO4J_PASSWORD", "set-NEO4J_PASSWORD-in-.env")
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

    def build_from_bandit(self, bandit_json_path="data/bandit-results.json"):
        """Đọc kết quả từ Bandit SAST và xây dựng các nút/cạnh trong đồ thị."""
        if not self.driver:
            logger.warning("No Neo4j connection. Running mock graph build for SAST.")
            return

        try:
            with open(bandit_json_path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.error(f"Failed to read Bandit results from {bandit_json_path}")
            return

        logger.info("Building Knowledge Graph from Bandit results...")
        with self.driver.session() as session:
            results = data.get("results", [])
            for result in results:
                target_file = result.get("filename", "Unknown")
                vuln_id = result.get("test_id", "Unknown")
                severity = result.get("issue_severity", "UNKNOWN")
                test_name = result.get("test_name", "Unknown")
                description = result.get("issue_text", "")[:200]

                session.run(
                    "MERGE (t:SubComponent {name: $name}) "
                    "MERGE (c:Component {name: 'SENTINEL_SOC'}) "
                    "MERGE (c)-[:CONTAINS]->(t)",
                    name=target_file,
                )

                session.run(
                    "MERGE (v:Vulnerability {id: $vuln_id}) "
                    "SET v.severity = $severity, v.package = $test_name, v.description = $description, v.type = 'SAST' "
                    "MERGE (t:SubComponent {name: $target}) "
                    "MERGE (t)-[:HAS_VULNERABILITY]->(v)",
                    vuln_id=vuln_id,
                    severity=severity,
                    test_name=test_name,
                    description=description,
                    target=target_file,
                )

            # Đếm số lượng nút
            result_count = session.run("MATCH (n) RETURN count(n) as count")
            single_result = result_count.single()
            count = single_result["count"] if single_result else 0
            logger.info(f"Knowledge Graph updated (SAST). Total nodes: {count}")

    def _mock_build(self):
        """Ghi lại SỰ THẬT rằng không dựng được đồ thị vì Neo4j ngoại tuyến.

        KHÔNG BỊA SỐ. Bản trước ghi cứng `{"nodes": 450, "edges": 1200}` kèm nhãn
        "Mocked Successfully" — hai con số đó không đến từ bất kỳ phép đếm nào. File nằm
        trong data/ nên bất kỳ ai (hoặc bất kỳ đoạn code nào về sau) nhặt lên đều sẽ
        tưởng là kết quả đo thật. Đây là bẫy trích dẫn số giả vào luận văn.
        """
        logger.warning(
            "[KG] KHÔNG dựng được đồ thị tri thức — Neo4j ngoại tuyến. "
            "Ghi trạng thái 'unavailable' (KHÔNG có số liệu để báo cáo)."
        )
        os.makedirs("data/demo_outputs", exist_ok=True)
        with open("data/demo_outputs/knowledge_graph.json", "w") as f:
            json.dump(
                {
                    "status": "unavailable",
                    "reason": "Neo4j unreachable — no graph was built",
                    "nodes": None,
                    "edges": None,
                    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
                f,
                indent=1,
            )
