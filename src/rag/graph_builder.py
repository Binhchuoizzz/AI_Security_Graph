import json
import logging
import os
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

logger = logging.getLogger(__name__)

class KnowledgeGraphBuilder:
    """Builds a Knowledge Graph in Neo4j from vulnerability data"""

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "SentinelSecurePass2026!")
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
        """Reads Trivy results and builds graph nodes/edges"""
        if not self.driver:
            logger.warning("No Neo4j connection. Running mock graph build.")
            self._mock_build()
            return

        try:
            with open(trivy_json_path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.error(f"Failed to read Trivy results from {trivy_json_path}")
            return

        logger.info("Building Knowledge Graph from Trivy results...")
        with self.driver.session() as session:
            # 1. Clear existing vulnerability nodes to avoid duplicates on rescan
            session.run("MATCH (v:Vulnerability) DETACH DELETE v")
            
            # 2. Add System Component Node
            session.run(
                "MERGE (c:Component {name: $name}) "
                "SET c.type = 'Application'",
                name="SENTINEL_SOC"
            )

            results = data.get("Results", [])
            for result in results:
                target = result.get("Target", "Unknown")
                vulnerabilities = result.get("Vulnerabilities", [])
                
                # Create sub-component for the target (e.g. requirements.txt, Dockerfile)
                session.run(
                    "MERGE (t:SubComponent {name: $name}) "
                    "MERGE (c:Component {name: 'SENTINEL_SOC'}) "
                    "MERGE (c)-[:CONTAINS]->(t)",
                    name=target
                )

                for vuln in vulnerabilities:
                    vuln_id = vuln.get("VulnerabilityID")
                    severity = vuln.get("Severity")
                    pkg_name = vuln.get("PkgName")
                    description = vuln.get("Description", "")[:200] # Truncate

                    session.run(
                        "MERGE (v:Vulnerability {id: $vuln_id}) "
                        "SET v.severity = $severity, v.package = $pkg_name, v.description = $description "
                        "MERGE (t:SubComponent {name: $target}) "
                        "MERGE (t)-[:HAS_VULNERABILITY]->(v)",
                        vuln_id=vuln_id, severity=severity, pkg_name=pkg_name, 
                        description=description, target=target
                    )
                    
            # Count nodes
            result = session.run("MATCH (n) RETURN count(n) as count")
            count = result.single()["count"]
            logger.info(f"Knowledge Graph updated. Total nodes: {count}")
            
    def _mock_build(self):
        """Mock behavior for offline or missing Neo4j demo"""
        logger.info("Generating mock Knowledge Graph output (Neo4j unreachable)")
        os.makedirs("demo_outputs", exist_ok=True)
        with open("demo_outputs/knowledge_graph.json", "w") as f:
            f.write('{"nodes": 450, "edges": 1200, "status": "Mocked Successfully"}')
