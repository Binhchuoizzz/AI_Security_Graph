"""
Main Entry Point cho SENTINEL System

Khởi chạy và kết nối 2 Tier:
- Tier 1: Streaming (DataPublisher + Subscriber + RuleEngine)
- Tier 2: LangGraph Agent (Guardrails + RAG + LLM)
"""

import argparse
import logging

from dotenv import load_dotenv  # type: ignore

load_dotenv()  # Nạp các biến môi trường (Tăng cường bảo mật)

from src.agent.state import SentinelState
from src.agent.workflow import agent_app
from src.rag.graph_builder import KnowledgeGraphBuilder
from src.streaming.subscriber import start_listening
from src.tier1_filter.scanner import VulnerabilityScanner

# Cấu hình logging mặc định
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def setup_logger(log_level: str):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)


def run_vulnerability_scan():
    """Quét lỗ hổng dùng Trivy và nạp vào Neo4j (V2 Architecture)"""
    logger.info("[PIPELINE] Running Vulnerability Scan (Trivy)...")
    scanner = VulnerabilityScanner(target_dir="/app", output_file="data/trivy-results.json")
    results_path = scanner.run_scan()
    logger.info(f"[PIPELINE] Vulnerability Scan complete. Findings saved to {results_path}")


def build_knowledge_graph():
    """Xây dựng Knowledge Graph từ OSV/Trivy results (V2 Architecture)"""
    logger.info("[PIPELINE] Building Knowledge Graph (Neo4j)...")
    builder = KnowledgeGraphBuilder()
    builder.build_from_trivy(trivy_json_path="data/trivy-results.json")
    builder.close()
    logger.info("[PIPELINE] Knowledge Graph build complete.")


def handle_escalated_batch(batch):
    """
    Callback được gọi bởi Subscriber khi có một cụm log bị ESCALATE.
    """
    logger.info(
        f"[MAIN] Received ESCALATED batch of {len(batch)} logs from Tier 1. Triggering LangGraph..."
    )

    # Khởi tạo State cho LangGraph
    initial_state = SentinelState(
        current_batch_logs=batch, current_batch_size=len(batch), narrative_summary=""
    )

    # Reset LoopDetector trước mỗi lần chạy đồ thị
    from src.guardrails import loop_detector

    loop_detector.reset()

    try:
        final_state = agent_app.invoke(initial_state)
        logger.info("[MAIN] LangGraph execution completed.")

        decisions = final_state.get("decisions", [])
        if decisions:
            logger.info(
                f"[MAIN] Final Decision: {decisions[-1].get('action')} - {decisions[-1].get('reasoning')}"
            )

    except Exception as e:
        logger.error(f"[MAIN] LangGraph execution failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="SENTINEL System Entrypoint")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["server", "scan", "full"],
        default="server",
        help="Chế độ chạy: server (lắng nghe traffic), scan (quét lỗ hổng), full (cả hai)",
    )
    parser.add_argument(
        "--config", type=str, default="config/default.yaml", help="Đường dẫn file cấu hình"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Mức độ log",
    )
    args = parser.parse_args()

    setup_logger(args.log_level)

    logger.info("=" * 60)
    logger.info(f" SENTINEL SYSTEM INITIALIZING | MODE: {args.mode.upper()}")
    logger.info("=" * 60)

    # Nếu ở chế độ Full hoặc Scan, chạy Vulnerability Pipeline trước
    if args.mode in ["scan", "full"]:
        run_vulnerability_scan()
        build_knowledge_graph()
        if args.mode == "scan":
            logger.info("[MAIN] Scan complete. Exiting...")
            return

    # Chế độ Server / Full: Khởi chạy APT Detection Engine
    logger.info("[MAIN] Starting Tier 1 Subscriber Loop (APT Detection Engine)...")
    try:
        start_listening(on_batch_ready=handle_escalated_batch, batch_size=10, timeout_sec=5)
    except KeyboardInterrupt:
        logger.info("[MAIN] Shutting down SENTINEL system.")


if __name__ == "__main__":
    main()
