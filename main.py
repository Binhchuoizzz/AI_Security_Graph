"""
Main Entry Point cho SENTINEL System

Khởi chạy và kết nối 2 Tier:
- Tier 1: Streaming (DataPublisher + Subscriber + RuleEngine)
- Tier 2: LangGraph Agent (Guardrails + RAG + LLM)
"""

import argparse
import logging
import os

# PHẢI ĐẶT TRƯỚC MỌI IMPORT NẶNG. Thư viện nền (LightGBM/OpenMP, NumPy/BLAS) đọc các biến này
# ĐÚNG MỘT LẦN lúc nạp; đặt sau `import` là không có tác dụng.
#
# Vì sao cần: nhóm luồng OpenMP mặc định bằng số lõi máy và QUAY BẬN giữa các lượt dự đoán.
# Đường nóng ở đây là suy luận TỪNG DÒNG, chia cho 13 luồng không nhanh hơn — đo được subscriber
# ăn **1328% CPU** mà chỉ chạy **75 sự kiện/giây**, vì vòng đọc Redis bị chính nhóm luồng ấy
# tranh mất lõi. Xem `MLGateway._force_single_thread`.
#
# `setdefault` để người vận hành vẫn ghi đè được từ ngoài khi thật sự cần.
for _var in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

from dotenv import load_dotenv  # type: ignore  # noqa: E402

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
    """Quét lỗ hổng dùng Trivy và Bandit SAST."""
    logger.info("[PIPELINE] Running Vulnerability Scans (Trivy + Bandit)...")
    scanner = VulnerabilityScanner(
        target_dir=".",
        output_file="data/trivy-results.json",
        sast_output_file="data/bandit-results.json",
    )
    results_path = scanner.run_scan()
    sast_results_path = scanner.run_sast_scan()
    logger.info(
        f"[PIPELINE] Vulnerability Scans complete. Findings saved to {results_path} and {sast_results_path}"
    )


def build_knowledge_graph():
    """Xây dựng Knowledge Graph từ OSV/Trivy và Bandit results (V2 Architecture)"""
    logger.info("[PIPELINE] Building Knowledge Graph (Neo4j)...")
    builder = KnowledgeGraphBuilder()
    builder.build_from_trivy(trivy_json_path="data/trivy-results.json")
    builder.build_from_bandit(bandit_json_path="data/bandit-results.json")
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
    # Số worker Tier-2 song song (decouple LLM khỏi vòng đọc + dùng nhiều slot llama.cpp).
    # Mặc định 2 (khớp llama.cpp -np 2). Đặt SENTINEL_AGENT_WORKERS=1 để chạy an toàn tối đa
    # (1 luồng agent, vẫn decoupled) hoặc =0 để về hành vi ĐỒNG BỘ cũ.
    agent_workers = int(os.getenv("SENTINEL_AGENT_WORKERS", "2"))

    # Thời gian một IP được im lặng trước khi lô đang gom bị XẢ SỚM (dù chưa đủ `batch_size`).
    #
    # Mặc định 5 giây giữ nguyên cho mọi phép đo đã công bố. Nhưng ở luồng lớn, sự kiện của
    # cùng một IP đến THƯA, nên 5 giây xả ra toàn lô lẻ: đo tại mốc 184.238 sự kiện — 1.551 sự
    # kiện tới Tier-2 mà thành **981 lô**, tức 1,6 sự kiện mỗi lô. Mỗi lô là một lượt gọi LLM
    # ~19,2 giây, nên riêng cái đó nhân chi phí suy luận lên hơn 6 lần so với lô đầy 10.
    #
    # Nới thời gian chờ KHÔNG đổi `batch_size` (vẫn 10 log/lô như mọi số Tier-2 đã đo), chỉ
    # cho lô có cơ hội đầy trước khi bị xả.
    batch_timeout = int(os.getenv("SENTINEL_BATCH_TIMEOUT", "5"))
    logger.info(
        f"[MAIN] Starting Tier 1 Subscriber Loop "
        f"(agent_workers={agent_workers}, batch_timeout={batch_timeout}s)..."
    )
    try:
        start_listening(
            on_batch_ready=handle_escalated_batch,
            batch_size=10,
            timeout_sec=batch_timeout,
            agent_workers=agent_workers,
        )
    except KeyboardInterrupt:
        logger.info("[MAIN] Shutting down SENTINEL system.")


if __name__ == "__main__":
    main()
