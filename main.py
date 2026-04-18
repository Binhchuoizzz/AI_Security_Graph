"""
Main Entry Point cho SENTINEL System

Khởi chạy và kết nối 2 Tier:
- Tier 1: Streaming (DataPublisher + Subscriber + RuleEngine)
- Tier 2: LangGraph Agent (Guardrails + RAG + LLM)
"""
import sys
import os
import threading
import subprocess
import time
import logging

from src.streaming.subscriber import start_listening
from src.agent.workflow import agent_app
from src.agent.state import SentinelState

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_publisher():
    """Chạy DataPublisher ở một process độc lập để bắn log vào Redis"""
    logger.info("[MAIN] Starting DataPublisher...")
    publisher_path = os.path.join(os.path.dirname(__file__), "src", "streaming", "publisher.py")
    
    # Chạy publisher script (nó sẽ đọc CSV và đẩy vào Redis liên tục)
    # Giả định publisher_path có thể chạy trực tiếp
    try:
        subprocess.run([sys.executable, publisher_path], check=True)
    except Exception as e:
        logger.error(f"[MAIN] Publisher process exited: {e}")


def handle_escalated_batch(batch):
    """
    Callback được gọi bởi Subscriber khi có một cụm log bị ESCALATE.
    """
    logger.info(f"[MAIN] Received ESCALATED batch of {len(batch)} logs from Tier 1. Triggering LangGraph...")
    
    # Khởi tạo State cho LangGraph
    initial_state = SentinelState(
        current_batch_logs=batch,
        current_batch_size=len(batch),
        narrative_summary=""
    )
    
    try:
        final_state = agent_app.invoke(initial_state)
        logger.info("[MAIN] LangGraph execution completed.")
        
        # Có thể kiểm tra actions của final_state ở đây, 
        # nhưng logic action đã được xử lý trong Action Executor Node
        decisions = final_state.get('decisions', [])
        if decisions:
            logger.info(f"[MAIN] Final Decision: {decisions[-1].get('action')} - {decisions[-1].get('reasoning')}")
            
    except Exception as e:
        logger.error(f"[MAIN] LangGraph execution failed: {e}")


def main():
    logger.info("=" * 60)
    logger.info(" SENTINEL SYSTEM INITIALIZING ")
    logger.info("=" * 60)
    
    # 1. Khởi chạy Publisher trên một thread riêng (tùy chọn, để dễ demo)
    # Nếu chạy thật, DataPublisher chạy ở server riêng. 
    # Trong mô hình này ta gộp chung cho tiện demo End-to-End.
    publisher_thread = threading.Thread(target=run_publisher, daemon=True)
    publisher_thread.start()
    
    # Đợi 2 giây cho Publisher và Redis khởi động ổn định
    time.sleep(2)
    
    # 2. Chạy Subscriber (Vòng lặp chính, block thread này)
    logger.info("[MAIN] Starting Tier 1 Subscriber Loop...")
    try:
        start_listening(
            on_batch_ready=handle_escalated_batch,
            batch_size=10,
            timeout_sec=5
        )
    except KeyboardInterrupt:
        logger.info("[MAIN] Shutting down SENTINEL system.")

if __name__ == "__main__":
    main()
