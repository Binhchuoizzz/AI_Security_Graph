"""
LangGraph Test Script
"""
import sys
import os
import logging
from pprint import pprint

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

from src.agent.workflow import agent_app
from src.agent.state import SentinelState

def run_test():
    # Khởi tạo state với 1 batch log giả lập
    mock_logs = [
        {"timestamp": "2026-04-17T10:00:00Z", "src_ip": "10.0.0.5", "message": "Failed password for root", "port": 22},
        {"timestamp": "2026-04-17T10:00:01Z", "src_ip": "10.0.0.5", "message": "Failed password for admin", "port": 22},
        {"timestamp": "2026-04-17T10:00:02Z", "src_ip": "10.0.0.5", "message": "Failed password for user", "port": 22},
    ]
    
    initial_state = SentinelState(
        current_batch_logs=mock_logs,
        current_batch_size=len(mock_logs),
        narrative_summary=""
    )

    print("\n" + "="*50)
    print("STARTING LANGGRAPH WORKFLOW")
    print("="*50)
    
    # Chạy graph
    # LƯU Ý: Nếu Oobabooga không chạy, LLM Client sẽ timeout sau 3 lần retry 
    # và trả về AWAIT_HITL an toàn (nhờ 3-layer fallback)
    try:
        final_state = agent_app.invoke(initial_state)
        
        print("\n" + "="*50)
        print("WORKFLOW COMPLETED. FINAL STATE:")
        print("="*50)
        print(f"Narrative Summary:\n{final_state.get('narrative_summary', '')}")
        print("\nLatest Decision:")
        pprint(final_state.get('decisions', [{}])[-1])
        print("\nExtracted IOCs:")
        pprint(final_state.get('extracted_iocs', []))
        
    except Exception as e:
        print(f"\n[ERROR] Graph execution failed: {e}")

if __name__ == "__main__":
    run_test()
