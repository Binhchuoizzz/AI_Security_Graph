"""
Minimal Viable Version - Đánh giá độ chính xác của LangGraph Agent.
Chạy trực tiếp pipeline trên tập ground truth nhỏ để test trước khi scale up.
"""
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent.workflow import agent_app
from src.agent.state import SentinelState

GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "ground_truth.json")

def load_ground_truth():
    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"[!] Không tìm thấy {GROUND_TRUTH_PATH}")
        return []
    with open(GROUND_TRUTH_PATH, 'r') as f:
        return json.load(f)

def run_evaluation():
    dataset = load_ground_truth()
    if not dataset:
        return

    print(f"[*] Bắt đầu chạy Evaluation trên {len(dataset)} mẫu ground truth...\n")
    
    correct_mitre = 0
    correct_action = 0
    total = len(dataset)

    for idx, sample in enumerate(dataset):
        print(f"--- Đánh giá Mẫu {sample['id']}: {sample['description']} ---")
        
        # Khởi tạo State với log giả lập từ ground truth
        initial_state = SentinelState(
            current_batch_logs=sample['logs'],
            current_batch_size=len(sample['logs']),
            narrative_summary=""
        )

        try:
            # Chạy LangGraph
            final_state = agent_app.invoke(initial_state)
            
            # Trích xuất quyết định cuối
            decisions = final_state.get('decisions', [])
            if not decisions:
                print("  [] Lỗi: LLM không đưa ra quyết định nào.")
                continue
                
            latest_decision = decisions[-1]
            pred_mitre = latest_decision.get('mitre_technique', '')
            pred_action = latest_decision.get('action', '')
            
            # Đánh giá MITRE Technique (Substring match vì LLM có thể trả 'T1110 - Brute Force')
            match_mitre = sample['expected_mitre_technique'] in pred_mitre
            if match_mitre:
                correct_mitre += 1
                
            # Đánh giá Action
            match_action = (sample['expected_action'] == pred_action)
            if match_action:
                correct_action += 1
                
            print(f"  Expected MITRE: {sample['expected_mitre_technique']} | Predicted: {pred_mitre} -> {'' if match_mitre else ''}")
            print(f"  Expected Action: {sample['expected_action']} | Predicted: {pred_action} -> {'' if match_action else ''}\n")

        except Exception as e:
            print(f"  [] Exception khi chạy graph: {e}\n")

    print("=" * 40)
    print("KẾT QUẢ ĐÁNH GIÁ (MINIMAL VIABLE)")
    print("=" * 40)
    print(f"MITRE Accuracy : {correct_mitre}/{total} ({(correct_mitre/total)*100:.1f}%)")
    print(f"Action Accuracy: {correct_action}/{total} ({(correct_action/total)*100:.1f}%)")

if __name__ == "__main__":
    run_evaluation()
