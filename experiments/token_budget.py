import tiktoken
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from src.agent.prompts import TRIAGE_SYSTEM_PROMPT
from src.rag.retriever import DualRetriever

def calculate_budget():
    # Sử dụng cl100k_base (chuẩn của OpenAI / tương tự độ dài tokenizer của llama/gemma)
    enc = tiktoken.get_encoding("cl100k_base")
    
    system_prompt_tokens = len(enc.encode(TRIAGE_SYSTEM_PROMPT))
    print(f"System Prompt Size: {system_prompt_tokens} tokens")
    
    # Truy xuất RAG context giả lập
    retriever = DualRetriever(use_cache=False)
    result = retriever.retrieve("brute force SSH port 22")
    rag_context = result['combined_prompt']
    
    rag_context_tokens = len(enc.encode(rag_context))
    print(f"RAG Context Size (Top 5 MITRE + Top 5 ISO): {rag_context_tokens} tokens")
    
    # Dữ liệu log giả lập
    log_data = "192.168.1.1 GET /api?id=1 HTTP/1.1 200\n" * 10
    log_data_tokens = len(enc.encode(log_data))
    print(f"Mock Log Data Size (10 lines): {log_data_tokens} tokens")
    
    total = system_prompt_tokens + rag_context_tokens + log_data_tokens
    print(f"\nTOTAL CONTEXT BUDGET: {total} tokens")
    print("Safe limit for Gemma 9B local: ~3000-4000 tokens")

if __name__ == "__main__":
    calculate_budget()
