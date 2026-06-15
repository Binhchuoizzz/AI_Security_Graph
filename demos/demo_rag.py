import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rag.retriever import DualRetriever

# Khởi tạo DualRetriever
print("[*] Đang nạp cơ sở dữ liệu Vector Index (FAISS + BM25)... Vui lòng đợi...")
retriever = DualRetriever(use_cache=True)

print("==========================================================")
print("📚 DEMO 5: RAG — DUAL-RAG HYBRID SEARCH (MITRE & NIST)")
print("==========================================================\n")

query = "brute force SSH login password attempt port 22"
print(f"Truy vấn mạng: '{query}'\n")

# Thực hiện tìm kiếm hỗn hợp
result = retriever.retrieve(query)

print("=== MITRE ATT&CK CONTEXT (500 ký tự đầu) ===")
print(f"{result['mitre_context'][:500]}\n")

print("=== NIST SP 800-61r2 CONTEXT (500 ký tự đầu) ===")
print(f"{result['nist_context'][:500]}")
print("==========================================================")
