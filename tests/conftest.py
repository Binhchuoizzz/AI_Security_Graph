"""
Conftest: Đảm bảo project root nằm trong sys.path cho tất cả test files.
"""
import sys
import os

# Thêm project root vào sys.path để import src.* và scripts.* hoạt động
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
