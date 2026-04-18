"""
Unit Tests for Guardrails (PromptFilter)
"""
import pytest
from src.guardrails.prompt_filter import PromptFilter

def test_sanitize_and_encapsulate():
    pf = PromptFilter()
    
    malicious_input = "SELECT * FROM users; <script>alert(1)</script>"
    
    output = pf.sanitize_and_encapsulate(malicious_input)
    
    assert "<escalated_log_data_v1>" in output
    assert "</escalated_log_data_v1>" in output
    assert "SELECT * FROM users" in output
    # Đảm bảo <script> không phá vỡ XML delimiter bằng cách nào đó.
    # Chi tiết assert sẽ phụ thuộc vào implementation của PromptFilter.
    assert "alert(1)" in output

def test_empty_input():
    pf = PromptFilter()
    assert pf.sanitize_and_encapsulate("") == "<escalated_log_data_v1>\n\n</escalated_log_data_v1>"
