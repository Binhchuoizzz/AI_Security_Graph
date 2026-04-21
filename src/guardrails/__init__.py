"""
Module Guardrails: Bao ve LLM Agent khoi Prompt Injection va Data Corruption.

Bao gom cac thanh phan:
- PromptFilter: Phat hien va chan Prompt Injection (Pattern + Encoding + Delimiter).
- TemplateMiner: Nen volume log bang thuat toan Drain3 (simplified).
- DataValidator: Kiem tra schema va lam sach du lieu dau vao.
- StateMonitor: Giam sat Context Window, Infinite Loop va Audit Trail.
"""
