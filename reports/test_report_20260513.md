# SENTINEL E2E Test Report

**Date:** 2026-05-13 08:49:56
**Result:** 15/15 PASSED | 0 FAILED | 0 SKIPPED

## Test Results

| # | Test Name | Status | Latency | Details |
|---|-----------|--------|---------|---------|
| T01 | Ground Truth File Valid | ✅ PASS | - | 141 samples loaded, structure valid |
| T02 | RAG Indexes Exist | ✅ PASS | - | All 6 index files present |
| T03 | DualRetriever Hybrid Search | ✅ PASS | 129.4ms | RAG search OK, context length=4014chars, latency=129.4ms |
| T04 | Structural Sanitizer | ✅ PASS | - | Null bytes, zero-width chars stripped; truncation works |
| T05 | Prompt Injection Detector | ✅ PASS | - | Injection detected + no false positive on clean log |
| T06 | Jailbreak Detector | ✅ PASS | - | Jailbreak detected, isolation escalated to CRITICAL |
| T07 | Delimited Data Encapsulation | ✅ PASS | - | Dynamic delimiters + smuggling prevention verified |
| T08 | Encoding Neutralizer | ✅ PASS | - | URL decode + HTML escape working correctly |
| T09 | Output Sanitizer (Data Exfil) | ✅ PASS | - | Markdown/HTML exfil vectors stripped from LLM output |
| T10 | Tier 1 Static Rules | ✅ PASS | - | SSH port escalated (score=240), safe traffic dropped |
| T11 | Session Baseline Port Scan | ✅ PASS | - | Port scanning detected after 15 unique ports (score=65) |
| T12 | Whitelist IP Bypass | ✅ PASS | - | Whitelisted IP correctly bypassed all rules |
| T13 | Agent State MemoryObject | ✅ PASS | - | IOC dedup, decisions, memory formatting, batch reset all correct |
| T14 | Template Miner Compression | ✅ PASS | - | Compression: 100x, 1 templates from 100 logs |
| T15 | GuardrailsPipeline Integration | ✅ PASS | - | Pipeline processed 3 logs, 1 injections detected |

## Summary
- **Pass Rate:** 100.0%
- **Architecture Status:** ✅ THESIS READY