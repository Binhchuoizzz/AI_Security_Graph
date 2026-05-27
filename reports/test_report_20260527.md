# SENTINEL E2E Test Report

**Date:** 2026-05-27 16:17:39
**Result:** 19/20 PASSED | 0 FAILED | 1 SKIPPED

## Test Results

| # | Test Name | Status | Latency | Details |
|---|-----------|--------|---------|---------|
| T01 | Ground Truth File Valid | ✅ PASS | - | 750 samples loaded, structure valid |
| T02 | RAG Indexes Exist | ✅ PASS | - | All 6 index files present |
| T03 | DualRetriever Hybrid Search | ✅ PASS | 220.1ms | RAG search OK, context length=4014chars, latency=220.1ms |
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
| T16 | NIST Index Size (≥60 vectors) | ✅ PASS | - | NIST index: 193 vectors, 2/3 IR-phase queries matched |
| T17 | Ground Truth Scale (≥700) | ✅ PASS | - | Ground truth: 750 samples, 15 classes, all ≥20; adversarial: 45 |
| T18 | DAPT2020 APT Chain | ✅ PASS | - | DAPT2020: 197 multi-day chains, check_apt_chain verified |
| T19 | Latency Benchmark | ⏭️ SKIP | - | llama.cpp server not running on port 5000/8080 — run measure_latency_baseline.py... |
| T20 | rank_bm25 Import & Usage | ✅ PASS | - | rank_bm25 imports OK, BM25Okapi scoring verified, used in DualRetriever |

## Summary
- **Pass Rate:** 95.0%
- **Architecture Status:** ✅ THESIS READY