# SENTINEL E2E Test Report

**Date:** 2026-05-29 12:37:03
**Result:** 20/20 PASSED | 0 FAILED | 0 SKIPPED

## Test Results

| # | Test Name | Status | Latency | Details |
|---|-----------|--------|---------|---------|
| T01 | Ground Truth File Valid | ✅ PASS | - | 750 samples loaded, structure valid |
| T02 | RAG Indexes Exist | ✅ PASS | - | All 6 index files present |
| T03 | DualRetriever Hybrid Search | ✅ PASS | 203.9ms | RAG search OK, context length=4014chars, latency=203.9ms |
| T04 | Structural Sanitizer | ✅ PASS | - | Null bytes, zero-width chars stripped; truncation works |
| T05 | Prompt Injection Detector | ✅ PASS | - | Injection detected + no false positive on clean log |
| T06 | Jailbreak Detector | ✅ PASS | - | Jailbreak detected, isolation escalated to CRITICAL |
| T07 | Delimited Data Encapsulation | ✅ PASS | - | Dynamic delimiters + smuggling prevention verified |
| T08 | Encoding Neutralizer | ✅ PASS | - | URL decode + HTML escape working correctly |
| T09 | Output Sanitizer (Data Exfil) | ✅ PASS | - | Markdown/HTML exfil vectors stripped from LLM output |
| T10 | Tier 1 Static Rules | ✅ PASS | - | SSH port escalated (score=40), safe traffic dropped |
| T11 | Session Baseline Port Scan | ✅ PASS | - | Port scanning detected after 15 unique ports (score=65) |
| T12 | Whitelist IP Bypass | ✅ PASS | - | Whitelisted IP correctly bypassed all rules |
| T13 | Agent State MemoryObject | ✅ PASS | - | IOC dedup, decisions, memory formatting, batch reset all correct |
| T14 | Template Miner Compression | ✅ PASS | - | Compression: 100x, 1 templates from 100 logs |
| T15 | GuardrailsPipeline Integration | ✅ PASS | - | Pipeline processed 3 logs, 1 injections detected |
| T16 | NIST Index Size (≥60 vectors) | ✅ PASS | - | NIST index: 193 vectors, 2/3 IR-phase queries matched |
| T17 | Ground Truth Scale (≥700) | ✅ PASS | - | Ground truth: 750 samples, 15 classes, all ≥20; adversarial: 45 |
| T18 | DAPT2020 APT Chain | ✅ PASS | - | DAPT2020: 197 multi-day chains, check_apt_chain verified |
| T19 | Latency Benchmark | ✅ PASS | - | Latency reduction: 99.8% (target ≥60%) |
| T20 | rank_bm25 Import & Usage | ✅ PASS | - | rank_bm25 imports OK, BM25Okapi scoring verified, used in DualRetriever |

## Summary
- **Pass Rate:** 100.0%
- **Architecture Status:** ✅ THESIS READY