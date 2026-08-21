# SENTINEL

A two-tier SOC architecture that routes each event by decision cost. A deterministic O(1) stream
filter and a LightGBM gateway resolve the bulk of traffic; only the residue reaches a LangGraph
agent running a local LLM. Everything runs on-premises on a single RTX 4060 Ti (16 GB) — no cloud
service is called at any point.

Master's thesis, Software Engineering — Nguyen Duc Binh (24MSE13183, MSE23HN),
FSB Institute of Management & Technology, FPT University.
Supervisors: Dr. Bui Van Hieu, Dr. Dang Van Hieu.

## Results

Read straight from `experiments/results/*.json`. Every ratio is quoted with its denominator; the
caveats are part of the result, not footnotes to it.

| | Headline | Denominator and caveat |
| :--- | :--- | :--- |
| Offload & latency | 97.5% offload · 0.88 ms median | Offload is a property of the traffic mix, not a constant: 97.47% at a 9.77% attack base rate, 90.57% at 31.56%. Median drops 17,174.7 → 0.88 ms, but p95 gets **worse** (25,829 vs 21,434 ms) — escalated cases pay both tiers. |
| Adversarial & integrity | 100% injection resistance · 98.75% evasion resistance | 678/678 hard adversarial samples. Evasion measured on the hard `extreme_broad` mode only (1,023/1,036). The HMAC chain catches edits, insertions and mid-deletions 30/30 each — **but not tail truncation (0/30)**. |
| ATT&CK attribution | 80.0% retrieval-only · 68.0% full pipeline | Attribution is **worse with the reasoning tier than without it**; reported as a limitation, not hidden. The grounding shield fired on 9.26% of batches and blocked 76 ungroundable `BLOCK_IP` actions; 0/1,421 assertions went unanchored. |
| Triage & HITL | −84.24% analyst load at 95.0% threat coverage | As a binary classifier the reasoning tier is worthless (MCC 0.0, 99.55% FP on confirmations, n = 1,066 at a 7.5% true-alert rate). Its value is as a router: the deferred queue is 15.76% of volume and 6.03× enriched. |
| Reasoning quality | 3.78 / 5.0 mean | Cross-family LLM-as-judge, n = 1,052. Context precision is the weakest axis at 2.54, and only 11.2% of justifications cite a checkable log value. |

The 97.5% figure has a specific denominator: the 2026-08-05 build of the demo stream — 99,717
scored events, 9.77% attack, no CSIC 2010. The current `data/demo.json` is a later, larger rebuild
(496,885 events), so re-running the offload measurement today will not reproduce it. The 90.57%
figure on the 25,649-event benchmark stream is unaffected.

## Repository

| Path | Contents |
| :--- | :--- |
| `src/` | Runtime: `streaming/` · `tier1_filter/` · `guardrails/` · `rag/` · `agent/` · `response/` · `ui/` |
| `experiments/` | Benchmark harnesses and `results/*.json` — the source of every number above |
| `scripts/` | Dataset builders, demo runner, number/reference audits |
| `tests/` | 613 tests (609 pass, 4 skip without Redis) |
| `docs/Thesis/` | Thesis LaTeX (EN + VI), submitted PDF, defence deck |
| `docs/Codebase/` | Runtime walkthrough, operating guide, defence script and demo runbook |
| `ml_lab/`, `llm_lab/` | Gateway training; QLoRA scaffolding for the fine-tuning direction in future work |

A stage-by-stage walkthrough of the runtime path is in
[`docs/Codebase/learning/00_DOC_CODE_THEO_LUONG.md`](docs/Codebase/learning/00_DOC_CODE_THEO_LUONG.md).

## Thesis and defence

| Artifact | Path |
| :--- | :--- |
| Submitted thesis (PDF) | [`docs/Thesis/MSE23HN_NguyenDucBinh_24MSE13183.pdf`](docs/Thesis/MSE23HN_NguyenDucBinh_24MSE13183.pdf) |
| LaTeX source, EN / VI | [`thesis_latex_en`](docs/Thesis/latex/thesis_latex_en/) · [`thesis_latex_vi`](docs/Thesis/latex/thesis_latex_vi/) |
| Defence deck, 12 slides, offline HTML | [`docs/Thesis/slides/index.html`](docs/Thesis/slides/index.html) |
| Number audit ledger | [`thesis_number_audit.json`](experiments/results/thesis_number_audit.json) |

The two LaTeX builds are a token-for-token mirror: `audit_thesis_numbers.py` reports zero numeric
divergence between them.

## Running it

Linux, Python 3.10+, 32 GB RAM, ~50 GB disk, NVIDIA GPU with ≥ 16 GB VRAM.
Full operating guide: [`RUN_PROJECT.md`](docs/Codebase/guides/RUN_PROJECT.md).

```bash
python3.10 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # set SENTINEL_LOG_SECRET — there is no hardcoded fallback
python -m src.rag.embedder    # build FAISS + BM25 indexes
```

Build the demo stream, then launch. Order matters: `build_demo.py` reads `data/csic.json`, so
reversing the two silently yields a stream with no application-layer evidence.

```bash
python scripts/build_csic_dataset.py --limit 36000
python scripts/build_demo.py
UNIFIED_STREAM_DELAY=0 UNIFIED_STREAM_BATCH=500 ./scripts/run_demo.sh --fresh
```

Dashboard on `http://localhost:8501`. Use `--small` for a ~10,000-event stratified subset.

## Tests and audits

`SENTINEL_FREEZE_DYNAMIC_RULES=1` is required for every command below. Without it the ML gateway
writes hundreds of learned rules straight into the shared `config/system_settings.yaml`.

```bash
SENTINEL_FREEZE_DYNAMIC_RULES=1 pytest
python experiments/e2e_test_runner.py --offline     # functional harness, 15/15
python scripts/audit_thesis_numbers.py              # claim <-> result key <-> thesis text
python scripts/audit_metric_denominators.py         # denominator and saturation traps
```

## License

MIT — see [`LICENSE`](LICENSE). Citation metadata in [`CITATION.cff`](CITATION.cff).
