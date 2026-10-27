# AI Agent Forensics and Audit Platform

A local Qwen/LangGraph agent with evidence capture, SHA-256 chains, Ed25519 checkpoints, independent verification, incident reconstruction and a Streamlit dashboard.

**Contribution:** links incident findings to verifiable raw events and evaluates malicious-content exposure separately from proposed policy violations and completed simulated actions. The measured contribution is the working integration and evaluation of established primitives and baselines.

Measured study: **432 live sessions**, 432 valid evidence bundles, 100% receipt coverage, and 9/9 corruption variants rejected. Held-out exposure F1 is 0.378; recall is 23.3%, so the detector is limited triage. All 18 bounded-execution failures remain in the results.

## Reproduce the main result

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run from the extracted project folder in PowerShell:

```powershell
uv sync --frozen
uv run agent-forensics evaluate
uv run agent-forensics figures
uv run python scripts/validate_submission.py
```

This verifies saved evidence and recomputes metrics and figures without downloading a model or using an API key. Results are in `results/summary.json` and `results/tables/metrics.csv`. A convenience script is `scripts/reproduce.ps1`.

```powershell
uv run agent-forensics dashboard
```

Open [localhost:8501](http://localhost:8501) for timelines, findings, verification, destination/marker observations and evidence downloads.

## Regenerate live evidence

The tested laptop has about 16 GB RAM and an RTX 3050 with 4 GB VRAM. Initial model/runtime downloads total about 3.2 GB and are checksum-verified.

```powershell
uv run agent-forensics fetch-model
uv run agent-forensics serve-model --gpu-layers 24
```

Leave the server running. In another terminal:

```powershell
uv run agent-forensics run --output-root output/live-rerun
uv run agent-forensics evaluate --root output/live-rerun
```

Use `--subset smoke --seed 42` for a short pilot. Full generation contains 432 sessions and can take hours. A separate output root creates new signing keys and preserves reference evidence. Seeded GPU output need not be identical.

## Data and submission

[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), revision `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, supplies 1,054 retained base cases under its MIT notice. The live study uses 60 attacks, 60 generated paired controls and 24 controlled scenarios across three seeds. Source URLs, citation and checksums are in `data/provenance.json`. AgentDojo is related work only.

The DOCX/PDF is in `output/report`; the ZIP is in `output/submission`. The genuine **institution-approved similarity report remains your external step**, as agreed. Run it on the exact final document and attach the returned report. The checklist records it as pending.

```powershell
uv run pytest -q
uv run agent-forensics package
uv run python scripts/validate_submission.py --archive output/submission/AI_Agent_Forensics_Submission.zip
```

Trusted public-key PEM SHA-256: `04c211ffb2f98e5149a23cedcd69d218fcb535ef33ca0e97c38b3e2ad76949a9`. Retain this fingerprint independently. Private keys, weights and environments are excluded from the ZIP.

See [reproduction details](docs/reproduction.md) and [architecture and limitations](docs/architecture.md). Tools are simulated; model decisions are real. Shared-policy action scores validate reconstruction rather than semantic generalization. Static-key compromise and dishonest capture remain outside the guarantee.
