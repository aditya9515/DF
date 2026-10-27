# AI Agent Forensics and Audit Platform

A local LangGraph/Qwen agent with structured evidence capture, SHA-256 chains, Ed25519 checkpoints, an independent verifier, incident findings, and a Streamlit timeline viewer.

**Contribution:** connects each incident finding to preserved, verifiable agent events and evaluates exposure separately from proposed policy violations and completed simulated actions. The cryptographic primitives and detector baselines are established methods. The report documents the measured contribution and limitations.

## Reproduce the main result

On Windows, install [uv](https://docs.astral.sh/uv/getting-started/installation/), open PowerShell in the extracted project folder, and run:

```powershell
uv sync --frozen
uv run agent-forensics evaluate
uv run agent-forensics figures
uv run python scripts/validate_submission.py
```

These commands verify saved evidence and recompute all detector metrics and figures without downloading a model. Results are in `results/summary.json` and `results/tables/metrics.csv`. A convenience script is `scripts/reproduce.ps1`.

## Explore the evidence

```powershell
uv run agent-forensics dashboard
uv run agent-forensics verify results/evidence/injecagent-dh-0465-control-s42 --public-key results/public_key.pem
```

The dashboard opens at [localhost:8501](http://localhost:8501). It supports event inspection, findings, independent verification, incident-report downloads and evidence ZIP downloads. Invalid evidence is explicitly marked.

A verified example is saved in `results/exports/injecagent-ds-0298-attack-s42.zip`, with its event-linked incident analysis in `results/exports/illustrative_incident.json`. Verify the ZIP with the independent public key using the same `verify` command. `docs/verification.json` records the successful fresh-environment reproduction check and exact matching table hashes.

## Generate new live sessions

The tested setup uses Python 3.12, about 16 GB RAM and an RTX 3050 Laptop GPU with 4 GB VRAM. The first model/runtime download is approximately 3.2 GB; weights and runtime archives have pinned SHA-256 checksums.

```powershell
uv run agent-forensics fetch-model
uv run agent-forensics doctor
uv run agent-forensics serve-model --gpu-layers 24
```

Keep that terminal open. In a second terminal:

```powershell
uv run agent-forensics run --output-root output/live-rerun
uv run agent-forensics evaluate --root output/live-rerun
uv run agent-forensics dashboard --root output/live-rerun
```

A separate output root is necessary because the submitted private signing key is excluded. Fresh runs create their own keys and preserve the reference evidence. Use `--subset smoke --seed 42` for two pilot sessions; full generation runs 432 sessions and can take hours on a laptop. Lower `--gpu-layers` if necessary; zero enables CPU inference. Sampling seeds do not guarantee bit-identical GPU output.

## Dataset and evaluation

- [InjecAgent paper](https://aclanthology.org/2024.findings-acl.624/) and [source repository](https://github.com/uiuc-kang-lab/InjecAgent), revision `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`. Original 1,054 base cases and MIT notice are retained in `data/raw/injecagent`; provenance contains source URLs and checksums.
- Live study: 60 public attacks, 60 generated paired controls, and 24 controlled scenarios; seeds 42, 43, 44. Six public tool families form development and eleven form the test pool. Controls and seed repetitions stay with their original group.
- AgentDojo is related work and a future integration, not an evaluated dataset. Tools are simulated; model responses and decisions come from real local inference.
- Three frozen detectors are compared on identical evidence. Policy-only and combined action checks share the allowlist used to define action truth; their agreement does not establish semantic generalization.
- `uv run agent-forensics integrity-tests` regenerates nine corruption tests. `uv run agent-forensics overhead` runs the event benchmark and twelve paired live scenarios; run it while the model is otherwise idle.

## Report and submission

The editable report and PDF are in `output/report`. The dataset citation, runnable code, saved results/figures and this README accompany them in `output/submission/AI_Agent_Forensics_Submission.zip` after packaging.

The institution-approved **similarity report remains an external step**. Run the checker on the exact final report. Place the genuine result at `output/report/Similarity_Report.pdf`; record its report date, percentage, exclusions and matched sources, attach it according to institutional instructions, then run `uv run agent-forensics package`. Never substitute a fabricated certificate. The checklist records the attachment as pending until supplied.

To rebuild the DOCX independently, run `uv sync --frozen --extra report`, then `uv run python scripts/build_report.py`. Render it to PDF and rerun the builder with `--pagination PATH_TO_RENDERED_PDF`. Render once more and inspect every page. `scripts/prepare_renderer.py` provides an isolated Windows LibreOffice renderer without installing desktop Office. The final DOCX preserves the supplied template's logo, typography and page geometry.

## Trust and checks

Trusted public-key PEM SHA-256: `04c211ffb2f98e5149a23cedcd69d218fcb535ef33ca0e97c38b3e2ad76949a9`. Retain this fingerprint independently of a received bundle. Final manifests fix session identity, count and head; retain an expected manifest digest separately when substitution by another signed session is a concern.

```powershell
uv run pytest -q
uv run ruff check src tests scripts --select E9,F
uv run agent-forensics package
uv run python scripts/validate_submission.py --archive output/submission/AI_Agent_Forensics_Submission.zip
```

The ZIP manifest checks packaged files; it cannot establish trust if the entire archive and its checksum are replaced. Static-key compromise, dishonest capture, evidence destruction, host-clock trust and model internals are outside the prototype guarantee. See `docs/architecture.md` for the evidence contract and `docs/sources.json` for references.
