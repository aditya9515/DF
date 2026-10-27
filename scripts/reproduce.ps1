$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
uv sync --frozen
if ($LASTEXITCODE -ne 0) { throw 'Dependency setup failed' }
uv run agent-forensics evaluate
if ($LASTEXITCODE -ne 0) { throw 'Evidence evaluation failed' }
uv run agent-forensics figures
if ($LASTEXITCODE -ne 0) { throw 'Figure generation failed' }
uv run python scripts/validate_submission.py
if ($LASTEXITCODE -ne 0) { throw 'Submission validation failed' }
