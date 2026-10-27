import json
from pathlib import Path
import typer
from .common import ROOT, read_jsonl

app = typer.Typer(help="Local AI agent evidence capture, verification and reproducible experiments.")


def show(value):
    typer.echo(json.dumps(value, indent=2, default=str))


@app.command()
def doctor():
    from .runtime import doctor

    show(doctor())


@app.command("fetch-data")
def fetch_data():
    from .data import fetch_data

    show(fetch_data())


@app.command("fetch-model")
def fetch_model():
    from .runtime import fetch_model

    fetch_model()


@app.command("serve-model")
def serve_model(gpu_layers: int = 24, background: bool = False):
    from .runtime import serve_model

    show(serve_model(gpu_layers=gpu_layers, background=background))


@app.command()
def run(subset: str = "all", limit: int | None = None, seed: int | None = None, output_root: Path | None = None):
    from .experiments import run_batch

    target = ROOT
    if output_root is not None:
        import shutil

        target = output_root.resolve()
        if target == ROOT.resolve():
            raise typer.BadParameter("Use a separate output root for regenerated evidence")
        if not (target / "data/cases.json").exists():
            shutil.copytree(ROOT / "data", target / "data", dirs_exist_ok=True)
        (target / "configs").mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "configs/model.json", target / "configs/model.json")
    show(
        {
            "sessions": run_batch(
                root=target, subset=subset, limit=limit, seeds=(seed,) if seed is not None else (42, 43, 44)
            )
        }
    )


@app.command()
def verify(bundle: Path, public_key: Path = ROOT / "results/public_key.pem"):
    from .evidence import verify, custody

    result = verify(bundle, public_key)
    artifact = bundle / "manifest.json" if bundle.is_dir() and (bundle / "manifest.json").exists() else bundle
    custody("evidence_verified" if result["valid"] else "evidence_verification_failed", artifact, ROOT)
    show(result)
    if not result["valid"]:
        raise typer.Exit(1)


@app.command()
def analyze(session: Path):
    from .triage import incident_report
    from .evidence import verify

    show(
        {
            "verification": verify(session, ROOT / "results/public_key.pem"),
            "analysis": incident_report(read_jsonl(session / "events.jsonl")),
        }
    )


@app.command()
def evaluate(root: Path = ROOT):
    from .experiments import evaluate

    result = evaluate(root)
    show({k: v for k, v in result.items() if k != "metrics"})


@app.command("integrity-tests")
def integrity_tests(root: Path = ROOT):
    from .experiments import tamper_experiment

    show(tamper_experiment(root))


@app.command()
def overhead(live: bool = True, root: Path = ROOT):
    from .experiments import overhead_experiment

    show(overhead_experiment(root=root, live=live))


@app.command()
def figures(root: Path = ROOT):
    from .figures import figures

    show(figures(root))


@app.command()
def package():
    from .packaging import package

    show(package())


@app.command()
def dashboard(root: Path = ROOT):
    import subprocess, sys
    import os

    env = dict(os.environ)
    env["AF_VIEW_ROOT"] = str(root.resolve())

    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(ROOT / "src/agent_forensics/dashboard.py"),
            "--server.address",
            "127.0.0.1",
            "--server.headless",
            "true",
        ],
        check=True,
        env=env,
    )


if __name__ == "__main__":
    app()
