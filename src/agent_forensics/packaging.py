from pathlib import Path
import zipfile
from .common import ROOT, file_hash, load_json, save_json


def package(root=ROOT):
    root = Path(root)
    destination = root / "output/submission"
    destination.mkdir(parents=True, exist_ok=True)
    report_metadata = root / "output/report/report_content.json"
    render_receipt = root / "output/report/render_receipt.json"
    provenance_ok = False
    if report_metadata.exists() and render_receipt.exists() and (root / "results/summary.json").exists():
        metadata = load_json(report_metadata)
        receipt = load_json(render_receipt)
        provenance_ok = (
            metadata.get("reported_sessions") == 432
            and metadata.get("source_hashes", {}).get("results/summary.json")
            == file_hash(root / "results/summary.json")
            and receipt.get("visual_review_passed")
            and receipt.get("docx_sha256") == file_hash(root / "output/report/Project_Report.docx")
            and receipt.get("pdf_sha256") == file_hash(root / "output/report/Project_Report.pdf")
        )
    checklist = {
        "project_report_docx": (root / "output/report/Project_Report.docx").exists(),
        "project_report_pdf": (root / "output/report/Project_Report.pdf").exists(),
        "dataset_source_and_citation": (root / "data/provenance.json").exists(),
        "runnable_code_and_lock": (root / "uv.lock").exists() and (root / "src/agent_forensics/cli.py").exists(),
        "saved_results_and_figures": (root / "results/summary.json").exists()
        and (root / "results/figures/detector_comparison.png").exists(),
        "readme": (root / "README.md").exists(),
        "report_matches_reviewed_results": bool(provenance_ok),
        "full_planned_experiment": (root / "results/summary.json").exists()
        and load_json(root / "results/summary.json")["sessions"] == 432,
        "institution_similarity_report": (root / "output/report/Similarity_Report.pdf").exists(),
        "similarity_note": "Pending user-provided institution-approved report for the exact final document; not generated or fabricated.",
    }
    save_json(root / "SUBMISSION_CHECKLIST.json", checklist)
    technical = {k: v for k, v in checklist.items() if k not in ("institution_similarity_report", "similarity_note")}
    if not all(technical.values()):
        raise ValueError("Technical submission is incomplete: " + ", ".join(k for k, v in technical.items() if not v))
    folders = ["src", "scripts", "tests", "configs", "data", "results", "references", "docs", "output/report"]
    files = [
        root / name
        for name in (
            "pyproject.toml",
            "uv.lock",
            "README.md",
            "AGENTS.md",
            "PROJECT_CONTEXT.md",
            "SUBMISSION_CHECKLIST.json",
            "LICENSE",
        )
        if (root / name).exists()
    ]
    for folder in folders:
        files += [
            p
            for p in (root / folder).rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and p.suffix not in (".pyc", ".tmp")
            and not p.name.endswith((".sqlite-wal", ".sqlite-shm"))
        ]
    files = sorted(set(files))
    manifest = {str(p.relative_to(root)).replace("\\", "/"): file_hash(p) for p in files}
    save_json(destination / "SHA256_MANIFEST.json", manifest)
    archive = destination / "AI_Agent_Forensics_Submission.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in files:
            z.write(p, str(p.relative_to(root)))
        z.write(destination / "SHA256_MANIFEST.json", "SHA256_MANIFEST.json")
    save_json(
        destination / "package_receipt.json",
        {
            "archive": archive.name,
            "sha256": file_hash(archive),
            "file_count": len(files) + 1,
            "similarity_pending": not checklist["institution_similarity_report"],
        },
    )
    return str(archive)
