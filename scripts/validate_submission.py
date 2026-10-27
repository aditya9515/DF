"""Validate scientific artifacts and a distributable archive; fail on incomplete work."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile
from agent_forensics.common import ROOT, file_hash, load_json
from agent_forensics.evidence import verify, verify_custody


def validate(root=ROOT, archive=None):
    root = Path(root)
    summary = load_json(root / "results/summary.json")
    cases = load_json(root / "data/cases.json")
    assert len(cases) == 144 and summary["sessions"] == 432, "Full planned experiment is required"
    expected = {f"{c['case_id']}-s{seed}" for c in cases for seed in (42, 43, 44)}
    outcomes = [load_json(p) for p in (root / "results/outcomes").glob("*.json")]
    outcomes = [o for o in outcomes if not o.get("measurement_only")]
    assert {o["session_id"] for o in outcomes} == expected, "Run IDs differ from planned manifest"
    public_key = root / "results/public_key.pem"
    for out in outcomes:
        result = verify(root / "results/evidence" / out["session_id"], public_key)
        assert result["valid"], (out["session_id"], result)
        assert result["session_id"] == out["session_id"], "Signed session substitution"
        assert result["complete"] == (out["status"] == "completed")
    assert verify_custody(root / "results/custody.jsonl", public_key)["valid"]
    assert summary["integrity_passed"] == 432
    mutations = load_json(root / "results/tamper_results.json")
    assert all(r["valid"] == r["expected_valid"] for r in mutations)
    assert len([r for r in mutations if not r["expected_valid"]]) == 9
    for source in load_json(root / "data/provenance.json")["files"]:
        assert file_hash(root / source["file"]) == source["sha256"], source["file"]
    for name in (
        "workflow",
        "dataset",
        "detector_comparison",
        "confusion_matrices",
        "integrity",
        "completeness",
        "overhead",
    ):
        assert (root / "results/figures" / f"{name}.png").stat().st_size > 1000
    report = load_json(root / "output/report/report_content.json")
    assert len(report["chapters"]) == 14
    assert 150 <= len(report["abstract"].split()) <= 200, "Abstract must contain 150-200 words"
    assert all(str(i) in report["chapters"] for i in range(1, 15))
    assert len(report["contents_pages"]) >= 27, "Final pagination map missing entries"
    assert report["reported_sessions"] == 432, "Report is based on a preliminary cohort"
    assert report["report_docx_sha256"] == file_hash(root / "output/report/Project_Report.docx")
    for name, digest in report["source_hashes"].items():
        assert file_hash(root / name) == digest, f"Report is stale relative to {name}"
    receipt = load_json(root / "output/report/render_receipt.json")
    assert receipt["visual_review_passed"], "Final visual report review is required"
    assert receipt["docx_sha256"] == file_hash(root / "output/report/Project_Report.docx")
    assert receipt["pdf_sha256"] == file_hash(root / "output/report/Project_Report.pdf")
    assert (
        file_hash(root / "references/Template.docx")
        == "bb61063470651d356a3071184fa07a3cf1339941e819e496ec7a421a43724950"
    )
    if archive:
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            manifest = json.loads(z.read("SHA256_MANIFEST.json"))
            assert len(names) == len(set(names))
            for name in names:
                path = Path(name)
                assert not path.is_absolute() and ".." not in path.parts
                assert not any(p in path.parts for p in (".private", ".models", ".venv", ".tools", "__pycache__"))
                payload = z.read(name)
                assert b"-----BEGIN PRIVATE KEY-----" not in payload.splitlines(), "Private key in submission"
                if name != "SHA256_MANIFEST.json":
                    assert hashlib.sha256(payload).hexdigest() == manifest[name], name
    print(
        json.dumps(
            {
                "valid": True,
                "sessions": len(outcomes),
                "intact_evidence": 432,
                "corruptions_rejected": 9,
                "archive_checked": bool(archive),
                "similarity_report_pending": not (root / "output/report/Similarity_Report.pdf").exists(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--archive", type=Path)
    a = p.parse_args()
    validate(a.root, a.archive)
