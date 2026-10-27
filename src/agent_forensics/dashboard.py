"""Streamlit viewer reads recorded evidence, not the mutable SQLite index."""

import io
import json
import zipfile
import pandas as pd
import streamlit as st
from agent_forensics.common import ROOT, load_json, read_jsonl
from agent_forensics.evidence import verify, custody
from agent_forensics.analysis import analyze
from agent_forensics.triage import incident_report
import os
from pathlib import Path

ROOT = Path(os.environ.get("AF_VIEW_ROOT", ROOT))

st.set_page_config(page_title="Agent Forensics", page_icon="🔎", layout="wide")
st.title("AI Agent Forensics & Audit Platform")
st.caption("Investigate local agent sessions with verifiable evidence and event-linked findings.")
summary_path = ROOT / "results/summary.json"
if summary_path.exists():
    summary = load_json(summary_path)
    cols = st.columns(4)
    for col, label, value in zip(
        cols,
        ["Recorded sessions", "Integrity checks passed", "Receipt completeness", "Failed sessions"],
        [summary["sessions"], summary["integrity_passed"], f"{summary['receipt_completeness']:.1%}", summary["failed"]],
    ):
        col.metric(label, value)
all_folders = [p for p in (ROOT / "results/evidence").glob("*") if p.is_dir()]
folders = sorted([p for p in all_folders if (p / "manifest.json").exists()])
pending = len(all_folders) - len(folders)
if pending:
    st.sidebar.caption(f"{pending} unfinished session(s) retained; finalized evidence shown below.")
if not folders:
    st.info("Run agent-forensics fetch-data, start the model, then run the smoke experiment.")
    st.stop()
search = st.sidebar.text_input("Filter session ID")
folders = [p for p in folders if search.lower() in p.name.lower()]
if not folders:
    st.warning("No matching sessions")
    st.stop()
folder = st.sidebar.selectbox("Session", folders, format_func=lambda p: p.name)
tabs = st.tabs(["Timeline", "Findings", "Verify or export", "Experiment results"])
events = read_jsonl(folder / "events.jsonl")
checked = verify(folder, ROOT / "results/public_key.pem")
if not checked["valid"]:
    st.error("Evidence integrity verification FAILED. Treat the following content as untrusted.")
elif not checked["complete"]:
    st.warning("Evidence is intact; this session ended in failure.")
else:
    st.success("Evidence chain, checkpoints, final manifest and trusted public key verified.")
with tabs[0]:
    st.dataframe(
        pd.DataFrame([{k: e[k] for k in ("sequence", "timestamp", "type", "actor", "event_id")} for e in events]),
        hide_index=True,
        width="stretch",
    )
    selected = st.selectbox(
        "Inspect event", range(len(events)), format_func=lambda i: f"{events[i]['sequence']} · {events[i]['type']}"
    )
    st.json(events[selected], expanded=2)
with tabs[1]:
    findings = analyze(events)
    annotations = incident_report(events)["observations"]
    st.json(findings["combined"], expanded=3)
    if annotations:
        st.json({"destination_and_marker_observations": annotations}, expanded=2)
    report = {
        "session_id": folder.name,
        "verification": checked,
        "findings": findings["combined"],
        "evidence_events": len(events),
        "observations": annotations,
    }
    st.download_button(
        "Download incident report",
        json.dumps(report, indent=2),
        file_name=folder.name + "-incident.json",
        mime="application/json",
    )
with tabs[2]:
    st.json(checked)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("events.jsonl", "manifest.json", "checkpoints.jsonl", "public_key.pem"):
            archive.write(folder / name, name)
        history = ROOT / "results/custody.jsonl"
        if history.exists():
            archive.write(history, "custody_snapshot.jsonl")
    st.download_button(
        "Download evidence bundle",
        buffer.getvalue(),
        file_name=folder.name + ".zip",
        mime="application/zip",
        on_click=lambda: custody("dashboard_evidence_download", folder / "manifest.json", ROOT),
    )
    uploaded = st.file_uploader("Verify an exported bundle against the project's trusted public key", type="zip")
    if uploaded:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            p = __import__("pathlib").Path(tmp) / "bundle.zip"
            p.write_bytes(uploaded.getvalue())
            result = verify(p, ROOT / "results/public_key.pem")
            st.json(result)
with tabs[3]:
    metrics = ROOT / "results/tables/metrics.csv"
    if metrics.exists():
        frame = pd.read_csv(metrics)
        split = st.selectbox("Evaluation split", ["test", "development"])
        st.dataframe(frame[frame.split == split], hide_index=True)
        for name in ("detector_comparison", "confusion_matrices", "integrity", "overhead"):
            p = ROOT / "results/figures" / f"{name}.png"
            if p.exists():
                st.image(str(p))
    else:
        st.info("Run agent-forensics evaluate after collecting sessions.")
