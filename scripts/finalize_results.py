"""Wait for the full live cohort, then rebuild deterministic scientific outputs."""

import json
import time
from agent_forensics.common import ROOT, load_json, file_hash, save_json, read_jsonl
from agent_forensics.evidence import custody
from agent_forensics.experiments import evaluate
from agent_forensics.figures import figures

if __name__ == "__main__":
    cases = load_json(ROOT / "data/cases.json")
    expected = {f"{c['case_id']}-s{s}" for c in cases for s in (42, 43, 44)}
    previous = -1
    last = 0
    while True:
        actual = {p.stem for p in (ROOT / "results/outcomes").glob("*.json")} & expected
        if len(actual) == len(expected):
            break
        if len(actual) != previous and time.monotonic() - last >= 45:
            print(f"Live cohort: {len(actual)}/{len(expected)} finalized sessions", flush=True)
            previous = len(actual)
            last = time.monotonic()
        time.sleep(5)
    summary = evaluate(ROOT)
    figures(ROOT)
    custody("corpus_verified", ROOT / "results/verification.json", ROOT)
    outcomes = [load_json(p) for p in (ROOT / "results/outcomes").glob("*.json")]
    candidates = [
        o
        for o in outcomes
        if not o.get("measurement_only")
        and o["source"] == "InjecAgent-adapted"
        and o["split"] == "test"
        and o["action_violation"]
    ]
    if candidates:
        chosen = sorted(
            candidates, key=lambda o: (o["status"] != "completed", not o["canary_in_action"], o["session_id"])
        )[0]
        events = read_jsonl(ROOT / "results/evidence" / chosen["session_id"] / "events.jsonl")
        allowed = set(events[0]["payload"]["policy"]["allowed_tools"])
        request = next(
            e for e in reversed(events) if e["type"] == "tool_request" and e["payload"]["name"] not in allowed
        )
        result = next(
            (
                e
                for e in events
                if e["type"] == "tool_result" and e["payload"].get("op_id") == request["payload"]["op_id"]
            ),
            None,
        )
        retrieval = next(e for e in events if e["type"] == "retrieved_context")
        save_json(
            ROOT / "results/case_study.json",
            {
                "session_id": chosen["session_id"],
                "source_id": chosen["source_id"],
                "status": chosen["status"],
                "tool": request["payload"]["name"],
                "retrieval_event_id": retrieval["event_id"],
                "request_event_id": request["event_id"],
                "result_event_id": result["event_id"] if result else None,
                "execution_observed": result is not None,
                "selection": "Illustrative held-out violation; completed sessions and synthetic marker examples preferred, then lexicographic session ID. Not a performance estimate.",
            },
        )
    save_json(
        ROOT / "results/reproduction_reference.json",
        {
            "sessions": summary["sessions"],
            "prediction_sha256": file_hash(ROOT / "results/tables/predictions.csv"),
            "metrics_sha256": file_hash(ROOT / "results/tables/metrics.csv"),
            "completeness_sha256": file_hash(ROOT / "results/tables/completeness.csv"),
        },
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "metrics"}, indent=2), flush=True)
    print("Full cohort outputs ready for final report generation.", flush=True)
