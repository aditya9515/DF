import copy
import json
from pathlib import Path
import random
import shutil
import time
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from .common import ROOT, append_jsonl, file_hash, load_json, read_jsonl, save_json, sha
from .agent import run_session
from .analysis import analyze
from .evidence import Recorder, ZERO, verify


def run_batch(root=ROOT, subset="all", limit=None, seeds=(42, 43, 44), endpoint="http://127.0.0.1:8081/v1"):
    root = Path(root)
    cases = load_json(root / "data/cases.json")
    if subset == "smoke":
        public = [c for c in cases if c["source"] == "InjecAgent-adapted"]
        cases = [public[0], public[1]]
        seeds = (42,)
    elif subset in ("development", "test"):
        cases = [c for c in cases if c["split"] == subset]
    if limit is not None:
        cases = cases[:limit]
    freeze = root / "configs/detector_freeze.json"
    detector_hash = file_hash(Path(__file__).with_name("analysis.py"))
    if freeze.exists() and load_json(freeze)["sha256"] != detector_hash:
        raise ValueError("Detector code changed after freeze")
    if not freeze.exists():
        save_json(
            freeze,
            {"sha256": detector_hash, "method": "Rules fixed before inference; no test-label tuning", "version": 1},
        )
    total = len(cases) * len(seeds)
    i = 0
    for split in ("development", "test"):
        for case in [c for c in cases if c["split"] == split]:
            for seed in seeds:
                outcome = run_session(case, seed, root, endpoint)
                i += 1
                print(
                    f"[{i}/{total}] {outcome['session_id']} {outcome['status']} {outcome['elapsed_s']:.1f}s violation={outcome['action_violation']}",
                    flush=True,
                )
                append_jsonl(
                    root / "results/progress.jsonl", {k: outcome[k] for k in ("session_id", "status", "elapsed_s")}
                )
    return total


def metric(y, p):
    precision, recall, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[False, True]).ravel()
    return {
        "accuracy": float(accuracy_score(y, p)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "n": len(y),
    }


def grouped_interval(rows, truth, prediction):
    groups = sorted(rows["group"].unique())
    rng = np.random.default_rng(42)
    values = []
    indexes = {g: rows.index[rows["group"] == g].to_numpy() for g in groups}
    for _ in range(500):
        idx = np.concatenate([indexes[g] for g in rng.choice(groups, len(groups), replace=True)])
        y = rows.loc[idx, truth]
        p = rows.loc[idx, prediction]
        tp = ((y == 1) & (p == 1)).sum()
        fp = ((y == 0) & (p == 1)).sum()
        fn = ((y == 1) & (p == 0)).sum()
        values.append(2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0)
    return [float(x) for x in np.percentile(values, [2.5, 97.5])]


def completeness(events, oracle):
    from collections import Counter

    executed = Counter(r["op_id"] for r in oracle if r["kind"] == "tool")
    expected = []
    for receipt in oracle:
        if receipt["kind"] == "tool":
            expected += [(receipt["op_id"], "tool_request"), (receipt["op_id"], "tool_result")]
        if receipt["kind"] == "model":
            expected += [
                (receipt["op_id"], "model_request"),
                (receipt["op_id"], "model_response" if receipt["ok"] else "model_error"),
            ]
            for proposal in receipt.get("proposals", []):
                op_id = proposal["id"]
                if executed[op_id]:
                    executed[op_id] -= 1
                else:
                    expected.append((op_id, "tool_request"))
    actual = [(e["payload"].get("op_id"), e["type"]) for e in events]
    remaining = list(actual)
    found = 0
    for pair in expected:
        if pair in remaining:
            found += 1
            remaining.remove(pair)
    return {
        "expected_receipts": len(expected),
        "captured_receipts": found,
        "receipt_completeness": found / len(expected) if expected else 0,
        "required_boundaries": all(
            t in [e["type"] for e in events]
            for t in ("session_start", "user_prompt", "retrieved_context", "session_end")
        ),
    }


def evaluate(root=ROOT):
    root = Path(root)
    rows = []
    checks = []
    counts = []
    snapshot = [(p, load_json(p)) for p in sorted((root / "results/outcomes").glob("*.json"))]
    snapshot = [(p, out) for p, out in snapshot if not out.get("measurement_only")]
    for path, out in snapshot:
        folder = root / "results/evidence" / out["session_id"]
        check = verify(folder, root / "results/public_key.pem")
        if check.get("session_id") != out["session_id"]:
            raise ValueError(f"Signed session substitution: {out['session_id']}")
        checks.append({"session_id": out["session_id"], **check})
        if not check["valid"]:
            raise ValueError(f"Cannot evaluate invalid evidence: {out['session_id']}")
        events = read_jsonl(folder / "events.jsonl")
        if events[0]["payload"].get("case_id") != out["case_id"]:
            raise ValueError("Outcome and signed case identity disagree")
        oracle = load_json(root / "results/oracles" / path.name)
        allowed = set(events[0]["payload"]["policy"]["allowed_tools"])
        oracle_violation = any(
            c["function"]["name"] not in allowed for r in oracle if r["kind"] == "model" for c in r.get("proposals", [])
        )
        if oracle_violation != out["action_violation"]:
            raise ValueError("Outcome and independently recorded proposals disagree")
        count = {"session_id": out["session_id"], **completeness(events, oracle)}
        counts.append(count)
        predictions = analyze(events)
        from .triage import incident_report

        save_json(root / "results/incidents" / path.name, incident_report(events))
        save_json(root / "results/findings" / path.name, predictions)
        for method, pred in predictions.items():
            rows.append(
                {
                    k: out[k]
                    for k in (
                        "session_id",
                        "source",
                        "source_id",
                        "split",
                        "group",
                        "category",
                        "seed",
                        "status",
                        "elapsed_s",
                        "attack_present",
                        "action_violation",
                        "safe_answer_completion_proxy",
                    )
                }
                | {
                    "method": method,
                    "predicted_attack": pred["attack_exposure"],
                    "predicted_violation": pred["action_violation"],
                }
            )
    if not rows:
        raise ValueError("No recorded sessions found")
    frame = pd.DataFrame(rows)
    metrics = []
    for (source, split, method), group in frame.groupby(["source", "split", "method"]):
        for task, truth, pred in (
            ("attack_exposure", "attack_present", "predicted_attack"),
            ("action_violation", "action_violation", "predicted_violation"),
        ):
            result = {
                "source": source,
                "split": split,
                "method": method,
                "task": task,
                **metric(group[truth], group[pred]),
            }
            result["f1_ci_low"], result["f1_ci_high"] = grouped_interval(group, truth, pred)
            metrics.append(result)
    destination = root / "results/tables"
    destination.mkdir(parents=True, exist_ok=True)
    frame.to_csv(destination / "predictions.csv", index=False)
    pd.DataFrame(metrics).to_csv(destination / "metrics.csv", index=False)
    pd.DataFrame(counts).to_csv(destination / "completeness.csv", index=False)
    outcomes = [out for _, out in snapshot]
    failures = [o for o in outcomes if o["status"] != "completed"]
    save_json(
        root / "results/summary.json",
        {
            "sessions": len(outcomes),
            "completed": len(outcomes) - len(failures),
            "failed": len(failures),
            "failure_reasons": {
                r: sum(o["failure"] == r for o in failures) for r in sorted({o["failure"] for o in failures})
            },
            "policy_violating_sessions": sum(o["action_violation"] for o in outcomes),
            "safe_answer_completion_proxy": sum(o["safe_answer_completion_proxy"] for o in outcomes) / len(outcomes),
            "integrity_passed": sum(c["valid"] for c in checks),
            "receipt_completeness": sum(c["captured_receipts"] for c in counts)
            / sum(c["expected_receipts"] for c in counts),
            "all_required_boundaries": all(c["required_boundaries"] for c in counts),
            "metrics": metrics,
            "prediction_sha256": file_hash(destination / "predictions.csv"),
            "live_inference": True,
        },
    )
    save_json(root / "results/verification.json", checks)
    return load_json(root / "results/summary.json")


def tamper_experiment(root=ROOT):
    root = Path(root)
    source = next((root / "results/evidence").glob("*"))
    trusted = root / "results/public_key.pem"
    events = read_jsonl(source / "events.jsonl")
    cases = {}
    changed = copy.deepcopy(events)
    changed[2]["payload"]["tampered"] = True
    cases["payload_edit"] = changed
    cases["middle_deletion"] = events[:2] + events[3:]
    cases["tail_deletion"] = events[:-1]
    cases["insertion"] = events[:2] + [events[1]] + events[2:]
    changed = copy.deepcopy(events)
    changed[1], changed[2] = changed[2], changed[1]
    cases["reordering"] = changed
    changed = copy.deepcopy(events)
    changed[2]["payload"]["tampered"] = True
    previous = ZERO
    for e in changed:
        e["previous_hash"] = previous
        e["hash"] = sha({k: v for k, v in e.items() if k != "hash"})
        previous = e["hash"]
    cases["rewritten_chain"] = changed
    results = [{"mutation": "intact_control", "expected_valid": True, "detected": False, **verify(source, trusted)}]
    for name, altered in list(cases.items()) + [
        ("signature_change", events),
        ("wrong_key", events),
        ("checkpoint_removal", events),
    ]:
        destination = root / "results/tampered" / name
        destination.mkdir(parents=True, exist_ok=True)
        for f in source.iterdir():
            if f.is_file():
                shutil.copy2(f, destination / f.name)
        (destination / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in altered), encoding="utf-8")
        keyfile = trusted
        if name == "signature_change":
            m = load_json(destination / "manifest.json")
            m["signature"] = "A" * 88
            save_json(destination / "manifest.json", m)
        if name == "wrong_key":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            keyfile = destination / "wrong_trusted.pem"
            keyfile.write_bytes(
                Ed25519PrivateKey.generate()
                .public_key()
                .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            )
        if name == "checkpoint_removal":
            (destination / "checkpoints.jsonl").write_text("", encoding="utf-8")
        checked = verify(destination, keyfile)
        results.append({"mutation": name, "expected_valid": False, "detected": not checked["valid"], **checked})
    save_json(root / "results/tamper_results.json", results)
    return results


def overhead_experiment(root=ROOT, live=True):
    root = Path(root)
    records = []
    bench = root / "tmp/overhead"
    bench.mkdir(parents=True, exist_ok=True)
    for repeat in range(5):
        start = time.perf_counter()
        with (bench / f"plain-{repeat}.jsonl").open("w", encoding="utf-8") as f:
            for i in range(1000):
                f.write(json.dumps({"sequence": i, "message": "benchmark", "payload": {"x": i}}) + "\n")
                f.flush()
        plain = time.perf_counter() - start
        target = bench / f"full-{repeat}-{time.time_ns()}"
        recorder = Recorder("benchmark", {}, target)
        start = time.perf_counter()
        for i in range(1000):
            recorder.emit("benchmark", "runner", {"x": i})
        recorder.finish("completed", {})
        full = time.perf_counter() - start
        records.append(
            {
                "repeat": repeat,
                "events": 1000,
                "plain_s": plain,
                "full_s": full,
                "extra_ms_per_event": 1000 * (full - plain) / 1000,
            }
        )
    save_json(root / "results/overhead_micro.json", records)
    if live:
        run_id = str(time.time_ns())
        cases = load_json(root / "data/cases.json")[:12]
        warmup = cases[0]
        run_session(warmup, 42, root, suffix=f"-warmup-{run_id}", instrumented=False)
        pairs = []
        rng = random.Random(42)
        for i, case in enumerate(cases):
            order = [False, True]
            rng.shuffle(order)
            outcomes = {}
            wall_times = {}
            for enabled in order:
                wall_start = time.perf_counter()
                result = run_session(case, 42, root, suffix=f"-overhead-{run_id}-{i}", instrumented=enabled)
                wall_times[enabled] = time.perf_counter() - wall_start
                outcomes[enabled] = result
                if enabled:
                    path = root / "results/outcomes" / f"{result['session_id']}.json"
                    result["measurement_only"] = True
                    save_json(path, result)
            pairs.append(
                {
                    "case_id": case["case_id"],
                    "run_id": run_id,
                    "plain_s": wall_times[False],
                    "full_s": wall_times[True],
                    "agent_plain_s": outcomes[False]["elapsed_s"],
                    "agent_full_s": outcomes[True]["elapsed_s"],
                    "plain_status": outcomes[False]["status"],
                    "full_status": outcomes[True]["status"],
                    "plain_tokens": outcomes[False]["total_tokens"],
                    "full_tokens": outcomes[True]["total_tokens"],
                    "order": order,
                }
            )
        save_json(root / "results/overhead_live.json", pairs)
    return records
