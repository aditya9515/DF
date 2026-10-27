import json
import sqlite3
import pytest
from agent_forensics.common import read_jsonl, save_json
from agent_forensics.evidence import Recorder, verify, export_bundle, keys


@pytest.fixture
def evidence(tmp_path):
    r = Recorder("session", {"policy": {"allowed_tools": ["Read"]}}, tmp_path)
    for i in range(17):
        r.emit("tool_result", "sandbox", {"value": i})
    r.finish("completed", {})
    return tmp_path, r.directory


def test_roundtrip_and_sqlite_guard(evidence):
    root, folder = evidence
    assert verify(folder, root / "results/public_key.pem")["valid"]
    with sqlite3.connect(root / "results/catalog.sqlite") as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM events")


@pytest.mark.parametrize(
    "mutation", ["edit", "delete", "truncate", "insert", "swap", "rewrite", "signature", "checkpoint", "parent"]
)
def test_tampering_is_detected(evidence, mutation):
    root, folder = evidence
    events = read_jsonl(folder / "events.jsonl")
    if mutation == "edit":
        events[2]["payload"]["value"] = 99
    if mutation == "delete":
        events.pop(2)
    if mutation == "truncate":
        events.pop()
    if mutation == "insert":
        events.insert(2, events[1])
    if mutation == "swap":
        events[1], events[2] = events[2], events[1]
    if mutation == "parent":
        events[2]["parent_ids"] = ["missing"]
    if mutation == "rewrite":
        from agent_forensics.common import sha

        previous = "0" * 64
        events[2]["payload"]["value"] = 99
        for event in events:
            event["previous_hash"] = previous
            event["hash"] = sha({k: v for k, v in event.items() if k != "hash"})
            previous = event["hash"]
    if mutation == "signature":
        manifest = json.loads((folder / "manifest.json").read_text())
        manifest["signature"] = "AAAA"
        save_json(folder / "manifest.json", manifest)
    if mutation == "checkpoint":
        (folder / "checkpoints.jsonl").write_text("")
    (folder / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    assert not verify(folder, root / "results/public_key.pem")["valid"]


def test_wrong_key_and_missing_manifest(evidence, tmp_path):
    root, folder = evidence
    _, pem = keys(tmp_path / "other")
    assert not verify(folder, tmp_path / "other/results/public_key.pem")["valid"]
    (folder / "manifest.json").unlink()
    assert not verify(folder, root / "results/public_key.pem")["complete"]


def test_export_and_failed_status(evidence):
    root, folder = evidence
    destination = export_bundle(folder, root / "export.zip", root)
    assert verify(destination, root / "results/public_key.pem")["valid"]
    recorder = Recorder("failed", {}, root)
    recorder.finish("failed", {"reason": "timeout"})
    result = verify(recorder.directory, root / "results/public_key.pem")
    assert result["valid"] and not result["complete"]


def test_payload_is_snapshot(tmp_path):
    r = Recorder("snapshot", {}, tmp_path)
    payload = {"list": [1]}
    r.emit("example", "test", payload)
    payload["list"].append(2)
    r.finish("completed", {})
    assert verify(r.directory, tmp_path / "results/public_key.pem")["valid"]
    assert r.events[1]["payload"]["list"] == [1]


def test_refuses_overwrite(evidence):
    root, _ = evidence
    with pytest.raises(FileExistsError):
        Recorder("session", {}, root)


def test_recipient_export_uses_new_operator_key(evidence):
    from agent_forensics.evidence import verify_custody

    root, folder = evidence
    original_key = (root / "results/public_key.pem").read_bytes()
    (root / ".private/signing.pem").unlink()
    exported = export_bundle(folder, root / "recipient-export.zip", root)
    assert verify(exported, root / "results/public_key.pem")["valid"]
    operator = root / "output/operator_audit/results"
    assert verify_custody(operator / "custody.jsonl", operator / "public_key.pem")["valid"]
    assert (root / "results/public_key.pem").read_bytes() == original_key


@pytest.mark.parametrize("name", ["../escape", "..\\escape", "D:\\outside", "/absolute", ""])
def test_rejects_unsafe_session_ids(tmp_path, name):
    with pytest.raises(ValueError):
        Recorder(name, {}, tmp_path)
